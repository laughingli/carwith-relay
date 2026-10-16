// Tesla CarWith 公网中继服务器 - 单文件零依赖版（适配 Glitch / Render / Railway）
// 部署：只需要上传这一个文件 + package.json（start: node relay-server.js）
// Leaflet CSS/JS 走 jsdelivr CDN，无需静态资源文件夹
// 架构：手机App -> WSS外连本中继；Tesla浏览器 -> HTTPS /c/<code> 加载车机页 -> WSS连本中继
//       中继仅转发JSON信令；高德瓦片从高德CDN直连，高德REST API由本服务端代理（绕过CORS）

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = process.env.PORT || 3000;

// ============ Session 管理 ============
const sessions = new Map();
const SESSION_TTL_MS = 2 * 60 * 60 * 1000;
const MAX_CAR_PER_SESSION = 3;

function genCode() {
    return String(Math.floor(100000 + Math.random() * 900000));
}
function touchSession(sid) {
    const s = sessions.get(sid);
    if (s) s.lastSeen = Date.now();
}
function cleanupSessions() {
    const now = Date.now();
    for (const [sid, s] of sessions.entries()) {
        const hasPhone = s.phoneWS && s.phoneWS.readyState === 1;
        const hasCars = [...s.carWSSet].some(ws => ws.readyState === 1);
        if (!hasPhone && !hasCars && now - s.lastSeen > SESSION_TTL_MS) {
            sessions.delete(sid);
            console.log(`[cleanup] session ${sid} expired`);
        }
    }
}
setInterval(cleanupSessions, 5 * 60 * 1000);

// ============ 简易 WebSocket 实现 ============
const WS_MAGIC = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
function wsAcceptKey(key) {
    return crypto.createHash('sha1').update(key + WS_MAGIC).digest('base64');
}
function sendWS(ws, data) {
    if (!ws || ws.readyState !== 1) return;
    try {
        const payload = Buffer.from(typeof data === 'string' ? data : JSON.stringify(data));
        const len = payload.length;
        let header;
        if (len < 126) {
            header = Buffer.alloc(2);
            header[0] = 0x81; header[1] = len;
        } else if (len < 65536) {
            header = Buffer.alloc(4);
            header[0] = 0x81; header[1] = 126;
            header.writeUInt16BE(len, 2);
        } else {
            header = Buffer.alloc(10);
            header[0] = 0x81; header[1] = 127;
            header.writeBigUInt64BE(BigInt(len), 2);
        }
        ws.socket.write(Buffer.concat([header, payload]));
    } catch (e) { console.error('[ws] send error', e.message); }
}
function closeWS(ws, code = 1000) {
    if (!ws || ws.readyState !== 1) return;
    try {
        ws.readyState = 3;
        const payload = Buffer.alloc(2);
        payload.writeUInt16BE(code, 0);
        const header = Buffer.from([0x88, 0x02]);
        ws.socket.write(Buffer.concat([header, payload]));
        ws.socket.end();
    } catch (_) {}
}
function handleWSUpgrade(req, socket, head, role, sid) {
    const key = req.headers['sec-websocket-key'];
    if (!key) { socket.destroy(); return; }
    const accept = wsAcceptKey(key);
    const resHeaders = [
        'HTTP/1.1 101 Switching Protocols',
        'Upgrade: websocket',
        'Connection: Upgrade',
        `Sec-WebSocket-Accept: ${accept}`,
        '\r\n'
    ];
    socket.write(resHeaders.join('\r\n'));
    socket.setTimeout(0);
    socket.setNoDelay(true);

    const ws = {
        socket, readyState: 1, role, sid,
        buffer: Buffer.alloc(0),
        ip: ((req.headers['x-forwarded-for'] || socket.remoteAddress || '').toString().split(',')[0].trim()).replace('::ffff:', '')
    };
    socket.on('data', (chunk) => {
        ws.buffer = Buffer.concat([ws.buffer, chunk]);
        processWSFrame(ws);
    });
    socket.on('close', () => handleWSClose(ws));
    socket.on('error', () => handleWSClose(ws));

    const session = sessions.get(sid);
    if (!session) { closeWS(ws, 1008); return; }
    if (role === 'phone') {
        if (session.phoneWS && session.phoneWS.readyState === 1) closeWS(session.phoneWS, 1000);
        session.phoneWS = ws;
        console.log(`[ws] phone connected session=${sid} ip=${ws.ip}`);
    } else {
        if (session.carWSSet.size >= MAX_CAR_PER_SESSION) { closeWS(ws, 1013); return; }
        session.carWSSet.add(ws);
        console.log(`[ws] car connected session=${sid} ip=${ws.ip} total=${session.carWSSet.size}`);
        sendWS(session.phoneWS, { type: 'car_connected', data: { count: session.carWSSet.size } });
    }
    broadcastSessionInfo(sid);
    touchSession(sid);
}
function processWSFrame(ws) {
    while (ws.buffer.length >= 2) {
        const b0 = ws.buffer[0], b1 = ws.buffer[1];
        const opcode = b0 & 0x0f;
        const masked = (b1 & 0x80) !== 0;
        let payloadLen = b1 & 0x7f;
        let offset = 2;
        if (payloadLen === 126) {
            if (ws.buffer.length < 4) return;
            payloadLen = ws.buffer.readUInt16BE(2);
            offset = 4;
        } else if (payloadLen === 127) {
            if (ws.buffer.length < 10) return;
            payloadLen = Number(ws.buffer.readBigUInt64BE(2));
            offset = 10;
        }
        if (!masked) { closeWS(ws, 1002); return; }
        if (ws.buffer.length < offset + 4 + payloadLen) return;
        const mask = ws.buffer.slice(offset, offset + 4);
        offset += 4;
        const payload = Buffer.alloc(payloadLen);
        for (let i = 0; i < payloadLen; i++) {
            payload[i] = ws.buffer[offset + i] ^ mask[i & 3];
        }
        ws.buffer = ws.buffer.slice(offset + payloadLen);

        if (opcode === 0x8) { closeWS(ws); return; }
        if (opcode === 0x9) {
            if (ws.readyState === 1) {
                try { ws.socket.write(Buffer.from([0x8A, 0x00])); } catch (_) {}
            }
            continue;
        }
        if (opcode === 0xA) continue;
        if (opcode === 0x1) handleWSMessage(ws, payload.toString('utf8'));
    }
}
function handleWSMessage(ws, text) {
    const sid = ws.sid;
    const session = sessions.get(sid);
    if (!session) return;
    touchSession(sid);
    try { JSON.parse(text); } catch (_) { return; }
    if (ws.role === 'phone') {
        for (const carWS of session.carWSSet) sendWS(carWS, text);
    } else {
        if (session.phoneWS && session.phoneWS.readyState === 1) sendWS(session.phoneWS, text);
    }
}
function handleWSClose(ws) {
    if (ws.readyState === 3) return;
    ws.readyState = 3;
    try { ws.socket.destroy(); } catch (_) {}
    const sid = ws.sid;
    const session = sessions.get(sid);
    if (!session) return;
    if (ws.role === 'phone') {
        if (session.phoneWS === ws) session.phoneWS = null;
        console.log(`[ws] phone disconnected session=${sid}`);
    } else {
        session.carWSSet.delete(ws);
        console.log(`[ws] car disconnected session=${sid} remain=${session.carWSSet.size}`);
        if (session.phoneWS) {
            sendWS(session.phoneWS, { type: 'car_disconnected', data: { count: session.carWSSet.size } });
        }
    }
    broadcastSessionInfo(sid);
}
function broadcastSessionInfo(sid) {
    const session = sessions.get(sid);
    if (!session) return;
    const info = {
        type: 'relay_info',
        data: {
            phoneOnline: !!(session.phoneWS && session.phoneWS.readyState === 1),
            carCount: session.carWSSet.size
        }
    };
    if (session.phoneWS) sendWS(session.phoneWS, info);
    for (const c of session.carWSSet) sendWS(c, info);
}

// ============ /api/ext 代理 (高德REST API CORS绕过) ============
function proxyExt(req, res, targetUrl) {
    try {
        const target = new URL(targetUrl);
        const lib = target.protocol === 'https:' ? https : http;
        const headers = {
            'User-Agent': 'Mozilla/5.0 (TeslaCarWith-Relay)',
            'Accept': 'application/json, */*',
            'Referer': 'https://www.amap.com/'
        };
        const preq = lib.request({
            hostname: target.hostname,
            port: target.port || (target.protocol === 'https:' ? 443 : 80),
            path: target.pathname + target.search,
            method: 'GET',
            headers,
            timeout: 10000
        }, (pres) => {
            const chunks = [];
            pres.on('data', c => chunks.push(c));
            pres.on('end', () => {
                const body = Buffer.concat(chunks);
                res.writeHead(pres.statusCode || 200, {
                    'Content-Type': 'application/json; charset=utf-8',
                    'Access-Control-Allow-Origin': '*',
                    'Cache-Control': 'no-cache'
                });
                res.end(body);
            });
        });
        preq.on('error', (e) => {
            res.writeHead(502, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ status: '0', info: 'PROXY_ERROR: ' + e.message }));
        });
        preq.on('timeout', () => { preq.destroy(); });
        preq.end();
    } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: '0', info: 'BAD_URL: ' + e.message }));
    }
}

// ============ 车机页面 HTML (内嵌，使用jsdelivr CDN加载Leaflet) ============
const CAR_HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>CarWith 云驾驶</title>
<link rel="stylesheet" href="https://cdn.staticfile.net/leaflet/1.9.4/leaflet.css" crossorigin="anonymous">
<script src="https://cdn.staticfile.net/leaflet/1.9.4/leaflet.js" crossorigin="anonymous"></script>
<style>
*{box-sizing:border-box;margin:0;padding:0;-webkit-user-select:none;user-select:none;-webkit-tap-highlight-color:transparent}
html,body{width:100%;height:100%;overflow:hidden;background:#0b1220;color:#e2e8f0;font-family:-apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif}
#map{position:absolute;inset:0;background:#0b1220}
.leaflet-container{background:#0b1220!important}
.dock{position:absolute;left:0;right:0;bottom:0;display:flex;align-items:center;justify-content:space-around;padding:14px 10px 18px;background:linear-gradient(180deg,rgba(10,15,30,0) 0%,rgba(10,15,30,0.85) 35%,rgba(10,15,30,0.95) 100%);z-index:500}
.app-ic{display:flex;flex-direction:column;align-items:center;gap:4px;width:64px;cursor:pointer;transition:transform .15s}
.app-ic:active{transform:scale(0.9)}
.app-ic .ic{width:44px;height:44px;border-radius:12px;background:linear-gradient(135deg,#3b82f6,#8b5cf6);display:flex;align-items:center;justify-content:center;font-size:22px;box-shadow:0 4px 10px rgba(59,130,246,0.3)}
.app-ic .ic.map{background:linear-gradient(135deg,#10b981,#06b6d4)}
.app-ic .ic.music{background:linear-gradient(135deg,#ec4899,#f43f5e)}
.app-ic .ic.qq{background:linear-gradient(135deg,#3b82f6,#60a5fa)}
.app-ic .ic.wyy{background:linear-gradient(135deg,#ef4444,#f97316)}
.app-ic .ic.dy{background:linear-gradient(135deg,#000,#333)}
.app-ic .ic.book{background:linear-gradient(135deg,#8b5cf6,#a78bfa)}
.app-ic.disabled{opacity:0.45;pointer-events:none;position:relative}
.app-ic .label{font-size:11px;color:#cbd5e1}
.topbar{position:absolute;top:0;left:0;right:0;padding:10px 14px;display:flex;justify-content:space-between;align-items:flex-start;z-index:500;background:linear-gradient(180deg,rgba(10,15,30,0.8),transparent);pointer-events:none}
.topbar > *{pointer-events:auto}
.badge{font-size:11px;padding:3px 9px;border-radius:10px;background:rgba(16,185,129,0.2);color:#10b981;border:1px solid rgba(16,185,129,0.4);display:flex;align-items:center;gap:4px}
.badge .dot{width:6px;height:6px;border-radius:50%;background:#10b981;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}
.search-bar{position:absolute;top:48px;left:14px;right:14px;display:flex;gap:8px;z-index:500}
.search-bar input{flex:1;padding:10px 14px;border-radius:12px;border:1px solid rgba(255,255,255,0.1);background:rgba(15,23,42,0.85);backdrop-filter:blur(10px);color:#fff;font-size:14px;outline:none;-webkit-user-select:text;user-select:text}
.search-bar input::placeholder{color:#64748b}
.search-bar button{padding:0 16px;border-radius:12px;border:none;background:linear-gradient(135deg,#3b82f6,#2563eb);color:#fff;font-size:14px;font-weight:600;cursor:pointer}
.vehicle-info{position:absolute;top:48px;right:14px;background:rgba(15,23,42,0.85);backdrop-filter:blur(10px);border-radius:12px;padding:8px 12px;border:1px solid rgba(255,255,255,0.08);z-index:500;font-size:12px}
.vehicle-info .row{display:flex;gap:6px;align-items:center;color:#94a3b8}
.vehicle-info .val{color:#fbbf24;font-weight:700;font-size:14px}
.music-card{position:absolute;top:90px;left:14px;right:120px;background:rgba(15,23,42,0.85);backdrop-filter:blur(10px);border-radius:12px;padding:10px 12px;border:1px solid rgba(255,255,255,0.08);z-index:500;display:none}
.music-card.on{display:flex;gap:10px;align-items:center}
.music-card .cover{width:44px;height:44px;border-radius:8px;background:linear-gradient(135deg,#ec4899,#8b5cf6);display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0}
.music-card .info{flex:1;min-width:0}
.music-card .title{font-size:13px;color:#fff;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.music-card .artist{font-size:11px;color:#94a3b8;margin-top:2px}
.music-card .ctrl{display:flex;gap:8px}
.music-card .ctrl button{background:rgba(255,255,255,0.1);border:none;color:#fff;width:30px;height:30px;border-radius:50%;font-size:14px;cursor:pointer;display:flex;align-items:center;justify-content:center}
.navi-card{position:absolute;top:14px;left:50%;transform:translateX(-50%);background:rgba(15,23,42,0.92);backdrop-filter:blur(12px);border-radius:14px;padding:12px 18px;border:1px solid rgba(59,130,246,0.4);z-index:500;display:none;max-width:80%;text-align:center}
.navi-card.on{display:block}
.navi-card .dir{font-size:24px;margin-bottom:4px}
.navi-card .name{font-size:13px;color:#fff;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.navi-card .dist{font-size:11px;color:#60a5fa;margin-top:4px}
#waitPhone{position:absolute;inset:0;background:rgba(0,0,0,0.8);display:flex;align-items:center;justify-content:center;flex-direction:column;z-index:1000;gap:14px}
#waitPhone .sp{width:40px;height:40px;border:3px solid rgba(59,130,246,0.3);border-top-color:#3b82f6;border-radius:50%;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
#waitPhone h3{color:#fff;font-size:17px;font-weight:600}
#waitPhone p{color:#94a3b8;font-size:13px;text-align:center;line-height:1.6;padding:0 30px}
#waitPhone .code{font-size:36px;font-weight:800;color:#60a5fa;letter-spacing:6px;margin:8px 0}
.toast{position:fixed;bottom:100px;left:50%;transform:translateX(-50%);background:rgba(0,0,0,0.85);color:#fff;padding:10px 20px;border-radius:20px;font-size:13px;z-index:2000;opacity:0;transition:opacity .3s;pointer-events:none}
.toast.on{opacity:1}
.search-results{position:absolute;top:92px;left:14px;right:70px;background:rgba(15,23,42,0.95);backdrop-filter:blur(12px);border-radius:12px;border:1px solid rgba(255,255,255,0.1);z-index:450;max-height:50vh;overflow-y:auto;display:none}
.search-results.on{display:block}
.search-results .item{padding:12px 14px;border-bottom:1px solid rgba(255,255,255,0.06);cursor:pointer}
.search-results .item:active{background:rgba(59,130,246,0.2)}
.search-results .item .nm{font-size:13px;color:#fff}
.search-results .item .ad{font-size:11px;color:#94a3b8;margin-top:2px}
.relay-badge{position:absolute;top:10px;right:14px;background:rgba(16,185,129,0.15);border:1px solid rgba(16,185,129,0.4);color:#10b981;padding:4px 10px;border-radius:10px;font-size:11px;font-weight:600;z-index:500;display:flex;align-items:center;gap:4px}
.leaflet-control-attribution{background:rgba(0,0,0,0.4)!important;color:#64748b!important;font-size:9px!important}
.leaflet-control-attribution a{color:#94a3b8!important}
.leaflet-control-zoom{display:none}
</style>
</head>
<body>
<div id="map"></div>
<div class="relay-badge"><span>☁️</span> 云连接</div>
<div class="vehicle-info" id="vehInfo" style="display:none">
  <div class="row"><span>🚗</span><span class="val" id="spdVal">0</span><span>km/h</span></div>
</div>
<div class="navi-card" id="naviCard">
  <div class="dir" id="naviDir">↑</div>
  <div class="name" id="naviName"></div>
  <div class="dist" id="naviDist"></div>
</div>
<div class="music-card" id="musicCard">
  <div class="cover">🎵</div>
  <div class="info"><div class="title" id="musicTitle"></div><div class="artist" id="musicArtist"></div></div>
  <div class="ctrl">
    <button onclick="sendMedia('prev')">⏮</button>
    <button onclick="togglePlay()" id="playBtn">▶</button>
    <button onclick="sendMedia('next')">⏭</button>
  </div>
</div>
<div class="search-bar" id="searchBar">
  <input type="text" id="searchInput" placeholder="🔍 搜索地点、地址、周边…" onkeydown="if(event.key==='Enter')doSearch()">
  <button onclick="doSearch()">搜索</button>
</div>
<div class="search-results" id="searchResults"></div>
<div class="dock">
  <div class="app-ic" onclick="showMe()"><div class="ic map">📍</div><div class="label">定位</div></div>
  <div class="app-ic" onclick="nearby('加油站')"><div class="ic">⛽</div><div class="label">加油</div></div>
  <div class="app-ic" onclick="nearby('充电站')"><div class="ic">🔌</div><div class="label">充电</div></div>
  <div class="app-ic" onclick="nearby('停车场')"><div class="ic">🅿️</div><div class="label">停车</div></div>
  <div class="app-ic disabled" title="敬请期待"><div class="ic music">🎵</div><div class="label">音乐</div></div>
  <div class="app-ic disabled" title="敬请期待"><div class="ic qq">🐧</div><div class="label">QQ</div></div>
  <div class="app-ic disabled" title="敬请期待"><div class="ic wyy">🎶</div><div class="label">网易云</div></div>
  <div class="app-ic disabled" title="敬请期待"><div class="ic dy">🎬</div><div class="label">抖音</div></div>
  <div class="app-ic disabled" title="敬请期待"><div class="ic book">📖</div><div class="label">阅读</div></div>
</div>
<div id="waitPhone">
  <div class="sp"></div>
  <h3>📱 等待手机连接...</h3>
  <p>请确保手机 App 已开启"公网中继"并显示"中继已连接"</p>
  <div class="code" id="codeDisplay">__SESSION_CODE__</div>
  <p>配对码用于安全绑定，<br>只有你的手机和车机才能互通</p>
</div>
<div class="toast" id="toast"></div>
<script>
const SESSION_CODE='__SESSION_CODE__';
const RELAY_HOST='__RELAY_HOST__';
const WS_PROTO='__WS_PROTO__';
const WS_URL=WS_PROTO+'://'+RELAY_HOST.replace(/^https?:\/\//,'')+'/ws/car/'+SESSION_CODE;
const AMAP_KEY='749e2ad1b11e17cb64d0feebf7a7963d';

let map, carMarker, carAcc, ws, phoneOnline=false;
let lastLat=0, lastLng=0, lastBearing=0;
let searchHiding;

function initMap(){
  map=L.map('map',{zoomControl:false,attributionControl:true,zoomSnap:0.25}).setView([39.9087,116.3975],13);
  L.tileLayer('https://webrd0{s}.is.autonavi.com/appmaptile?lang=zh_cn&size=1&scale=1&style=8&x={x}&y={y}&z={z}',{subdomains:['1','2','3','4'],maxZoom:19,minZoom:3,attribution:'© 高德地图'}).addTo(map);
  const carIcon=L.divIcon({className:'',html:'<div style="width:28px;height:28px;transform:rotate(0deg)" id="carIconWrap"><div style="width:28px;height:28px;background:linear-gradient(135deg,#3b82f6,#1d4ed8);border-radius:50%;border:3px solid #fff;box-shadow:0 2px 8px rgba(59,130,246,0.6);display:flex;align-items:center;justify-content:center;font-size:14px">🚗</div></div>',iconSize:[28,28],iconAnchor:[14,14]});
  carMarker=L.marker([39.9087,116.3975],{icon:carIcon,interactive:false}).addTo(map);
  carAcc=L.circle([39.9087,116.3975],{radius:20,color:'#3b82f6',fillColor:'#3b82f6',fillOpacity:0.15,weight:1,interactive:false}).addTo(map);
  map.on('click',(e)=>{hideResults()});
  connectWS();
}

function connectWS(){
  ws=new WebSocket(WS_URL);
  ws.onopen=()=>{toast('☁️ 中继已连接')};
  ws.onclose=(e)=>{phoneOnline=false;document.getElementById('waitPhone').style.display='flex';document.getElementById('searchBar').style.opacity='0.4';setTimeout(connectWS,2000)};
  ws.onerror=()=>{};
  ws.onmessage=(e)=>{
    try{const m=JSON.parse(e.data);handleMsg(m)}catch(_){}
  };
}

function handleMsg(m){
  if(!m||!m.type)return;
  const d=m.data||{};
  switch(m.type){
    case 'relay_info':
      phoneOnline=!!d.phoneOnline;
      if(phoneOnline){
        document.getElementById('waitPhone').style.display='none';
        document.getElementById('searchBar').style.opacity='1';
      }else{
        document.getElementById('waitPhone').style.display='flex';
        document.getElementById('searchBar').style.opacity='0.4';
      }
      break;
    case 'car_connected':case 'car_disconnected':break;
    case 'navi':
      if(d&&d.latitude&&d.longitude){updateCar(d.latitude,d.longitude,d.bearing||0,d.speed||0)}
      if(d&&d.navigating===false||d.streetName===''){document.getElementById('naviCard').classList.remove('on')}
      else if(d){
        document.getElementById('naviCard').classList.add('on');
        document.getElementById('naviName').textContent=d.nextStreetName||d.streetName||'导航中';
        document.getElementById('naviDist').textContent=d.nextDistance?((d.nextDistance<1000)?Math.round(d.nextDistance)+'m':(d.nextDistance/1000).toFixed(1)+'km')+' · '+d.directionIcon:'';
        const dirMap={'straight':'↑','slightly-left':'↖','left':'←','hard-left':'⇐','slightly-right':'↗','right':'→','hard-right':'⇉','uturn':'⟲','uturn-left':'⟲','uturn-right':'⟳','arrive':'📍','start':'🚩'};
        document.getElementById('naviDir').textContent=dirMap[d.directionIcon]||'↑';
      }
      break;
    case 'vehicle':
      if(d){
        document.getElementById('vehInfo').style.display='block';
        document.getElementById('spdVal').textContent=Math.round(d.speed||0);
      }
      break;
    case 'music':
      if(d&&d.isPlaying||d.title){
        document.getElementById('musicCard').classList.add('on');
        document.getElementById('musicTitle').textContent=d.title||'未知';
        document.getElementById('musicArtist').textContent=d.artist||'';
        document.getElementById('playBtn').textContent=d.isPlaying?'⏸':'▶';
      }else{document.getElementById('musicCard').classList.remove('on')}
      break;
    case 'connection':break;
    case 'frame':break;
  }
}

function updateCar(lat,lng,bearing,speed){
  lastLat=lat;lastLng=lng;lastBearing=bearing;
  const pos=[lat,lng];
  carMarker.setLatLng(pos);
  document.getElementById('carIconWrap').style.transform='rotate('+bearing+'deg)';
  carAcc.setLatLng(pos);
  carAcc.setRadius(speed>30?Math.max(20,speed*0.5):20);
  if(map.getZoom()<5){map.setView(pos,15,{animate:true})}
}

function showMe(){
  if(lastLat&&lastLng)map.setView([lastLat,lastLng],16,{animate:true});
}

function doSearch(){
  if(!phoneOnline){toast('📱 等待手机连接...');return}
  const kw=document.getElementById('searchInput').value.trim();
  if(!kw)return;
  const loc=lastLat?lastLng+','+lastLat:'116.397428,39.90923';
  fetch('/api/ext?url='+encodeURIComponent('https://restapi.amap.com/v3/place/text?keywords='+encodeURIComponent(kw)+'&location='+loc+'&radius=50000&offset=8&page=1&key='+AMAP_KEY+'&output=json'))
    .then(r=>r.json()).then(j=>{
      if(j.status==='1'&&j.pois&&j.pois.length){showResults(j.pois)}
      else{toast('未找到相关地点')}
    }).catch(()=>toast('搜索失败，请检查网络'));
}

function nearby(kw){
  if(!phoneOnline){toast('📱 等待手机连接...');return}
  if(!lastLat){toast('暂无定位信息');return}
  fetch('/api/ext?url='+encodeURIComponent('https://restapi.amap.com/v3/place/around?keywords='+encodeURIComponent(kw)+'&location='+lastLng+','+lastLat+'&radius=5000&offset=8&page=1&key='+AMAP_KEY+'&output=json'))
    .then(r=>r.json()).then(j=>{
      if(j.status==='1'&&j.pois&&j.pois.length){showResults(j.pois)}
      else{toast('附近未找到'+kw)}
    }).catch(()=>toast('搜索失败'));
}

function showResults(pois){
  const el=document.getElementById('searchResults');
  el.innerHTML='';
  pois.forEach(p=>{
    const loc=p.location.split(',');
    const lng=parseFloat(loc[0]),lat=parseFloat(loc[1]);
    const it=document.createElement('div');
    it.className='item';
    it.innerHTML='<div class="nm">'+p.name+'</div><div class="ad">'+(p.address||p.pname+p.cityname+p.adname)+' · '+(p.distance?p.distance+'m':'')+'</div>';
    it.onclick=()=>{selectPlace(p.name,lat,lng);el.classList.remove('on')};
    el.appendChild(it);
  });
  el.classList.add('on');
  clearTimeout(searchHiding);
}
function hideResults(){document.getElementById('searchResults').classList.remove('on')}
function selectPlace(name,lat,lng){
  document.getElementById('searchInput').value=name;
  if(lastLat){
    getRoute(lastLng,lastLat,lng,lat,name);
  }else{
    startNavi(lat,lng,name);
  }
}
function getRoute(flng,flat,tlng,tlat,name){
  fetch('/api/ext?url='+encodeURIComponent('https://restapi.amap.com/v3/direction/driving?origin='+flng+','+flat+'&destination='+tlng+','+tlat+'&key='+AMAP_KEY+'&output=json&extensions=all'))
    .then(r=>r.json()).then(j=>{
      if(j.status==='1'&&j.route&&j.route.paths&&j.route.paths[0]){
        const path=j.route.paths[0];
        toast('🧭 开始导航 · '+(path.distance/1000).toFixed(1)+'km · 约'+Math.round(path.duration/60)+'分钟');
        startNavi(tlat,tlng,name);
      }else{startNavi(tlat,tlng,name)}
    }).catch(()=>startNavi(tlat,tlng,name));
}
function startNavi(lat,lng,name){
  if(ws&&ws.readyState===1){
    ws.send(JSON.stringify({type:'navi',data:{action:'start',lat:lat,lng:lng,name:name}}));
    map.setView([lat,lng],15,{animate:true});
    toast('🚗 已发送导航到手机');
  }
}
function sendMedia(cmd,pos){
  if(ws&&ws.readyState===1)ws.send(JSON.stringify({type:'media',data:{command:cmd,position:pos||0}}));
}
function togglePlay(){
  const btn=document.getElementById('playBtn');
  sendMedia(btn.textContent==='▶'?'play':'pause');
}
function toast(msg){
  const t=document.getElementById('toast');
  t.textContent=msg;t.classList.add('on');
  setTimeout(()=>t.classList.remove('on'),2500);
}
window.addEventListener('load',initMap);
</script>
</body>
</html>`;

// ============ HTTP 路由 ============
const server = http.createServer((req, res) => {
    try { route(req, res); } catch (e) {
        console.error('[http] error', e);
        res.writeHead(500); res.end('Server Error');
    }
});

function route(req, res) {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const pathname = url.pathname;

    if (req.method === 'OPTIONS') {
        res.writeHead(204, {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type'
        });
        res.end(); return;
    }

    if (pathname === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, sessions: sessions.size, ts: Date.now() }));
        return;
    }

    if (pathname === '/api/session' && req.method === 'POST') {
        let code;
        do { code = genCode(); } while (sessions.has(code));
        sessions.set(code, { phoneWS: null, carWSSet: new Set(), created: Date.now(), lastSeen: Date.now() });
        const scheme = req.headers['x-forwarded-proto'] || 'http';
        const host = req.headers.host;
        const carUrl = `${scheme}://${host}/c/${code}`;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ code, carUrl, wsUrl: `${scheme === 'https' ? 'wss' : 'ws'}://${host}/ws/phone/${code}` }));
        return;
    }

    if (pathname === '/api/ext' && req.method === 'GET') {
        const targetUrl = url.searchParams.get('url');
        if (!targetUrl) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ status: '0', info: 'missing url param' }));
            return;
        }
        proxyExt(req, res, targetUrl);
        return;
    }

    let m;
    if ((m = pathname.match(/^\/(?:c|car)\/(\d{6})\/?$/))) {
        const code = m[1];
        if (!sessions.has(code)) {
            res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>CarWith</title><meta name="viewport" content="width=device-width,initial-scale=1"><style>body{background:#000;color:#fff;font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;padding:20px}.box{text-align:center;max-width:400px}h2{color:#ef4444;margin:0 0 12px}p{color:#94a3b8;line-height:1.6;margin:6px 0}</style></head><body><div class="box"><h2>⚠️ 会话已失效</h2><p>配对码 <b style="color:#fff">${code}</b> 不存在或已过期</p><p>请在手机App上重新生成配对码</p></div></body></html>`);
            return;
        }
        const scheme = req.headers['x-forwarded-proto'] || 'http';
        const host = req.headers.host;
        const filled = CAR_HTML
            .replace(/__SESSION_CODE__/g, code)
            .replace(/__RELAY_HOST__/g, `${scheme}://${host}`)
            .replace(/__WS_PROTO__/g, scheme === 'https' ? 'wss' : 'ws');
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache, no-store' });
        res.end(filled);
        return;
    }

    if (pathname === '/' || pathname === '') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(`<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Tesla CarWith Relay</title>
<style>body{background:#0f172a;color:#e2e8f0;font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px}
.box{max-width:600px;text-align:center}h1{color:#3b82f6;margin:0 0 8px}
p{color:#94a3b8;line-height:1.6;margin:10px 0}
code{background:#1e293b;padding:4px 10px;border-radius:6px;color:#60a5fa;font-size:15px;display:inline-block;margin:4px 0}
.badge{display:inline-block;background:#10b981;color:#fff;padding:2px 10px;border-radius:10px;font-size:12px;font-weight:600;margin-left:8px}</style></head><body>
<div class="box"><h1>🚗 Tesla CarWith Relay <span class="badge">ONLINE</span></h1>
<p>这是 CarWith 公网中继服务器。</p><p>请在手机App生成配对码，然后在特斯拉浏览器访问：</p>
<p><code>https://${req.headers.host}/c/&lt;6位配对码&gt;</code></p>
<p style="margin-top:24px;font-size:13px;opacity:0.6">Active sessions: ${sessions.size}</p>
</div></body></html>`);
        return;
    }

    res.writeHead(404); res.end('Not Found');
}

server.on('upgrade', (req, socket, head) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const pathname = url.pathname;
    let m;
    if ((m = pathname.match(/^\/ws\/phone\/(\d{6})$/))) {
        const code = m[1];
        if (!sessions.has(code)) { socket.write('HTTP/1.1 404 Not Found\r\n\r\n'); socket.destroy(); return; }
        handleWSUpgrade(req, socket, head, 'phone', code);
    } else if ((m = pathname.match(/^\/ws\/car\/(\d{6})$/))) {
        const code = m[1];
        if (!sessions.has(code)) { socket.write('HTTP/1.1 404 Not Found\r\n\r\n'); socket.destroy(); return; }
        handleWSUpgrade(req, socket, head, 'car', code);
    } else {
        socket.write('HTTP/1.1 404 Not Found\r\n\r\n'); socket.destroy();
    }
});

server.listen(PORT, () => {
    console.log(`[relay] Tesla CarWith relay listening on port ${PORT}`);
});
