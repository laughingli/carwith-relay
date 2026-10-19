#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tesla CarWith 公网中继服务器 - Python 标准库单文件版 (零依赖)
用法: python relay-server.py [port]
手机App -> WSS外连本中继；Tesla浏览器 -> HTTPS /c/<code> -> WSS连本中继
"""
import os
import sys
import json
import time
import random
import hashlib
import base64
import struct
import socket as socket_mod
import threading
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, quote_plus
from urllib.request import Request, urlopen
from urllib.error import URLError

PORT = int(os.environ.get('PORT', sys.argv[1] if len(sys.argv) > 1 else 3000))

# ============ Session 管理 ============
sessions = {}
SESSION_TTL_MS = 2 * 60 * 60 * 1000
MAX_CAR_PER_SESSION = 3
_lock = threading.RLock()


def gen_code():
    return f"{random.randint(100000, 999999)}"


def touch_session(sid):
    with _lock:
        s = sessions.get(sid)
        if s:
            s['last_seen'] = int(time.time() * 1000)


def cleanup_sessions():
    while True:
        time.sleep(5 * 60)
        now = int(time.time() * 1000)
        with _lock:
            for sid in list(sessions.keys()):
                s = sessions[sid]
                has_phone = s.get('phone_ws') and s['phone_ws'].alive
                has_cars = any(ws.alive for ws in s['car_wss'])
                if not has_phone and not has_cars and now - s['last_seen'] > SESSION_TTL_MS:
                    del sessions[sid]
                    print(f"[cleanup] session {sid} expired")


threading.Thread(target=cleanup_sessions, daemon=True).start()


# ============ 简易 WebSocket ============
WS_MAGIC = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'


def ws_accept_key(key):
    sha1 = hashlib.sha1((key + WS_MAGIC).encode()).digest()
    return base64.b64encode(sha1).decode()


class WebSocket:
    def __init__(self, sock, role, sid, ip):
        self.sock = sock
        self.role = role
        self.sid = sid
        self.ip = ip
        self.alive = True
        self._buf = b''
        self._send_lock = threading.Lock()
        self._frag_opcode = None
        self._frag_buf = bytearray()
        self._thread = threading.Thread(target=self._recv_loop, daemon=True)
        self._thread.start()

    def _recv_loop(self):
        self.sock.settimeout(30)
        try:
            while self.alive:
                try:
                    chunk = self.sock.recv(65536)
                except socket_mod.timeout:
                    self._send_raw(b'\x89\x00')
                    continue
                except OSError as e:
                    if self.alive:
                        print(f"[ws] recv OSError role={self.role} sid={self.sid}: {e}")
                    break
                if not chunk:
                    if self.alive:
                        print(f"[ws] connection closed by peer role={self.role} sid={self.sid}")
                    break
                self._buf += chunk
                while self.alive:
                    try:
                        if not self._process_frame():
                            break
                    except Exception as e:
                        import traceback
                        print(f"[ws] frame error role={self.role} sid={self.sid}: {e}")
                        traceback.print_exc()
                        self.close(1002)
                        return
        except Exception as e:
            import traceback
            if self.alive:
                print(f"[ws] recv loop error role={self.role} sid={self.sid}: {e}")
                traceback.print_exc()
        finally:
            self.close()

    def _process_frame(self):
        if len(self._buf) < 2:
            return False
        b0, b1 = self._buf[0], self._buf[1]
        fin = (b0 & 0x80) != 0
        opcode = b0 & 0x0f
        masked = (b1 & 0x80) != 0
        plen = b1 & 0x7f
        off = 2

        if opcode >= 0x3 and opcode <= 0x7:
            self.close(1002)
            return False

        if plen == 126:
            if len(self._buf) < 4:
                return False
            plen = struct.unpack('>H', self._buf[2:4])[0]
            off = 4
        elif plen == 127:
            if len(self._buf) < 10:
                return False
            raw_len = struct.unpack('>Q', self._buf[2:10])[0]
            if raw_len & 0x8000000000000000:
                self.close(1009)
                return False
            plen = raw_len
            off = 10

        if not masked:
            self.close(1002)
            return False

        if len(self._buf) < off + 4 + plen:
            return False

        mask = self._buf[off:off + 4]
        off += 4
        payload = bytearray(plen)
        for i in range(plen):
            payload[i] = self._buf[off + i] ^ mask[i & 3]
        self._buf = self._buf[off + plen:]

        if opcode == 0x8:
            close_code = 1000
            if len(payload) >= 2:
                close_code = struct.unpack('>H', payload[:2])[0]
            self.close(close_code)
            return False

        if opcode == 0x9:
            if len(payload) <= 125:
                self._send_raw(b'\x8a' + bytes([len(payload)]) + bytes(payload))
            return True

        if opcode == 0xa:
            return True

        if opcode == 0x0:
            if self._frag_opcode is None:
                self.close(1002)
                return False
            self._frag_buf.extend(payload)
            if fin:
                final_opcode = self._frag_opcode
                final_payload = bytes(self._frag_buf)
                self._frag_opcode = None
                self._frag_buf = bytearray()
                self._dispatch_message(final_opcode, final_payload)
            return True

        if self._frag_opcode is not None:
            self.close(1002)
            return False

        if not fin:
            self._frag_opcode = opcode
            self._frag_buf = bytearray(payload)
            return True

        self._dispatch_message(opcode, bytes(payload))
        return True

    def _dispatch_message(self, opcode, payload):
        if opcode == 0x1:
            try:
                text = payload.decode('utf-8')
            except UnicodeDecodeError:
                self.close(1007)
                return
            on_message(self, text)
        elif opcode == 0x2:
            on_binary(self, payload)

    def send(self, data):
        if not self.alive:
            return
        if isinstance(data, (bytes, bytearray)):
            payload = bytes(data)
            opcode = 0x2
        else:
            if not isinstance(data, str):
                data = json.dumps(data, ensure_ascii=False)
            payload = data.encode('utf-8')
            opcode = 0x1
        self._send_frame(opcode, payload)

    def _send_frame(self, opcode, payload):
        length = len(payload)
        b0 = 0x80 | opcode
        if length < 126:
            header = struct.pack('>BB', b0, length)
        elif length < 65536:
            header = struct.pack('>BBH', b0, 126, length)
        else:
            header = struct.pack('>BBQ', b0, 127, length)
        self._send_raw(header + payload)

    def _send_raw(self, data):
        try:
            with self._send_lock:
                self.sock.sendall(data)
        except OSError as e:
            if self.alive:
                print(f"[ws] send error role={self.role} sid={self.sid}: {e}")
            self.close()

    def close(self, code=1000):
        if not self.alive:
            return
        self.alive = False
        try:
            if code is not None and code > 0:
                self._send_raw(b'\x88\x02' + struct.pack('>H', code))
        except OSError:
            pass
        try:
            self.sock.shutdown(socket_mod.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass
        on_close(self)


def on_message(ws, text):
    sid = ws.sid
    with _lock:
        s = sessions.get(sid)
        if not s:
            return
        touch_session(sid)
        try:
            json.loads(text)
        except Exception:
            return
        if ws.role == 'phone':
            for car in list(s['car_wss']):
                if car.alive:
                    car.send(text)
        else:
            phone = s.get('phone_ws')
            if phone and phone.alive:
                phone.send(text)


def on_binary(ws, data):
    sid = ws.sid
    with _lock:
        s = sessions.get(sid)
        if not s:
            return
        touch_session(sid)
        if ws.role == 'phone':
            for car in list(s['car_wss']):
                if car.alive:
                    car.send(data)
        else:
            phone = s.get('phone_ws')
            if phone and phone.alive:
                phone.send(data)


def on_close(ws):
    sid = ws.sid
    with _lock:
        s = sessions.get(sid)
        if not s:
            return
        if ws.role == 'phone':
            if s.get('phone_ws') is ws:
                s['phone_ws'] = None
            print(f"[ws] phone disconnected session={sid}")
        else:
            s['car_wss'].discard(ws)
            print(f"[ws] car disconnected session={sid} remain={len(s['car_wss'])}")
            phone = s.get('phone_ws')
            if phone and phone.alive:
                phone.send({'type': 'car_disconnected', 'data': {'count': len(s['car_wss'])}})
        broadcast_info(sid)


def broadcast_info(sid):
    s = sessions.get(sid)
    if not s:
        return
    info = {
        'type': 'relay_info',
        'data': {
            'phoneOnline': bool(s.get('phone_ws') and s['phone_ws'].alive),
            'carCount': len(s['car_wss'])
        }
    }
    phone = s.get('phone_ws')
    if phone and phone.alive:
        phone.send(info)
    for c in list(s['car_wss']):
        if c.alive:
            c.send(info)


def upgrade_websocket(handler, role, sid, initial_body=b''):
    try:
        key = handler.headers.get('sec-websocket-key')
        if not key:
            print(f"[ws] missing sec-websocket-key from {handler.client_address}, headers={list(handler.headers.keys())}")
            handler.send_error(400)
            return
        accept = ws_accept_key(key)
        proto = handler.headers.get('sec-websocket-protocol', '')
        resp_lines = [
            'HTTP/1.1 101 Switching Protocols',
            'Upgrade: websocket',
            'Connection: Upgrade',
            f'Sec-WebSocket-Accept: {accept}',
        ]
        if proto:
            resp_lines.append(f'Sec-WebSocket-Protocol: {proto}')
        resp = '\r\n'.join(resp_lines) + '\r\n\r\n'
        with _lock:
            s = sessions.get(sid)
            if not s:
                print(f"[ws] session {sid} not found for {role}")
                handler.connection.sendall(b'HTTP/1.1 404 Not Found\r\n\r\n')
                handler.connection.close()
                return
            if role == 'car' and len(s['car_wss']) >= MAX_CAR_PER_SESSION:
                handler.connection.sendall(b'HTTP/1.1 503 Too Many Cars\r\n\r\n')
                handler.connection.close()
                return
        sock = handler.connection
        sock.sendall(resp.encode('latin-1'))
        sock.settimeout(30)
        xff = handler.headers.get('x-forwarded-for', '')
        if xff:
            ip = xff.split(',')[0].strip().replace('::ffff:', '')
        else:
            try:
                ip = sock.getpeername()[0].replace('::ffff:', '')
            except Exception:
                ip = str(handler.client_address[0]) if handler.client_address else 'unknown'
        ws = WebSocket(sock, role, sid, ip)
        if initial_body:
            ws._buf += initial_body
            try:
                while ws._process_frame():
                    pass
            except Exception:
                pass
        with _lock:
            s = sessions.get(sid)
            if not s:
                ws.close(1008)
                return
            if role == 'phone':
                old = s.get('phone_ws')
                if old and old.alive:
                    old.close(1000)
                s['phone_ws'] = ws
                print(f"[ws] phone connected session={sid} ip={ip}")
            else:
                s['car_wss'].add(ws)
                print(f"[ws] car connected session={sid} ip={ip} total={len(s['car_wss'])}")
                phone = s.get('phone_ws')
                if phone and phone.alive:
                    phone.send({'type': 'car_connected', 'data': {'count': len(s['car_wss'])}})
        broadcast_info(sid)
        touch_session(sid)
    except Exception as e:
        import traceback
        print(f"[ws] upgrade error role={role} sid={sid}: {e}")
        traceback.print_exc()
        try:
            handler.connection.sendall(b'HTTP/1.1 500 Internal Server Error\r\n\r\n')
        except Exception:
            pass
        try:
            handler.connection.close()
        except Exception:
            pass


# ============ 高德代理 ============
def proxy_ext(handler, target_url):
    try:
        req = Request(target_url, headers={
            'User-Agent': 'Mozilla/5.0 (TeslaCarWith-Relay)',
            'Accept': 'application/json, */*',
            'Referer': 'https://www.amap.com/'
        })
        with urlopen(req, timeout=10) as r:
            body = r.read()
            handler.send_response(r.status)
            handler.send_header('Content-Type', 'application/json; charset=utf-8')
            handler.send_header('Access-Control-Allow-Origin', '*')
            handler.send_header('Cache-Control', 'no-cache')
            handler.end_headers()
            handler.wfile.write(body)
    except Exception as e:
        handler.send_response(502)
        handler.send_header('Content-Type', 'application/json')
        handler.end_headers()
        handler.wfile.write(json.dumps({'status': '0', 'info': f'PROXY_ERROR: {e}'}).encode())


# ============ 车机 HTML ============
CAR_HTML = r'''<!DOCTYPE html>
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
#mirror{position:fixed;inset:0;z-index:9999;display:none;background:#000}
#mirror.on{display:block}
#mirror img{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);max-width:100vw;max-height:100vh;width:auto;height:auto;object-fit:contain;display:block;-webkit-user-select:none;user-select:none;touch-action:none;-webkit-touch-callout:none;-webkit-tap-highlight-color:transparent}
#mirror .exit{position:absolute;top:env(safe-area-inset-top,12px);right:16px;width:44px;height:44px;border-radius:50%;background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.15);color:rgba(255,255,255,0.7);font-size:20px;cursor:pointer;z-index:10001;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);transition:all .15s}
#mirror .exit:active{background:rgba(239,68,68,0.5);color:#fff;transform:scale(0.92)}
body.casting #map,body.casting .relay-badge,body.casting .vehicle-info,body.casting .navi-card,body.casting .music-card,body.casting .search-bar,body.casting .search-results,body.casting .dock,body.casting .cast-btn,body.casting #waitPhone{display:none!important}
.cast-btn{position:absolute;top:env(safe-area-inset-top,12px);right:14px;width:40px;height:40px;border-radius:50%;background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.12);color:rgba(255,255,255,0.6);font-size:18px;cursor:pointer;z-index:500;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);transition:all .2s}
.cast-btn.on{background:rgba(239,68,68,0.25);border-color:rgba(239,68,68,0.4);color:#fca5a5}
.cast-btn:active{transform:scale(0.9)}
.cast-ind{position:absolute;top:env(safe-area-inset-top,12px);left:50%;transform:translateX(-50%);background:rgba(239,68,68,0.15);border:1px solid rgba(239,68,68,0.3);color:#fca5a5;padding:3px 10px;border-radius:10px;font-size:11px;z-index:805;display:none;align-items:center;gap:5px;backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px)}
.cast-ind.on{display:flex}
.cast-ind .dt{width:6px;height:6px;border-radius:50%;background:#ef4444;animation:pulse 1s infinite}
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
<div class="cast-ind" id="castInd"><span class="dt"></span><span>投屏中</span></div>
<button class="cast-btn" id="castBtn" onclick="toggleCast()" title="屏幕投屏">📱</button>
<div id="mirror">
  <button class="exit" onclick="stopCast()">✕</button>
  <img id="mirrorImg" alt="screen mirror" draggable="false">
</div>
<script>
const SESSION_CODE='__SESSION_CODE__';
const RELAY_HOST='__RELAY_HOST__';
const WS_PROTO='__WS_PROTO__';
const WS_URL=WS_PROTO+'://'+RELAY_HOST.replace(/^https?:\/\//,'')+'/ws/car/'+SESSION_CODE;
const AMAP_KEY='749e2ad1b11e17cb64d0feebf7a7963d';

let map, carMarker, carAcc, ws, phoneOnline=false;
let lastLat=0, lastLng=0, lastBearing=0;
let searchHiding;
let castActive=false, mirrorTouchId=null;

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
      if(d&&(d.navigating===false||d.streetName==='')){document.getElementById('naviCard').classList.remove('on')}
      else if(d){
        document.getElementById('naviCard').classList.add('on');
        document.getElementById('naviName').textContent=d.nextStreetName||d.streetName||'导航中';
        document.getElementById('naviDist').textContent=d.nextDistance?((d.nextDistance<1000)?Math.round(d.nextDistance)+'m':(d.nextDistance/1000).toFixed(1)+'km')+' · '+(d.directionIcon||''):'';
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
      if(d&&(d.isPlaying||d.title)){
        document.getElementById('musicCard').classList.add('on');
        document.getElementById('musicTitle').textContent=d.title||'未知';
        document.getElementById('musicArtist').textContent=d.artist||'';
        document.getElementById('playBtn').textContent=d.isPlaying?'⏸':'▶';
      }else{document.getElementById('musicCard').classList.remove('on')}
      break;
    case 'connection':break;
    case 'screencast':
      castActive=!!d.active;
      const btn=document.getElementById('castBtn');
      const ind=document.getElementById('castInd');
      const mirror=document.getElementById('mirror');
      if(castActive){btn.classList.add('on');btn.textContent='⏹';ind.classList.add('on');document.body.classList.add('casting')}
      else{btn.classList.remove('on');btn.textContent='📱';ind.classList.remove('on');mirror.classList.remove('on');document.body.classList.remove('casting')}
      if(d.error){toast('❌ '+d.error);castActive=false;btn.classList.remove('on');btn.textContent='📱';ind.classList.remove('on');mirror.classList.remove('on');document.body.classList.remove('casting')}
      break;
    case 'frame':
      if(d&&typeof d==='string'){
        const img=document.getElementById('mirrorImg');
        const m=document.getElementById('mirror');
        img.src='data:image/jpeg;base64,'+d;
        if(!m.classList.contains('on'))m.classList.add('on');
        if(!document.body.classList.contains('casting'))document.body.classList.add('casting');
        if(!castActive){castActive=true;document.getElementById('castBtn').classList.add('on');document.getElementById('castBtn').textContent='⏹';document.getElementById('castInd').classList.add('on')}
      }
      break;
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
    it.innerHTML='<div class="nm">'+p.name+'</div><div class="ad">'+(p.address||(p.pname||'')+(p.cityname||'')+(p.adname||''))+' · '+(p.distance?p.distance+'m':'')+'</div>';
    it.onclick=()=>{selectPlace(p.name,lat,lng);el.classList.remove('on')};
    el.appendChild(it);
  });
  el.classList.add('on');
  clearTimeout(searchHiding);
}
function hideResults(){document.getElementById('searchResults').classList.remove('on')}
function selectPlace(name,lat,lng){
  document.getElementById('searchInput').value=name;
  if(lastLat){getRoute(lastLng,lastLat,lng,lat,name)}
  else{startNavi(lat,lng,name)}
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
function toggleCast(){
  if(!phoneOnline){toast('📱 等待手机连接...');return}
  const want=!castActive;
  if(ws&&ws.readyState===1)ws.send(JSON.stringify({type:'screencast',data:{active:want}}));
  if(!want){document.getElementById('mirror').classList.remove('on');document.getElementById('castInd').classList.remove('on');document.getElementById('castBtn').classList.remove('on');document.getElementById('castBtn').textContent='📱';document.body.classList.remove('casting');castActive=false}
  else{toast('📱 正在请求投屏...')}
}
function stopCast(){
  if(ws&&ws.readyState===1)ws.send(JSON.stringify({type:'screencast',data:{active:false}}));
  document.getElementById('mirror').classList.remove('on');
  document.getElementById('castInd').classList.remove('on');
  document.getElementById('castBtn').classList.remove('on');
  document.getElementById('castBtn').textContent='📱';
  document.body.classList.remove('casting');
  castActive=false;
}
function sendMirrorTouch(ev,action){
  ev.preventDefault();
  const img=document.getElementById('mirrorImg');
  const r=img.getBoundingClientRect();
  const touches=ev.changedTouches?[...ev.changedTouches]:[ev];
  touches.forEach(t=>{
    const nx=(t.clientX-r.left)/r.width;
    const ny=(t.clientY-r.top)/r.height;
    if(nx<0||nx>1||ny<0||ny>1)return;
    if(ws&&ws.readyState===1)ws.send(JSON.stringify({type:'touch',data:{x:nx,y:ny,action:action}}));
  });
}
window.addEventListener('load',()=>{
  initMap();
  const mirrorImg=document.getElementById('mirrorImg');
  mirrorImg.addEventListener('touchstart',e=>sendMirrorTouch(e,0),{passive:false});
  mirrorImg.addEventListener('touchmove',e=>sendMirrorTouch(e,2),{passive:false});
  mirrorImg.addEventListener('touchend',e=>sendMirrorTouch(e,1),{passive:false});
  mirrorImg.addEventListener('touchcancel',e=>sendMirrorTouch(e,1),{passive:false});
  mirrorImg.addEventListener('mousedown',e=>{e.preventDefault();sendMirrorTouch(e,0);mirrorTouchId='mouse'});
  mirrorImg.addEventListener('mousemove',e=>{if(mirrorTouchId==='mouse')sendMirrorTouch(e,2)});
  mirrorImg.addEventListener('mouseup',e=>{if(mirrorTouchId==='mouse'){sendMirrorTouch(e,1);mirrorTouchId=null}});
  mirrorImg.addEventListener('mouseleave',e=>{if(mirrorTouchId==='mouse'){sendMirrorTouch(e,1);mirrorTouchId=null}});
});
</script>
</body>
</html>'''


# ============ HTTP Handler ============
class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("[http] %s - %s\n" % (self.address_string(), fmt % args))

    def _set_cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        self._route('GET')

    def do_POST(self):
        self._route('POST')

    def _route(self, method):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path == '/health':
            body = json.dumps({'ok': True, 'sessions': len(sessions), 'ts': int(time.time()*1000)}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path == '/api/session' and method == 'POST':
            length = int(self.headers.get('Content-Length', 0) or 0)
            if length > 0:
                try:
                    self.rfile.read(length)
                except Exception:
                    pass
            xff = self.headers.get('x-forwarded-for', '')
            client_ip = xff.split(',')[0].strip().replace('::ffff:', '') if xff else self.client_address[0]
            with _lock:
                while True:
                    code = gen_code()
                    if code not in sessions:
                        break
                sessions[code] = {
                    'phone_ws': None,
                    'car_wss': set(),
                    'created': int(time.time()*1000),
                    'last_seen': int(time.time()*1000),
                }
            scheme = self.headers.get('X-Forwarded-Proto', 'http')
            host = self.headers.get('Host', f'localhost:{PORT}')
            ws_proto = 'wss' if scheme == 'https' else 'ws'
            body = json.dumps({
                'code': code,
                'carUrl': f'{scheme}://{host}/c/{code}',
                'wsUrl': f'{ws_proto}://{host}/ws/phone/{code}',
            }).encode()
            print(f"[api] session created code={code} ip={client_ip}")
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path == '/api/ext' and method == 'GET':
            target = qs.get('url', [None])[0]
            if not target:
                body = json.dumps({'status': '0', 'info': 'missing url param'}).encode()
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            proxy_ext(self, target)
            return

        m = re.match(r'^/(?:c|car)/(\d{6})/?$', path)
        if m:
            code = m.group(1)
            with _lock:
                exists = code in sessions
            if not exists:
                html = (
                    '<!DOCTYPE html><html><head><meta charset="utf-8"><title>CarWith</title>'
                    '<meta name="viewport" content="width=device-width,initial-scale=1">'
                    '<style>body{background:#000;color:#fff;font-family:-apple-system,sans-serif;display:flex;'
                    'align-items:center;justify-content:center;height:100vh;margin:0;padding:20px}'
                    '.box{text-align:center;max-width:400px}h2{color:#ef4444;margin:0 0 12px}'
                    'p{color:#94a3b8;line-height:1.6;margin:6px 0}</style></head><body>'
                    f'<div class="box"><h2>⚠️ 会话已失效</h2><p>配对码 <b style="color:#fff">{code}</b> '
                    '不存在或已过期</p><p>请在手机App上重新生成配对码</p></div></body></html>'
                ).encode('utf-8')
                self.send_response(404)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(html)))
                self.end_headers()
                self.wfile.write(html)
                return
            scheme = self.headers.get('X-Forwarded-Proto', 'http')
            host = self.headers.get('Host', f'localhost:{PORT}')
            ws_proto = 'wss' if scheme == 'https' else 'ws'
            filled = (CAR_HTML
                      .replace('__SESSION_CODE__', code)
                      .replace('__RELAY_HOST__', f'{scheme}://{host}')
                      .replace('__WS_PROTO__', ws_proto))
            body = filled.encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Cache-Control', 'no-cache, no-store')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path == '/' or path == '':
            host = self.headers.get('Host', f'localhost:{PORT}')
            with _lock:
                sc = len(sessions)
            html = (
                '<!DOCTYPE html><html><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width,initial-scale=1">'
                '<title>Tesla CarWith Relay</title>'
                '<style>body{background:#0f172a;color:#e2e8f0;font-family:-apple-system,sans-serif;'
                'display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px}'
                '.box{max-width:600px;text-align:center}h1{color:#3b82f6;margin:0 0 8px}'
                'p{color:#94a3b8;line-height:1.6;margin:10px 0}'
                'code{background:#1e293b;padding:4px 10px;border-radius:6px;color:#60a5fa;font-size:15px;'
                'display:inline-block;margin:4px 0}'
                '.badge{display:inline-block;background:#10b981;color:#fff;padding:2px 10px;border-radius:10px;'
                'font-size:12px;font-weight:600;margin-left:8px}</style></head><body>'
                '<div class="box"><h1>🚗 Tesla CarWith Relay <span class="badge">ONLINE</span></h1>'
                '<p>这是 CarWith 公网中继服务器。</p>'
                '<p>请在手机App生成配对码，然后在特斯拉浏览器访问：</p>'
                f'<p><code>https://{host}/c/&lt;6位配对码&gt;</code></p>'
                f'<p style="margin-top:24px;font-size:13px;opacity:0.6">Active sessions: {sc}</p>'
                '</div></body></html>'
            ).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(html)))
            self.end_headers()
            self.wfile.write(html)
            return

        self.send_response(404)
        self.end_headers()
        self.wfile.write(b'Not Found')

    def do_GET_upgrade(self):
        pass

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (ConnectionResetError, BrokenPipeError):
            pass


class UpgradingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def get_request(self):
        sock, addr = self.socket.accept()
        # Peek the first bytes to see if this is an Upgrade request
        sock.settimeout(5)
        try:
            # We can't peek easily, so we override process_request instead
            pass
        except Exception:
            pass
        return sock, addr

    def process_request(self, sock, addr):
        # Wrap socket to look like what BaseHTTPRequestHandler expects
        # We need to do upgrade detection here
        threading.Thread(target=self._handle, args=(sock, addr), daemon=True).start()

    def _handle(self, sock, addr):
        try:
            sock.settimeout(10)
            # Read initial request line + headers
            data = b''
            while b'\r\n\r\n' not in data:
                chunk = sock.recv(4096)
                if not chunk:
                    sock.close()
                    return
                data += chunk
                if len(data) > 65536:
                    sock.close()
                    return
            header_end = data.find(b'\r\n\r\n')
            header_block = data[:header_end].decode('latin-1', errors='replace')
            rest = data[header_end + 4:]
            lines = header_block.split('\r\n')
            if not lines:
                sock.close()
                return
            request_line = lines[0]
            headers = {}
            for ln in lines[1:]:
                if ':' in ln:
                    k, v = ln.split(':', 1)
                    headers[k.strip().lower()] = v.strip()
            # Check upgrade
            upgrade = headers.get('upgrade', '').lower() == 'websocket'
            if upgrade:
                self._handle_ws_upgrade(sock, addr, request_line, headers, rest)
            else:
                self._handle_http(sock, addr, header_block, rest)
        except Exception as e:
            print(f"[srv] connection error: {e}")
            try:
                sock.close()
            except Exception:
                pass

    def _handle_http(self, sock, addr, header_block, initial_body):
        # Create a rfile that replays headers + any initial body
        from io import BytesIO
        class FakeSocket:
            def __init__(self, initial, real):
                self.buf = BytesIO(initial)
                self.real = real
                self.real.settimeout(10)
            def makefile(self, mode, bufsize=-1):
                return self
            def read(self, n=-1):
                data = self.buf.read(n)
                if n == -1:
                    rest = self.real.recv(65536)
                    return data + rest
                if len(data) < n:
                    try:
                        rest = self.real.recv(n - len(data))
                    except Exception:
                        rest = b''
                    data = data + rest
                return data
            def readline(self, limit=-1):
                line = self.buf.readline(limit if limit > 0 else -1)
                if not line.endswith(b'\n'):
                    try:
                        while True:
                            ch = self.real.recv(1)
                            if not ch:
                                break
                            line += ch
                            if ch == b'\n':
                                break
                    except Exception:
                        pass
                return line
            def sendall(self, data):
                self.real.sendall(data)
            def close(self):
                try:
                    self.real.close()
                except Exception:
                    pass
        # Add body
        full_initial = (header_block + '\r\n\r\n').encode('latin-1') + initial_body
        fake = FakeSocket(full_initial, sock)
        handler = Handler(fake, addr, self)
        try:
            handler.handle()
        except Exception as e:
            pass
        try:
            sock.close()
        except Exception:
            pass

    def _handle_ws_upgrade(self, sock, addr, request_line, headers, initial_body):
        parts = request_line.split(' ')
        if len(parts) < 2:
            sock.close()
            return
        path = parts[1]
        # Build a mock handler for passing to upgrade_websocket
        class MockHandler:
            def __init__(self):
                self.connection = sock
                self.headers = headers
                self.path = path
                self.client_address = addr
            def send_error(self, code):
                try:
                    sock.sendall(f'HTTP/1.1 {code} Error\r\n\r\n'.encode())
                    sock.close()
                except Exception:
                    pass
        mh = MockHandler()
        m_phone = re.match(r'^/ws/phone/(\d{6})$', path)
        m_car = re.match(r'^/ws/car/(\d{6})$', path)
        if m_phone:
            print(f"[ws] upgrade request: phone sid={m_phone.group(1)} from={addr[0]} initial_body_len={len(initial_body)}")
            upgrade_websocket(mh, 'phone', m_phone.group(1), initial_body)
        elif m_car:
            print(f"[ws] upgrade request: car sid={m_car.group(1)} from={addr[0]} initial_body_len={len(initial_body)}")
            upgrade_websocket(mh, 'car', m_car.group(1), initial_body)
        else:
            try:
                sock.sendall(b'HTTP/1.1 404 Not Found\r\n\r\n')
                sock.close()
            except Exception:
                pass


if __name__ == '__main__':
    print(f"[relay] Tesla CarWith relay listening on port {PORT}")
    print(f"[relay] Local URL: http://localhost:{PORT}")
    server = UpgradingHTTPServer(('0.0.0.0', PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[relay] stopping...")
        server.server_close()
