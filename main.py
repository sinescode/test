import hmac
import hashlib
import requests
import string
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import json
import codecs
import time
from datetime import datetime
import urllib3
import os
import sys
import base64
import signal
import threading
import psutil
import re
import subprocess
import importlib
import argparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

EXIT_FLAG = False
SUCCESS_COUNTER = 0
TARGET_ACCOUNTS = 0
RARE_COUNTER = 0
COUPLES_COUNTER = 0
RARITY_SCORE_THRESHOLD = 3
LOCK = threading.Lock()

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_FOLDER = os.path.join(CURRENT_DIR, "BIGBULL-ERA")
TOKENS_FOLDER = os.path.join(BASE_FOLDER, "TOKENS-JWT")
ACCOUNTS_FOLDER = os.path.join(BASE_FOLDER, "ACCOUNTS")
RARE_ACCOUNTS_FOLDER = os.path.join(BASE_FOLDER, "RARE ACCOUNTS")
COUPLES_ACCOUNTS_FOLDER = os.path.join(BASE_FOLDER, "COUPLES ACCOUNTS")
GHOST_FOLDER = os.path.join(BASE_FOLDER, "GHOST")
GHOST_ACCOUNTS_FOLDER = os.path.join(GHOST_FOLDER, "ACCOUNTS")
GHOST_RARE_FOLDER = os.path.join(GHOST_FOLDER, "RAREACCOUNT")
GHOST_COUPLES_FOLDER = os.path.join(GHOST_FOLDER, "COUPLESACCOUNT")

for folder in [BASE_FOLDER, TOKENS_FOLDER, ACCOUNTS_FOLDER, RARE_ACCOUNTS_FOLDER, COUPLES_ACCOUNTS_FOLDER, GHOST_FOLDER, GHOST_ACCOUNTS_FOLDER, GHOST_RARE_FOLDER, GHOST_COUPLES_FOLDER]:
    os.makedirs(folder, exist_ok=True)

REGION_LANG = {"ME": "ar","IND": "hi","ID": "id","VN": "vi","TH": "th","BD": "bn","PK": "ur","TW": "zh","CIS": "ru","SAC": "es","BR": "pt"}
REGION_URLS = {"IND": "https://client.ind.freefiremobile.com/","ID": "https://clientbp.ggblueshark.com/","BR": "https://client.us.freefiremobile.com/","ME": "https://clientbp.common.ggbluefox.com/","VN": "https://clientbp.ggblueshark.com/","TH": "https://clientbp.common.ggbluefox.com/","CIS": "https://clientbp.ggblueshark.com/","BD": "https://clientbp.ggblueshark.com/","PK": "https://clientbp.ggblueshark.com/","SG": "https://clientbp.ggblueshark.com/","SAC": "https://client.us.freefiremobile.com/","TW": "https://clientbp.ggblueshark.com/"}
hex_key = "32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533"
key = bytes.fromhex(hex_key)
hex_data = "8J+agCBQUkVNSVVNIEFDQ09VTlQgR0VORVJBVE9SIPCfkqsgQnkgU1BJREVFUklPIHwgTm90IEZvciBTYWxlIPCfkas="
client_data = base64.b64decode(hex_data).decode('utf-8')
GARENA = "UklaRVI="

FILE_LOCKS = {}

def get_file_lock(filename):
    if filename not in FILE_LOCKS:
        FILE_LOCKS[filename] = threading.Lock()
    return FILE_LOCKS[filename]

ACCOUNT_RARITY_PATTERNS = {
    "REPEATED_DIGITS_4": [r"(\d)\1{3,}", 3],
    "REPEATED_DIGITS_3": [r"(\d)\1\1(\d)\2\2", 2],
    "SEQUENTIAL_5": [r"(12345|23456|34567|45678|56789)", 4],
    "SEQUENTIAL_4": [r"(0123|1234|2345|3456|4567|5678|6789|9876|8765|7654|6543|5432|4321|3210)", 3],
    "PALINDROME_6": [r"^(\d)(\d)(\d)\3\2\1$", 5],
    "PALINDROME_4": [r"^(\d)(\d)\2\1$", 3],
    "SPECIAL_COMBINATIONS_HIGH": [r"(69|420|1337|007)", 4],
    "SPECIAL_COMBINATIONS_MED": [r"(100|200|300|400|500|666|777|888|999)", 2],
    "QUADRUPLE_DIGITS": [r"(1111|2222|3333|4444|5555|6666|7777|8888|9999|0000)", 4],
    "MIRROR_PATTERN_HIGH": [r"^(\d{2,3})\1$", 3],
    "MIRROR_PATTERN_MED": [r"(\d{2})0\1", 2],
    "GOLDEN_RATIO": [r"1618|0618", 3]
}

ACCOUNT_COUPLES_PATTERNS = {
    "MATCHING_PAIRS": [
        r"(\d{2})01.*\d{2}02",
        r"(\d{2})11.*\d{2}12",
        r"(\d{2})21.*\d{2}22",
    ],
    "COMPLEMENTARY_DIGITS": [
        r".*13.*14$",
        r".*07.*08$",
        r".*51.*52$",
    ],
    "LOVE_NUMBERS": [
        r".*520.*521$",
        r".*1314$",
    ]
}

POTENTIAL_COUPLES = {}
COUPLES_LOCK = threading.Lock()

def check_account_rarity(account_data):
    account_id = account_data.get("account_id", "")
    
    if account_id == "N/A" or not account_id:
        return False, None, None, 0
    
    rarity_score = 0
    detected_patterns = []
    
    for rarity_type, pattern_data in ACCOUNT_RARITY_PATTERNS.items():
        pattern = pattern_data[0]
        score = pattern_data[1]
        if re.search(pattern, account_id):
            rarity_score += score
            detected_patterns.append(rarity_type)
    
    account_id_digits = [int(d) for d in account_id if d.isdigit()]
    
    if len(set(account_id_digits)) == 1 and len(account_id_digits) >= 4:
        rarity_score += 5
        detected_patterns.append("UNIFORM_DIGITS")
    
    if len(account_id_digits) >= 4:
        differences = [account_id_digits[i+1] - account_id_digits[i] for i in range(len(account_id_digits)-1)]
        if len(set(differences)) == 1:
            rarity_score += 4
            detected_patterns.append("ARITHMETIC_SEQUENCE")
    
    if len(account_id) <= 8 and account_id.isdigit() and int(account_id) < 1000000:
        rarity_score += 3
        detected_patterns.append("LOW_ACCOUNT_ID")
    
    if rarity_score >= RARITY_SCORE_THRESHOLD:
        reason = f"Account ID {account_id} - Score: {rarity_score} - Patterns: {', '.join(detected_patterns)}"
        return True, "RARE_ACCOUNT", reason, rarity_score
    
    return False, None, None, rarity_score

def check_account_couples(account_data, thread_id):
    account_id = account_data.get("account_id", "")
    
    if account_id == "N/A" or not account_id:
        return False, None, None
    
    with COUPLES_LOCK:
        for stored_id, stored_data in POTENTIAL_COUPLES.items():
            stored_account_id = stored_data.get('account_id', '')
            
            couple_found, reason = check_account_couple_patterns(account_id, stored_account_id)
            if couple_found:
                partner_data = stored_data
                del POTENTIAL_COUPLES[stored_id]
                return True, reason, partner_data
        
        POTENTIAL_COUPLES[account_id] = {
            'uid': account_data.get('uid', ''),
            'account_id': account_id,
            'name': account_data.get('name', ''),
            'password': account_data.get('password', ''),
            'region': account_data.get('region', ''),
            'thread_id': thread_id,
            'timestamp': datetime.now().isoformat()
        }
    
    return False, None, None

def check_account_couple_patterns(account_id1, account_id2):
    if account_id1 and account_id2 and abs(int(account_id1) - int(account_id2)) == 1:
        return True, f"Sequential Account IDs: {account_id1} & {account_id2}"
    
    if account_id1 == account_id2[::-1]:
        return True, f"Mirror Account IDs: {account_id1} & {account_id2}"
    
    if account_id1 and account_id2:
        sum_acc = int(account_id1) + int(account_id2)
        if sum_acc % 1000 == 0 or sum_acc % 10000 == 0:
            return True, f"Complementary sum: {account_id1} + {account_id2} = {sum_acc}"
    
    love_numbers = ['520', '521', '1314', '3344']
    for love_num in love_numbers:
        if love_num in account_id1 and love_num in account_id2:
            return True, f"Both contain love number: {love_num}"
    
    return False, None

def save_rare_account(account_data, rarity_type, reason, rarity_score, is_ghost=False):
    try:
        if is_ghost:
            rare_filename = os.path.join(GHOST_RARE_FOLDER, "rare-ghost.json")
        else:
            region = account_data.get('region', 'UNKNOWN')
            rare_filename = os.path.join(RARE_ACCOUNTS_FOLDER, f"rare-{region}.json")
        
        rare_entry = {
            'uid': account_data["uid"],
            'password': account_data["password"],
            'account_id': account_data.get("account_id", "N/A"),
            'name': account_data["name"],
            'region': "BIGBULL" if is_ghost else account_data.get('region', 'UNKNOWN'),
            'rarity_type': rarity_type,
            'rarity_score': rarity_score,
            'reason': reason,
            'date_identified': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'jwt_token': account_data.get('jwt_token', ''),
            'thread_id': account_data.get('thread_id', 'N/A')
        }
        
        file_lock = get_file_lock(rare_filename)
        with file_lock:
            rare_list = []
            if os.path.exists(rare_filename):
                try:
                    with open(rare_filename, 'r', encoding='utf-8') as f:
                        rare_list = json.load(f)
                except (json.JSONDecodeError, IOError):
                    rare_list = []
            
            existing_ids = [acc.get('account_id') for acc in rare_list]
            if account_data.get("account_id", "N/A") not in existing_ids:
                rare_list.append(rare_entry)
                
                temp_filename = rare_filename + '.tmp'
                with open(temp_filename, 'w', encoding='utf-8') as f:
                    json.dump(rare_list, f, indent=2, ensure_ascii=False)
                os.replace(temp_filename, rare_filename)
                return True
            else:
                return False
        
    except Exception as e:
        print(f"[ERROR] Error saving rare account: {e}")
        return False

def save_couples_account(account1, account2, reason, is_ghost=False):
    try:
        if is_ghost:
            couples_filename = os.path.join(GHOST_COUPLES_FOLDER, "couples-ghost.json")
        else:
            region = account1.get('region', 'UNKNOWN')
            couples_filename = os.path.join(COUPLES_ACCOUNTS_FOLDER, f"couples-{region}.json")
        
        couples_entry = {
            'couple_id': f"{account1.get('account_id', 'N/A')}_{account2.get('account_id', 'N/A')}",
            'account1': {
                'uid': account1["uid"],
                'password': account1["password"],
                'account_id': account1.get("account_id", "N/A"),
                'name': account1["name"],
                'thread_id': account1.get('thread_id', 'N/A')
            },
            'account2': {
                'uid': account2["uid"],
                'password': account2["password"],
                'account_id': account2.get("account_id", "N/A"),
                'name': account2["name"],
                'thread_id': account2.get('thread_id', 'N/A')
            },
            'reason': reason,
            'region': "BIGBULL" if is_ghost else account1.get('region', 'UNKNOWN'),
            'date_matched': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        file_lock = get_file_lock(couples_filename)
        with file_lock:
            couples_list = []
            if os.path.exists(couples_filename):
                try:
                    with open(couples_filename, 'r', encoding='utf-8') as f:
                        couples_list = json.load(f)
                except (json.JSONDecodeError, IOError):
                    couples_list = []
            
            existing_couples = [couple.get('couple_id') for couple in couples_list]
            if couples_entry['couple_id'] not in existing_couples:
                couples_list.append(couples_entry)
                
                temp_filename = couples_filename + '.tmp'
                with open(temp_filename, 'w', encoding='utf-8') as f:
                    json.dump(couples_list, f, indent=2, ensure_ascii=False)
                os.replace(temp_filename, couples_filename)
                return True
            else:
                return False
        
    except Exception as e:
        print(f"[ERROR] Error saving couples account: {e}")
        return False

def print_rarity_found(account_data, rarity_type, reason, rarity_score):
    print(f"\n[!] RARE ACCOUNT FOUND!")
    print(f"    Type: {rarity_type}")
    print(f"    Rarity Score: {rarity_score}")
    print(f"    Name: {account_data['name']}")
    print(f"    UID: {account_data['uid']}")
    print(f"    Account ID: {account_data.get('account_id', 'N/A')}")
    print(f"    Reason: {reason}")
    print(f"    Thread: {account_data.get('thread_id', 'N/A')}")
    print(f"    Region: {account_data.get('region', 'N/A')}\n")

def print_couples_found(account1, account2, reason):
    print(f"\n[!] COUPLES ACCOUNT FOUND!")
    print(f"    Reason: {reason}")
    print(f"    Account 1: {account1['name']} (ID: {account1.get('account_id', 'N/A')}) - Thread {account1.get('thread_id', 'N/A')}")
    print(f"    Account 2: {account2['name']} (ID: {account2.get('account_id', 'N/A')}) - Thread {account2.get('thread_id', 'N/A')}")
    print(f"    UIDs: {account1['uid']} & {account2['uid']}")
    print(f"    Region: {account1.get('region', 'N/A')}\n")

def install_requirements():
    required_packages = [
        'requests',
        'pycryptodome',
        'urllib3',
        'psutil'
    ]
    
    print("[*] Checking required packages...")
    
    for package in required_packages:
        try:
            if package == 'pycryptodome':
                import Crypto
            else:
                importlib.import_module(package)
            # print(f"[+] {package} is installed")
        except ImportError:
            print(f"[!] Installing {package}...")
            try:
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
                print(f"[+] {package} installed successfully")
            except subprocess.CalledProcessError:
                print(f"[!] Failed to install {package}")
                return False
    return True

def get_region_url(region_code: str) -> str:
    return REGION_URLS.get(region_code, "https://clientbp.ggblueshark.com/")

def safe_exit(signum=None, frame=None):
    global EXIT_FLAG
    EXIT_FLAG = True
    print("\n[!] Safe exit triggered. Closing script...")
    sys.exit(0)

signal.signal(signal.SIGINT, safe_exit)
signal.signal(signal.SIGTERM, safe_exit)

def generate_exponent_number():
    exponent_digits = {'0': '⁰', '1': '¹', '2': '²', '3': '³', '4': '⁴', '5': '⁵', '6': '⁶', '7': '⁷', '8': '⁸', '9': '⁹'}
    number = random.randint(1, 99999)
    number_str = f"{number:05d}"
    exponent_str = ''.join(exponent_digits[digit] for digit in number_str)
    return exponent_str

def generate_random_name(base_name):
    exponent_part = generate_exponent_number()
    return f"{base_name[:7]}{exponent_part}"

def generate_custom_password(prefix):
    garena_decoded = base64.b64decode(GARENA).decode('utf-8')
    characters = string.ascii_uppercase + string.digits
    random_part1 = ''.join(random.choice(characters) for _ in range(5))
    random_part2 = ''.join(random.choice(characters) for _ in range(5))
    return f"{prefix}_{random_part1}_{garena_decoded}_{random_part2}"

def EnC_Vr(N):
    if N < 0: 
        return b''
    H = []
    while True:
        BesTo = N & 0x7F 
        N >>= 7
        if N: 
            BesTo |= 0x80
        H.append(BesTo)
        if not N: 
            break
    return bytes(H)

def CrEaTe_VarianT(field_number, value):
    field_header = (field_number << 3) | 0
    return EnC_Vr(field_header) + EnC_Vr(value)

def CrEaTe_LenGTh(field_number, value):
    field_header = (field_number << 3) | 2
    encoded_value = value.encode() if isinstance(value, str) else value
    return EnC_Vr(field_header) + EnC_Vr(len(encoded_value)) + encoded_value

def CrEaTe_ProTo(fields):
    packet = bytearray()    
    for field, value in fields.items():
        if isinstance(value, dict):
            nested_packet = CrEaTe_ProTo(value)
            packet.extend(CrEaTe_LenGTh(field, nested_packet))
        elif isinstance(value, int):
            packet.extend(CrEaTe_VarianT(field, value))           
        elif isinstance(value, str) or isinstance(value, bytes):
            packet.extend(CrEaTe_LenGTh(field, value))           
    return packet

def E_AEs(Pc):
    Z = bytes.fromhex(Pc)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    K = AES.new(key , AES.MODE_CBC , iv)
    R = K.encrypt(pad(Z , AES.block_size))
    return R

def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def save_jwt_token(account_data, jwt_token, region, is_ghost=False):
    try:
        if is_ghost:
            token_filename = os.path.join(GHOST_FOLDER, "tokens-ghost.json")
        else:
            token_filename = os.path.join(TOKENS_FOLDER, f"tokens-{region}.json")
        
        token_entry = {
            'uid': account_data["uid"],
            'account_id': account_data.get("account_id", "N/A"),
            'jwt_token': jwt_token,
            'name': account_data["name"],
            'password': account_data["password"],
            'date_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'region': "BIGBULL" if is_ghost else region,
            'thread_id': account_data.get('thread_id', 'N/A')
        }
        
        file_lock = get_file_lock(token_filename)
        with file_lock:
            tokens_list = []
            if os.path.exists(token_filename):
                try:
                    with open(token_filename, 'r', encoding='utf-8') as f:
                        tokens_list = json.load(f)
                except (json.JSONDecodeError, IOError):
                    tokens_list = []
            
            existing_account_ids = [token.get('account_id') for token in tokens_list]
            if account_data.get("account_id", "N/A") not in existing_account_ids:
                tokens_list.append(token_entry)
                
                temp_filename = token_filename + '.tmp'
                with open(temp_filename, 'w', encoding='utf-8') as f:
                    json.dump(tokens_list, f, indent=2, ensure_ascii=False)
                
                os.replace(temp_filename, token_filename)
                return True
            else:
                return False
        
    except Exception as e:
        print(f"[ERROR] Error saving JWT token: {e}")
        return False

def save_normal_account(account_data, region, is_ghost=False):
    try:
        if is_ghost:
            account_filename = os.path.join(GHOST_ACCOUNTS_FOLDER, "ghost.json")
        else:
            account_filename = os.path.join(ACCOUNTS_FOLDER, f"accounts-{region}.json")
        
        account_entry = {
            'uid': account_data["uid"],
            'password': account_data["password"],
            'account_id': account_data.get("account_id", "N/A"),
            'name': account_data["name"],
            'region': "BIGBULL" if is_ghost else region,
            'date_created': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'thread_id': account_data.get('thread_id', 'N/A')
        }
        
        file_lock = get_file_lock(account_filename)
        with file_lock:
            accounts_list = []
            if os.path.exists(account_filename):
                try:
                    with open(account_filename, 'r', encoding='utf-8') as f:
                        accounts_list = json.load(f)
                except (json.JSONDecodeError, IOError):
                    accounts_list = []
            
            existing_account_ids = [acc.get('account_id') for acc in accounts_list]
            if account_data.get("account_id", "N/A") not in existing_account_ids:
                accounts_list.append(account_entry)
                
                temp_filename = account_filename + '.tmp'
                with open(temp_filename, 'w', encoding='utf-8') as f:
                    json.dump(accounts_list, f, indent=2, ensure_ascii=False)
                
                os.replace(temp_filename, account_filename)
                return True
            else:
                return False
        
    except Exception as e:
        print(f"[ERROR] Error saving normal account: {e}")
        return False

def smart_delay():
    time.sleep(random.uniform(1, 2))

def create_acc(region, account_name, password_prefix, is_ghost=False):
    if EXIT_FLAG:
        return None
    try:
        password = generate_custom_password(password_prefix)
        data = f"password={password}&client_type=2&source=2&app_id=100067"
        message = data.encode('utf-8')
        signature = hmac.new(key, message, hashlib.sha256).hexdigest()
        
        url = "https://100067.connect.garena.com/oauth/guest/register"
        headers = {
            "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
            "Authorization": "Signature " + signature,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip",
            "Connection": "Keep-Alive"
        }
        
        response = requests.post(url, headers=headers, data=data, timeout=30, verify=False)
        response.raise_for_status()
        
        if 'uid' in response.json():
            uid = response.json()['uid']
            print(f"[+] Guest account created: {uid}")
            smart_delay()
            return token(uid, password, region, account_name, password_prefix, is_ghost)
        return None
    except Exception as e:
        print(f"[-] Create account failed: {e}")
        smart_delay()
        return None

def token(uid, password, region, account_name, password_prefix, is_ghost=False):
    if EXIT_FLAG:
        return None
    try:
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {
            "Accept-Encoding": "gzip",
            "Connection": "Keep-Alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
        }
        body = {
            "uid": uid,
            "password": password,
            "response_type": "token",
            "client_type": "2",
            "client_secret": key,
            "client_id": "100067"
        }
        
        response = requests.post(url, headers=headers, data=body, timeout=30, verify=False)
        response.raise_for_status()
        
        if 'open_id' in response.json():
            open_id = response.json()['open_id']
            access_token = response.json()["access_token"]
            refresh_token = response.json()['refresh_token']
            
            result = encode_string(open_id)
            field = to_unicode_escaped(result['field_14'])
            field = codecs.decode(field, 'unicode_escape').encode('latin1')
            print(f"[+] Token granted for: {uid}")
            smart_delay()
            return Major_Regsiter(access_token, open_id, field, uid, password, region, account_name, password_prefix, is_ghost)
        return None
    except Exception as e:
        print(f"[-] Token grant failed: {e}")
        smart_delay()
        return None

def encode_string(original):
    keystream = [0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37,
                 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30]
    encoded = ""
    for i in range(len(original)):
        orig_byte = ord(original[i])
        key_byte = keystream[i % len(keystream)]
        result_byte = orig_byte ^ key_byte
        encoded += chr(result_byte)
    return {"open_id": original, "field_14": encoded}

def to_unicode_escaped(s):
    return ''.join(c if 32 <= ord(c) <= 126 else f'\\u{ord(c):04x}' for c in s)

def Major_Regsiter(access_token, open_id, field, uid, password, region, account_name, password_prefix, is_ghost=False):
    if EXIT_FLAG:
        return None
    try:
        if is_ghost:
            url = "https://loginbp.ggblueshark.com/MajorRegister"
        else:
            if region.upper() in ["ME", "TH"]:
                url = "https://loginbp.common.ggbluefox.com/MajorRegister"
            else:
                url = "https://loginbp.ggblueshark.com/MajorRegister"
            
        name = generate_random_name(account_name)
        
        headers = {
            "Accept-Encoding": "gzip",
            "Authorization": "Bearer",   
            "Connection": "Keep-Alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "Expect": "100-continue",
            "Host": "loginbp.ggblueshark.com" if is_ghost or region.upper() not in ["ME", "TH"] else "loginbp.common.ggbluefox.com",
            "ReleaseVersion": "OB52",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
            "X-GA": "v1 1",
            "X-Unity-Version": "2018.4."
        }

        lang_code = "pt" if is_ghost else REGION_LANG.get(region.upper(), "en")
        payload = {
            1: name,
            2: access_token,
            3: open_id,
            5: 102000007,
            6: 4,
            7: 1,
            13: 1,
            14: field,
            15: lang_code,
            16: 1,
            17: 1
        }

        payload_bytes = CrEaTe_ProTo(payload)
        encrypted_payload = E_AEs(payload_bytes.hex())
        
        response = requests.post(url, headers=headers, data=encrypted_payload, verify=False, timeout=30)
        
        if response.status_code == 200:
            print(f"[+] MajorRegister successful: {name}")
            
            login_result = perform_major_login(uid, password, access_token, open_id, region, is_ghost)
            account_id = login_result.get("account_id", "N/A")
            jwt_token = login_result.get("jwt_token", "")
            
            if not is_ghost and jwt_token and account_id != "N/A" and region.upper() != "BR":
                region_bound = force_region_binding(region, jwt_token)
                if region_bound:
                    print(f"[+] Region {region} bound successfully!")
                else:
                    print(f"[-] Region binding failed for {region}")
            
            account_data = {
                "uid": uid, 
                "password": password, 
                "name": name, 
                "region": "GHOST" if is_ghost else region, 
                "status": "success",
                "account_id": account_id,
                "jwt_token": jwt_token
            }
            
            return account_data
        else:
            print(f"[-] MajorRegister returned status: {response.status_code}")
            return None
    except Exception as e:
        print(f"[-] Major_Regsiter error: {str(e)}")
        smart_delay()
        return None

def perform_major_login(uid, password, access_token, open_id, region, is_ghost=False):
    try:
        lang = "pt" if is_ghost else REGION_LANG.get(region.upper(), "en")
        
        payload_parts = [
            b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.114.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02',
            lang.encode("ascii"),
            b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
        ]
        
        payload = b''.join(payload_parts)
        
        if is_ghost:
            url = "https://loginbp.ggblueshark.com/MajorLogin"
        elif region.upper() in ["ME", "TH"]:
            url = "https://loginbp.common.ggbluefox.com/MajorLogin"
        else:
            url = "https://loginbp.ggblueshark.com/MajorLogin"
        
        headers = {
            "Accept-Encoding": "gzip",
            "Authorization": "Bearer",
            "Connection": "Keep-Alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "Expect": "100-continue",
            "Host": "loginbp.ggblueshark.com" if is_ghost or region.upper() not in ["ME", "TH"] else "loginbp.common.ggbluefox.com",
            "ReleaseVersion": "OB52",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
            "X-GA": "v1 1",
            "X-Unity-Version": "2018.4.11f1"
        }

        data = payload
        data = data.replace(b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390', access_token.encode())
        data = data.replace(b'1d8ec0240ede109973f3321b9354b44d', open_id.encode())
        
        d = encrypt_api(data.hex())
        final_payload = bytes.fromhex(d)

        response = requests.post(url, headers=headers, data=final_payload, verify=False, timeout=30)
        
        if response.status_code == 200 and len(response.text) > 10:
            jwt_start = response.text.find("eyJ")
            if jwt_start != -1:
                jwt_token = response.text[jwt_start:]
                second_dot = jwt_token.find(".", jwt_token.find(".") + 1)
                if second_dot != -1:
                    jwt_token = jwt_token[:second_dot + 44]
                    
                    account_id = decode_jwt_token(jwt_token)
                    return {"account_id": account_id, "jwt_token": jwt_token}
        
        return {"account_id": "N/A", "jwt_token": ""}
    except Exception as e:
        print(f"[-] MajorLogin failed: {e}")
        return {"account_id": "N/A", "jwt_token": ""}

def decode_jwt_token(jwt_token):
    try:
        parts = jwt_token.split('.')
        if len(parts) >= 2:
            payload_part = parts[1]
            padding = 4 - len(payload_part) % 4
            if padding != 4:
                payload_part += '=' * padding
            decoded = base64.urlsafe_b64decode(payload_part)
            data = json.loads(decoded)
            account_id = data.get('account_id') or data.get('external_id')
            if account_id:
                return str(account_id)
    except Exception as e:
        print(f"[-] JWT decode failed: {e}")
    return "N/A"

def force_region_binding(region, jwt_token):
    try:
        if region.upper() in ["ME", "TH"]:
            url = "https://loginbp.common.ggbluefox.com/ChooseRegion"
        else:
            url = "https://loginbp.ggblueshark.com/ChooseRegion"
        
        if region.upper() == "CIS":
            region_code = "RU"
        else:
            region_code = region.upper()
            
        fields = {1: region_code}
        proto_data = CrEaTe_ProTo(fields)
        encrypted_data = encrypt_api(proto_data.hex())
        payload = bytes.fromhex(encrypted_data)
        
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 12; M2101K7AG Build/SKQ1.210908.001)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'Authorization': f"Bearer {jwt_token}",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB52"
        }
        
        response = requests.post(url, data=payload, headers=headers, verify=False, timeout=30)
        return response.status_code == 200
    except Exception as e:
        print(f"[-] Region binding failed: {e}")
        return False

def generate_single_account(region, account_name, password_prefix, total_accounts, thread_id, is_ghost=False):
    global SUCCESS_COUNTER, RARE_COUNTER, COUPLES_COUNTER
    if EXIT_FLAG:
        return None
        
    with LOCK:
        if SUCCESS_COUNTER >= total_accounts:
            return None

    account_result = create_acc(region, account_name, password_prefix, is_ghost)
    if not account_result:
        return None

    account_id = account_result.get("account_id", "N/A")
    jwt_token = account_result.get("jwt_token", "")
    
    account_result['thread_id'] = thread_id

    with LOCK:
        SUCCESS_COUNTER += 1
        current_count = SUCCESS_COUNTER

    print(f"[INFO] Registration {current_count}/{total_accounts}")
    print(f"       Name: {account_result['name']}")
    print(f"       UID: {account_result['uid']}")
    print(f"       Account ID: {account_id}")
    print(f"       Password: {account_result['password']}")
    if is_ghost:
        print(f"       Mode: GHOST")
    else:
        print(f"       Region: {region}")
    
    is_rare, rarity_type, rarity_reason, rarity_score = check_account_rarity(account_result)
    if is_rare:
        with LOCK:
            RARE_COUNTER += 1
        print_rarity_found(account_result, rarity_type, rarity_reason, rarity_score)
        save_rare_account(account_result, rarity_type, rarity_reason, rarity_score, is_ghost)
        print(f"[+] Rare account saved! (Total rare: {RARE_COUNTER})")
    
    is_couple, couple_reason, partner_data = check_account_couples(account_result, thread_id)
    if is_couple and partner_data:
        with LOCK:
            COUPLES_COUNTER += 1
        print_couples_found(account_result, partner_data, couple_reason)
        save_couples_account(account_result, partner_data, couple_reason, is_ghost)
        print(f"[+] Couples accounts saved! (Total couples: {COUPLES_COUNTER})")
    
    if is_ghost:
        save_success = save_normal_account(account_result, "GHOST", is_ghost=True)
        if save_success:
            print("[+] GHOST account saved")
        
        if jwt_token:
            token_saved = save_jwt_token(account_result, jwt_token, "GHOST", is_ghost=True)
            if token_saved:
                print("[+] JWT token saved for GHOST account")
    else:
        save_success = save_normal_account(account_result, region)
        if save_success:
            print(f"[+] Account #{current_count} saved to ACCOUNTS folder")
        else:
            print(f"[-] Account {account_result['uid']} already exists")
        
        if jwt_token:
            token_saved = save_jwt_token(account_result, jwt_token, region)
            if token_saved:
                print(f"[+] JWT token saved for {account_result['uid']}")
    
    return {"account": account_result}

def worker(region, account_name, password_prefix, total_accounts, thread_id, is_ghost=False):
    print(f"[*] Thread {thread_id} started")
    
    accounts_generated = 0
    while not EXIT_FLAG:
        with LOCK:
            if SUCCESS_COUNTER >= total_accounts:
                break
        
        result = generate_single_account(region, account_name, password_prefix, total_accounts, thread_id, is_ghost)
        if result:
            accounts_generated += 1
        
        time.sleep(random.uniform(0.5, 1.5))
    
    print(f"[*] Thread {thread_id} finished: {accounts_generated} accounts generated")

def main():
    global SUCCESS_COUNTER, TARGET_ACCOUNTS, RARE_COUNTER, COUPLES_COUNTER, RARITY_SCORE_THRESHOLD

    parser = argparse.ArgumentParser(description="BIGBULL V12 CLI - Free Fire Account Generator")
    
    parser.add_argument("--region", required=True, help="Region code (e.g., IND, ID, VN, BR, ME, TH, GHOST)", type=str.upper)
    parser.add_argument("--count", required=True, help="Total Accounts to Generate", type=int)
    parser.add_argument("--name", required=True, help="Account name prefix", type=str)
    parser.add_argument("--pass-prefix", required=True, help="Password prefix", type=str)
    parser.add_argument("--threads", required=False, help="Number of threads (Speed)", type=int, default=1)
    parser.add_argument("--threshold", required=False, help="Rarity Threshold (Default: 2)", type=int, default=2)

    args = parser.parse_args()

    selected_region = args.region
    is_ghost = False
    if selected_region == "GHOST":
        is_ghost = True
        selected_region = "BR" # Ghost mode uses BR backend logic usually

    if selected_region not in REGION_LANG and not is_ghost:
        print(f"[-] Invalid region: {args.region}")
        print(f"[*] Valid regions: {', '.join(REGION_LANG.keys())}, GHOST")
        sys.exit(1)

    account_count = args.count
    account_name = args.name
    password_prefix = args.pass_prefix
    thread_count = args.threads
    RARITY_SCORE_THRESHOLD = args.threshold
    TARGET_ACCOUNTS = account_count

    print(f"[*] Starting BIGBULL Generator CLI")
    if is_ghost:
        print(f"[!] Mode: GHOST MODE")
    else:
        print(f"[!] Region: {selected_region}")
    print(f"[!] Target Accounts: {account_count}")
    print(f"[!] Name Prefix: {account_name}")
    print(f"[!] Password Prefix: {password_prefix}")
    print(f"[!] Rarity Threshold: {RARITY_SCORE_THRESHOLD}+")
    print(f"[!] Threads: {thread_count}")
    print(f"[*] Saving to: {ACCOUNTS_FOLDER}")
    print(f"[*] Starting in 3 seconds...")
    time.sleep(3)

    SUCCESS_COUNTER = 0
    RARE_COUNTER = 0
    COUPLES_COUNTER = 0
    start_time = time.time()
    threads = []

    print(f"\n[*] Starting generation with {thread_count} threads...\n")

    for i in range(thread_count):
        t = threading.Thread(target=worker, args=(selected_region, account_name, password_prefix, account_count, i+1, is_ghost))
        t.daemon = True
        t.start()
        threads.append(t)

    try:
        while any(t.is_alive() for t in threads):
            time.sleep(2)
            with LOCK:
                current_count = SUCCESS_COUNTER
            progress = (current_count / account_count) * 100
            print(f"[STATS] Progress: {current_count}/{account_count} ({progress:.1f}%) | Rare: {RARE_COUNTER} | Couples: {COUPLES_COUNTER}")
            if current_count >= account_count:
                break
                
    except KeyboardInterrupt:
        print("\n[!] Generation interrupted by user!")
        EXIT_FLAG = True
        for t in threads:
            t.join(timeout=1)

    for t in threads:
        t.join(timeout=5)

    end_time = time.time()
    elapsed_time = end_time - start_time

    print(f"\n[+] Generation completed!")
    print(f"[STATS] Accounts generated: {SUCCESS_COUNTER}/{account_count}")
    print(f"[STATS] Rare accounts found: {RARE_COUNTER}")
    print(f"[STATS] Couples pairs found: {COUPLES_COUNTER}")
    print(f"[STATS] Time taken: {elapsed_time:.2f} seconds")
    print(f"[STATS] Speed: {SUCCESS_COUNTER/elapsed_time:.2f} accounts/second")
    
    if is_ghost:
        print(f"[+] GHOST accounts saved in: {GHOST_ACCOUNTS_FOLDER}")
        print(f"[+] Rare GHOST accounts saved in: {GHOST_RARE_FOLDER}")
        print(f"[+] Couples GHOST accounts saved in: {GHOST_COUPLES_FOLDER}")
    else:
        print(f"[+] Accounts saved in: {ACCOUNTS_FOLDER}")
        print(f"[+] Rare accounts saved in: {RARE_ACCOUNTS_FOLDER}")
        print(f"[+] Couples accounts saved in: {COUPLES_ACCOUNTS_FOLDER}")
        print(f"[+] JWT tokens saved in: {TOKENS_FOLDER}")

if __name__ == "__main__":
    try:
        if install_requirements():
            main()
    except KeyboardInterrupt:
        safe_exit()
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        print(f"[*] Restarting script in 2 seconds...")
        time.sleep(2)
        os.execv(sys.executable, [sys.executable] + sys.argv)