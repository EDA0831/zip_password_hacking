
import pyzipper   # zipfile 상위호환 — AES + ZipCrypto 둘 다 지원
import itertools
from multiprocessing import Manager, freeze_support
from concurrent.futures import ProcessPoolExecutor, as_completed
from colorama import init, Fore, Style
 
init(autoreset=True)   # colorama: print마다 색 자동 리셋
 
# 브루트포스에 쓸 문자셋 (대/소문자 + 숫자 + 기호)
CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()'
 
# 사전 파일 (스크립트와 같은 폴더에 있다고 가정)
WORDLISTS = ["fasttrack.txt", "rockyou.txt", "wifite.txt"]
 
# 몇 번 시도마다 "다른 프로세스가 찾았나" 확인할지 (Manager 통신 비용이 있어 매번은 안 함)
CHECK_EVERY = 5000
 
 
def open_zip(filename):
    """zip을 열고 (ZipFile, 검증용_멤버이름) 반환. 실패하면 (None, None).
    검증용 멤버는 '폴더가 아니고 크기 > 0'인 파일 (폴더/빈 파일은 비번과 무관하게 열려 오탐)."""
    try:
        zf = pyzipper.AESZipFile(filename)   # AES·ZipCrypto 자동 처리
    except FileNotFoundError:
        return None, None
    except pyzipper.BadZipFile:
        return None, None
    files = [i for i in zf.infolist() if not i.is_dir()]
    target = next((i.filename for i in files if i.file_size > 0),
                  files[0].filename if files else None)
    if target is None:
        zf.close()
        return None, None
    return zf, target
 
 
def try_password(zf, member, pwd):
    """비번 하나로 zip 안 파일 하나를 읽어본다. 맞으면 True, 틀리면 False.
    틀린 비번은 RuntimeError·BadZipFile·zlib오류 등을 던지므로 예외는 전부 실패 처리.
    (단, 위 open_zip에서 파일 유효성은 이미 확인 → 여기 예외 = 사실상 '틀린 비번')"""
    try:
        zf.read(member, pwd=pwd.encode("utf-8", errors="ignore"))
        return True
    except Exception:
        return False
 
 
def dictionary_admission(filename, attack_file, stop_event):
    """[워커] 사전 파일 하나를 담당해 한 줄씩 대입. 찾으면 비번 반환, 아니면 None.
    stop_event: 다른 프로세스가 먼저 찾으면 켜지는 공유 신호."""
    import os
    if not os.path.exists(attack_file):
        return None
    zf, member = open_zip(filename)
    if zf is None:
        return None
    print(f"[*] 사전 시작: {attack_file}")
    try:
        with open(attack_file, "r", errors="ignore") as f:
            for i, line in enumerate(f):
                if i % CHECK_EVERY == 0 and stop_event.is_set():
                    return None
                candidate = line.strip()
                if candidate and try_password(zf, member, candidate):
                    stop_event.set()
                    return candidate
    finally:
        zf.close()
    return None
 
 
def bruteforce(filename, attack_string, start_value, end_value, stop_event):
    """[워커] start_value~end_value 길이의 모든 조합을 대입. 찾으면 비번 반환, 아니면 None."""
    zf, member = open_zip(filename)
    if zf is None:
        return None
    print(f"[*] 브루트 시작: 길이 {start_value}~{end_value - 1}")
    try:
        count = 0
        for length in range(start_value, end_value):
            for combo in itertools.product(attack_string, repeat=length):
                count += 1
                if count % CHECK_EVERY == 0 and stop_event.is_set():
                    return None
                zip_pw = ''.join(combo)
                if try_password(zf, member, zip_pw):
                    stop_event.set()
                    return zip_pw
    finally:
        zf.close()
    return None
 
 
def crack(zip_path):
    """사전 3종 + 브루트 3구간을 여러 프로세스로 동시에 돌린다.
    하나가 찾으면 stop_event로 전체 중단."""
    # 대상 zip이 열리는지 먼저 확인 (없는 파일/깨진 zip이면 프로세스 띄우기 전에 걸러냄)
    zf, member = open_zip(zip_path)
    if zf is None:
        print(f"[!] zip을 열 수 없음(파일 없음/깨짐): {zip_path}")
        return
    zf.close()
 
    found_pw = None
    with Manager() as manager:
        stop_event = manager.Event()   # 프로세스 간 공유되는 '찾음' 신호
        with ProcessPoolExecutor() as executor:   # max_workers 기본값 = 코어 수
            futures = []
            for wl in WORDLISTS:
                futures.append(executor.submit(dictionary_admission, zip_path, wl, stop_event))
            # 길이 1~2 / 3 / 4 를 각각 다른 프로세스에 (5자↑는 72^5≈19억이라 비현실적)
            for (s, e) in ((1, 3), (3, 4), (4, 5)):
                futures.append(executor.submit(bruteforce, zip_path, CHARS, s, e, stop_event))
 
            for fut in as_completed(futures):
                try:
                    result = fut.result()
                    if result is not None and found_pw is None:
                        found_pw = result
                except Exception as es_1:
                    print("[메인] 워커 예외:", type(es_1).__name__, es_1)
 
    if found_pw is not None:
        print(f"[+] 찾았다! 비밀번호: {Fore.GREEN}{found_pw}{Style.RESET_ALL}")
    else:
        print("[!] 비밀번호를 찾지 못함 (사전 + 길이4 브루트 소진)")
 
 
def start_attack():
    """메인 루프. zip 파일명을 입력받아 크랙, exit로 종료."""
    while True:
        zip_path = input(f"{Fore.RED}입력>>{Style.RESET_ALL}")
        if zip_path == "exit":
            print("종료...")
            return
        crack(zip_path)
 
 
if __name__ == '__main__':
    freeze_support()   # Windows에서 multiprocessing 쓸 때 필수
    print("입력>> 에 패스워드 걸린 zip파일을 입력하시오")
    print("exit 입력하면 프로그램 종료")
    start_attack()
