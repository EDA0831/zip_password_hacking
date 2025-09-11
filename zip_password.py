import zipfile
import sys
import itertools
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Back, Style
found = threading.Event()
lock = threading.Lock()
init(autoreset=True)



def dictionary_admission(filename, attack_file):
    with zipfile.ZipFile(filename) as zf:
        with open(attack_file, "r", errors="ignore") as f:
            for line in f:
                if found.is_set():
                    return
                candidate = line.strip()
                try:
                    zf.extractall(pwd=candidate.encode("utf-8"))
                    with lock:
                        if not found.is_set():
                            print(f"[+] 찾았다! 비밀번호: {Fore.GREEN}{candidate}{Style.RESET_ALL}")
                            found.set()
                    break
                except:
                    continue

def bruteforce(filename, attack_string, start_value, end_value):
    with zipfile.ZipFile(filename) as zf:
        for length in range(start_value, end_value):
            for combo in itertools.product(attack_string, repeat=length):
                if found.is_set():
                    return
                zip_pw = ''.join(combo)
                try:
                    zf.extractall(pwd=zip_pw.encode("utf-8"))
                    with lock:
                        if not found.is_set():
                            print(f"[+] 찾았다! 비밀번호: {Fore.GREEN}{zip_pw}{Style.RESET_ALL}")
                            found.set()
                    return
                except:
                    continue



def start_attack():
    # zip_path = "test.zip"
    rockyou = "rockyou.txt"
    wifite = "wifite.txt"
    fasttrack = "fasttrack.txt"
    chars = 'abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()'
    while True:
        found.clear()
        zip_path = input(f"{Fore.RED}입력>>{Style.RESET_ALL}")
        if zip_path == "exit":
            print("종료...")
            return
        with ThreadPoolExecutor(max_workers=21) as executor:
            futures = [
                executor.submit(dictionary_admission, zip_path, rockyou),
                executor.submit(dictionary_admission, zip_path, wifite),
                executor.submit(dictionary_admission, zip_path, fasttrack),
                executor.submit(bruteforce, zip_path, chars, 1, 2),
                executor.submit(bruteforce, zip_path, chars, 2, 3),
                executor.submit(bruteforce, zip_path, chars, 3, 4),
                executor.submit(bruteforce, zip_path, chars, 5, 6),
                executor.submit(bruteforce, zip_path, chars, 6, 7),
                executor.submit(bruteforce, zip_path, chars, 7, 8),
                executor.submit(bruteforce, zip_path, chars, 9, 10),
                executor.submit(bruteforce, zip_path, chars, 10, 11),
                executor.submit(bruteforce, zip_path, chars, 11, 12),
                executor.submit(bruteforce, zip_path, chars, 12, 13),
                executor.submit(bruteforce, zip_path, chars, 13, 14),
                executor.submit(bruteforce, zip_path, chars, 14, 15),
                executor.submit(bruteforce, zip_path, chars, 15, 16),
                executor.submit(bruteforce, zip_path, chars, 16, 17),
                executor.submit(bruteforce, zip_path, chars, 17, 18),
                executor.submit(bruteforce, zip_path, chars, 18, 19),
                executor.submit(bruteforce, zip_path, chars, 19, 20),
                executor.submit(bruteforce, zip_path, chars, 20, 21),
                executor.submit(bruteforce, zip_path, chars, 21, 22),
                executor.submit(bruteforce, zip_path, chars, 22, 23),
            ]
            for fut in as_completed(futures):
                try:
                    fut.result()  # ← 워커 내부 예외를 여기서 재-발생시켜 확인
                except Exception as es_1:
                    print("[메인] 워커 예외:", type(es_1).__name__, es_1)


if __name__=='__main__':
    print("입력>> 에 패스워드 걸린 zip파일을 입력하시오")
    print("exit 입력하면 프로그램 종료")
    start_attack()
