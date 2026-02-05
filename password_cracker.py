import hashlib
import itertools
import string
import argparse
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

# supported hash types
hash_name = [
    "md5", "sha1", "sha224", "sha256", "sha384",
    "sha3_224", "sha3_256", "sha3_384", "sha3_512", "sha512"
]

# --------------------------------------------------
# generate passwords (brute force)
def generate_passwords(min_length, max_length, characters):
    for length in range(min_length, max_length + 1):
        for pwd in itertools.product(characters, repeat=length):
            yield ''.join(pwd)

# --------------------------------------------------
# check hash function (MISSING in your screenshot – now fixed)
def check_hash(hash_fn, password, target_hash):
    return hash_fn(password.encode()).hexdigest() == target_hash

# --------------------------------------------------
# main cracking functiongit init

def crack_hash(hash, wordlist=None, hash_type="md5",
               min_length=0, max_length=0,
               characters=string.ascii_letters + string.digits,
               max_workers=4):

    hash_fn = getattr(hashlib, hash_type, None)

    if hash_fn is None or hash_type not in hash_name:
        raise ValueError(f"[!] Invalid hash type: {hash_type}")

    # ---------------- WORDLIST ATTACK ----------------
    if wordlist:
        with open(wordlist, 'r') as f:
            lines = f.readlines()

        total_lines = len(lines)
        print(f"[*] Cracking hash using wordlist ({total_lines} passwords)")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(check_hash, hash_fn, line.strip(), hash): line
                for line in lines
            }

            for future in tqdm(futures, total=total_lines, desc="Cracking hash"):
                if future.result():
                    return futures[future].strip()

    # ---------------- BRUTE FORCE ATTACK ----------------
    elif min_length > 0 and max_length > 0:
        total_combinations = sum(
            len(characters) ** length
            for length in range(min_length, max_length + 1)
        )

        print(f"[*] Cracking hash using {hash_type}")
        print(f"[*] Password length: {min_length} to {max_length}")
        print(f"[*] Total combinations: {total_combinations}")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            with tqdm(total=total_combinations,
                      desc="Generating and cracking hash") as pbar:

                for pwd in generate_passwords(min_length, max_length, characters):
                    future = executor.submit(check_hash, hash_fn, pwd, hash)
                    pbar.update(1)

                    if future.result():
                        return pwd

    return None

# --------------------------------------------------
# main
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hash cracker")

    parser.add_argument("hash", help="The hash to crack")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist")
    parser.add_argument("--hash_type", default="md5", help="Hash type (md5, sha256...)")
    parser.add_argument("--min_length", type=int, help="Minimum password length")
    parser.add_argument("--max_length", type=int, help="Maximum password length")
    parser.add_argument("-c", "--characters",
                        default=string.ascii_letters + string.digits,
                        help="Characters to use for password generation")
    parser.add_argument("--max_workers", type=int, default=4,
                        help="Maximum number of threads")

    args = parser.parse_args()

    cracked_password = crack_hash(
        args.hash,
        args.wordlist,
        args.hash_type,
        args.min_length,
        args.max_length,
        args.characters,
        args.max_workers
    )

    if cracked_password:
        print(f"[+] Found password: {cracked_password}")
    else:
        print("[-] Password not found")
