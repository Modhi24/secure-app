# secure-app
Secure Web Application - Detection and Mitigation of Security Vulnerabilities
# Secure Web Application

A CSC 429 project built with Flask and SQLite. It supports registration, login, a protected dashboard, comments, and an administrator-only account list. The final version uses bound SQL parameters, bcrypt, sanitized comments, role checks, HTTPS, and encrypted session cookies.

## Run locally in Windows PowerShell

Extract the ZIP and open PowerShell in the folder containing `app.py`. Run:

```powershell
python -m venv venv
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe setup_local_tls.py
$env:SESSION_ENCRYPTION_KEY = (.\venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
.\venv\Scripts\python.exe app.py
```

Open [https://127.0.0.1:5000](https://127.0.0.1:5000). The browser can display a trust warning because the certificate was generated locally. Use the certificate from `.local-tls/cert.pem` when verifying or explicitly trusting the local test server. Run the certificate setup once per certificate pair. Keep the same key in the current terminal across restarts to preserve sessions. A new key requires users to sign in again.

SQLite creates `database.db` on first run. Start with the clean database in a fresh extracted folder for the demo. If reusing an older database, old plaintext or MD5 accounts cannot authenticate and need a fresh registration under a new username or an account reset. Keep databases, the TLS private key, and the session encryption key out of Git.

## Verify the final build

| Check | Steps | Expected |
| --- | --- | --- |
| Registration and SQL parameter binding | Register a disposable account named `O'Connor` with a password that meets the rules. Sign in first with an incorrect password, then with the correct password. Review the placeholders and separate parameter tuples in `app.py`. | The apostrophe is treated as text. Only the correct password signs in. |
| Password rules and storage | Try `abc`, then use a disposable password meeting all visible rules. Inspect the resulting row in a local SQLite viewer. | The weak password is rejected and the accepted account has a bcrypt hash starting with `$2b$12$`. |
| Comments | Sign in and post `<b>Hello</b><em>plain</em>`. | Hello stays bold. The em tag is removed and its text stays. |
| Role-based access | Register two accounts. In another PowerShell window in the app folder, run `.\venv\Scripts\python.exe make_admin.py demo-admin` using the name of the second account. Sign in again after assigning the role. Open `/admin` as each account. | A standard account gets 403 and the administrator sees the account list. |
| HTTPS and cookie flags | Sign in over HTTPS. In DevTools open **Network**, choose the POST to `/login`, then inspect **Response Headers → Set-Cookie**. Alternatively, inspect Cookies under **Application**. | `secure_app_session` has `Secure`, `HttpOnly` and `SameSite=Lax`. |
| Session encryption | In the same response inspect the cookie value. Review `session_security.py`, where Fernet encrypts the serialized session before it is sent to the browser. | The cookie holds an encrypted token. The test results in the report cover authenticated decryption, expiry, and invalid-token handling. |
| Logout and Back | Sign in, open the dashboard, click Logout, then use Back. In a separate check enter the dashboard URL directly after logging out. | Both return to Login. |

See `Security_Report.docx` for before-and-after findings, actual tests, challenges, and the access-control matrix.

## References

- [Flask configuration](https://flask.palletsprojects.com/en/stable/config/)
- [Fernet authenticated encryption](https://cryptography.io/en/latest/fernet/)
- [bcrypt](https://github.com/pyca/bcrypt)
- [Bleach sanitization](https://bleach.readthedocs.io/en/latest/clean.html)

