
# HTB Machine Abducted Write-Up
## austinjump-sec
#### *I apologize for the lack of screenshots as my Kali .iso is on a volatile Ventoy USB, next time I will consider transfering screenshots to seperate device before closing* 

## 1. Recon
Started assessment with ``nmap -sV -Pn`` which revealed three ports and two services, SMB on port 139 and 445, SSH on 22.    

I quickly enumerated share-names and connected to a low-privilege share HB-Reception, it was there I noticed I could write files and directories, this behavior pointed me towards CVE-2017-7494 but after a few failed payloads I quickly pivoted to CVE-2026-4480 using a PoC Python script. 

This gave me a shell as user ``nobody``

## 2. Lateral Movement
After taking note of the suspicious SMB privileges I tried creating a symlink to /home/marcus, SUID S bit manipulation however this SMB share was securely filtering files into root executable files /var/spool/samba. Taking note of this gives me a big hint for my second lateral move. <br> <br>  After running linpeas and exploring manually I found an obfuscated rclone password ``HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw``, this was easily able to be cracked with command  
``rclone reveal HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw`` which gives us the final password: ``iXzvcib3SrpZ``.
<br>
After logging in with SSH I concluded the password belongs to Scott.

## 3. 2nd Lateral Movement
From here user flag was accessible with command ``cat /marcus/home/user.txt``. <br> <br>
I noticed that the transfer shares .conf allows wide links and defaults to Marcus, making it logistically the next move. After taking note of weird SMB symlink behavior I was quick to try and drop SSH keys using an SMB symlink. I created an SSH certificate, then the symlink to /home/marcus and placed it in child directory /.ssh/authorized_keys. Copying the certificate and logging in with ssh. 

## Privilege Escalation
After enough digging I found a /etc/systemd/system/smbd.service.d file belonging and writeable to my group as Marcus, this means I can drop in my own malicious .conf file to automatically integrate, with root privileges. I did this using command,  
``cat > /etc/systemd/system/smbd.service.d/rootbash.conf << 'EOF'
[Service]
ExecStartPre=/bin/bash -c 'chmod +s /bin/bash'
EOF``. <br>
For the changes to actuall apply, I had to restart the service with ``systemctl daemon-reload
systemctl restart smbd`` and run ``bash -p`` to enter the privileged bash environment. 
From here, root flag was accessible with ``cat /root/root.txt``
