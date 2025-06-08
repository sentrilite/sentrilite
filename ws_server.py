# Copyright (c) 2025 Sentrilite, Inc. All rights reserved.
#
# This software is the confidential and proprietary information of
# Sentrilite ("Confidential Information"). You shall not
# disclose such Confidential Information and shall use it only
# in accordance with the terms of the license agreement you entered
# into with Sentrilite.

import asyncio
import json
import os
import time
import subprocess
import websockets
from websockets.server import serve
import datetime
import sys

clients = set()
intruder_seen = False

rules_path = "rules.json"
custom_rules = []
rules_last_mtime = 0

xdr_rules = []
xdr_rules_path = "xdr_rules.json"

alerts = []
alerts_path = "alerts.json"

_sfile_mtime = 0
sensitive_files = set()
sensitive_files_path = "sensitive_files.json"

license_expired = False

# Load EDR rules at startup
if os.path.exists(rules_path):
    try:
        with open(rules_path, "r") as f:
            custom_rules = json.load(f)
    except Exception as e:
        print("[RULES] Failed to load rules at startup:", e)

# Load XDR rules at startup
if os.path.exists(xdr_rules_path):
    try:
        with open(xdr_rules_path, "r") as f:
            xdr_rules = json.load(f)
    except Exception as e:
        print("[XDR] Failed to load XDR rules at startup:", e)

# Load alerts at startup
def load_alerts():
    global alerts
    try:
        if os.path.exists(alerts_path):
            with open(alerts_path) as f:
                content = f.read().strip()
                if content:
                    alerts = json.loads(content)
                else:
                    alerts = []  # 🛡️ Handle empty file case
        else:
            alerts = []
        print(f"[ALERTS] Loaded {len(alerts)} alerts from disk.")
    except Exception as e:
        print(f"[ALERTS] Failed to load alerts: {e}")
        alerts = []

def save_alerts():
    try:
        with open(alerts_path, "w") as f:
            json.dump(alerts, f, indent=2)
    except Exception as e:
        print(f"[ALERTS] Failed to save alerts: {e}")

load_alerts()

def load_rules_if_changed():
    global custom_rules, rules_last_mtime
    try:
        mtime = os.path.getmtime(rules_path)
        if mtime != rules_last_mtime:
            with open(rules_path, "r") as f:
                custom_rules = json.load(f)
            print(f"[RULES] Reloaded {len(custom_rules)} custom rules.")
            rules_last_mtime = mtime
    except Exception as e:
        print(f"[RULES] Error loading rules: {e}")

def load_sensitive_files_if_changed():
    global _sfile_mtime, sensitive_files

    try:
        if not os.path.exists(sensitive_files_path):
            # File doesn't exist, reset state safely
            if _sfile_mtime != 0:
                print("[*] sensitive_files.json missing, resetting sensitive file list.")
            _sfile_mtime = 0
            sensitive_files = set()
            return

        mtime = os.path.getmtime(sensitive_files_path)
        if mtime != _sfile_mtime:
            with open(sensitive_files_path) as f:
                data = json.load(f)
                sensitive_files = set(data.get("files", []))
                _sfile_mtime = mtime
                print(f"[+] Loaded {len(sensitive_files)} sensitive files.")
    except Exception as e:
        print("[!] Could not load sensitive files:", e)

def save_xdr_rules():
    try:
        with open(xdr_rules_path, "w") as f:
            json.dump(xdr_rules, f, indent=2)
    except Exception as e:
        print("[XDR] Failed to save XDR rules:", e)

def apply_custom_rules(event):
    for rule in custom_rules:
        key = rule.get("match_key", "")
        values = rule.get("match_values", [])
        if not key or not values:
            continue
        event_value = (event.get(key) or "").lower()
        if any(val.lower() in event_value for val in values):
            event["tags"].extend(rule.get("tags", []))
            event["risk_level"] = min(event["risk_level"], rule.get("risk_level", 3))

    return event

def apply_xdr_rule(rule):
    ip = rule["value"].get("ip")
    port = rule["value"].get("port")

    if rule["type"] == "block":
        if ip and port:
            if "-" in port:
                start, end = port.split("-")
                print(f"[XDR] Blocking {ip} TCP/UDP port range {start}-{end}")
                subprocess.run(["iptables", "-A", "OUTPUT", "-p", "tcp", "-d", ip, "--dport", f"{start}:{end}", "-j", "DROP"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["iptables", "-A", "OUTPUT", "-p", "udp", "-d", ip, "--dport", f"{start}:{end}", "-j", "DROP"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                print(f"[XDR] Blocking {ip} TCP/UDP port {port}")
                subprocess.run(["iptables", "-A", "OUTPUT", "-p", "tcp", "-d", ip, "--dport", port, "-j", "DROP"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["iptables", "-A", "OUTPUT", "-p", "udp", "-d", ip, "--dport", port, "-j", "DROP"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif ip:
            print(f"[XDR] Blocking all traffic to IP {ip}")
            subprocess.run(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    elif rule["type"] == "allow":
        if ip and port:
            if "-" in port:
                start, end = port.split("-")
                print(f"[XDR] Allowing {ip} TCP/UDP port range {start}-{end}")
                subprocess.run(["iptables", "-A", "OUTPUT", "-p", "tcp", "-d", ip, "--dport", f"{start}:{end}", "-j", "ACCEPT"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["iptables", "-A", "OUTPUT", "-p", "udp", "-d", ip, "--dport", f"{start}:{end}", "-j", "ACCEPT"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                print(f"[XDR] Allowing {ip} TCP/UDP port {port}")
                subprocess.run(["iptables", "-A", "OUTPUT", "-p", "tcp", "-d", ip, "--dport", port, "-j", "ACCEPT"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["iptables", "-A", "OUTPUT", "-p", "udp", "-d", ip, "--dport", port, "-j", "ACCEPT"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def clear_xdr_iptables_rules():
    subprocess.run(["iptables", "-F", "OUTPUT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("[XDR] Flushed OUTPUT chain")

def apply_sensitive_file_rules(event):
    arg = (event.get("arg1") or "").lower()
    for sfile in sensitive_files:
        if sfile.lower() in arg:
            event["risk_level"] = 1
            event.setdefault("tags", []).append("info-disclosure")
            break

async def broadcast(event):
    if not clients:
        return
    msg = json.dumps(event)
    await asyncio.gather(*(ws.send(msg) for ws in clients), return_exceptions=True)

async def trace_events_reader():
    global license_expired
    print("[*] Launching trace_events...")
    proc = await asyncio.create_subprocess_exec(
        "./trace_events",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    print(f"[*] trace_events started with PID {proc.pid}")

    # Wait briefly to detect early exit (e.g., license expiry)
    await asyncio.sleep(1)

    if proc.returncode is not None:
        # trace_events exited immediately (probably license expired)
        stdout, stderr = await proc.communicate()
        print("❌ trace_events exited unexpectedly!")

        license_error_reason = "License invalid or expired. Please contact support."  # default fallback

        if stdout:
            decoded_stdout = stdout.decode().strip()
            print("[trace_events stdout]", decoded_stdout)
            if decoded_stdout:
                license_error_reason = decoded_stdout  # use this instead
    
        if stderr:
            decoded_stderr = stderr.decode().strip()
            print("[trace_events stderr]", decoded_stderr)
            if decoded_stderr:
                license_error_reason = decoded_stderr  # prefer stderr if available
    
        license_expired = True
        sys.exit(1)
    
        # Now: instead of exiting, keep sending "license expired" event every minute
        while True:
            license_error_event = {
                "timestamp": time.time(),
                "cpu": 0,
                "pid": 0,
                "ppid": 0,
                "uid": 0,
                "comm": "trace_events",
                "cmd": "License error",
                "arg1": "",
                "msg_type": -1,
                "msg_type_str": "LICENSE_ERROR",
                "_": license_error_reason,   # <-- send the real reason here
                "risk_level": 1
            }
    
            await broadcast(license_error_event)
            print("[!] License error event sent to dashboard:", license_error_reason)
            await asyncio.sleep(60)  # Wait 60 seconds before sending again

    # If trace_events started fine, continue normal reading
    while True:
        line = await proc.stdout.readline()
        if not line:
            err = await proc.stderr.read()
            if err:
                print("❌ trace_events stderr:", err.decode())
                if "License" in err.decode():
                    license_expired = True
                    sys.exit()

                # Optional: if trace_events crashes later
                trace_crash_event = {
                    "timestamp": time.time(),
                    "event_type": "trace_error",
                    "message": "trace_events crashed unexpectedly.",
                    "details": {
                        "stderr": err.decode()
                    }
                }
                await broadcast(trace_crash_event)

            await asyncio.sleep(1)
            continue

        raw = line.decode(errors="ignore").strip()
        if not raw.startswith("{"):
            continue

        load_rules_if_changed()
        load_sensitive_files_if_changed()

        try:
            event = json.loads(raw)
            # ✅ Save alert if present
            if event.get("alert_type") and event.get("alert_message"):
                alert = {
                    "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "type": event.get("alert_type", "unknown"),
                    "message": event.get("alert_message", ""),
                    "pid": str(event.get("pid", "")),
                    "cmd": event.get("cmd", "") or event.get("comm", ""),
                    "ip": event.get("ip", "127.0.0.1"),
                    "risk_level": event.get("risk_level", 3)
                }
                alerts.append(alert)
                save_alerts()  # Call your existing function here
                print(f"[ALERTS] Saved {len(alerts)} alerts to disk.")

            event = apply_custom_rules(event)
            apply_sensitive_file_rules(event)
            await broadcast(event)
        except json.JSONDecodeError:
            print("❌ JSON parse error:", raw)


async def handler(websocket):
    global xdr_rules
    clients.add(websocket)
    is_health_check = False
    data = {}
    try:
        async for message in websocket:
            try:
                data = json.loads(message)
            except json.JSONDecodeError:
                print("ERROR: parsing data: "+str(message))
                continue

            if data.get("type") == "health":
                is_health_check = True
                alert_status = "None"
                for alert in alerts:
                    if alert.get("risk_level") == 1:
                        alert_status = "Critical"
                        break

                await websocket.send(json.dumps({
                    "type": "health",
                    "status": "ok",
                    "alert_status": alert_status
                }))
                break  # Important: break to exit async for loop
            else:
                # First real client message, log the connection
                if not is_health_check and data.get("type") not in ("get_alerts",):
                    print("[+] WebSocket connected:", websocket.remote_address)

            # Process messages here
            if data.get("type") == "get_rules":
                await websocket.send(json.dumps({"type": "rule_list", "rules": custom_rules}))

            elif data.get("type") == "add_rule":
                match_key = data.get("match_key")
                match_values = data.get("match_values", [])
            
                # Special case for sensitive file tracking
                if match_key == "file":
                    try:
                        # Load existing sensitive files
                        if os.path.exists(sensitive_files_path):
                            with open(sensitive_files_path, "r") as f:
                                sf_data = json.load(f)
                                current = set(sf_data.get("files", []))
                        else:
                            current = set()
            
                        # Add new values
                        updated = current.union(match_values)
                        with open(sensitive_files_path, "w") as f:
                            json.dump({"files": sorted(updated)}, f, indent=2)
            
                        print(f"[+] Updated sensitive_files.json: {match_values}")
                    except Exception as e:
                        print(f"[!] Failed to update sensitive_files.json: {e}")
            
                    # Optionally, do not store this in custom_rules or rules.json
                    await websocket.send(json.dumps({
                        "type": "rule_list", "rules": custom_rules
                    }))
                    continue  # exit here, skip below
            
                # Standard rule path
                new_rule = {
                    "match_key": match_key,
                    "match_values": match_values,
                    "tags": data["tags"],
                    "risk_level": data["risk_level"]
                }
                custom_rules.append(new_rule)
                with open(rules_path, "w") as f:
                    json.dump(custom_rules, f, indent=2)
            
                await websocket.send(json.dumps({
                    "type": "rule_list", "rules": custom_rules
                }))

            elif data.get("type") == "delete_all_rules":
                custom_rules.clear()
                with open(rules_path, "w") as f:
                    json.dump(custom_rules, f, indent=2)
                await websocket.send(json.dumps({"type": "rule_list", "rules": custom_rules}))

            elif data.get("type") == "get_xdr_rules":
                await websocket.send(json.dumps({"type": "xdr_rule_list", "rules": xdr_rules}))

            elif data.get("type") == "add_xdr_rule":
                new_rule = {
                    "type": data["rule_type"],
                    "value": data["value"]
                }
                xdr_rules.append(new_rule)
                save_xdr_rules()
                apply_xdr_rule(new_rule)
                await websocket.send(json.dumps({"type": "xdr_rule_list", "rules": xdr_rules}))

            elif data.get("type") == "clear_xdr_rules":
                xdr_rules.clear()
                save_xdr_rules()
                clear_xdr_iptables_rules()
                await websocket.send(json.dumps({"type": "xdr_rule_list", "rules": xdr_rules}))

            elif data.get("type") == "clear_alerts":
                try:
                    # Optional: backup
                    if os.path.exists(alerts_path):
                        import shutil, datetime
                        ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%S")
                        shutil.copy(alerts_path, f"alerts_backup_{ts}.json")
            
                    # Clear in memory and disk
                    alerts.clear()
                    with open(alerts_path, "w") as f:
                        json.dump([], f)
            
                    print("[ALERTS] alerts.json cleared by dashboard.")
            
                    # ✅ Optional ack
                    await websocket.send(json.dumps({"type": "clear_alerts_ack"}))
            
                except Exception as e:
                    print(f"[ALERTS] Failed to clear alerts: {e}")

            elif data.get("type") == "get_alerts":
                try:
                    if os.path.exists(alerts_path):
                        with open(alerts_path, "r") as f:
                            loaded_alerts = json.load(f)
                    else:
                        loaded_alerts = []
            
                    await websocket.send(json.dumps({
                        "type": "alert_list",   # Keep same as your central.html
                        "alerts": loaded_alerts
                    }))
            
                    # print(f"[ALERTS] Sent {len(loaded_alerts)} alerts to {websocket.remote_address}")
            
                    break
            
                except Exception as e:
                    print(f"[ALERTS] Failed to load alerts: {e}")
                    await websocket.send(json.dumps({
                        "type": "alert_list",
                        "alerts": [],
                        "error": str(e)
                    }))
                    break

    except Exception as e:
        if not is_health_check:
            print(f"❌ WebSocket handler error: {e}")
    finally:
        if not is_health_check and data.get("type") not in ("get_alerts",):
            print("[-] WebSocket disconnected:", websocket.remote_address)

        clients.discard(websocket)
        if not websocket.closed:    # Clean close if still open
            await websocket.close(code=1000, reason="Normal closure") 


async def main():
    async with serve(handler, "0.0.0.0", 8765):
        print("[*] WebSocket server started on ws://0.0.0.0:8765")
        await trace_events_reader()

if __name__ == "__main__":
    asyncio.run(main())

