# Sentrilite: Redefining EDR/XDR Through Observability, AI-LLM insights and Real-Time Response

Thank you for choosing **Sentrilite** for advanced lightweight server and endpoint monitoring.
The README covers Agent and Kernel Modules - installation guide.
Website: https://sentrilite.com
Contact: info@sentrilite.com

This ZIP bundle contains the lightweight eBPF-powered Sentrilite agent with built-in risk scoring,
license validation, and real-time main and server dashboard support.

---

## 📦 Contents of this Bundle

| File              | Purpose
|-------------------|------------------------------------------
| `trace_syscall.o` | eBPF kernel object for syscall monitoring
| `install.sh`      | Script to load the ebpf kernel module
| `trace_events`    | Userspace program for network/socket activity
| `ws_server.py`    | Python websocket server that forwards live events to browser dashboard
| `dashboard.html`  | Local frontend UI for viewing live events
| `net.conf`        | Configuration file
| `bpftool`         | Tool to load and attach kernel tracepoints. Source: https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git
| `license.key`     | License key file
| `install.README`  | This installation guide
| `LICENSE.txt`     | License Agreement

---

## ⚙️ System Requirements

- Ubuntu 20.04+
- Python 3.8+
- Root privileges (for loading eBPF programs)
- Kernel with eBPF support (Linux 5.8+ recommended)

---

## ⚙️ General  Requirements
- Tool                    Purpose                                         How to Install
- bpftool:                Load eBPF programs and manage maps              sudo apt install bpftool (Ubuntu)
- python3, pip3           Run the websocket server (ws_server.py)         sudo apt install python3 python3-pip
- websockets              WebSocket server library                        pip3 install websockets
- libbpf & headers        Required by the kernel loader (trace_events)    Pre-installed on most modern distros (use bundled binary)
- nginx                   Required to view dashboard                      sudo apt install nginx

---

## 🔐 Licensing

The project is currently using a trial license.key .
Once obtained, place the license.key file in the same directory before launching the application.

---

## 🛠️ Installation Steps

1. **Unzip the bundle:**

unzip sentrilite_agent_bundle.zip
cd sentrilite

2. Load the bpf program:
sudo ./install.sh

3. Open net.conf and configure:
license_file=license.key    # Path to your license file
iface=enX0 # your ethernet or your network interface

4. sudo apt update
sudo apt install python3 python3-pip
pip3 install websockets

5. Launch the Server:
sudo python3 ws_server.py

6. Open the Dashboard:
Copy the dashboard.html to /var/www/html or web root directory.
Open dashboard.html in your browser: http://<YOUR-SERVER-IP>/dashboard.html
You should see live events appear in real-time.

Log format in the Web UI:
[2025-04-14T00:12:32.008Z] PID=1234 COMM=ssh CMD=/bin/bash ARG= IP=127.0.0.1 TYPE=EXECVE

7. Open the Main Dashboard:
Copy the main.html to /var/www/html on your main admin server.
Open the main.html in your browser: http://<YOUR-SERVER-IP>/main.html
Click choose file and select a file containing your server lists.
Example file format:
Server_1_ip_address,prod
Server_2_ip_address,test

Once uploaded correctly, Sentrilite agent will monitor and show status/alerts/AI insights
for these servers.

For more detail information, refer to dashboard_usage.README

---

## 🛠️ Un-installation Steps

Run the following commands as root.

sudo rm -f /sys/fs/bpf/events /sys/fs/bpf/bpf_data
sudo rm -rf /sys/fs/bpf/trace_syscall

---

## Support

For licensing, troubleshooting, or feature requests:
📧 info@sentrilite.com
🌐 https://sentrilite.com
