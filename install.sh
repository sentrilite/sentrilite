#!/bin/bash

set -e

echo "[*] Cleaning up previous BPF objects..."
sudo rm -f /sys/fs/bpf/events /sys/fs/bpf/bpf_data
sudo rm -rf /sys/fs/bpf/trace_syscall
sudo mkdir -p /sys/fs/bpf/trace_syscall

echo "[*] Loading trace_syscall.o into /sys/fs/bpf/trace_syscall ..."
sudo ./bpftool prog loadall trace_syscall.o /sys/fs/bpf/trace_syscall autoattach

echo "[*] BPF programs currently loaded:"
sudo ./bpftool prog show | grep tracepoint || true

echo "[*] Enabling tracepoints for relevant syscalls..."
for syscall in sys_enter_socket sys_enter_connect sys_enter_accept sys_exit_accept sys_enter_execve sys_exit_clone; do
    echo 1 | sudo tee /sys/kernel/debug/tracing/events/syscalls/${syscall}/enable >/dev/null
done

echo "[*] Locating 'events' perf event array map..."
MAP_ID=$(sudo ./bpftool map show | grep 'perf_event_array.*name events' | awk '{print $1}' | tr -d ':')

if [ -z "$MAP_ID" ]; then
    echo "❌ Could not find perf_event_array map named 'events'"
    exit 1
fi

echo "[*] Pinning map ID $MAP_ID to /sys/fs/bpf/events ..."
sudo ./bpftool map pin id "$MAP_ID" /sys/fs/bpf/events

echo "[*] Confirming pinned map..."
sudo ./bpftool map show pinned /sys/fs/bpf/events

# Extract bpf_data ID by fuzzy matching its name
MAP_ID=$(sudo ./bpftool map show | grep 'bpf_data' | awk '{print $1}' | tr -d ':')

if [ -n "$MAP_ID" ]; then
    sudo mkdir -p /sys/fs/bpf/trace_syscall
    sudo bpftool map pin id "$MAP_ID" /sys/fs/bpf/trace_syscall/bpf_data
    echo "✅ Pinned bpf_data at /sys/fs/bpf/trace_syscall/bpf_data"
else
    echo "❌ Could not find bpf_data"
    exit 1
fi

echo "✅ BPF tracepoints and maps successfully loaded and pinned."

