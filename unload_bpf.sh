#!/bin/bash
set -e

echo "[*] Unloading BPF tracepoints and maps..."

sudo rm -f /sys/fs/bpf/events
sudo rm -f /sys/fs/bpf/bpf_data
sudo rm -rf /sys/fs/bpf/trace_syscall

# Optionally disable syscalls explicitly
for syscall in sys_enter_socket sys_enter_connect sys_enter_accept sys_exit_accept sys_enter_execve sys_exit_clone; do
    echo 0 | sudo tee /sys/kernel/debug/tracing/events/syscalls/${syscall}/enable >/dev/null
done

echo "✅ Tracepoints unloaded."

