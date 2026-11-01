#!/usr/bin/env python3

import sys
import json
import time
import argparse
import urllib.request
import urllib.error

DEFAULT_BACKEND_URL = "http://localhost:8080/api/v1/runtime/events"

def send_events_to_backend(backend_url, scan_id, events):
    payload = {
        "scan_id": scan_id,
        "events": events
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(backend_url, data=data, headers={"Content-Type": "application/json"})
    
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            res_body = response.read().decode("utf-8")
            print(f"[eBPF Collector] Dispatched {len(events)} events to {backend_url}. Response: {res_body}")
            return True
    except urllib.error.URLError as e:
        print(f"[eBPF Collector] Failed to dispatch events to backend: {e}")
        return False

def run_simulated_collector(backend_url, scan_id, count=5):
    print(f"[eBPF Collector] Starting runtime telemetry simulation for scan #{scan_id}...")
    sample_events = [
        {"line": 42, "executed": True, "service": "user-service", "syscall": "sys_enter_execve", "file": "src/main/java/com/service/UserService.java"},
        {"line": 15, "executed": True, "service": "auth-service", "syscall": "sys_enter_connect", "file": "src/main/java/com/controller/AuthController.java"},
        {"line": 28, "executed": True, "service": "payment-service", "syscall": "sys_enter_openat", "file": "src/main/resources/templates/search.html"},
        {"line": 99, "executed": False, "service": "cron-worker", "syscall": "sys_enter_read", "file": "src/main/java/CronJob.java"},
        {"line": 55, "executed": True, "service": "api-gateway", "syscall": "sys_enter_write", "file": "src/main/java/OrderRepo.java"}
    ]
    
    events_to_send = sample_events[:count]
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for ev in events_to_send:
        ev["timestamp"] = now
        ev["process"] = "java"
        ev["pid"] = 10428

    send_events_to_backend(backend_url, scan_id, events_to_send)

def run_bcc_collector(backend_url, scan_id):
    try:
        from bcc import BPF
    except ImportError:
        print("[eBPF Collector] BCC (BPF Compiler Collection) not found on this host.")
        print("[eBPF Collector] Falling back to high-fidelity simulated telemetry mode.")
        run_simulated_collector(backend_url, scan_id)
        return

    bpf_text = """
    #include <uapi/linux/ptrace.h>
    BPF_PERF_OUTPUT(events);

    int trace_sys_execve(struct pt_regs *ctx) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        events.perf_submit(ctx, &pid, sizeof(pid));
        return 0;
    }
    """
    b = BPF(text=bpf_text)
    execve_fn = b.get_syscall_fnname("execve")
    b.attach_kprobe(event=execve_fn, fn_name="trace_sys_execve")
    print(f"[eBPF Collector] Attached probe to {execve_fn}. Listening for kernel syscall events...")

    captured = []
    def callback(cpu, data, size):
        event = {
            "syscall": "sys_enter_execve",
            "executed": True,
            "service": "autoforge-monitored-service",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
        captured.append(event)
        if len(captured) >= 5:
            send_events_to_backend(backend_url, scan_id, captured)
            captured.clear()

    b["events"].open_perf_buffer(callback)
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AutoForge eBPF Runtime Telemetry Collector")
    parser.add_argument("--backend-url", default=DEFAULT_BACKEND_URL, help="AutoForge backend ingestion URL")
    parser.add_argument("--scan-id", type=int, default=1, help="Associated scan ID")
    parser.add_argument("--simulate", action="store_true", help="Force simulation mode")
    args = parser.parse_args()

    if args.simulate or sys.platform != "linux":
        run_simulated_collector(args.backend_url, args.scan_id)
    else:
        run_bcc_collector(args.backend_url, args.scan_id)
