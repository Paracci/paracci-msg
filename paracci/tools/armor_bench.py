
import time
import sys
import os
import json
import psutil
from datetime import datetime

# Add project root directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from core.crypto import hash_secret_raw, LowLevelArgon2Type

def run_bench():
    print("--- Paracci Quantum Armor Calibration Tool ---", flush=True)
    print(f"[*] System: {psutil.cpu_count(logical=True)} Cores | {round(psutil.virtual_memory().total / (1024**3), 2)} GB RAM", flush=True)
    print("[!] Target: Find the heaviest profile that fixes message opening time to ~180 seconds (3 min).\n", flush=True)

    # Test scenarios (Memory and Time combinations)
    # Memory (MB)
    memories = [128, 256, 512, 1024, 2048] 
    # Iterations
    iterations = [4, 8, 16, 32, 64, 128, 256]
    
    results = []
    
    print(f"{'Memory (MB)':<12} | {'Iteration (t)':<14} | {'Duration (s)':<12} | {'Status'}", flush=True)
    print("-" * 60, flush=True)

    try:
        for m_mb in memories:
            m_kb = m_mb * 1024
            
            # Memory check
            if psutil.virtual_memory().available < (m_mb * 1024 * 1024 * 1.5):
                print(f"[!] Insufficient memory for {m_mb}MB, skipping.", flush=True)
                continue

            for t in iterations:
                # Test preparation
                secret = b"benchmarking_secret_key_123"
                salt = b"benchmarking_salt_123"
                
                start_time = time.time()
                
                # Argon2id Workload (Parallelism: 2 - Kept constant to avoid locking all cores)
                # Note: If p increases, duration decreases but the system might hang. 2 is good for safety.
                hash_secret_raw(
                    secret=secret,
                    salt=salt,
                    time_cost=t,
                    memory_cost=m_kb,
                    parallelism=2,
                    hash_len=32,
                    type=LowLevelArgon2Type.ID
                )
                
                end_time = time.time()
                duration = end_time - start_time
                
                status = ""
                if 170 <= duration <= 190:
                    status = "TARGET"
                elif duration > 300:
                    status = "TOO HEAVY"
                
                results.append({
                    "memory_mb": m_mb,
                    "iterations": t,
                    "duration": duration
                })
                
                print(f"{m_mb:<12} | {t:<14} | {duration:<12.2f} | {status}", flush=True)
                
                # If duration exceeds 4 minutes, stop testing further iterations for this memory level
                if duration > 240:
                    break
            
            print("-" * 60, flush=True)
            
    except KeyboardInterrupt:
        print("\n[!] Test stopped by user.", flush=True)

    # Reporting
    report_file = f"armor_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(f"# Paracci Armor Calibration Report\n\n")
        f.write(f"- **Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"- **System:** {psutil.cpu_count()} Threads / {round(psutil.virtual_memory().total/(1024**3))}GB RAM\n\n")
        f.write("| Memory (MB) | Iteration (t) | Duration (s) | Recommendation |\n")
        f.write("| :--- | :--- | :--- | :--- |\n")
        
        best_match = None
        min_diff = 9999
        
        for r in results:
            diff = abs(r["duration"] - 180)
            rec = ""
            if diff < min_diff:
                min_diff = diff
                best_match = r
            
            if r["duration"] > 170 and r["duration"] < 200:
                rec = "**Perfect (3min)**"
            
            f.write(f"| {r['memory_mb']} | {r['iterations']} | {r['duration']:.2f} | {rec} |\n")
        
        if best_match:
            f.write(f"\n## Recommended Setting (Quantum Armor)\n")
            f.write(f"The best 3-minute protection setting for your computer:\n")
            f.write(f"- **Memory (m):** `{best_match['memory_mb']} MB` ({best_match['memory_mb']*1024} KB)\n")
            f.write(f"- **Iteration (t):** `{best_match['iterations']}`\n")
            f.write(f"- **Parallelism (p):** `2` (For stability)\n")

    print(f"\n[OK] Report created: {report_file}", flush=True)
    print("[*] You can see the closest setting to 3 minutes in the report.", flush=True)

if __name__ == "__main__":
    run_bench()
