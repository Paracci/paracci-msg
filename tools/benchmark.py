import os
import sys
import time
import json
import shutil
import tempfile
import subprocess
import platform
from pathlib import Path

# Add project root directory
ROOT_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT_DIR / "paracci"))

# Unicode support (for Windows console)
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

from core.burn import BurnDB, init_device
from core.identity import get_or_create_device_identity
from core.session import (
    create_initiator_session,
    accept_initiator_and_create_responder,
    finalize_initiator_session,
    apply_bond_nonce_to_y,
    confirm_safety_code,
    get_session_safety_code
)
from core.envelope import seal_envelope, open_envelope

DEFAULT_PIN = "Correct-Horse-95175328"

def get_cpu_info():
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output(["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_Processor).Name"]).decode("utf-8")
            lines = [line.strip() for line in out.splitlines() if line.strip()]
            if lines:
                return lines[0]
    except Exception:
        pass
    return platform.processor() or "Unknown CPU"

def get_ram_info():
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output(["powershell", "-NoProfile", "-Command", "[math]::round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)"]).decode("utf-8")
            lines = [line.strip() for line in out.splitlines() if line.strip()]
            if lines:
                gb = lines[0]
                return f"{gb} GB"
    except Exception:
        pass
    return "Unknown RAM"

def get_gpu_info():
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output(["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_VideoController).Name"]).decode("utf-8")
            lines = [line.strip() for line in out.splitlines() if line.strip()]
            if lines:
                return ", ".join(lines)
    except Exception:
        pass
    return "Unknown GPU"

def setup_user_bench(user_name: str, temp_dir: Path):
    data_dir = temp_dir / f"data_{user_name}"
    data_dir.mkdir(parents=True, exist_ok=True)
    
    db = BurnDB(data_dir / "sessions.db")
    device_key = init_device(db, DEFAULT_PIN)
    
    config = {
        "username": f"User {user_name.upper()}",
        "avatar_color": "#10b981" if user_name == "x" else "#3b82f6",
        "downloads_dir": "downloads",
        "anti_screenshot": True,
        "quiet_mode": False,
        "default_ttl": 0
    }
    with open(data_dir / "config.json", "w") as f:
        json.dump(config, f)
        
    (data_dir / "downloads").mkdir(exist_ok=True)
    return db, device_key

def run_benchmark_for_profile(profile_name: str):
    with tempfile.TemporaryDirectory() as tmpdir_str:
        tmpdir = Path(tmpdir_str)
        db_x, key_x = setup_user_bench("x", tmpdir)
        db_y, key_y = setup_user_bench("y", tmpdir)
        
        identity_x = get_or_create_device_identity(db_x, key_x)
        identity_y = get_or_create_device_identity(db_y, key_y)
        
        # 1. Session Init (X)
        start = time.perf_counter()
        meta_x_init, init_file = create_initiator_session(
            "Benchmark Channel", 
            profile=profile_name,
            my_username="User X",
            identity_pub=identity_x.public_key,
            identity_priv=identity_x.private_key
        )
        t_init_x = time.perf_counter() - start
        
        # 2. Bond Accept & Responder Create (Y)
        start = time.perf_counter()
        meta_y, resp_file = accept_initiator_and_create_responder(
            init_file, 
            "Benchmark Channel",
            my_username="User Y",
            identity_pub=identity_y.public_key,
            identity_priv=identity_y.private_key
        )
        t_accept_y = time.perf_counter() - start
        
        # 3. Bond Finalize (X)
        start = time.perf_counter()
        meta_x_final = finalize_initiator_session(meta_x_init, resp_file)
        t_finalize_x = time.perf_counter() - start
        
        # 4. Apply Bond Nonce (Y)
        start = time.perf_counter()
        meta_y_final = apply_bond_nonce_to_y(meta_y, meta_x_final.bond_nonce)
        t_bond_y = time.perf_counter() - start
        
        # Confirm safety codes
        code_x = get_session_safety_code(meta_x_final)
        meta_x_final = confirm_safety_code(meta_x_final, code_x)
        code_y = get_session_safety_code(meta_y_final)
        meta_y_final = confirm_safety_code(meta_y_final, code_y)
        
        # 5. Message Seal (X)
        payload = b"Benchmarking Paracci Secure Messaging Protocol Envelope Performance"
        start = time.perf_counter()
        sealed = seal_envelope(payload, meta_x_final)
        t_seal = time.perf_counter() - start
        
        # 6. Message Open (Y)
        start = time.perf_counter()
        opened = open_envelope(sealed.file_bytes, meta_y_final)
        t_open = time.perf_counter() - start
        
        assert opened.payload == payload
        
        return {
            "init_x": t_init_x,
            "accept_y": t_accept_y,
            "finalize_x": t_finalize_x,
            "bond_y": t_bond_y,
            "seal": t_seal,
            "open": t_open
        }

def main():
    print("--- PARACCI PROFILE BENCHMARK SYSTEM ---")
    
    cpu = get_cpu_info()
    ram = get_ram_info()
    gpu = get_gpu_info()
    
    print(f"  CPU: {cpu}")
    print(f"  RAM: {ram}")
    print(f"  GPU: {gpu}")
    print("----------------------------------------")
    
    results = {}
    profiles = ["standard", "paranoid", "quantum"]
    
    for p in profiles:
        print(f"[*] Running benchmark for profile: {p.upper()} (this may take a while)...")
        try:
            results[p] = run_benchmark_for_profile(p)
            print(f"  [✔] {p.upper()} finished successfully.")
        except Exception as e:
            print(f"  [!] {p.upper()} failed: {e}")
            
    print("\n---------------- RESULTS ----------------")
    print(json.dumps(results, indent=4))
    print("-----------------------------------------")
    
    # Store temporary JSON for parsing
    with open(ROOT_DIR / "benchmark_result.json", "w") as f:
        json.dump({
            "system": {
                "cpu": cpu,
                "ram": ram,
                "gpu": gpu
            },
            "results": results
        }, f, indent=4)
        
    print(f"[✔] Benchmark data saved to benchmark_result.json")

if __name__ == "__main__":
    main()
