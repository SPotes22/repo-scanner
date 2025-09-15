#!/usr/bin/env python3
import os
import re
import subprocess
import sys
import shutil

# -------------------------------
# Dependencias: detect-secrets
# -------------------------------
def ensure_dependencies():
    if shutil.which("detect-secrets") is None:
        print("[*] Instalando detect-secrets...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "detect-secrets"])
        except subprocess.CalledProcessError:
            print("[!] Error instalando detect-secrets. Instálalo manualmente.")
            sys.exit(1)

# -------------------------------
# Escaneo con detect-secrets
# -------------------------------
def run_detect_secrets(path="."):
    print(f"[*] Ejecutando detect-secrets en {path}...")
    try:
        subprocess.check_call(["detect-secrets", "scan", path])
    except subprocess.CalledProcessError:
        print("[!] detect-secrets encontró secretos.")
        return False
    return True

# -------------------------------
# Escaneo manual de patrones maliciosos
# -------------------------------
def scan_for_malware(path="."):
    suspicious_patterns = [
        r"os\.fork\(",
        r"subprocess\.Popen",
        r"subprocess\.call",
        r"eval\(",
        r"exec\(",
        r"while\s+True",
    ]
    regex = re.compile("|".join(suspicious_patterns))

    for root, _, files in os.walk(path):
        for f in files:
            if f.endswith(".py"):
                file_path = os.path.join(root, f)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                        if regex.search(content):
                            print(f"[!] Posible código peligroso en: {file_path}")
                            return False
                except Exception as e:
                    print(f"[!] No se pudo leer {file_path}: {e}")
    return True

# -------------------------------
# Pipeline principal
# -------------------------------
def main():
    print("=== PIPELINE DE DETECCIÓN DE SECRETOS Y MALWARE ===")
    ensure_dependencies()

    safe = True
    safe &= run_detect_secrets(".")
    safe &= scan_for_malware(".")

    if safe:
        print("[✓] Escaneo limpio. Puedes ejecutar tu código con seguridad.")
    else:
        print("[✗] Se encontraron riesgos. Corrige antes de ejecutar.")

if __name__ == "__main__":
    main()

