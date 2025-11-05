# DAST helpers using OWASP ZAP container (quick placeholder)
import subprocess
def run_zap_scan(url):
    try:
        cmd = f"docker run --rm owasp/zap2docker-stable zap-baseline.py -t {url}"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
        return res.stdout or res.stderr
    except Exception as e:
        return f"[Erro ZAP: {e}]"
