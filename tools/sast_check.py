# SAST helpers (Bandit + placeholder Sonar)
import subprocess
def run_bandit(path='.'):
    try:
        res = subprocess.run(f"bandit -r {path} -f json", shell=True, capture_output=True, text=True, timeout=300)
        return res.stdout or res.stderr
    except Exception as e:
        return f"[Erro Bandit: {e}]"
