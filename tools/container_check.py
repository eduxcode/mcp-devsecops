# Container scanning helpers (Trivy)
import subprocess, shutil
def trivy_scan_image(image):
    try:
        if shutil.which('trivy') is None:
            return '[Trivy não encontrado. Instale Trivy localmente ou use docker image aquasec/trivy]'
        res = subprocess.run(f"trivy image --quiet --format json {image}", shell=True, capture_output=True, text=True, timeout=300)
        return res.stdout or res.stderr
    except Exception as e:
        return f"[Erro Trivy: {e}]"

def analyze_dockerfile(path):
    p = Path(path)
    try:
        txt = p.read_text()
        issues = []
        if 'USER root' in txt or 'USER root' in txt.upper():
            issues.append('Evite usar USER root em Dockerfile.')
        if 'COPY' not in txt:
            issues.append('Nenhum COPY detectado — verifique build context.')
        return '\n'.join(issues) if issues else 'Dockerfile básico ok.'
    except Exception as e:
        return f'[Erro ao ler Dockerfile: {e}]'
