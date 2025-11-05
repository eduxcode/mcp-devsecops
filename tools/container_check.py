# Container scanning helpers (Trivy)
import subprocess
import shutil
from pathlib import Path

def trivy_scan(image_name):
    """
    Executa análise de vulnerabilidades em imagem usando Trivy
    Args:
        image_name: Nome da imagem Docker a ser analisada
    Returns:
        Resultado da análise em formato JSON
    """
    cmd = f"trivy image --quiet --format json {image_name}"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout or result.stderr
    except Exception as e:
        return f"[Erro Trivy: {e}]"

def trivy_scan_image(image):
    """
    Versão estendida do trivy_scan com verificações adicionais
    Args:
        image: Nome da imagem Docker a ser analisada
    Returns:
        Resultado da análise em formato JSON
    """
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
