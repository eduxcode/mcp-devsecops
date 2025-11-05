# SAST helpers (Bandit + SonarQube)
import subprocess

def run_bandit(path='.'):
    """
    Executa análise SAST usando Bandit
    Args:
        path: Caminho do código a ser analisado (default: diretório atual)
    Returns:
        Output do Bandit em formato JSON
    """
    try:
        cmd = f"bandit -r {path} -f json"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        return res.stdout or res.stderr
    except subprocess.TimeoutExpired:
        return "[Erro: Bandit timeout após 300 segundos]"
    except Exception as e:
        return f"[Erro Bandit: {e}]"

def run_sonarqube_scan(project_key, token):
    """
    Executa análise usando SonarQube
    Args:
        project_key: Identificador do projeto no SonarQube
        token: Token de autenticação do SonarQube
    Returns:
        Mensagem de status da análise
    """
    try:
        # Placeholder para futura implementação completa do SonarQube
        return f"Executaria análise SonarQube para {project_key} usando token {token[:6]}***"
    except Exception as e:
        return f"[Erro SonarQube: {e}]"
