# Policy checks for Kyverno/OPA (simple heuristics)
from pathlib import Path
def analyze_yaml(p):
    try:
        txt = Path(p).read_text()
        issues = []
        if 'limits:' not in txt and 'resources:' not in txt:
            issues.append('Sem limites de recursos detectados.')
        return '\n'.join(issues) if issues else 'YAML com boas práticas aparentes.'
    except Exception as e:
        return f'[Erro ao ler YAML: {e}]'

def analyze_rego(p):
    txt = Path(p).read_text()
    if 'deny' in txt or 'allow' in txt:
        return 'Política Rego possui regras.'
    return 'Política Rego sem regras deny/allow detectadas.'
