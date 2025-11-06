# Policy checks for Kyverno/OPA (simple heuristics)
import json
import yaml
from pathlib import Path

def analyze_config(p):
    """
    Analisa arquivos de configuração (YAML/JSON) para políticas e boas práticas.
    
    Args:
        p (str): Caminho do arquivo a ser analisado
    
    Returns:
        str: Resultado da análise com sugestões
    """
    try:
        path = Path(p)
        txt = path.read_text()
        issues = []
        
        # Determina o tipo de arquivo
        if path.suffix.lower() in ['.yaml', '.yml']:
            config = yaml.safe_load(txt)
            file_type = "YAML"
        elif path.suffix.lower() == '.json':
            config = json.loads(txt)
            file_type = "JSON"
        else:
            return f'Tipo de arquivo não suportado: {path.suffix}'
            
        # Análise de recursos e limites
        if isinstance(config, dict):
            # Verifica limites de recursos
            if not any(key in str(config) for key in ['limits:', 'resources:', '"limits":', '"resources":']):
                issues.append('- Sem limites de recursos detectados')
                
            # Verifica configurações de segurança comuns
            if not any(key in str(config) for key in ['securityContext', 'networkPolicy', 'rbac']):
                issues.append('- Configurações de segurança recomendadas ausentes')
                
            # Verifica políticas específicas
            if 'spec' in config:
                if not any(key in str(config['spec']) for key in ['rules', 'policies', 'validate']):
                    issues.append('- Nenhuma regra de validação encontrada em spec')

        return f'Análise do arquivo {file_type}:\n' + ('\n'.join(issues) if issues else f'{file_type} com boas práticas aparentes.')
    except yaml.YAMLError:
        return f'[Erro ao processar YAML: Verifique a sintaxe do arquivo]'
    except json.JSONDecodeError:
        return f'[Erro ao processar JSON: Verifique a sintaxe do arquivo]'
    except Exception as e:
        return f'[Erro ao analisar arquivo: {e}]'

def analyze_rego(p):
    txt = Path(p).read_text()
    if 'deny' in txt or 'allow' in txt:
        return 'Política Rego possui regras.'
    return 'Política Rego sem regras deny/allow detectadas.'
