# Simple report helpers
from pathlib import Path
def to_markdown(title, body, out):
    p = Path(out)
    p.write_text(f"# {title}\n\n" + body, encoding='utf-8')
    return str(p)
