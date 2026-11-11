import json
from dataclasses import dataclass
from pathlib import Path

@dataclass(frozen=True)
class Grant:
    organization: str
    generation: int
    expires_at: int

def load_grants(path="fixtures/grants.json"):
    values=json.loads(Path(path).read_text(encoding="utf-8"))
    result={}
    for value in values:
        if value["organization"] in result: raise ValueError("组织授权记录重复")
        if value["generation"]<1: raise ValueError("令牌代次无效")
        result[value["organization"]]=Grant(value["organization"],value["generation"],value["expires_at"])
    return result
