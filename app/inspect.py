from pathlib import Path
from app.oauth import load_grants
print({k:v.generation for k,v in load_grants().items()})
