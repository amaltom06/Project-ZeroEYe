"""Record the dependency versions actually tested in this workspace."""
from importlib.metadata import distribution,version
from packaging.requirements import Requirement
from pathlib import Path

def resolve(roots):
    found=set();pending=list(roots)
    while pending:
        name=pending.pop().lower().replace('_','-')
        if name in found:continue
        found.add(name)
        for raw in distribution(name).requires or []:
            req=Requirement(raw)
            if req.marker is None or req.marker.evaluate({'extra':''}):pending.append(req.name)
    return sorted(found)
for destination,roots in [('agents/windows/requirements.lock.txt',['pywin32','requests','defusedxml']),('agents/windows/requirements-dev.lock.txt',['pywin32','requests','defusedxml','pytest','pyinstaller']),('apps/ai-service/requirements.lock.txt',['fastapi','uvicorn','pydantic','httpx','pytest'])]:
    packages=resolve(roots)
    rows=['# Versions tested on Windows / Python 3.14.3. Regenerate after a verified update.']
    for name in packages:
        marker='; sys_platform == "win32"' if name=='pywin32' else ''
        rows.append(name+'=='+version(name)+marker)
    Path(destination).write_text('\n'.join(rows)+'\n',encoding='utf8')
    print(destination+': '+str(len(packages))+' pinned packages')
