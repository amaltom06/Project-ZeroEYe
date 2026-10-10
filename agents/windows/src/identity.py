import base64
import json
import os
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

def state_dir():
    path=Path(os.environ.get('ZEROEYE_AGENT_HOME',str(Path(os.environ.get('PROGRAMDATA','C:/ProgramData'))/'ZeroEye')))
    path.mkdir(parents=True,exist_ok=True)
    return path

def validate_url(url):
    parsed=urlsplit(url)
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {'','/'}:
        raise ValueError('Use an origin URL without credentials, path, query or fragment')
    if parsed.scheme!='https' and not (parsed.scheme=='http' and parsed.hostname in {'127.0.0.1','localhost','::1'}):
        raise ValueError('HTTPS is required except for loopback development')
    return url.rstrip('/')

def save_identity(path,data):
    import win32crypt
    protected=win32crypt.CryptProtectData(data['deviceToken'].encode(),'ZEROEYE device credential',None,None,None,4)
    stored={**data,'deviceToken':base64.b64encode(protected).decode()}
    fd,tmp=tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd,'w',encoding='utf8') as stream:json.dump(stored,stream);stream.flush();os.fsync(stream.fileno())
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

def load_identity(path):
    import win32crypt
    data=json.loads(path.read_text(encoding='utf8'))
    data['deviceToken']=win32crypt.CryptUnprotectData(base64.b64decode(data['deviceToken']),None,None,None,0)[1].decode()
    data['backend']=validate_url(data['backend'])
    return data


def protect_state_directory(path):
    """Installer/source enrollment requires admin; only SYSTEM and Administrators may access state."""
    import win32security
    import win32con
    dacl=win32security.ACL()
    inherit=win32con.OBJECT_INHERIT_ACE|win32con.CONTAINER_INHERIT_ACE
    for kind in [win32security.WinLocalSystemSid,win32security.WinBuiltinAdministratorsSid]:
        sid=win32security.CreateWellKnownSid(kind,None)
        dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION,inherit,win32con.FILE_ALL_ACCESS,sid)
    win32security.SetNamedSecurityInfo(str(path),win32security.SE_FILE_OBJECT,win32security.DACL_SECURITY_INFORMATION|win32security.PROTECTED_DACL_SECURITY_INFORMATION,None,None,dacl,None)
