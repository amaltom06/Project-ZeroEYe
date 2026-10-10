import argparse
import getpass
import platform
import socket
import threading
import requests
from identity import state_dir,validate_url,save_identity,load_identity,protect_state_directory

def main():
    parser=argparse.ArgumentParser(description='ZEROEYE visible Windows Security-log monitor')
    parser.add_argument('action',choices=['enroll','run','revoke','reset-checkpoint'])
    args=parser.parse_args();directory=state_dir();path=directory/'identity.json'
    if args.action=='enroll':
        if path.exists():raise SystemExit('An identity already exists. Revoke it before re-enrollment.')
        print('ZEROEYE monitors selected Security event logs on systems you are authorized to administer.')
        if input('Type MONITOR to consent: ')!='MONITOR':raise SystemExit('Enrollment cancelled')
        protect_state_directory(directory)
        backend=validate_url(input('Backend origin (HTTPS; loopback HTTP for development): ').strip())
        enrollment=getpass.getpass('One-use enrollment token: ')
        response=requests.post(backend+'/api/agent/enroll',json={'enrollmentToken':enrollment,'hostname':socket.gethostname(),'osVersion':platform.platform()[:128],'agentVersion':'0.1.0'},timeout=(5,15),allow_redirects=False,stream=True)
        from transport import read_response
        data=read_response(response,expected=201)
        if data.get('simulated'):raise SystemExit('Native monitoring requires a real organization. This demo device should be revoked in Devices.')
        data['backend']=backend;data['collectCommandLine']=False
        save_identity(path,data)
        print('Enrolled with a SYSTEM/Administrators-only state directory. Command lines are excluded by default.')
    elif args.action=='run':
        from runner import run
        stop=threading.Event()
        try:run(stop)
        except KeyboardInterrupt:stop.set()
    elif args.action=='revoke':
        if not path.exists():return
        from transport import Transport
        data=load_identity(path);transport=Transport(data['backend'],data['deviceToken'])
        try:transport.post('/revoke',{});print('Backend credential revoked.')
        except Exception:print('Backend unavailable. Revoke this device in ZEROEYE Devices. Local credential will be removed.')
        finally:transport.close();path.unlink(missing_ok=True)
    elif args.action=='reset-checkpoint':
        print('This resets the bookmark to the newest available record after log rollover/clearing. Pending queue data is retained; the gap must be reviewed.')
        if input('Type RESET to acknowledge this evidence gap: ')!='RESET':return
        from collector import Collector
        from queue_store import QueueStore
        data=load_identity(path);queue=QueueStore(directory/'queue.sqlite')
        try:
            bookmark=Collector().latest_bookmark(data['eventIds'])
            if bookmark:queue.enqueue(None,bookmark)
        finally:queue.close()
if __name__=='__main__':main()
