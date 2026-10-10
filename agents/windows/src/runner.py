import logging
import random
import time
from datetime import datetime,timezone,timedelta
from logging.handlers import RotatingFileHandler
from collector import Collector
from identity import state_dir,load_identity
from queue_store import QueueStore,QueueFull
from transport import Transport,retry_delay

ALLOWED={4624,4625,4634,4648,4672,4688,4720,4726,4740,1102}
def setup_logging(directory):
    logger=logging.getLogger('zeroeye');logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler=RotatingFileHandler(directory/'agent.log',maxBytes=2*1024*1024,backupCount=3,encoding='utf8')
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'));logger.addHandler(handler)
    return logger

def run(stop):
    directory=state_dir();log=setup_logging(directory);identity=load_identity(directory/'identity.json')
    if identity.get('simulated'):
        raise RuntimeError('Native collection refuses demo device credentials. Use the synthetic generator for demo organizations.')
    queue=QueueStore(directory/'queue.sqlite');collector=Collector();transport=Transport(identity['backend'],identity['deviceToken'])
    event_ids=set(identity['eventIds'])&ALLOWED;attempt=0;retry_at=0;heartbeat_at=0;health=None
    log.info('ZEROEYE agent started; collecting selected Security event IDs; command-line collection=%s',identity.get('collectCommandLine',False))
    try:
        if not queue.checkpoint():
            latest=collector.latest_bookmark(event_ids)
            if latest:queue.enqueue(None,latest)
            log.info('Initial checkpoint set at enrollment start; historical logs are not imported')
        while not stop.is_set():
            try:
                for event,bookmark in collector.collect(queue.checkpoint(),event_ids):
                    if stop.is_set():break
                    if event and not identity.get('collectCommandLine',False):event['metadata'].pop('commandLine',None)
                    queue.enqueue(event,bookmark)
                health=None
            except QueueFull:
                health='Queue full; collection paused';log.warning(health)
            except Exception as exc:
                # No raw log contents, credentials, or exception request objects enter diagnostics.
                health='Collection failed: '+type(exc).__name__
                log.error('%s. Check Security-log permissions and bookmark validity.',health)
            now=time.monotonic()
            if now>=retry_at:
                try:
                    batch=queue.batch()
                    stale=[];allowed=[];cutoff=datetime.now(timezone.utc)-timedelta(days=30)
                    for row_id,event in batch:
                        if event['windowsEventId'] not in event_ids or datetime.fromisoformat(event['timestamp'])<cutoff:stale.append(row_id)
                        else:allowed.append((row_id,event))
                    if stale:
                        log.warning('Discarding %d queued records outside current policy or 30-day accepted window',len(stale));queue.acknowledge(stale)
                    if allowed:
                        result=transport.post('/events',{'events':[e for _,e in allowed]})
                        if result.get('accepted',0)+result.get('duplicates',0)!=len(allowed):raise RuntimeError('Incomplete acknowledgement')
                        queue.acknowledge([i for i,_ in allowed])
                    attempt=0;retry_at=0
                except Exception as exc:
                    attempt+=1;retry_at=now+retry_delay(attempt,random.random());log.warning('Upload failed (%s); retry %d scheduled',type(exc).__name__,attempt)
            if now>=heartbeat_at:
                try:
                    policy=transport.post('/heartbeat',{'queueDepth':queue.depth(),'error':health})
                    configured=policy.get('eventIds')
                    if not isinstance(configured,list) or not configured or any(type(n)!=int or n not in ALLOWED for n in configured):raise ValueError('Invalid collection policy')
                    event_ids=set(configured);heartbeat_at=now+30
                except Exception as exc:
                    heartbeat_at=now+30;log.warning('Heartbeat failed (%s)',type(exc).__name__)
            stop.wait(5)
    finally:
        transport.close();queue.close();log.info('ZEROEYE agent stopped cleanly')
