import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parents[1]/'src'))
import pytest
from parser import normalize
from queue_store import QueueStore,QueueFull
from identity import validate_url
from transport import Transport,retry_delay,UploadError

XML='''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><EventRecordID>42</EventRecordID><Channel>Security</Channel><Computer>host</Computer><TimeCreated SystemTime="2026-10-10T10:00:00.0000000Z"/></System><EventData><Data Name="TargetUserName">alice</Data><Data Name="IpAddress">-</Data><Data Name="LogonType">3</Data></EventData></Event>'''
def test_parse_missing_ip_and_repeatable_key():
    event=normalize(XML);assert event['username']=='alice';assert 'sourceIp' not in event;assert event['metadata']['logonType']=='3';assert event['eventKey']==normalize(XML)['eventKey']
def test_1102_userdata_actual_provider():
    xml=XML.replace('Microsoft-Windows-Security-Auditing','Microsoft-Windows-Eventlog').replace('<EventID>4625','<EventID>1102').replace('<EventData>','<UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog"><SubjectUserName>admin</SubjectUserName>').replace('</EventData>','</LogFileCleared></UserData>')
    event=normalize(xml);assert event['username']=='admin';assert event['provider']=='Microsoft-Windows-Eventlog'
def test_reject_unexpected_channel_and_xml_entities():
    assert normalize(XML.replace('<Channel>Security','<Channel>System')) is None
    with pytest.raises(Exception):normalize('<!DOCTYPE Event [<!ENTITY x SYSTEM "file:///secret">]><Event>&x;</Event>')
def test_durable_queue_and_bookmark_atomicity(tmp_path):
    path=tmp_path/'q.db';q=QueueStore(path,max_events=1);event=normalize(XML);q.enqueue(event,'bookmark-1');q.enqueue(event,'bookmark-2');assert q.depth()==1
    with pytest.raises(QueueFull):q.enqueue({**event,'eventKey':'different'},'bookmark-3')
    assert q.checkpoint()=='bookmark-2';q.close();q=QueueStore(path);assert q.checkpoint()=='bookmark-2';assert q.depth()==1;q.acknowledge([q.batch()[0][0]]);assert q.depth()==0;q.close()
def test_queue_byte_bound(tmp_path):
    q=QueueStore(tmp_path/'q.db',max_bytes=1)
    with pytest.raises(QueueFull):q.enqueue(normalize(XML),'bad')
    assert q.checkpoint() is None;q.close()
def test_https_and_loopback_only():
    assert validate_url('https://example.test/')=='https://example.test'
    assert validate_url('http://127.0.0.1:4000')=='http://127.0.0.1:4000'
    for url in ['http://example.test','https://user:password@example.test','https://example.test?token=secret']:
        with pytest.raises(ValueError):validate_url(url)
def test_retry_bounded():assert retry_delay(99,0.5)<=300.5;assert retry_delay(1,0)==2
class FakeResponse:
    status_code=200;content=b'{}'
    def iter_content(self,chunk_size):yield b'{"ok":true}'
    def close(self):pass
def test_transport_ack_and_rejects_redirect(monkeypatch):
    t=Transport('https://example.test','secret')
    def post(url,**kwargs):assert kwargs['allow_redirects'] is False;assert kwargs['timeout']==(5,15);return FakeResponse()
    monkeypatch.setattr(t.session,'post',post);assert t.post('/heartbeat',{})=={'ok':True}
    FakeResponse.status_code=302
    with pytest.raises(UploadError):t.post('/events',{})
    FakeResponse.status_code=200;t.close()

@pytest.mark.skipif(sys.platform!='win32',reason='Windows DPAPI only')
def test_dpapi_identity_roundtrip(tmp_path):
    from identity import save_identity,load_identity
    path=tmp_path/'identity.json';save_identity(path,{'deviceToken':'test-only-device-token','backend':'https://example.test'})
    assert 'test-only-device-token' not in path.read_text()
    assert load_identity(path)['deviceToken']=='test-only-device-token'

def test_response_memory_bound():
    from transport import read_response
    class Huge(FakeResponse):
        def iter_content(self,chunk_size):
            for _ in range(17):yield b'x'*4096
    with pytest.raises(UploadError):read_response(Huge())

@pytest.mark.skipif(sys.platform!='win32',reason='Windows runner imports modern Event Log bindings')
def test_runner_acknowledges_and_stops_cleanly(tmp_path,monkeypatch):
    import threading
    import runner
    stop=threading.Event();closed=[]
    class FakeCollector:
        def latest_bookmark(self,ids):return 'initial'
        def collect(self,bookmark,ids):yield normalize(XML),'last'
    class FakeTransport:
        def __init__(self,*args):pass
        def post(self,path,payload):
            if path=='/heartbeat':stop.set();return {'eventIds':[4625]}
            assert path=='/events';return {'accepted':len(payload['events']),'duplicates':0}
        def close(self):closed.append(True)
    monkeypatch.setattr(runner,'state_dir',lambda:tmp_path)
    monkeypatch.setattr(runner,'load_identity',lambda path:{'backend':'https://example.test','deviceToken':'test-only','eventIds':[4625],'simulated':False})
    monkeypatch.setattr(runner,'Collector',FakeCollector);monkeypatch.setattr(runner,'Transport',FakeTransport)
    runner.run(stop);q=QueueStore(tmp_path/'queue.sqlite')
    assert q.depth()==0;assert q.checkpoint()=='last';assert closed==[True];q.close()
