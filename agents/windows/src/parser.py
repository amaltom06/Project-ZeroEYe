"""Normalize allowlisted Security-log fields; never forward raw XML."""
import hashlib
import ipaddress
from datetime import datetime, timezone
from defusedxml import ElementTree as ET

EVENT_IDS = {4624,4625,4634,4648,4672,4688,4720,4726,4740,1102}
NS = {'e':'http://schemas.microsoft.com/win/2004/08/events/event'}
def normalize(xml: str) -> dict | None:
    root = ET.fromstring(xml)
    system = root.find('e:System', NS)
    if system is None:
        raise ValueError('Missing System')
    event_id = int(system.findtext('e:EventID', namespaces=NS) or 0)
    provider = system.find('e:Provider', NS)
    provider_name = provider.attrib.get('Name', '') if provider is not None else ''
    # 1102 uses Microsoft-Windows-Eventlog, with UserData rather than EventData.
    if event_id not in EVENT_IDS or provider_name not in {'Microsoft-Windows-Security-Auditing','Microsoft-Windows-Eventlog'}:
        return None
    if provider_name == 'Microsoft-Windows-Eventlog' and event_id != 1102:
        return None
    channel = system.findtext('e:Channel', namespaces=NS)
    if channel != 'Security':
        return None
    created = system.find('e:TimeCreated', NS)
    if created is None:
        raise ValueError('Missing timestamp')
    stamp = datetime.fromisoformat(created.attrib['SystemTime'].replace('Z','+00:00'))
    if stamp.tzinfo is None:
        raise ValueError('Timestamp has no offset')
    timestamp = stamp.astimezone(timezone.utc).isoformat()
    data = {el.attrib['Name']:el.text or '' for el in root.findall('e:EventData/e:Data', NS) if 'Name' in el.attrib}
    for el in root.findall('.//e:UserData//*', NS):
        data[el.tag.split('}')[-1]] = el.text or ''
    def field(*names):
        for name in names:
            value=data.get(name)
            if value and value not in {'-','(null)'}:
                return value
        return None
    record_id=system.findtext('e:EventRecordID', namespaces=NS) or 'unknown'
    computer=system.findtext('e:Computer', namespaces=NS) or 'unknown'
    key=hashlib.sha256((computer+'|Security|'+record_id+'|'+timestamp+'|'+str(event_id)).encode()).hexdigest()
    metadata={'recordId':record_id[:30],'channel':'Security'}
    if field('LogonType'):metadata['logonType']=field('LogonType')[:8]
    if field('Status'):metadata['status']=field('Status')[:40]
    # Command line collection is opt-in; the runner removes it unless locally enabled.
    if field('CommandLine'):metadata['commandLine']=field('CommandLine')[:2048]
    event={'eventKey':key,'provider':provider_name,'windowsEventId':event_id,'timestamp':timestamp,'metadata':metadata}
    user=field('TargetUserName','SubjectUserName')
    if user:event['username']=user[:256]
    source=field('IpAddress')
    if source:
        try:event['sourceIp']=str(ipaddress.ip_address(source))
        except ValueError:pass
    process=field('NewProcessName','ProcessName')
    if process:event['processName']=process[:512]
    return event
