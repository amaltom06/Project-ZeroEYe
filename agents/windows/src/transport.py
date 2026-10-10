import json
import requests
from identity import validate_url
class UploadError(Exception):pass

def read_response(response,expected=200):
    try:
        if response.status_code!=expected:raise UploadError('Backend rejected request: HTTP '+str(response.status_code))
        body=bytearray()
        for chunk in response.iter_content(chunk_size=4096):
            if len(body)+len(chunk)>65536:raise UploadError('Backend response too large')
            body.extend(chunk)
        return json.loads(body)
    finally:response.close()

class Transport:
    def __init__(self,backend,device_token):
        self.backend=validate_url(backend);self.session=requests.Session();self.session.headers.update({'Authorization':'Bearer '+device_token})
    def post(self,path,payload):
        # TLS verification stays enabled; redirects cannot move credentials to another origin.
        response=self.session.post(self.backend+'/api/agent'+path,json=payload,timeout=(5,15),allow_redirects=False,stream=True)
        return read_response(response)
    def close(self):self.session.close()

def retry_delay(attempt,jitter=0.5):return min(300,2**min(attempt,8))+jitter
