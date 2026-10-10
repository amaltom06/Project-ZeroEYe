import sys
import threading
import servicemanager
import win32service
import win32serviceutil
from runner import run

class ZeroEyeService(win32serviceutil.ServiceFramework):
    _svc_name_='ZeroEyeAgent'
    _svc_display_name_='ZEROEYE Security Monitoring Agent'
    _svc_description_='Visible monitoring of selected Windows Security event logs with outbound HTTPS telemetry. No remote command execution.'
    def __init__(self,args):super().__init__(args);self.stop=threading.Event()
    def SvcStop(self):self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING);self.stop.set()
    def SvcDoRun(self):
        servicemanager.LogInfoMsg('ZEROEYE monitoring service started')
        try:run(self.stop)
        except Exception as exc:
            servicemanager.LogErrorMsg('ZEROEYE service failed: '+type(exc).__name__)
            raise
if __name__=='__main__':
    if len(sys.argv)==1:
        servicemanager.Initialize();servicemanager.PrepareToHostSingle(ZeroEyeService);servicemanager.StartServiceCtrlDispatcher()
    else:win32serviceutil.HandleCommandLine(ZeroEyeService)
