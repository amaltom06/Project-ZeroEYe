"""Modern Windows Event Log API with persistent XML bookmarks."""
import win32evtlog as evt
from parser import normalize
class Collector:
    def collect(self,bookmark,event_ids,limit=100):
        ids=' or '.join('EventID='+str(int(i)) for i in sorted(event_ids))
        query=evt.EvtQuery('Security',evt.EvtQueryChannelPath|evt.EvtQueryForwardDirection,'*[System[('+ids+')]]')
        mark=evt.EvtCreateBookmark(bookmark)
        try:
            if bookmark:
                # Strict seeking surfaces overwritten/cleared log gaps instead of silently skipping evidence.
                evt.EvtSeek(query,1,evt.EvtSeekRelativeToBookmark|evt.EvtSeekStrict,mark)
            for handle in evt.EvtNext(query,limit,0,0):
                try:
                    xml=evt.EvtRender(handle,evt.EvtRenderEventXml)
                    normalized=normalize(xml)
                    evt.EvtUpdateBookmark(mark,handle)
                    rendered=evt.EvtRender(mark,evt.EvtRenderBookmark)
                    yield normalized,rendered
                finally:handle.Close()
        finally:query.Close();mark.Close()
    def latest_bookmark(self,event_ids):
        ids=' or '.join('EventID='+str(int(i)) for i in sorted(event_ids))
        query=evt.EvtQuery('Security',evt.EvtQueryChannelPath|evt.EvtQueryReverseDirection,'*[System[('+ids+')]]')
        mark=evt.EvtCreateBookmark(None)
        try:
            handles=evt.EvtNext(query,1,0,0)
            if not handles:return None
            handle=handles[0]
            try:evt.EvtUpdateBookmark(mark,handle);return evt.EvtRender(mark,evt.EvtRenderBookmark)
            finally:handle.Close()
        finally:query.Close();mark.Close()
