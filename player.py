import xbmc
import threading

class Threading(object):
    def __init__(self):
        self.thread = threading.Thread(target=self.run, args=())
        self.thread.daemon = True
        self.thread.start()

    def run(self):
        xbmc.log("################ Starting control VideoPlayer events ################", level=xbmc.LOGINFO)
        while not xbmc.Monitor().abortRequested():
            self.player = VideoPlayerStateChange()
            if xbmc.Monitor().waitForAbort(1):
                break

class VideoPlayerStateChange(xbmc.Player):
    def __init__(self):
        xbmc.Player.__init__(self) 

    def onPlayBackError(self):
        xbmc.log("################ PlayBackError ################", level=xbmc.LOGINFO)

    def onPlayBackPaused(self):
        xbmc.log("################ I'm paused ################", level=xbmc.LOGINFO)

    def onPlayBackResumed(self):
        xbmc.log("################ I'm Resumed ################", level=xbmc.LOGINFO)

    def onPlayBackStarted(self):
        xbmc.log("################ Playback Started ################", level=xbmc.LOGINFO)

if ( __name__ == "__main__" ):
    Threading()