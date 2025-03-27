# Save this file as BurpToVSCode.py (for example)
# Ensure Jython is installed and Burp is configured to load .py files via Jython

from burp import IBurpExtender, IContextMenuFactory, IContextMenuInvocation
from javax.swing import JMenuItem
import httplib, urllib

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Simple Request Sender")
        # Register to add a custom right-click option
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        # Create a menu item to send selected requests to your local server
        sendItem = JMenuItem(
            "Send request to VSCode",
            actionPerformed=lambda x: self.sendSelectedRequests(invocation)
        )
        return [sendItem]

    def sendSelectedRequests(self, invocation):
        selected_msgs = invocation.getSelectedMessages()
        if not selected_msgs:
            return

        for msg in selected_msgs:
            request_bytes = msg.getRequest()
            if request_bytes is None:
                continue
            request_str = self._helpers.bytesToString(request_bytes)

            # Send to your local endpoint (POST)
            try:
                conn = httplib.HTTPConnection("localhost", 3700)
                body = urllib.urlencode({"request": request_str})
                headers = {"Content-type": "application/x-www-form-urlencoded"}
                conn.request("POST", "/burp-data", body, headers)
                response = conn.getresponse()
                conn.close()
            except Exception as e:
                # For quick debugging in Burp's Extender output
                print("Error sending request:", e)
