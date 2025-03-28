from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem
import httplib
import json

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Burp To VsCode")
        callbacks.registerContextMenuFactory(self)
    
    def createMenuItems(self, invocation):
        # Create menu item to send both request and response
        sendItem = JMenuItem(
            "Send REQ/RES to VSCode",
            actionPerformed=lambda x: self.sendSelectedRequestsAndResponses(invocation)
        )
        return [sendItem]
    
    def sendSelectedRequestsAndResponses(self, invocation):
        selected_msgs = invocation.getSelectedMessages()
        if not selected_msgs:
            return
        
        for msg in selected_msgs:
            # Get request details
            request_bytes = msg.getRequest()
            if request_bytes is None:
                continue
            
            request_str = self._helpers.bytesToString(request_bytes)
            
            # Get response details (if available)
            response_bytes = msg.getResponse()
            response_str = self._helpers.bytesToString(response_bytes) if response_bytes else None
            
            # Parse request details
            request_info = self._helpers.analyzeRequest(msg)
            url = request_info.getUrl()
            method = request_info.getMethod()
            
            # Prepare payload
            payload = {
                'request': {
                    'raw': request_str,
                    'method': method,
                    'url': str(url)
                },
                'response': response_str
            }
            
            # Send to local endpoint
            try:
                conn = httplib.HTTPConnection("localhost", 3700)
                headers = {"Content-type": "application/json"}
                
                # Convert payload to JSON
                json_payload = json.dumps(payload)
                
                conn.request("POST", "/burp-data", json_payload, headers)                
                
                conn.close()
            except Exception as e:
                print("Error sending request:", e)

# Export the extender
def createBurpExtender(callbacks):
    return BurpExtender()