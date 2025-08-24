from burp import IBurpExtender, IContextMenuFactory, ITab
from javax.swing import JPanel, JLabel, JTextField, JButton, JMenuItem, BoxLayout, Box
from java.awt import FlowLayout
import httplib
import json

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):
    # ---- bootstrap ---------------------------------------------------------
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        callbacks.setExtensionName("Burp to VSCode")

        self.port = callbacks.loadExtensionSetting("destPort") or "3700"
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)

    # ---- ITab --------------------------------------------------------------
    def getTabCaption(self):
        return "VSCode Sender"

    def getUiComponent(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))

        row = JPanel()
        row = JPanel(FlowLayout(FlowLayout.LEFT, 5, 0))  # small 5-px gap
        row.add(JLabel("Port:"))
        self.portField = JTextField(6)
        self.portField.setText(self.port)
        row.add(self.portField)
        row.add(JButton("Save", actionPerformed=self._savePort))

        panel.add(row)
        return panel

    def _savePort(self, _):
        self.port = self.portField.getText().strip()
        self._callbacks.saveExtensionSetting("destPort", self.port)

    # ---- context-menu ------------------------------------------------------
    def createMenuItems(self, invocation):
        return [JMenuItem("Send REQ/RES to VSCode",
                          actionPerformed=lambda _: self._send(invocation))]

    def _send(self, invocation):
        for msg in (invocation.getSelectedMessages() or []):
            req = self._helpers.bytesToString(msg.getRequest())
            if not req:
                continue
            res = self._helpers.bytesToString(msg.getResponse()) if msg.getResponse() else None
            info = self._helpers.analyzeRequest(msg)

            payload = json.dumps({
                "request": {"raw": req,
                            "method": info.getMethod(),
                            "url": str(info.getUrl())},
                "response": res
            })

            try:
                conn = httplib.HTTPConnection("localhost", int(self.port))
                conn.request("POST", "/burp-data", payload,
                             {"Content-Type": "application/json"})
                conn.close()
            except Exception as e:
                print("Error sending:", e)

# Burp entry-point
def createBurpExtender(callbacks):
    return BurpExtender()
