##
# SAML BurpSuite Extension
# Ben Campbell <eat_meatballs[at]hotmail.co.uk>
# http://rewtdance.blogspot.co.uk
# http://github.com/Meatballs1/burp_saml
#
# Load extension in the Extender tab.
#
# Tested in Burpsuite Pro v1.5.14
##

from burp import IBurpExtender
from burp import IBurpExtenderCallbacks
from burp import ITab

from javax import swing

import zlib, base64, re, xml.dom.minidom

class BurpExtender(IBurpExtender, ITab):
    
    #
    # implement IBurpExtender
    #
    def	registerExtenderCallbacks(self, callbacks):
        print "SAML BurpSuite Extension"
        print "Ben Campbell <eat_meatballs[at]hotmail.co.uk>"
        print "http://rewtdance.blogspot.co.uk"
        print "http://github.com/Meatballs1/burp_saml"
        
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("SAML Decoder")

        # Create Tab
        self._jPanel = swing.JPanel()
        self._jPanel.setLayout(swing.BoxLayout(self._jPanel, swing.BoxLayout.Y_AXIS))
        self._jTextIn = swing.JTextArea("in", 20,120)
        self._jTextIn.setLineWrap(True)
        self._jTextOut = swing.JTextArea("out", 20,120)
        self._jTextOut.setLineWrap(True)

        self._jButtonPanel = swing.JPanel()
        self._jButtonEncode = swing.JButton('Encode', actionPerformed=self.encode)
        self._jButtonDecode = swing.JButton('Decode', actionPerformed=self.decode)
        self._jButtonPanel.add(self._jButtonEncode)
        self._jButtonPanel.add(self._jButtonDecode)
        self._jPanel.add(self._jTextIn)
        self._jPanel.add(self._jButtonPanel)
        self._jPanel.add(self._jTextOut)
        callbacks.customizeUiComponent(self._jPanel)

        # register ourselves as a message editor tab factory
        callbacks.addSuiteTab(self)
        return

    #
    # implement ITab
    #
    def getTabCaption(self):
        return "SAML"

    #
    # implement ITab
    #
    def getUiComponent(self):
        return self._jPanel

    # http://stackoverflow.com/questions/1089662/python-inflate-and-deflate-implementations
    def decode(self, button):
        msg = self._jTextIn.getText()
        urldecoded = self._helpers.urlDecode(msg)
        b64decoded = base64.b64decode(urldecoded)
        decompressed = zlib.decompress(b64decoded, -15)
        x = xml.dom.minidom.parseString(decompressed)
        xml_pretty = x.toprettyxml(indent='\t')
        if decompressed is None:
            self._jTextOut.setText("Invalid input")
        else:
            self._jTextOut.setText(str(xml_pretty))

    def encode(self, button):
        msg = self._jTextOut.getText()
        stripped = re.sub(r'\n|\t', '', msg)
        zlibbed = zlib.compress(stripped)[2:-4]
        b64encoded = base64.b64encode(zlibbed)
        urlencoded = self._helpers.urlEncode(b64encoded)
        if urlencoded is None:
            self._jTextIn.setText("Invalid input")
        else:
            self._jTextIn.setText(urlencoded)
