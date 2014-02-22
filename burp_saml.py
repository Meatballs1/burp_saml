##
# SAML BurpSuite Extension
# Ben Campbell <eat_meatballs[at]hotmail.co.uk>
# http://rewtdance.blogspot.co.uk
# http://github.com/Meatballs1/burp_saml
#
# Load extension in the Extender tab.
#
# Tested in Burpsuite Pro v1.6beta
##

from burp import IBurpExtender
from burp import IBurpExtenderCallbacks
from burp import ITab

from javax import swing
from java import awt

import zlib, base64, re, xml.dom.minidom, struct, binascii

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

        # SAML Binding Format
        self._jTextIn = swing.JTextArea("SAML Binding In", 20,120)
        self._jTextIn.setLineWrap(True)
        self._jScrollPaneIn = swing.JScrollPane(self._jTextIn)
        self._jScrollPaneIn.setVerticalScrollBarPolicy(swing.JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)
        self._jScrollPaneIn.setPreferredSize(awt.Dimension(20,120))
        self._jTextOut = swing.JTextArea("SAML Binding Out", 20,120)
        self._jTextOut.setLineWrap(True)
        self._jScrollPaneOut = swing.JScrollPane(self._jTextOut)
        self._jScrollPaneOut.setVerticalScrollBarPolicy(swing.JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)
        self._jScrollPaneOut.setPreferredSize(awt.Dimension(20,120))
        self._jButtonPanel = swing.JPanel()
        self._jButtonEncode = swing.JButton('Encode', actionPerformed=self.encode)
        self._jButtonDecode = swing.JButton('Decode', actionPerformed=self.decode)
        self._jButtonPanel.add(self._jButtonEncode)
        self._jButtonPanel.add(self._jButtonDecode)
        self._jPanel.add(self._jScrollPaneIn)
        self._jPanel.add(self._jButtonPanel)
        self._jPanel.add(self._jScrollPaneOut)

        # SAML Artifact Format
        self._jTextArtIn = swing.JTextArea("SAML Artifact In", 20,120)
        self._jTextArtIn.setLineWrap(True)
        self._jScrollPaneArtIn = swing.JScrollPane(self._jTextArtIn)
        self._jScrollPaneArtIn.setVerticalScrollBarPolicy(swing.JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)
        self._jScrollPaneArtIn.setPreferredSize(awt.Dimension(20,120))
        self._jTextArtOut = swing.JTextArea("SAML Artifact Out", 20,120)
        self._jTextArtOut.setLineWrap(True)
        self._jScrollPaneArtOut = swing.JScrollPane(self._jTextArtOut)
        self._jScrollPaneArtOut.setVerticalScrollBarPolicy(swing.JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)
        self._jScrollPaneArtOut.setPreferredSize(awt.Dimension(20,120))
        self._jButtonArtPanel = swing.JPanel()
        self._jButtonArtEncode = swing.JButton('Encode', actionPerformed=self.art_encode)
        self._jButtonArtDecode = swing.JButton('Decode', actionPerformed=self.art_decode)
        self._jButtonArtPanel.add(self._jButtonArtEncode)
        self._jButtonArtPanel.add(self._jButtonArtDecode)
        self._jPanel.add(self._jScrollPaneArtIn)
        self._jPanel.add(self._jButtonArtPanel)
        self._jPanel.add(self._jScrollPaneArtOut)

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

    def art_decode(self, button):
        msg = self._jTextArtIn.getText()
        urldecoded = self._helpers.urlDecode(msg)
        b64decoded = base64.b64decode(urldecoded)
        type_code = b64decoded[0:2]
        endpoint_index = b64decoded[2:4]
        remaining_artefact = b64decoded[4:]

        art_type = struct.unpack('>H',type_code)[0]
        if art_type != 4:
            self._jTextArtOut.setText("Invalid Artifact!")
            return

        endpi = struct.unpack('>H',endpoint_index)[0]
        source_id_sha1 = binascii.hexlify(remaining_artefact[0:20])
        message_handle = binascii.hexlify(remaining_artefact[20:])

        out = "Artifact Type: %s\n" % art_type
        out += "Endpoint Index: %s\n" % endpi
        out += "Source ID (SHA-1): %s\n" % source_id_sha1
        out += "Message Handle: %s" % message_handle

        if out is None:
            self._jTextArtOut.setText("Invalid input")
        else:
            self._jTextArtOut.setText(out)

    def art_encode(self, button):
        self._jTextArtIn.setText("Not implemented")

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

