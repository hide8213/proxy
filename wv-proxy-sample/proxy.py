#!/usr/bin/env python
"""Reference Modular DRM proxy application.
    
  Reference proxy application that works on AppEngine.  The proxy only accepts
  POST requests from CDMs that implement the Widevine License Exchange protocol.
"""

import base64
import binascii
import contextlib
import hashlib
import json
import urllib2


from Crypto.Cipher import AES
import webapp2


LICENSE_SERVER_URL = "https://license.uat.widevine.com/cenc/getlicense"
PROVIDER = "widevine_test"
#NO LONGER REQUIRED# CONTENT_ID = "TEST_CONTENT_ID_1"
ALLOWED_TRACK_TYPES = "SD_HD"
CONTENT_ID = binascii.a2b_hex("1ae8ccd0e7985cc0b6203a55855a1034afc252980e970ca90e5202"
                        "689f947ab9")
_IV = binascii.a2b_hex("d58ce954203b7c9a9a9d467f59839249")


class ProxyHandler(webapp2.RequestHandler):
    """Modular DRM License Server proxy handler.
        
        Proxies requests between applications using Widevine CDM and Widevine
        License Server.
        """
    
    def post(self):
        """Handles HTTP Posts sent to the proxy."""
        self.response.headers.add_header("Access-Control-Allow-Origin", "*")
        if not self.request.body:
            self._Send400("Empty Request")
            return None
        self._SetContentId()
        try:
            response = self._SendRequest(self._BuildRequest())
            status_ok, response = self._ProcessLicenseResponse(response)
            if status_ok:
                self.response.write(response)
            else:
                self._Send500(response)
        except TypeError:
            self._Send400("Invalid License Request")
    
    def get(self):
        """Handles HTTP Gets sent to the proxy."""
        self.debug_info = None
        self._Send400("GET Not Supported")
    
    def options(self):
        """Handles HTTP Options sent to the proxy."""
        try:
            origin = self.request.headers["Origin"]
        except KeyError:
            origin = "*"
        self.response.headers.add_header("Access-Control-Allow-Origin", origin)
        self.response.headers.add_header("Access-Control-Allow-Methods",
                                         "POST, OPTIONS")
        self.response.headers.add_header("Access-Control-Allow-Headers",
                                         "origin, x-requested-with, content-type, accept")
        self.response.status = 200
    
    def _SetContentId(self):
        self.content_id = CONTENT_ID
    
    def _Send400(self, text):
        self.response.status = 400
        self.response.write(text)
    
    def _Send500(self, text):
        self.response.status = 500
        self.response.write(text)
    
    def _SendRequest(self, message_body):
        try:
            with contextlib.closing(urllib2.urlopen("{0}/{1}".format(LICENSE_SERVER_URL, PROVIDER),
                                    message_body)) as f:
              return f.read()
        except urllib2.HTTPError:
            self._Send500("License Request Failed")
    
    def _BuildRequest(self):
        """Builds JSON requests to be sent to the license server."""
        message = self._BuildMessage()
        request = base64.standard_b64encode(message)
        signature = self._GenerateSignature(message)
        license_server_request = json.dumps({"request": request,
                                            "signature": signature,
                                            "signer": PROVIDER})
        print license_server_request
        return license_server_request
    
    def _BuildMessage(self):
        """Build a license request to be sent to Widevine Service."""
        base64_payload = base64.standard_b64encode(self.request.body)
        if self.content_id:
            request = {"payload": base64_payload,
                "content_id": base64.standard_b64encode(self.content_id),
                "provider": PROVIDER,
                "allowed_track_types": ALLOWED_TRACK_TYPES}
        else:
            request = {"payload": base64_payload,
                "content_id": base64.standard_b64encode("empty"),
                "provider": PROVIDER,
                "allowed_track_types": ALLOWED_TRACK_TYPES} 
        print request
        return json.dumps(request)
    
    def _GenerateSignature(self, message):
        """Generate the message signature."""
        sha = hashlib.sha1()
        sha.update(message)
        sha1_message = sha.digest()
        cipher = AES.new(_KEY, AES.MODE_CBC, _IV)
        padding = binascii.a2b_hex("" if len(sha1_message) % 16 == 0
                                   else (16 - (len(sha1_message) % 16)) * "00")
        aes_msg = cipher.encrypt(sha1_message + padding)
        return base64.standard_b64encode(aes_msg)
    
    def _ProcessLicenseResponse(self, response):
        """Processes the license response."""
        license_response = json.loads(response)
        print license_response
        if license_response["status"] == "OK":
            license_decoded = base64.standard_b64decode(license_response["license"])
            return (True, license_decoded)
        else:
            return (False, license_response["status"])


app = webapp2.WSGIApplication([("/proxy", ProxyHandler)])
