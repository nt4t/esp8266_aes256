###############################################################################
#
# The MIT License (MIT)
#
# Copyright (c) Crossbar.io Technologies GmbH
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
###############################################################################

import sys
import os

import base64, re
import binascii
from Crypto.Cipher import AES
from Crypto import Random

from twisted.internet import reactor
from twisted.python import log
from twisted.web.server import Site
from twisted.web.static import File

from autobahn.twisted.websocket import WebSocketServerFactory, \
    WebSocketServerProtocol

from autobahn.twisted.resource import WebSocketResource

class AESCipher:
    """
      Usage:
      aes = AESCipher( settings.SECRET_KEY[:16], 32)
      encryp_msg = aes.encrypt( 'ppppppppppppppppppppppppppppppppppppppppppppppppppppppp' )
      msg = aes.decrypt( encryp_msg )
      print("'{}'".format(msg))
    """
    def __init__(self, key, blk_sz):
        self.key = key
        self.blk_sz = blk_sz

    def encrypt( self, iv, raw ):
        if raw is None or len(raw) == 0:
            raise NameError("No value given to encrypt")
        raw = raw + '\0' * (self.blk_sz - len(raw) % self.blk_sz)
        # iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        # return iv, base64.b64encode(cipher.encrypt( raw ) ).decode('utf-8')
        return binascii.b2a_base64(cipher.encrypt( raw ) ).decode('utf-8')

    # def decrypt( self, enc ):
        # if enc is None or len(enc) == 0:
            # raise NameError("No value given to decrypt")
        # enc = base64.b64decode(enc)
        # iv = enc[:16]
        # cipher = AES.new(self.key, AES.MODE_CBC, iv )
        # return re.sub(b'\x00*$', b'', cipher.decrypt( enc[16:])).decode('utf-8')
        # return cipher.decrypt(enc)

    def decryptIv( self, iv, enc ):
        if enc is None or len(enc) == 0:
            raise NameError("No value given to decrypt")
        enc = base64.b64decode(enc)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return cipher.decrypt(enc)


class EchoServerProtocol(WebSocketServerProtocol):

    def onConnect(self, request):
        print("WebSocket connection request: {}".format(request))

    def onMessage(self, payload, isBinary):
        print(payload)
        print("\n---\n")
        crypt_msg = payload.split(" ")
        print(crypt_msg[-1])
        print(crypt_msg[-2])

        #decrypt incoming message
        aes = AESCipher(b"1234" * 8, 32)
        msg = aes.decryptIv(crypt_msg[-2], crypt_msg[-1])
        print(msg)

        #ecrypt ansver 
        aes = AESCipher(b"1234" * 8, 32)
        iv = crypt_msg[-2]
        
        iv = Random.new().read( 16 )
        iv = binascii.b2a_base64(iv).encode('utf-8').rstrip()
        iv += '1' * (16 - (len(iv)) % 16)    #align data to be a multiple of 16 in lenght

        encryp_msg = aes.encrypt( binascii.a2b_base64(iv), 'hello from server' )
        # print(encryp_msg)
        uname = os.uname()
        name = '{sysname} {release} {civ} {cmsg}'.format(
            sysname="linux",
            release="1.0",
            civ=iv,
            cmsg=encryp_msg,
        )
        print name

        self.sendMessage(name, isBinary)


if __name__ == '__main__':
    iv = Random.new().read( 16 )
    iv = binascii.b2a_base64(iv).encode('utf-8').rstrip()
    iv += '1' * (16 - (len(iv)) % 16)    #align data to be a multiple of 16 in lenght
    # iv += binascii.b2a_base64(Random.new().read( 1 )) * (16 - (len(iv)) % 16)    #align data to be a multiple of 16 in lenght
    print (iv) 

    log.startLogging(sys.stdout)

    factory = WebSocketServerFactory(u"ws://127.0.0.1:8080")
    # factory = WebSocketServerFactory(u"ws://192.168.12.49:8080")
    factory.protocol = EchoServerProtocol

    resource = WebSocketResource(factory)

    # we server static files under "/" ..
    root = File(".")

    # and our WebSocket server under "/ws" (note that Twisted uses
    # bytes for URIs)
    root.putChild(b"ws", resource)

    # both under one Twisted Web Site
    site = Site(root)
    reactor.listenTCP(8080, site)

    reactor.run()
