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

secret_key = "Secretkey"
secret_key += '.' * (16 - (len(secret_key)) % 16
                    )  #align data to be a multiple of 16 in lenght


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

    def encrypt(self, iv, raw):
        if raw is None or len(raw) == 0:
            raise NameError("No value given to encrypt")
        raw = raw + '\0' * (self.blk_sz - len(raw) % self.blk_sz)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return binascii.b2a_base64(cipher.encrypt(raw)).decode('utf-8')

    def decrypt(self, iv, enc):
        if enc is None or len(enc) == 0:
            raise NameError("No value given to decrypt")
        enc = base64.b64decode(enc)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return cipher.decrypt(enc)

    def makeIv(self):
        ivrandh = Random.new().read(16)
        ivrandl = Random.new().read(16)
        ivrandh = binascii.b2a_base64(ivrandh).encode('utf-8').rstrip()
        llenght = (16 - (len(ivrandh)) % 16
                  )  #align data to be a multiple of 16 in lenght
        ivrandl = binascii.b2a_base64(ivrandl).encode('utf-8').rstrip()
        iv = ivrandh + ivrandl[:llenght - 0]
        # print (iv)
        return iv


class EchoServerProtocol(WebSocketServerProtocol):

    def onConnect(self, request):
        print("WebSocket connection request: {}".format(request))

    def onMessage(self, payload, isBinary):
        print(payload)
        crypt_msg = payload.split(" ")
        # print(crypt_msg[-1])
        # print(crypt_msg[-2])

        #decrypt incoming message
        aes = AESCipher(secret_key, 32)
        inc_msg = aes.decrypt(crypt_msg[-2], crypt_msg[-1])
        print("decrypted message:", inc_msg)

        #ecrypt ansver
        aes = AESCipher(secret_key, 32)

        iv = aes.makeIv()

        encryp_msg = aes.encrypt(binascii.a2b_base64(iv), 'hello from server')
        uname = os.uname()
        message = '{sysname} {release} {civ} {cmsg}'.format(
            sysname=uname[0],
            release=uname[1],
            civ=iv,
            cmsg=encryp_msg,
        )
        print message

        self.sendMessage(message, isBinary)


if __name__ == '__main__':

    log.startLogging(sys.stdout)

    factory = WebSocketServerFactory(u"ws://127.0.0.1:8080")
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
