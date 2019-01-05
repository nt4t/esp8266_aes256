try:
    from ucryptolib import aes
    import urandom
    import ubinascii as binascii
    import re
except ImportError:
    print("SKIP")

import uwebsockets.client
import os

def encrypt(key, iv, raw):
    if raw is None or len(raw) == 0:
        raise NameError("No value given to encrypt")

    crypto = aes(b"1234" * 8, 2, iv)
    enc = crypto.encrypt(raw)
    return binascii.b2a_base64(enc).decode('utf-8')


def decrypt(key, iv, raw):
    crypto = aes(b"1234" * 8, 2, iv)
    return crypto.decrypt(binascii.a2b_base64(raw)).decode('utf-8')


def makeIv():
    riv = urandom.getrandbits(30)
    ivstr = str(riv) 
    ivstr += '1' * (16 - (len(ivstr)) % 16)
    return ivstr

def hello():
    with uwebsockets.client.connect('ws://192.168.12.1:8080/ws') as websocket:

        iv = makeIv()

        instr = "zxzzxzbzzbzzzaa"
        instr += 'i' * (16 - (len(instr) % 16))
        print(instr)
        enc = encrypt("", iv, instr)
        print(enc)

        uname = os.uname()
        name = '{sysname} {release} {civ} {cmsg}'.format(
            sysname=uname.sysname,
            release=uname.release,
            civ=iv,
            cmsg=enc,
        )
        websocket.send(name)
        print("> {}".format(name))

        greeting = websocket.recv()
        print("< {}".format(greeting))


        encmsg = greeting.split(' ')
        print("----.")
        print(encmsg[-2])
        print(encmsg[-1])
        
        print(decrypt("", encmsg[-2], encmsg[-1]))
        # print(crypto.decrypt(binascii.a2b_base64(encmsg[-1])).decode('utf-8'))


hello()
