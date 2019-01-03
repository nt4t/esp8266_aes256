try:
    from ucryptolib import aes
    import urandom
    import ubinascii as binascii
    import re
except ImportError:
    print("SKIP")

import uwebsockets.client
import os

# def encode():


def hello():
    with uwebsockets.client.connect('ws://192.168.12.1:8080/ws') as websocket:

        iv = urandom.getrandbits(30)
        ivstr = str(iv) 
        ivstr += '1' * (16 - (len(ivstr)) % 16)
        print(ivstr)

        crypto = aes(b"1234" * 8, 2, ivstr)
        # crypto = aes(b"1234" * 4, 2, b"5678" * 4)
        instr = "zxzzxzbzzbzzzaa"
        instr += 'i' * (16 - (len(instr) % 16))
        print(instr)
        enc = crypto.encrypt(instr)
        print(enc)
        enc = binascii.b2a_base64(enc)
        print(enc)

        uname = os.uname()
        name = '{sysname} {release} {version} {machine}'.format(
            sysname=uname.sysname,
            release=uname.release,
            version=uname.version,
            # machine=uname.machine,
            machine=enc,
        )
        websocket.send(name)
        print("> {}".format(name))

        greeting = websocket.recv()
        print("< {}".format(greeting))
        encmsg = greeting.split(' ')
        print(binascii.a2b_base64(encmsg[-1]))
        print(len(encmsg[-1]))
        print(re.sub(b'\x00*$', b'', encmsg[-1]))

        crypto = aes(b"1234" * 8, 2, ivstr)
        # crypto = aes(b"1234" * 4, 2, b"5678" * 4)
        # print(crypto.decrypt(binascii.a2b_base64(encmsg[-1])))
        print("----")
        # print((binascii.a2b_base64(enc)))
        # print((re.sub(b'\x00*$', b'', encmsg[-1]))
        xmsg = encmsg[-1].split("'")
        print(binascii.a2b_base64(xmsg[-2]))

        print(crypto.decrypt(binascii.a2b_base64(xmsg[-2])))
        # print(crypto.decrypt(binascii.a2b_base64(enc)))
        # print(crypto.decrypt(re.sub(b'\x00*$', b'', encmsg[-1])))
hello()
