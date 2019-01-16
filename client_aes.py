try:
    from ucryptolib import aes
    import urandom
    import ubinascii as binascii
    import re
    import uwebsockets.client
    import os
except ImportError:
    print("SKIP")

secret_key = "Secretkey"
secret_key += '.' * (16 - (len(secret_key)) % 16
                    )  #align data to be a multiple of 16 in lenght


def encrypt(key, iv, raw):
    if raw is None or len(raw) == 0:
        raise NameError("No value given to encrypt")

    crypto = aes(secret_key, 2, iv)
    enc = crypto.encrypt(raw)
    return binascii.b2a_base64(enc).decode('utf-8')


def decrypt(key, iv, raw):
    crypto = aes(secret_key, 2, iv)
    # crypto = aes(secret_key, 2, binascii.a2b_base64(iv).decode('utf-8'))
    return crypto.decrypt(binascii.a2b_base64(raw)).decode('utf-8')


def makeIv():
    hrand = urandom.getrandbits(30)  #30 - max value for esp8266
    lrand = urandom.getrandbits(16)
    ivstr = str(hrand) + str(lrand)
    ivstr += '1' * (16 - (len(ivstr)) % 16
                   )  #align data to be a multiple of 16 in lenght
    return ivstr


def hello():
    with uwebsockets.client.connect('ws://192.168.12.1:8080/ws') as websocket:
    # with uwebsockets.client.connect('ws://192.168.12.49:8080/ws') as websocket:

        iv = makeIv()

        instr = "test message from esp"
        instr += '.' * (16 - (len(instr) % 16))
        # print(instr)

        enc = encrypt("", iv, instr)
        # print(enc)

        uname = os.uname()
        message = '{sysname} {release} {civ} {cmsg}'.format(
            sysname=uname.sysname,
            release=uname.release,
            civ=iv,
            cmsg=enc,
        )
        websocket.send(message)
        print("> {}".format(message))

        greeting = websocket.recv()
        print("< {}".format(greeting))
        # print(greeting)

        encmsg = greeting.split(' ')
        received_iv = binascii.a2b_base64(encmsg[-2])
        received_encmsg = encmsg[-1]

        print("decrypted message: ", decrypt("", received_iv, received_encmsg))


hello()
