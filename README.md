
# Micropython websockets AES 256 on the client side (esp8266 implementation)

## Client install

```
ampy -p /dev/ttyUSB0 mkdir uwebsockets                
ampy -p /dev/ttyUSB0 put uwebsockets/uwebsockets/client.py uwebsockets/client.py
ampy -p /dev/ttyUSB0 put uwebsockets/uwebsockets/protocol.py uwebsockets/protocol.py

import upip
upip.install('micropython-logging')
```

## Server install

```
pip install pycrypto
pip install twisted
```

## Screenshot 

```
% ampy -p /dev/ttyUSB0 run client_aes.py
> esp8266 2.2.0-dev(9422289) 3531538633029611 MhFjaR83WVYqY0/RIFZYQvtjQXMvGOakZBHG3CuEr3w=

< Linux SE 29+DSbAdkGmjKmAVgeYoxw==47V+coKw I2Nzw0pP0w4JyQbSrl8jJemfRbZ0/Fjcp5aQ05VXt1c=

decrypted message:  hello from server
```

```
% python server_aes.py
2019-01-15 14:24:21+0700 [-] Log opened.
2019-01-15 14:24:21+0700 [-] Site starting on 8080
2019-01-15 14:24:21+0700 [-] Starting factory <twisted.web.server.Site instance at 0x2b8f1c188248>
2019-01-15 14:24:40+0700 [-] WebSocket connection request: {"origin": "http://localhost", "headers": {"origin": "http://localhost", "upgrade": "websocket", "sec-websocket-version": "13", "connection": "Upgrade", "sec-websocket-key": "pDHA8BNTQdApUUS3lp4Kzg==", "host": "192.168.12.49:8080"}, "host": "192.168.12.49", "version": 13, "params": {}, "extensions": [], "peer": "tcp4:192.168.12.104:29371", "path": "/ws", "protocols": []}
2019-01-15 14:24:40+0700 [-] esp8266 2.2.0-dev(9422289) 3531538633029611 MhFjaR83WVYqY0/RIFZYQvtjQXMvGOakZBHG3CuEr3w=
2019-01-15 14:24:40+0700 [-] 
2019-01-15 14:24:40+0700 [-] ('decrypted message:', 'test message from ecp...........')
2019-01-15 14:24:40+0700 [-] Linux SE 29+DSbAdkGmjKmAVgeYoxw==47V+coKw I2Nzw0pP0w4JyQbSrl8jJemfRbZ0/Fjcp5aQ05VXt1c=
2019-01-15 14:24:40+0700 [-] 
```

## TODO

Better iv implementation on the client side
