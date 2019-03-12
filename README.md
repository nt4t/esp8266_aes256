
# Micropython websocket AES 256 on the client side (esp8266 implementation)

## Client install

```
ampy -p /dev/ttyUSB0 mkdir uwebsockets                
ampy -p /dev/ttyUSB0 put uwebsockets/uwebsockets/client.py uwebsockets/client.py
ampy -p /dev/ttyUSB0 put uwebsockets/uwebsockets/protocol.py uwebsockets/protocol.py

import upip
upip.install('micropython-logging')
```

#### Set correct server ip address

```
with uwebsockets.client.connect('ws://192.168.12.1:8080/ws') as websocket:
```

## Server install

```
pip install pycrypto
pip install twisted
```

## Screenshot 

```
% ampy -p /dev/ttyUSB0 run client_aes.py
> esp8266 2.2.0-dev(9422289) MWUxY2FjNmFkNzdkNzA5MQ== o9Zm+9y2jqIKuwuD5/burHCkSKWd4YEY4NolKe7SbNM=

< Linux orangepipcplus mvq+5gmQxyHe+ytGRtYm/w== pyvzXmWbbZdhoe7Tp95KBKFV8tYF+YW3QwinvDlKD4o=

decrypted message:  hello from server
```

```
% python server_aes.py
2019-03-12 15:11:15+0700 [-] Log opened.
2019-03-12 15:11:15+0700 [-] Site starting on 8080
2019-03-12 15:11:15+0700 [-] Starting factory <twisted.web.server.Site instance at 0xb60cad00>
2019-03-12 15:11:34+0700 [-] WebSocket connection request: {"origin": "http://localhost", "headers": {"origin": "http://localhost", "upgrade": "websocket", "sec-websocket-version": "13", "connection": "Upgrade", "sec-websocket-key": "Bl6d3mgDAxXSES2wpDytIw==", "host": "192.168.12.1:8080"}, "host": "192.168.12.1", "version": 13, "params": {}, "extensions": [], "peer": "tcp4:192.168.12.104:23100", "path": "/ws", "protocols": []}
2019-03-12 15:11:34+0700 [-] esp8266 2.2.0-dev(9422289) MWUxY2FjNmFkNzdkNzA5MQ== o9Zm+9y2jqIKuwuD5/burHCkSKWd4YEY4NolKe7SbNM=
2019-03-12 15:11:34+0700 [-] 
2019-03-12 15:11:34+0700 [-] ('decrypted message:', 'test message from esp...........')
2019-03-12 15:11:34+0700 [-] Linux orangepipcplus mvq+5gmQxyHe+ytGRtYm/w== pyvzXmWbbZdhoe7Tp95KBKFV8tYF+YW3QwinvDlKD4o=
2019-03-12 15:11:34+0700 [-] 
```

## TODO

Better iv implementation on the client side
