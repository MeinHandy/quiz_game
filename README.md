# quiz_game
Dependencies: <br>
pip install pycryptodome <br>
pip install rsa

To join a server, make sure you and the server have identical public keys (server_public_key) <br>
All other keys will be generated on first launch, this may cause some inital lag. <br>
<br>
Do not share any private key <br>
If you share a private key, immediately delete old keys, and regenerate new keys. <br>
<br>
Adding servers does require some technical knowledge, but only requires to add the server ip and port. <br>
[Client side changes](https://github.com/MeinHandy/quiz_game/blob/5da008f67db99bc7ec20ad132080de7c12535d89/client.py#L151C19-L151C19) <br>
[Server side changes](https://github.com/MeinHandy/quiz_game/blob/5da008f67db99bc7ec20ad132080de7c12535d89/server.py#L153C1-L153C1)
