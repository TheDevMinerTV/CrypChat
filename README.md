# CrypChat

CrypChat is a distributed and end-to-end encrypted chat platform.

## Security

This is a project I whipped up for school in about four days, do not expect it to be actually secure.

## Configuring

Create a file named `config.json` with the following content in it (you may change the values):

Explanation of the configuration:

- `peerName`: This is the name of your client
- `host`: This is the IP where the WebSocket server should listen on
- `port`: This is the port where the WebSocket server should listen on
- `seedPeers`: These are all other peers the you want to recieve more peers from

```json
{
	"peerName": "Alice",

	"host": "0.0.0.0",
	"port": 8009,

	"seedPeers": ["ws://127.0.0.1:8010"]
}
```

## TODO

- [ ] PeerManager
  - [ ] Proxy sent messages to all other peers
- [ ] CryptoClient
  - [x] Generate IV
  - [ ] Use ECIES
- [ ] CLI
  - [ ] Send chat messages
  - [ ] Manually connect to peers
  - [ ] Disconnect peers

## Possible exploits

- MITM the handshake process
  - capture the public keys of both parties and "intercept-decrypt-dump-encrypt-send" the packets between the peers
