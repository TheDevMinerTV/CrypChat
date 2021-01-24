import { randomBytes } from 'crypto';
import Fastify from 'fastify';
import { Server as WSServer } from 'ws';
import { Configuration } from './config';
import { CryptoClient } from './CryptoClient';
import { PeerManager } from './PeerManager';
import { BaseContext } from './types/Context';

const CONFIG_FILE = process.env.CONFIG_FILE ?? './config.json';

Configuration.read(CONFIG_FILE);

const client = new CryptoClient(randomBytes(8).toString('hex'), Configuration.peerName);

const httpServer = Fastify();
const wsServer = new WSServer({ server: httpServer.server, perMessageDeflate: true });

PeerManager.initialize(new BaseContext(client, wsServer, httpServer));

wsServer.on('connection', async (ws, req) => PeerManager.get().handleConnection(ws, req));

wsServer.on('close', () => {
	console.log('close');
});

async function main() {
	await httpServer.listen(Configuration.port, Configuration.host);
	const address = httpServer.server.address();

	console.log(
		`Listening on ${typeof address === 'object' ? `${address?.address}:${address?.port}` : address}`
	);

	for (const peer of Configuration.seedPeers) {
		PeerManager.get().connectToPeer(peer, 'seed');
	}
}

main();
