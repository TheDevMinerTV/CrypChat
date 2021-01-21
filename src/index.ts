import Chalk from 'chalk';
import { randomBytes } from 'crypto';
import Fastify from 'fastify';
import { Server as WSServer } from 'ws';
import { Configuration } from './config';
import { CryptoClient } from './CryptoClient';
import { PeerManager } from './PeerManager';
import { SocketHandler } from './SocketHandler';
import { BaseContext, PeerContext } from './types/Context';

const CONFIG_FILE = process.env.CONFIG_FILE ?? './config.json';

Configuration.read(CONFIG_FILE);

const client = new CryptoClient(randomBytes(8).toString('hex'), Configuration.peerName);

const httpServer = Fastify();
const wsServer = new WSServer({ server: httpServer.server, perMessageDeflate: true });

const peers = new Map<string, SocketHandler>();

PeerManager.initialize(new BaseContext(client, wsServer, httpServer, peers));

wsServer.on('connection', async (ws, req) => {
	const context = new PeerContext(
		client,
		ws,
		wsServer,
		httpServer,
		peers,
		req.socket.remoteAddress,
		req.socket.remotePort
	);

	const handler = new SocketHandler(context, true);

	console.log(Chalk.green(`[WS] Connection from ${context.ip}:${context.port} was opened`));

	peers.set(context.socketId, handler);
});

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
