import Chalk from 'chalk';
import { FastifyInstance } from 'fastify';
import { IncomingMessage } from 'http';
import WebSocket from 'ws';
import { CryptoClient } from './CryptoClient';
import { SocketHandler } from './SocketHandler';
import { BaseContext, PeerContext } from './types/Context';
import { EWSCommand } from './types/EWSCommand';
import { EWSState } from './types/EWSState';
import { IPeer } from './types/TWSMessage';

const PEERMANAGER = Chalk.bold.hex('#6200D3');
const WS = Chalk.bold.green;
const WARN = Chalk.yellow;
const SUCCESS = Chalk.green;

export class PeerManager {
	private static instance: PeerManager;

	protected readonly client: CryptoClient;
	protected readonly wsServer: WebSocket.Server;
	protected readonly httpServer: FastifyInstance;
	protected readonly peers = new Map<string, SocketHandler>();

	public readonly urlToSocketId = new Map<string, string>();
	public readonly idToSocketId = new Map<string, string>();

	constructor(context: BaseContext) {
		this.wsServer = context.wsServer;
		this.httpServer = context.httpServer;
		this.client = context.client;

		this.logActiveConnections();
		setInterval(() => this.logActiveConnections(), 30 * 1000);
	}

	private log(message: string) {
		console.log(`${PEERMANAGER('[Peers ]')} ${message}`);
	}

	private static log(message: string) {
		console.log(`${PEERMANAGER('[Peers ]')} ${message}`);
	}

	static initialize(context: BaseContext) {
		if (this.instance) {
			throw new Error('ALREADY_INITIALIZED');
		}

		this.log('Initializing...');

		this.instance = new this(context);
	}

	static get() {
		if (!this.instance) {
			throw new Error('NOT_INITIALIZED');
		}

		return this.instance;
	}

	handleConnection(ws: WebSocket, req: IncomingMessage) {
		const context = new PeerContext(
			this.client,
			ws,
			this.wsServer,
			this.httpServer,
			req.socket.remoteAddress,
			req.socket.remotePort
		);

		const handler = new SocketHandler(context, true);

		ws.on('open', () =>
			this.log(SUCCESS(`Connection from ${WS(`${context.ip}:${context.port}`)} was opened`))
		);

		this.peers.set(context.socketId, handler);
	}

	connectToPeer(url: string, type: 'seed'): void;
	connectToPeer(
		url: string,
		type: 'announced',
		announcer: string,
		rsaPublicKey: string,
		dhPublicKey: string,
		id: string
	): void;

	connectToPeer(
		url: string,
		type: 'seed' | 'announced',
		announcer?: string,
		rsaPublicKey?: string,
		dhPublicKey?: string,
		id?: string
	) {
		if (this.urlToSocketId.has(url)) {
			return this.log(WARN(`Already connected to ${WS(url)}, ignoring...`));
		}

		if (type === 'announced' && id) {
			console.log('Got announced peer', id);

			const socketId = this.idToSocketId.get(id);

			if (socketId) {
				return this.log(WARN(`Already connected to ${WS(url)} (${id}) via socket ${socketId}, ignoring...`));
			}
		}

		this.log(`Connecting to ${type} ${WS(url)}...`);

		const ws = new WebSocket(url);

		const remote = (url.split('//').pop() as string).split(':') as string[];

		const context = new PeerContext(
			this.client,
			ws,
			this.wsServer,
			this.httpServer,
			remote.shift() as string,
			parseInt(remote.shift() as string),
			id,
			rsaPublicKey,
			dhPublicKey
		);

		const handler = new SocketHandler(context, false, announcer);

		ws.on('open', () =>
			this.log(
				SUCCESS(
					`Connection to ${WS(`${context.ip}:${context.port}`)} ${
						announcer ? `(announced by ${announcer}) ` : ''
					}was opened`
				)
			)
		);

		this.peers.set(context.socketId, handler);
		this.urlToSocketId.set(url, context.socketId);

		if (id) {
			this.idToSocketId.set(id, context.socketId);
		}
	}

	disconnectPeer(socketId: string, code = 1000) {
		const peer = this.peers.get(socketId);

		if (!peer) {
			this.log(WARN(`${socketId} was not connected`));

			return;
		}

		this.log(`Disconnecting peer ${WARN(`${peer.ip}:${peer.port}`)}`);

		peer.close(code);

		this.removePeer(socketId);
	}

	removePeer(socketId: string) {
		const peer = this.peers.get(socketId);

		if (!peer) {
			return;
		}

		this.log(`Removing peer ${WARN(`${peer.ip}:${peer.port}`)}`);

		this.peers.delete(peer.socketId);
		this.urlToSocketId.delete(`ws://${peer.ip}:${peer.port}`);
	}

	getConnectedPeers(): string[] {
		const peers: string[] = [];

		for (const peer of this.peers.values()) {
			if (peer._state === EWSState.READY && peer.id && peer.dhPublicKey) {
				peers.push(`ws://${peer.ip}:${peer.port}`);
			}
		}

		return peers;
	}

	getReadyPeers(): IPeer[] {
		const peers: IPeer[] = [];

		for (const peer of this.peers.values()) {
			if (peer._state === EWSState.READY && peer.id && peer.dhPublicKey && peer.rsaPublicKey) {
				peers.push({
					url: `ws://${peer.ip}:${peer.port}`,
					id: peer.id,
					dhPublicKey: peer.dhPublicKey,
					rsaPublicKey: peer.rsaPublicKey
				});
			}
		}

		return peers;
	}

	announcePeer(socketId: string) {
		const peer = this.peers.get(socketId);

		if (!peer) {
			throw new Error('PEER_NOT_CONNECTED');
		}

		this.log(`Announcing ${WS(`${peer.ip}:${peer.port}`)} to all ready peers...`);

		for (const peer of this.peers.values()) {
			if (
				peer.socketId !== socketId &&
				peer._state === EWSState.READY &&
				peer.dhPublicKey &&
				peer.rsaPublicKey &&
				peer.id
			) {
				peer.send({
					command: EWSCommand.ANNOUNCE_PEER,
					data: {
						url: `ws://${peer.ip}:${peer.port}`,
						dhPublicKey: peer.dhPublicKey,
						rsaPublicKey: peer.rsaPublicKey,
						id: peer.id
					}
				});
			}
		}
	}

	broadcastMessage(message: string, from = this.client.id) {
		this.log(`Broadcasting message "${WS(message)}" to all ready peers...`);

		for (const peer of this.peers.values()) {
			if (peer.id !== from && peer._state === EWSState.READY && peer.dhPublicKey && peer.rsaPublicKey) {
				peer.send({
					command: EWSCommand.SEND_MESSAGE,
					data: { message, from }
				});
			}
		}
	}

	logActiveConnections() {
		this.log(`${this.peers.size} peers known`);

		for (const peer of this.peers.values()) {
			this.log(
				`- [${peer.isIncoming ? '>' : '<'}] [${peer.socketId}] | ${peer.id ? `[${peer.id}] ` : ''}${
					peer.ip
				}:${peer.port} | ${EWSState[peer._state]} (referred to as ${peer.peerName}${
					peer.announcedBy ? `, announced by ${peer.announcedBy}` : ''
				})`
			);
		}
	}
}
