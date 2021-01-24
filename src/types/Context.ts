import Crypto from 'crypto';
import { FastifyInstance } from 'fastify';
import WebSocket from 'ws';
import { CryptoClient } from '../CryptoClient';

export class BaseContext {
	constructor(
		public readonly client: CryptoClient,
		public readonly wsServer: WebSocket.Server,
		public readonly httpServer: FastifyInstance
	) {}
}

export class PeerContext {
	public readonly socketId: string;

	constructor(
		public readonly client: CryptoClient,
		public readonly ws: WebSocket,
		public readonly wsServer: WebSocket.Server,
		public readonly httpServer: FastifyInstance,
		public readonly ip = '???.???.???.???',
		public readonly port = -1,
		public readonly id?: string,
		public readonly rsaPublicKey?: string,
		public readonly dhPublicKey?: string
	) {
		this.socketId = Crypto.randomBytes(8).toString('hex');
	}
}
