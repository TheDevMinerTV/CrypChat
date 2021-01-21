import Chalk from 'chalk';
import { EventEmitter } from 'events';
import { FastifyInstance } from 'fastify';
import StrictEventEmitter from 'strict-event-emitter-types';
import WebSocket from 'ws';
import { Configuration } from './config';
import { CryptoClient } from './CryptoClient';
import { PeerManager } from './PeerManager';
import { PeerContext } from './types/Context';
import { EWSCommand } from './types/EWSCommand';
import { EWSState } from './types/EWSState';
import { ISignedWSMessage, TDecryptedWSMessage } from './types/TWSMessage';

const PUBKEY = Chalk.bold.gray;
const PERSON = Chalk.bold.yellow;
const WS = Chalk.bold.hex('#FF00AA');
const ERROR = Chalk.red;

interface ISocketHandlerEvents {
	handshakeStarted(): void;
	ready(): void;
}

type TSocketHandlerEmitter = StrictEventEmitter<EventEmitter, ISocketHandlerEvents>;

export class SocketHandler extends (EventEmitter as { new (): TSocketHandlerEmitter }) {
	protected readonly client: CryptoClient;
	protected readonly ws: WebSocket;
	protected readonly wsServer: WebSocket.Server;
	protected readonly httpServer: FastifyInstance;
	protected readonly peers: Map<string, SocketHandler>;

	readonly socketId: string;
	readonly ip: string;

	peerName?: string;
	dhPublicKey?: string;
	rsaPublicKey?: string;
	id?: string;

	port: number;
	_state = EWSState.CREATED;

	public readonly announcedId?: string;
	public readonly announcedRSAPublicKey?: string;
	public readonly announcedDHPublicKey?: string;

	constructor(
		context: PeerContext,
		public readonly isIncoming = false,
		public readonly announcedBy?: string
	) {
		super();

		this.client = context.client;
		this.ws = context.ws;
		this.socketId = context.socketId;
		this.wsServer = context.wsServer;
		this.httpServer = context.httpServer;
		this.peers = context.peers;
		this.ip = context.ip;
		this.port = context.port;

		this.announcedId = context.id;
		this.announcedRSAPublicKey = context.rsaPublicKey;
		this.announcedDHPublicKey = context.dhPublicKey;

		this.ws.on('message', (m) => this.onMessage(m));
		this.ws.on('error', (e) => this.log(ERROR(e)));
		this.ws.on('close', (c) => {
			this.log(
				ERROR(`Connection ${isIncoming ? 'from' : 'to'} ${this.ip}:${this.port} closed${c ? `: ${c}` : ''}`)
			);

			PeerManager.get().removePeer(this.socketId);
		});

		this.ws.on('open', () => {
			if (!isIncoming) {
				if (Configuration.verbose) {
					this.log('Starting handshake...');
				}

				this.send({
					command: EWSCommand.HANDSHAKE,
					data: {
						name: Configuration.peerName,
						id: this.client.id,
						rsaPublicKey: this.client.rsa.publicKey.export({ format: 'pem', type: 'pkcs1' }).toString('hex'),
						dhPublicKey: this.client.dh.getPublicKey().toString('hex'),
						port: Configuration.port
					}
				});
			}
		});

		this.on('ready', () => {
			// Ask for peers after handshake
			if (Configuration.verbose) {
				this.log('Asking for peers...');
			}

			this.send({ command: EWSCommand.GET_PEERS, data: {} });

			// Announce this peer to other peers
			if (Configuration.verbose) {
				this.log('Announcing peer...');
			}

			PeerManager.get().announcePeer(this.socketId);
		});

		this.on('handshakeStarted', () => {
			if (Configuration.verbose) {
				this.log('Starting handshake...');
			}

			if (this.isIncoming) {
				this.send({
					command: EWSCommand.HANDSHAKE,
					data: {
						id: this.client.id,
						name: Configuration.peerName,
						rsaPublicKey: this.client.rsa.publicKey.export({ format: 'pem', type: 'pkcs1' }).toString('hex'),
						dhPublicKey: this.client.dh.getPublicKey().toString('hex'),
						port: Configuration.port
					}
				});
			}
		});
	}

	private log(message: string) {
		console.log(
			`${WS('[WS    ]')} ${PERSON(`[${this.id ?? 'Unknown'}]`)} ${PUBKEY(
				`[${EWSState[this.state].padEnd(19, ' ')}]`
			)} ${message}`
		);
	}

	protected async onMessage(m: WebSocket.Data): Promise<void> {
		let j: TDecryptedWSMessage;

		try {
			const signedData = Buffer.from(m.toString(), 'hex').toString();

			const s: ISignedWSMessage = JSON.parse(signedData);

			let data =
				this._state === EWSState.READY
					? this.client.decrypt(this.socketId, s.message)
					: Buffer.from(s.message, 'hex').toString();

			j = JSON.parse(data);

			let publicKey = this.rsaPublicKey;

			if (this.state === EWSState.CREATED && j.command === EWSCommand.HANDSHAKE) {
				publicKey = j.data.rsaPublicKey;
			}

			if (!publicKey) {
				throw new Error('NO_PUBLIC_KEY');
			} else if (
				!this.client.verify(
					Buffer.from(s.message, 'hex'),
					Buffer.from(publicKey),
					Buffer.from(s.signature, 'hex')
				)
			) {
				throw new Error('SIGNATURE_INVALID');
			} else if (typeof j.data !== 'object') {
				throw new Error('DATA_INVALID');
			} else if (Array.isArray(j.data)) {
				throw new Error('DATA_IS_ARRAY');
			} else if (typeof j.command !== 'number') {
				throw new Error('OPERATOR_INVALID');
			}
		} catch (error) {
			return this.log(Chalk.red(error));
		}

		// this.log(`[>] ${EWSOperator[j.op]}: ${JSON.stringify(j.d)}`);

		if (!(j.data.success === true || j.data.success === undefined)) {
			this.log(ERROR(j.data.error));

			return;
		}

		if ([this.ws.CLOSING, this.ws.CLOSED].includes(this.ws.readyState)) {
			return;
		}

		switch (j.command) {
			case EWSCommand.HANDSHAKE:
				if (this.state !== EWSState.CREATED) {
					this.log(ERROR(`Handshake called but state is ${EWSState[this.state]}`));

					return PeerManager.get().disconnectPeer(this.socketId, 1003);
				}

				if (['127.0.0.1', 'localhost'].includes(this.ip) && j.data.port === Configuration.port) {
					this.log(ERROR(`Client tried to fake port to my configured port`));

					return PeerManager.get().disconnectPeer(this.socketId, 1003);
				}

				if (this.announcedId && this.announcedId !== j.data.id) {
					this.log(ERROR(`Client ID mismatched the announced one`));
					console.log(this.announcedId);
					console.log(this.id);

					return PeerManager.get().disconnectPeer(this.socketId, 1003);
				} else if (this.announcedRSAPublicKey && this.announcedRSAPublicKey !== j.data.rsaPublicKey) {
					this.log(ERROR(`Client RSA public key mismatched the announced one`));
					console.log(this.announcedRSAPublicKey);
					console.log(j.data.rsaPublicKey);

					return PeerManager.get().disconnectPeer(this.socketId, 1003);
				} else if (this.announcedDHPublicKey && this.announcedDHPublicKey !== j.data.dhPublicKey) {
					this.log(ERROR(`Client DH public key mismatched the announced one`));
					console.log(this.announcedDHPublicKey);
					console.log(j.data.dhPublicKey);

					return PeerManager.get().disconnectPeer(this.socketId, 1003);
				}

				const pm = PeerManager.get();

				if (this.isIncoming && pm.idToSocketId.has(j.data.id)) {
					this.log(ERROR(`Already connected`));

					return PeerManager.get().disconnectPeer(this.socketId, 1000);
				}

				try {
					this.client.handshake(this.socketId, Buffer.from(j.data.dhPublicKey, 'hex'));

					this.id = j.data.id;
					this.peerName = j.data.name;
					this.rsaPublicKey = j.data.rsaPublicKey;
					this.dhPublicKey = j.data.dhPublicKey;
					this.port = j.data.port;

					this.state = EWSState.HANDSHAKE_STARTED;

					this.emit('handshakeStarted');

					this.send({
						command: EWSCommand.HANDSHAKE_VERIFICATION,
						data: {
							success: true,
							verification: this.client.encrypt(this.socketId, 'cryptoverification')
						}
					});
				} catch (error) {
					this.send({
						command: EWSCommand.HANDSHAKE_VERIFICATION,
						data: { success: false, error: error.message }
					});
				}

				break;

			case EWSCommand.HANDSHAKE_VERIFICATION:
				if (!(this.state === EWSState.HANDSHAKE_STARTED)) {
					this.log(ERROR(`Handshake verification called but state is ${EWSState[this.state]}`));

					return PeerManager.get().disconnectPeer(this.socketId, 1003);
				}

				try {
					const verificationDecrypted = this.client.decrypt(this.socketId, j.data.verification);

					if (verificationDecrypted !== 'cryptoverification') {
						throw new Error('VERIFICATION_INVALID');
					}

					this.state = EWSState.HANDSHAKE_VALIDATED;

					this.send({ command: EWSCommand.HANDSHAKE_ACK, data: { success: true } });
				} catch (error) {
					this.send({
						command: EWSCommand.HANDSHAKE_VERIFICATION,
						data: { success: false, error: error.message }
					});
				}

				break;

			case EWSCommand.HANDSHAKE_ACK:
				if (!(this.state === EWSState.HANDSHAKE_VALIDATED)) {
					this.log(ERROR(`Handshake Ack called but state is ${EWSState[this.state]}`));

					return PeerManager.get().disconnectPeer(this.socketId, 1003);
				}

				this.state = EWSState.READY;

				this.emit('ready');

				break;

			case EWSCommand.GET_PEERS:
				if (!(this.state === EWSState.READY)) {
					this.log(ERROR(`GetPeers called but state is ${EWSState[this.state]}`));

					return PeerManager.get().disconnectPeer(this.socketId, 1003);
				}

				this.send({
					command: EWSCommand.GET_PEERS_RESPONSE,
					data: { success: true, peers: PeerManager.get().getReadyPeers() }
				});

				break;

			case EWSCommand.GET_PEERS_RESPONSE: {
				if (!(this.state === EWSState.READY && this.id)) {
					this.log(ERROR(`GetPeersResponse called but state is ${EWSState[this.state]}`));

					return PeerManager.get().disconnectPeer(this.socketId, 1003);
				}

				const peers = j.data.peers.filter(
					(p) =>
						![`ws://127.0.0.1:${Configuration.port}`, `ws://0.0.0.0:${Configuration.port}`]
							.concat(PeerManager.get().getConnectedPeers())
							.includes(p.url)
				);

				this.log(`Got ${peers.length} peers: ${peers.map((p) => p.url).join(' ')}`);

				PeerManager.get().broadcastMessage('Connecting to all peers...');

				for (const peer of peers) {
					PeerManager.get().connectToPeer(
						peer.url,
						'announced',
						this.id,
						peer.rsaPublicKey,
						peer.dhPublicKey,
						peer.id
					);
				}

				break;
			}

			case EWSCommand.ANNOUNCE_PEER: {
				if (!(this.state === EWSState.READY && this.id)) {
					this.log(ERROR(`AnnouncePeer called but state is ${EWSState[this.state]}`));

					return PeerManager.get().disconnectPeer(this.socketId, 1003);
				}

				const peer = j.data;

				if (
					[`ws://127.0.0.1:${Configuration.port}`, `ws://0.0.0.0:${Configuration.port}`]
						.concat(PeerManager.get().getConnectedPeers())
						.includes(peer.url)
				) {
					return;
				}

				PeerManager.get().connectToPeer(
					peer.url,
					'announced',
					this.id,
					peer.rsaPublicKey,
					peer.dhPublicKey,
					peer.id
				);

				break;
			}

			case EWSCommand.SEND_MESSAGE: {
				if (!(this.state === EWSState.READY && this.id)) {
					this.log(ERROR(`SendMessage called but state is ${EWSState[this.state]}`));

					return PeerManager.get().disconnectPeer(this.socketId, 1003);
				}

				this.log(`Incoming message from ${this.id}: ${j.data.message}`);

				break;
			}
		}
	}

	send(j: TDecryptedWSMessage) {
		const m = JSON.stringify(j);

		if (Configuration.verbose) {
			this.log(`[<] ${EWSCommand[j.command]}: ${JSON.stringify(j.data)}`);
		}

		const msg =
			this.state === EWSState.READY ? this.client.encrypt(this.socketId, m) : Buffer.from(m).toString('hex');

		this.ws.send(
			Buffer.from(
				JSON.stringify({
					message: msg,
					signature: this.client.sign(Buffer.from(msg, 'hex'))
				} as ISignedWSMessage)
			).toString('hex')
		);
	}

	close(code = 1000) {
		this.log(`[!] Connection closed`);

		this.ws.close(code);
	}

	get state() {
		return this._state;
	}

	set state(state: EWSState) {
		this.log(`Changing state from ${EWSState[this._state]} to ${EWSState[state]}`);

		this._state = state;
	}
}
