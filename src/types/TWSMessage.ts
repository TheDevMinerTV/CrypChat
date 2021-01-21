import { EWSCommand } from './EWSCommand';

export interface IPeer {
	url: string;
	id: string;
	rsaPublicKey: string;
	dhPublicKey: string;
}

export interface ISignedWSMessage {
	signature: string;
	message: string;
}

interface IDecryptedWSMessage<TCommand extends EWSCommand, TData extends any = any> {
	command: TCommand;
	data: TData;
}

interface IFailableBaseMessage<TCommand extends EWSCommand, TData extends any = any> {
	command: TCommand;
	data: { success: false; error: string } | ({ success: true } & TData);
}

type THandshakeMessage = IDecryptedWSMessage<
	EWSCommand.HANDSHAKE,
	{ id: string; name: string; rsaPublicKey: string; dhPublicKey: string; port: number }
>;

type THandshakeVerificationMessage = IFailableBaseMessage<
	EWSCommand.HANDSHAKE_VERIFICATION,
	{ verification: string }
>;

type THandshakeAckMessage = IFailableBaseMessage<EWSCommand.HANDSHAKE_ACK>;
type TGetPeersMessage = IDecryptedWSMessage<EWSCommand.GET_PEERS>;
type TGetPeersResponseMessage = IFailableBaseMessage<EWSCommand.GET_PEERS_RESPONSE, { peers: IPeer[] }>;
type TAnnouncePeerMessage = IDecryptedWSMessage<EWSCommand.ANNOUNCE_PEER, IPeer>;
type TSendMessageMessage = IDecryptedWSMessage<EWSCommand.SEND_MESSAGE, { message: string; from: string }>;

export type TDecryptedWSMessage =
	| THandshakeMessage
	| THandshakeVerificationMessage
	| THandshakeAckMessage
	| TGetPeersMessage
	| TGetPeersResponseMessage
	| TAnnouncePeerMessage
	| TSendMessageMessage;
