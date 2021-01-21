import FS from 'fs';

export interface IConfiguration {
	peerName: string;
	host: string;
	port: number;
	seedPeers: string[];
	verbose: boolean;
}

export class Configuration {
	static peerName: string;
	static host = '127.0.0.1';
	static port = 8009;
	static seedPeers: string[] = [];
	static verbose = false;

	static read(path: string): void {
		const config = JSON.parse(FS.readFileSync(path, 'utf-8')) as IConfiguration;

		this.peerName = config.peerName;
		this.host = config.host;
		this.port = config.port;
		this.seedPeers = config.seedPeers;
		this.verbose = config.verbose;
	}
}
