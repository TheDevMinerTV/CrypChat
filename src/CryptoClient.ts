import Chalk from 'chalk';
import Crypto from 'crypto';
import FS from 'fs';
import Stream from 'stream';
import Zlib from 'zlib';
import { Configuration } from './config';

const PUBKEY = Chalk.bold.gray;
const PERSON = Chalk.bold.yellow;
const ENCRYPTED = Chalk.bold.red;
const DECRYPTED = Chalk.bold.blue;
const CRYPTO = Chalk.bold.hex('#FFA500');

export class CryptoClient {
	secrets = new Map<string, Buffer>();
	publics = new Map<Buffer, string>();

	dh: Crypto.DiffieHellman;
	rsa: Crypto.KeyPairKeyObjectResult;

	/**
	 * @param {string} id
	 */
	constructor(public id: string, public readonly name: string) {
		this.log('Generating RSA key...');

		this.rsa = Crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

		this.log(
			`Generated 2048 RSA key:\n${PUBKEY(
				this.rsa.publicKey.export({ format: 'pem', type: 'pkcs1' }).toString().trim()
			)}`
		);

		this.log('Generating Diffie-Hellman key...');

		this.dh = Crypto.getDiffieHellman('modp15');
		this.dh.generateKeys();

		this.log(
			`Generated ${this.dh.getPrivateKey().length} bit Diffie-Hellman key: ${PUBKEY(
				this.dh.getPublicKey().toString('hex')
			)}`
		);
	}

	private log(message: string) {
		if (Configuration.verbose) {
			console.log(`${CRYPTO('[Crypto]')} ${PERSON(`[${this.id}]`)} ${message}`);
		}
	}

	sign(data: Buffer) {
		const signature = Crypto.sign('sha256', data, {
			key: this.rsa.privateKey,
			padding: Crypto.constants.RSA_PKCS1_PADDING
		}).toString('hex');

		this.log(`Signed "${DECRYPTED(data.toString('hex'))}": ${ENCRYPTED(signature)}`);

		return signature;
	}

	verify(data: Buffer, publicKey: Buffer, signature: Buffer) {
		const isValid = Crypto.verify('sha256', data, publicKey, signature);

		if (isValid) {
			this.log(`Verified "${DECRYPTED(data.toString('hex'))}": ${ENCRYPTED(signature.toString('hex'))}`);

			return true;
		} else {
			this.log(
				`Failed to verify "${DECRYPTED(data.toString('hex'))}": ${ENCRYPTED(signature.toString('hex'))}`
			);

			return false;
		}
	}

	handshake(person: string, publicKey: Buffer) {
		this.log(
			`Starting handshake with ${PERSON(person)} ${PUBKEY(this.dh.getPublicKey().toString('hex'))}...`
		);

		this.secrets.set(person, this.dh.computeSecret(publicKey));
		this.publics.set(publicKey, person);

		this.log(`Handshake completed with ${PERSON(person)}`);
	}

	generateIV() {
		return Crypto.randomBytes(16);
	}

	encrypt(person: string, data: string) {
		const secret = this.secrets.get(person);

		if (!secret) {
			throw new Error('A handshake with this person has not been completed yet');
		}

		const key = Crypto.createHash('sha256').update(secret).digest();
		const iv = this.generateIV();

		const cipher = Crypto.createCipheriv('aes-256-gcm', key, iv);

		const encrypted = cipher.update(data, 'utf-8', 'hex') + cipher.final('hex');

		this.log(`Encrypted "${DECRYPTED(data)}" for ${PERSON(person)}: ${ENCRYPTED(encrypted)}`);

		return { encrypted, iv: iv.toString('hex'), tag: cipher.getAuthTag().toString('hex') };
	}

	encryptStream(person: string, stream: Stream.Readable, compress = false) {
		const secret = this.secrets.get(person);

		if (!secret) {
			throw new Error('A handshake with this person has not been completed yet');
		}

		const key = Crypto.createHash('sha256').update(secret).digest();
		const iv = this.generateIV();

		const cipher = Crypto.createCipheriv('aes-256-gcm', key, iv);

		stream.once('end', () => this.log(`Encrypted stream for ${PERSON(person)}`));

		if (compress) {
			stream.pipe(Zlib.createGzip()).pipe(cipher);
		} else {
			stream.pipe(cipher);
		}

		return { stream: cipher, iv: iv.toString('hex'), tag: cipher.getAuthTag().toString('hex') };
	}

	encryptFile(person: string, path: string, compress = false) {
		const stream = FS.createReadStream(path);

		const { stream: cipher, iv } = this.encryptStream(person, stream, compress);

		cipher.once('end', () => this.log(`Encrypted file at ${ENCRYPTED(path)} for ${PERSON(person)}`));

		return { stream: cipher, iv, tag: cipher.getAuthTag().toString('hex') };
	}

	decrypt(person: string, data: string, iv: string, tag: string) {
		const secret = this.secrets.get(person);

		if (!secret) {
			throw new Error('A handshake with this person has not been completed yet');
		}

		const key = Crypto.createHash('sha256').update(secret).digest();

		const decipher = Crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'));

		decipher.setAuthTag(Buffer.from(tag, 'hex'));

		const dec = decipher.update(data, 'hex', 'utf-8') + decipher.final('utf-8');

		this.log(`Decrypted "${ENCRYPTED(data)}" from ${PERSON(person)}: ${DECRYPTED(dec)}`);

		return dec;
	}

	decryptStream(person: string, stream: Stream.Readable, iv: string, tag: string, compressed = false) {
		const secret = this.secrets.get(person);

		if (!secret) {
			throw new Error('A handshake with this person has not been completed yet');
		}

		const key = Crypto.createHash('sha256').update(secret).digest();

		const decipher = Crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'));

		decipher.setAuthTag(Buffer.from(tag, 'hex'));

		decipher.once('end', () => this.log(`Decrypted stream from ${PERSON(person)}`));

		let str: Stream.Readable = stream.pipe(decipher);

		if (compressed) {
			str = decipher.pipe(Zlib.createGunzip());
		}

		return str;
	}

	decryptFile(
		person: string,
		stream: Stream.Readable,
		path: string,
		iv: string,
		tag: string,
		compressed = false
	) {
		const decipherStream = this.decryptStream(person, stream, iv, compressed, tag);

		const writeStream = FS.createWriteStream(path);

		decipherStream.pipe(writeStream);

		return;
	}

	toString() {
		let str = `${PERSON(this.id)}: ${PUBKEY(this.dh.getPublicKey().toString('hex'))}\nKnown public keys:\n`;

		for (const [publicKey, person] of this.publics) {
			str += `${PERSON(person)}: ${PUBKEY(publicKey.toString('hex'))}\n`;
		}

		return str;
	}
}
