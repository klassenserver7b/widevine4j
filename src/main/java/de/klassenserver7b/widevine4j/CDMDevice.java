package de.klassenserver7b.widevine4j;

import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;

import com.google.protobuf.ByteString;

import de.klassenserver7b.widevine4j.protobuf.ClientIdentification;

public class CDMDevice {
	private final boolean android;
	private ClientIdentification clientId;
	private final AsymmetricKeyParameter devicePrivateKey;

	public CDMDevice(boolean android, byte[] clientIdBlob, byte[] privateKey, byte[] vmpBlob) throws IOException {
		this.android = android;
		clientId = ClientIdentification.parseFrom(clientIdBlob);

		try (StringReader reader = new StringReader(new String(privateKey, StandardCharsets.UTF_8))) {
			PEMParser pemParser = new PEMParser(reader);

			PrivateKeyInfo privateKeyInfo = ((PEMKeyPair) pemParser.readObject()).getPrivateKeyInfo();
			devicePrivateKey = PrivateKeyFactory.createKey(privateKeyInfo);
		}

		if (vmpBlob != null)
			clientId = ClientIdentification.newBuilder(clientId).setVmpData(ByteString.copyFrom(vmpBlob)).build();
	}

	public ClientIdentification getClientId() {
		return clientId;
	}

	public byte[] decrypt(byte[] encrypted) throws InvalidCipherTextException {
		OAEPEncoding oaepEncoding = new OAEPEncoding(new RSAEngine());
		oaepEncoding.init(false, devicePrivateKey);

		int inputBlock = oaepEncoding.getInputBlockSize();
		int outputBlock = oaepEncoding.getOutputBlockSize();

		int blocksCount = (encrypted.length + inputBlock - 1) / inputBlock;
		byte[] result = new byte[blocksCount * outputBlock];

		int outputSize = 0;

		for (int i = 0; i < blocksCount; i++) {
			int inputBlockLength = Math.min(inputBlock, encrypted.length - i * inputBlock);
			byte[] decryptedBlock = oaepEncoding.processBlock(encrypted, i * inputBlock, inputBlockLength);
			outputSize += decryptedBlock.length;

			System.arraycopy(decryptedBlock, 0, result, i * outputBlock, Math.min(outputBlock, decryptedBlock.length));
		}

		return Arrays.copyOfRange(result, 0, outputSize);
	}

	public byte[] sign(byte[] data) throws CryptoException {
		SHA1Digest digest = new SHA1Digest();
		PSSSigner signer = new PSSSigner(new RSAEngine(), digest, digest.getDigestSize());

		signer.init(true, devicePrivateKey);
		signer.update(data, 0, data.length);

		return signer.generateSignature();
	}

	public boolean isAndroid() {
		return android;
	}
}
