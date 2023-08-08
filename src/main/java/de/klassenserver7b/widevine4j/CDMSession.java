package de.klassenserver7b.widevine4j;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import de.klassenserver7b.widevine4j.protobuf.DrmCertificate;
import de.klassenserver7b.widevine4j.protobuf.EncryptedClientIdentification;
import de.klassenserver7b.widevine4j.protobuf.License;
import de.klassenserver7b.widevine4j.protobuf.LicenseRequest;
import de.klassenserver7b.widevine4j.protobuf.LicenseType;
import de.klassenserver7b.widevine4j.protobuf.ProtocolVersion;
import de.klassenserver7b.widevine4j.protobuf.SignedDrmCertificate;
import de.klassenserver7b.widevine4j.protobuf.SignedMessage;

public class CDMSession {
	public static final byte[] CERTIFICATE_REQUEST = { 0x08, 0x04 };

	private final byte[] sessionId;
	private final CDMDevice device;
	private byte[] licenseRequest;

	private final byte[] initData;
	private DrmCertificate certificate;

	private byte[] derivedAuthKey;
	private byte[] derivedEncKey;

	public CDMSession(CDMDevice device, byte[] pssh) {
		this.device = device;

		byte[] psshData = PSSH.getData(pssh);

		if (psshData != null)
			initData = psshData;
		else
			initData = pssh;

		if (!device.isAndroid()) {
			sessionId = new byte[16];
			new Random().nextBytes(sessionId);
		} else {
			Random rng = new Random();
			sessionId = String.format("%08X%08X0100000000000000", rng.nextInt(), rng.nextInt())
					.getBytes(StandardCharsets.US_ASCII);
		}
	}

	public void updateCertificate(byte[] cert) throws IllegalStateException {
		try {
			SignedMessage msg = SignedMessage.parseFrom(cert);
			SignedDrmCertificate signedDeviceCertificate = SignedDrmCertificate.parseFrom(msg.getMsg());
			certificate = DrmCertificate.parseFrom(signedDeviceCertificate.getDrmCertificate());
		} catch (InvalidProtocolBufferException ignored) {
			try {
				certificate = DrmCertificate.parseFrom(cert);
			} catch (InvalidProtocolBufferException e) {
				throw new IllegalStateException("Can't parse certificate", new Throwable().fillInStackTrace());
			}
		}
	}

	public byte[] getLicenseRequest(boolean privacyMode) throws IllegalStateException {
		LicenseRequest.Builder requestBuilder = LicenseRequest.newBuilder().setType(LicenseRequest.RequestType.NEW)
				.setKeyControlNonce(new Random().nextInt()).setProtocolVersion(ProtocolVersion.VERSION_2_1)
				.setRequestTime(OffsetDateTime.now().toEpochSecond())
				.setContentId(LicenseRequest.ContentIdentification.newBuilder()
						.setWidevinePsshData(LicenseRequest.ContentIdentification.WidevinePsshData.newBuilder()
								.addPsshData(ByteString.copyFrom(initData)).setLicenseType(LicenseType.AUTOMATIC)
								.setRequestId(ByteString.copyFrom(sessionId))));

		if (!privacyMode)
			requestBuilder.setClientId(device.getClientId());
		else {
			try {
				EncryptedClientIdentification.Builder encryptedClientId = EncryptedClientIdentification.newBuilder();

				byte[] paddedClientId = /* Padding.addPKCS7Padding( */device.getClientId().toByteArray()/* , 16) */;

				KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", new BouncyCastleProvider());
				keyGenerator.init(128);
				SecretKey secretKey = keyGenerator.generateKey();

				SecureRandom secureRandom = new SecureRandom();
				byte[] iv = new byte[16];
				secureRandom.nextBytes(iv);
				IvParameterSpec ivSpec = new IvParameterSpec(iv);

				Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", new BouncyCastleProvider());
				cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

				encryptedClientId.setEncryptedClientId(ByteString.copyFrom(cipher.doFinal(paddedClientId)));

				try (ASN1InputStream asn1InputStream = new ASN1InputStream(certificate.getPublicKey().newInput())) {
					RSAPublicKey rsaPublicKey = RSAPublicKey.getInstance(asn1InputStream.readObject());
					KeyFactory keyFactory = KeyFactory.getInstance("RSA", new BouncyCastleProvider());
					RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(rsaPublicKey.getModulus(),
							rsaPublicKey.getPublicExponent());
					PublicKey key = keyFactory.generatePublic(publicKeySpec);

					Cipher rsaCipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding",
							new BouncyCastleProvider());
					rsaCipher.init(Cipher.ENCRYPT_MODE, key);

					encryptedClientId
							.setEncryptedPrivacyKey(ByteString.copyFrom(rsaCipher.doFinal(secretKey.getEncoded())));
					encryptedClientId.setEncryptedClientIdIv(ByteString.copyFrom(iv));
					encryptedClientId.setProviderIdBytes(certificate.getProviderIdBytes());
					encryptedClientId.setServiceCertificateSerialNumber(certificate.getSerialNumber());
				} catch (IOException | InvalidKeySpecException e) {
					e.printStackTrace();
					return null;
				}

				requestBuilder.setEncryptedClientId(encryptedClientId);
			} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchPaddingException
					| IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
				e.printStackTrace();
				return null;
			}
		}

		licenseRequest = requestBuilder.build().toByteArray();

		SignedMessage signed;
		try {
			signed = SignedMessage.newBuilder().setMsg(ByteString.copyFrom(licenseRequest))
					.setSignature(ByteString.copyFrom(device.sign(licenseRequest))).build();
			return signed.toByteArray();
		} catch (CryptoException e) {
			throw new IllegalStateException(e);
		}
	}

	public List<ContentKey> decodeLicense(byte[] license) throws IllegalStateException {
		if (licenseRequest == null)
			throw new IllegalArgumentException("license cannot be null");

		SignedMessage signedMessage;
		try {
			signedMessage = SignedMessage.parseFrom(license);
		} catch (InvalidProtocolBufferException e) {
			throw new IllegalStateException(e);
		}

		byte[] sessionKey;
		try {
			sessionKey = device.decrypt(signedMessage.getSessionKey().toByteArray());
		} catch (InvalidCipherTextException e) {
			throw new IllegalStateException(e);
		}
		if (sessionKey.length != 16)
			throw new IllegalStateException("session key couldn't be decrypted");

		deriveKeys(licenseRequest, sessionKey);

		byte[] licenseMsgBytes = signedMessage.getMsg().toByteArray();
		License licenseMsg;
		try {
			licenseMsg = License.parseFrom(licenseMsgBytes);
		} catch (InvalidProtocolBufferException e) {
			throw new IllegalStateException(e);
		}

		byte[] licenseMsgHmac = CryptoUtils.getHmacSHA256(licenseMsgBytes, derivedAuthKey);
		if (!Arrays.equals(licenseMsgHmac, signedMessage.getSignature().toByteArray()))
			throw new IllegalStateException("license signature mismatch");

		ArrayList<ContentKey> decryptedKeys = new ArrayList<>();

		for (License.KeyContainer keyContainer : licenseMsg.getKeyList()) {
			if (keyContainer.getType() == License.KeyContainer.KeyType.CONTENT) {
				try {
					SecretKeySpec secretKeySpec = new SecretKeySpec(derivedEncKey, "AES");
					IvParameterSpec ivSpec = new IvParameterSpec(keyContainer.getIv().toByteArray());

					Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", new BouncyCastleProvider());
					cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);

					byte[] kid = keyContainer.getId().toByteArray();
					byte[] decryptedKey = cipher.doFinal(keyContainer.getKey().toByteArray());

					decryptedKeys.add(new ContentKey(kid, decryptedKey));

				} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException
						| InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
					e.printStackTrace();
				}
			}
		}

		return decryptedKeys;
	}

	private void deriveKeys(byte[] licenseRequest, byte[] sessionKey) {
		byte[] encKey = new byte[16 + licenseRequest.length];
		System.arraycopy("\u0001ENCRYPTION\u0000".getBytes(StandardCharsets.UTF_8), 0, encKey, 0, 11);
		System.arraycopy(licenseRequest, 0, encKey, 12, licenseRequest.length);
		System.arraycopy(new byte[] { 0, 0, 0, (byte) 0x80 }, 0, encKey, 12 + licenseRequest.length, 4);

		byte[] authKey = new byte[20 + licenseRequest.length];
		System.arraycopy("\u0001AUTHENTICATION\u0000".getBytes(StandardCharsets.UTF_8), 0, authKey, 0, 15);
		System.arraycopy(licenseRequest, 0, authKey, 16, licenseRequest.length);
		System.arraycopy(new byte[] { 0, 0, 2, 0 }, 0, authKey, 16 + licenseRequest.length, 4);

		derivedEncKey = CryptoUtils.getCmacAES(encKey, sessionKey);

		byte[] authCmacKey1 = CryptoUtils.getCmacAES(authKey, sessionKey);
		authKey[0] = 2;
		byte[] authCmacKey2 = CryptoUtils.getCmacAES(authKey, sessionKey);

		derivedAuthKey = new byte[authCmacKey1.length + authCmacKey2.length];
		System.arraycopy(authCmacKey1, 0, derivedAuthKey, 0, authCmacKey1.length);
		System.arraycopy(authCmacKey2, 0, derivedAuthKey, authCmacKey1.length, authCmacKey2.length);
	}
}
