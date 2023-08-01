package de.klassenserver7b.widevine4j;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

public class CryptoUtils {
	public static byte[] getHmacSHA256(byte[] data, byte[] key) {
		HMac hmac = new HMac(new SHA256Digest());
		hmac.init(new KeyParameter(key));

		hmac.update(data, 0, data.length);

		byte[] result = new byte[hmac.getMacSize()];
		hmac.doFinal(result, 0);

		return result;
	}

	public static byte[] getCmacAES(byte[] data, byte[] key) {
		CMac cmac = new CMac(AESEngine.newInstance(), 128);
		cmac.init(new KeyParameter(key));

		cmac.update(data, 0, data.length);

		byte[] result = new byte[cmac.getMacSize()];
		cmac.doFinal(result, 0);

		return result;
	}
}
