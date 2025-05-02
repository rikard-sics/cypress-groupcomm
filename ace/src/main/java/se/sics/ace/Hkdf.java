package se.sics.ace;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import net.i2p.crypto.eddsa.Utils;

public class Hkdf {

	private static final int hashLen = 32;
	
	/**
	 * HMAC-based Extract-and-Expand Key Derivation Function.
	 * https://tools.ietf.org/html/rfc5869
	 * 
	 * @param salt optional salt value
	 * @param ikm input keying material
	 * @param info context and application specific information
	 * @param len length of output keying material in octets
	 * @return output keying material
	 * 
	 * @throws InvalidKeyException if the HMAC procedure fails
	 * @throws NoSuchAlgorithmException if an unknown HMAC is used
	 */
	public static byte[] extractExpand(byte[] salt, byte[] ikm, byte[] info, int len)
			throws InvalidKeyException, NoSuchAlgorithmException {

		final String digest = "SHA256"; // Hash to use

		String HMAC_ALG_NAME = "Hmac" + digest;
		Mac hmac = Mac.getInstance(HMAC_ALG_NAME);
		int hashLen = hmac.getMacLength();

		// Perform extract
		hmac.init(new SecretKeySpec(salt, HMAC_ALG_NAME));
		byte[] rgbExtract = hmac.doFinal(ikm);

		// Perform expand
		hmac.init(new SecretKeySpec(rgbExtract, HMAC_ALG_NAME));
		int c = (len / hashLen) + 1;
		byte[] okm = new byte[len];
		int maxLen = (hashLen * c > len) ? hashLen * c : len;
		byte[] T = new byte[maxLen];
		byte[] last = new byte[0];
		for (int i = 0; i < c; i++) {
			hmac.reset();
			hmac.update(last);
			hmac.update(info);
			hmac.update((byte) (i + 1));
			last = hmac.doFinal();
			System.arraycopy(last, 0, T, i * hashLen, hashLen);
		}
		System.arraycopy(T, 0, okm, 0, len);
		return okm;
	}
	
	/**
	 * Returns the length of the hash output, in bytes
	 * @return   the length of the hash output
	 */
	public static int getHashLen() {
		return hashLen;
	}
	
	// https://tools.ietf.org/html/rfc5869#appendix-A.1
	// Could be put in standalone JUnit test
	public static void main(String[] args) throws Exception {
		byte[] ikm = new byte[] { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
				0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };
		byte[] salt = new byte[] { (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
				(byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b, (byte) 0x0c };
		byte[] info = new byte[] { (byte) 0xf0, (byte) 0xf1, (byte) 0xf2, (byte) 0xf3, (byte) 0xf4, (byte) 0xf5,
				(byte) 0xf6, (byte) 0xf7, (byte) 0xf8, (byte) 0xf9 };
		int L = 42;

		byte[] correctOkm = new byte[] { (byte) 0x3c, (byte) 0xb2, (byte) 0x5f, (byte) 0x25, (byte) 0xfa, (byte) 0xac,
				(byte) 0xd5, (byte) 0x7a, (byte) 0x90, (byte) 0x43, (byte) 0x4f, (byte) 0x64, (byte) 0xd0, (byte) 0x36,
				(byte) 0x2f, (byte) 0x2a, (byte) 0x2d, (byte) 0x2d, (byte) 0x0a, (byte) 0x90, (byte) 0xcf, (byte) 0x1a,
				(byte) 0x5a, (byte) 0x4c, (byte) 0x5d, (byte) 0xb0, (byte) 0x2d, (byte) 0x56, (byte) 0xec, (byte) 0xc4,
				(byte) 0xc5, (byte) 0xbf, (byte) 0x34, (byte) 0x00, (byte) 0x72, (byte) 0x08, (byte) 0xd5, (byte) 0xb8,
				(byte) 0x87, (byte) 0x18, (byte) 0x58, (byte) 0x65 };

		byte[] okm = extractExpand(salt, ikm, info, L);

		System.out.println(Utils.bytesToHex(okm));
		System.out.println("Matches expected: " + Arrays.equals(correctOkm, okm));
	}
	

}
