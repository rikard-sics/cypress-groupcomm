/*******************************************************************************
 * Copyright (c) 2020 RISE and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Rikard Höglund (RISE)
 *    Marco Tiloca (RISE)
 ******************************************************************************/
package org.eclipse.californium.edhoc;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.EllipticCurve;
import java.util.Arrays;

import javax.crypto.KeyAgreement;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.StringUtil;

import com.upokecenter.cbor.CBORObject;

import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.math.Field;
import net.i2p.crypto.eddsa.math.FieldElement;
import net.i2p.crypto.eddsa.math.bigint.BigIntegerFieldElement;
import net.i2p.crypto.eddsa.math.bigint.BigIntegerLittleEndianEncoding;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

/**
 * Class implementing the X25519 function, supporting functionality, tests and
 * shared secret calculation.
 *
 */
public class SharedSecretCalculation {

	/*
	 * Useful links:
	 * https://crypto.stackexchange.com/questions/63732/curve-25519-x25519-
	 * ed25519-convert-coordinates-between-montgomery-curve-and-t/63734
	 * https://tools.ietf.org/html/rfc7748
	 * 
	 * https://tools.ietf.org/html/rfc8032
	 * 
	 * https://github.com/bifurcation/fourq
	 * https://blog.mozilla.org/warner/2011/11/29/ed25519-keys/
	 * 
	 * https://github.com/bcgit/bc-java/blob/master/core/src/test/java/org/
	 * bouncycastle/math/ec/rfc7748/test/X25519Test.java
	 * 
	 * https://cryptojedi.org/peter/data/pairing-20131122.pdf
	 * 
	 * https://github.com/bcgit/bc-java/blob/master/prov/src/main/java/org/
	 * bouncycastle/jcajce/provider/asymmetric/ec/KeyPairGeneratorSpi.java#L251
	 * 
	 * https://stackoverflow.com/questions/57852431/how-to-generate-curve25519-
	 * key-pair-for-diffie-hellman-algorithm
	 * 
	 * https://tools.ietf.org/html/rfc7748
	 * 
	 */

	// Create the ed25519 field
	private static Field ed25519Field = new Field(256, // b
			StringUtil.hex2ByteArray("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // q(2^255-19)
			new BigIntegerLittleEndianEncoding());

	/**
	 * Build OneKey using Curve25519. This method does not need Java 11 or
	 * BouncyCastle, also it does not start from Ed25519 keys but generates
	 * Curve25519 keys directly. Note that this OneKey will not have the
	 * internal Java keys set.
	 * 
	 * @return the generated Curve25519 OneKey
	 */
	public static OneKey generateCurve25519OneKey() {

		int SCALAR_SIZE = 32;
		int POINT_SIZE = 32;

		byte[] kA = new byte[SCALAR_SIZE];
		byte[] qA = new byte[POINT_SIZE];

		SecureRandom random = new SecureRandom();

		random.nextBytes(kA);

		byte[] basePoint = new byte[32];
		basePoint[0] = 0x09;
		qA = SharedSecretCalculation.X25519(kA, basePoint);

		OneKey key = buildCurve25519OneKey(kA, qA);

		return key;
	}

	/**
	 * Build OneKey using Ed25519.
	 * 
	 * @return the generated Ed25519 OneKey
	 */
	public static OneKey generateEd25519OneKey() {

		OneKey key = null;
		try {
			key = OneKey.generateKey(KeyKeys.OKP_Ed25519);
		} catch (CoseException e) {
			System.err.println("Failed to generate Ed25519 key: " + e);
		}

		return key;
	}

	/**
	 * Generate a COSE OneKey using Curve25519 for X25519. Note that this key
	 * will be lacking the Java keys internally.
	 * 
	 * https://cryptojedi.org/peter/data/pairing-20131122.pdf
	 * 
	 * FIXME: Not working
	 * 
	 * @return the COSE OneKey
	 */
	@Deprecated
	static OneKey generateCurve25519KeyTest() {

		// https://github.com/bcgit/bc-java/blob/master/prov/src/main/java/org/bouncycastle/jcajce/provider/asymmetric/ec/KeyPairGeneratorSpi.java#L251
		// https://stackoverflow.com/questions/57852431/how-to-generate-curve25519-key-pair-for-diffie-hellman-algorithm

		// Start by generating a Curve25519 key pair with BouncyCastle

		// MyRandom rand = new MyRandom();
		SecureRandom rand = new SecureRandom();

		X9ECParameters curveParams = CustomNamedCurves.getByName("Curve25519");
		// byte[] seed = StringUtil.hex2ByteArray(
		//  		"1122334455667788112233445566778811223344556677881122334455667788");
		ECParameterSpec ecSpec = new ECParameterSpec(curveParams.getCurve(), curveParams.getG(), curveParams.getN(),
				curveParams.getH(), curveParams.getSeed());

		// System.out.println("Spec using seed: " +
		// StringUtil.byteArray2HexString(ecSpec.getSeed()));

		KeyPairGenerator kpg = null;
		try {
			kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
			kpg.initialize(ecSpec);
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
			System.err.println("Failed to generate Curve25519 key: " + e);
		}

		KeyPair keyPair = kpg.generateKeyPair();
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();

		BCECPublicKey pubKey = (BCECPublicKey) publicKey;
		BCECPrivateKey privKey = (BCECPrivateKey) privateKey;

		// Build the COSE OneKey

		System.out.println("D " + StringUtil.byteArray2HexString(privKey.getD().toByteArray()));
		System.out.println("Seed priv " + StringUtil.byteArray2HexString(privKey.getParameters().getSeed()));
		System.out.println("Seed pub " + StringUtil.byteArray2HexString(pubKey.getParameters().getSeed()));
		System.out.println();
		System.out.println("Q pub " + pubKey.getQ().toString());
		System.out.println("Q pub uncompressed " + StringUtil.byteArray2HexString(pubKey.getQ().getEncoded(false)));
		System.out.println("Q pub 1st half " + StringUtil.byteArray2HexString(Arrays.copyOf(pubKey.getQ().getEncoded(false), 32)));
		System.out.println("Q compressed   " + StringUtil.byteArray2HexString(pubKey.getQ().getEncoded(true)));
		System.out.println("Sing of v?   " + StringUtil.byteArray2HexString(Arrays.copyOf(pubKey.getQ().getEncoded(true), 1)));
		System.out
				.println("Actual U?   " + StringUtil.byteArray2HexString(Arrays.copyOfRange(pubKey.getQ().getEncoded(true), 1, 33)));
		System.out.println(
				"getAffineXCoord " + StringUtil.byteArray2HexString(pubKey.getQ().getAffineXCoord().toBigInteger().toByteArray()));
		System.out.println(
				"getAffineYCoord " + StringUtil.byteArray2HexString(pubKey.getQ().getAffineYCoord().toBigInteger().toByteArray()));
		System.out.println();
		System.out
				.println("getRawXCoord " + StringUtil.byteArray2HexString(pubKey.getQ().getRawXCoord().toBigInteger().toByteArray()));
		System.out
				.println("getRawYCoord " + StringUtil.byteArray2HexString(pubKey.getQ().getRawYCoord().toBigInteger().toByteArray()));
		System.out.println();
		System.out.println("getXCoord " + StringUtil.byteArray2HexString(pubKey.getQ().getXCoord().toBigInteger().toByteArray()));
		System.out.println("getYCoord " + StringUtil.byteArray2HexString(pubKey.getQ().getYCoord().toBigInteger().toByteArray()));
		System.out.println();
		System.out.println("Pubkey encoded: " + StringUtil.byteArray2HexString(pubKey.getEncoded()));
		System.out.println("Privkey encoded: " + StringUtil.byteArray2HexString(privKey.getEncoded()));
		System.out.println();
		System.out.println("S: " + StringUtil.byteArray2HexString(privKey.getS().toByteArray()));
		System.out.println();
		privKey.getParameters().getH();
		System.out.println("H: " + StringUtil.byteArray2HexString(privKey.getParameters().getH().toByteArray()));
		System.out.println();
		System.out.println("Pubkey (Java) encoded: " + StringUtil.byteArray2HexString(publicKey.getEncoded()));
		System.out.println("Privkey (Java) encoded: " + StringUtil.byteArray2HexString(privateKey.getEncoded()));

		// Get the private D
		byte[] rgbD = invertArray(privKey.getD().toByteArray());
		// Get the public point Q (compressed true)
		byte[] rgbX = pubKey.getQ().getXCoord().getEncoded();

		OneKey key = new OneKey();

		key.add(KeyKeys.KeyType, KeyKeys.KeyType_OKP);
		key.add(KeyKeys.OKP_Curve, KeyKeys.OKP_X25519);
		key.add(KeyKeys.OKP_X, CBORObject.FromObject(rgbX));
		key.add(KeyKeys.OKP_D, CBORObject.FromObject(rgbD));

		return key;
	}

	/**
	 * Build a COSE OneKey from raw byte arrays containing the public and
	 * private keys. Considers EdDSA with the curve Ed25519.
	 * 
	 * @param privateKey the private key bytes
	 * @param publicKey the public key bytes
	 * 
	 * @return a OneKey representing the input material
	 */
	public static OneKey buildEd25519OneKey(byte[] privateKey, byte[] publicKey) {
		byte[] rgbX = publicKey;
		byte[] rgbD = privateKey;

		CBORObject keyMap = CBORObject.NewMap();
		
		keyMap.Add(KeyKeys.Algorithm.AsCBOR(), AlgorithmID.EDDSA.AsCBOR());
		keyMap.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
		keyMap.Add(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
		keyMap.Add(KeyKeys.OKP_X.AsCBOR(), CBORObject.FromObject(rgbX));
		
		if (privateKey != null)
			keyMap.Add(KeyKeys.OKP_D.AsCBOR(), CBORObject.FromObject(rgbD));

		OneKey key = null;
		try {
			key = new OneKey(keyMap);
		} catch (CoseException e) {
			System.err.println("Failed to generate COSE OneKey: " + e);
		}

		return key;
	}

	/**
	 * Build a COSE OneKey from raw byte arrays containing the public and
	 * private keys. Considers EdDSA with the curve Curve25519. Will not fill
	 * the Java private and public key in the COSE key. So can only be used for
	 * shared secret calculation.
	 * 
	 * @param privateKey the private key bytes (private scalar here)
	 * @param publicKey the public key bytes
	 * 
	 * @return a OneKey representing the input material
	 */
	public static OneKey buildCurve25519OneKey(byte[] privateKey, byte[] publicKey) {
		byte[] rgbX = publicKey;
		byte[] rgbD = privateKey;

		OneKey key = new OneKey();
		
		key.add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
		key.add(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_X25519);
		key.add(KeyKeys.OKP_X.AsCBOR(), CBORObject.FromObject(rgbX));
		
		// FIXME: D should be seed?
		if (privateKey != null)
			key.add(KeyKeys.OKP_D.AsCBOR(), CBORObject.FromObject(rgbD));

		return key;
	}

	/**
	 * Build a Java key pair from raw byte arrays containing the public and
	 * private keys. Considers EdDSA with the curve Ed25519.
	 * 
	 * @param privateKey the private key bytes
	 * @param publicKey the public key bytes
	 * @return a Java KeyPair representing the input material
	 */
	static KeyPair buildEd25519JavaKey(byte[] privateKey, byte[] publicKey) {
		EdDSAPrivateKeySpec privSpec = new EdDSAPrivateKeySpec(privateKey, EdDSANamedCurveTable.getByName("Ed25519"));
		EdDSAPrivateKey priv = new EdDSAPrivateKey(privSpec);
		EdDSAPublicKeySpec pubSpec = new EdDSAPublicKeySpec(publicKey, EdDSANamedCurveTable.getByName("Ed25519"));
		EdDSAPublicKey pub = new EdDSAPublicKey(pubSpec);

		KeyPair pair = new KeyPair(pub, priv);

		return pair;
	}

	/**
	 * Calculate public key for a corresponding private key. Considers EdDSA
	 * with the curve Ed25519.
	 * 
	 * @param privateKey the private key bytes
	 * @return the public key bytes
	 */
	static byte[] calculatePublicEd25519FromPrivate(byte[] privateKey) {
		EdDSANamedCurveSpec spec = EdDSANamedCurveTable.getByName("Ed25519");
		byte[] seed = privateKey;
		EdDSAPrivateKeySpec privKeySpec = new EdDSAPrivateKeySpec(seed, spec);
		EdDSAPublicKeySpec pubKeySpec = new EdDSAPublicKeySpec(privKeySpec.getA(), spec);

		EdDSAPublicKey pubKeyKey = new EdDSAPublicKey(pubKeySpec);
		return pubKeyKey.getAbyte();
	}

	/**
	 * Build a COSE OneKey from raw byte arrays containing the public and
	 * private keys. Considers ECDSA_384. Will recompute the Y value according
	 * to the indicated sign.
	 *
	 * @param privateKey the private key bytes
	 * @param publicKeyX the public key X parameter bytes
	 * @param signY the sign of the Y value to be recomputed
	 * 
	 * @return a OneKey representing the input material
	 */
	static OneKey buildEcdsa384OneKey(byte[] privateKey, byte[] publicKeyX, boolean signY) {
		// Recalculate Y value
		byte[] publicKeyY = null;
		try {
			publicKeyY = recomputeEcdsa384YFromX(publicKeyX, signY);
		} catch (CoseException e) {
			System.err.println("Failed to recompute missing Y value: " + e);
		}

		return buildEcdsa384OneKey(privateKey, publicKeyX, publicKeyY);
	}

	/**
	 * Build a COSE OneKey from raw byte arrays containing the public and
	 * private keys. Considers ECDSA_384.
	 *
	 * @param privateKey the private key bytes
	 * @param publicKeyX the public key X parameter bytes
	 * @param publicKeyY the public key Y parameter bytes. If none is provided a
	 *            valid Y will be recomputed. Note that the sign positive Y will
	 *            always be returned.
	 * 
	 * @return a OneKey representing the input material
	 */
	static OneKey buildEcdsa384OneKey(byte[] privateKey, byte[] publicKeyX, byte[] publicKeyY) {

		// Attempt to recalculate Y value if missing
		if (publicKeyY == null) {
			try {
				publicKeyY = recomputeEcdsa384YFromX(publicKeyX, true);
			} catch (CoseException e) {
				System.err.println("Failed to recompute missing Y value: " + e);
			}
		}

		CBORObject keyMap = CBORObject.NewMap();

		keyMap.Add(KeyKeys.Algorithm.AsCBOR(), AlgorithmID.ECDSA_384.AsCBOR());
		keyMap.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
		keyMap.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P384);
		keyMap.Add(KeyKeys.EC2_X.AsCBOR(), CBORObject.FromObject(publicKeyX));
		if (publicKeyY != null)
			keyMap.Add(KeyKeys.EC2_Y.AsCBOR(), CBORObject.FromObject(publicKeyY));
		if (privateKey != null)
			keyMap.Add(KeyKeys.EC2_D.AsCBOR(), CBORObject.FromObject(privateKey));

		OneKey key = null;
		try {
			key = new OneKey(keyMap);
		} catch (CoseException e) {
			System.err.println("Failed to generate COSE OneKey: " + e);
		}

		return key;
	}

	/**
	 * Build a COSE OneKey from raw byte arrays containing the public X key and
	 * the private key. Considers ECDSA_256. Will recompute the Y value
	 * according to the indicated sign.
	 * 
	 * @param privateKey the private key bytes
	 * @param publicKeyX the public key X parameter bytes
	 * @param signY the sign of the Y value to be recomputed
	 * 
	 * @return a OneKey representing the input material
	 */
	public static OneKey buildEcdsa256OneKey(byte[] privateKey, byte[] publicKeyX, boolean signY) {
		// Recalculate Y value
		byte[] publicKeyY = null;
		try {
			publicKeyY = recomputeEcdsa256YFromX(publicKeyX, signY);
		} catch (CoseException e) {
			System.err.println("Failed to recompute missing Y value: " + e);
		}

		return buildEcdsa256OneKey(privateKey, publicKeyX, publicKeyY);
	}

	/**
	 * Build a COSE OneKey from raw byte arrays containing the public and
	 * private keys. Considers ECDSA_256.
	 *
	 * @param privateKey the private key bytes
	 * @param publicKeyX the public key X parameter bytes
	 * @param publicKeyY the public key Y parameter bytes. If none is provided a
	 *            valid Y will be recomputed. Note that the sign positive Y will
	 *            always be returned.
	 * 
	 * @return a OneKey representing the input material
	 */
	public static OneKey buildEcdsa256OneKey(byte[] privateKey, byte[] publicKeyX, byte[] publicKeyY) {

        // Attempt to recalculate Y value if missing
		if (publicKeyY == null) {
			try {
				publicKeyY = recomputeEcdsa256YFromX(publicKeyX, true);
			} catch (CoseException e) {
				System.err.println("Failed to recompute missing Y value: " + e);
			}
		}

		CBORObject keyMap = CBORObject.NewMap();
		
		keyMap.Add(KeyKeys.Algorithm.AsCBOR(), AlgorithmID.ECDSA_256.AsCBOR());
		keyMap.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
		keyMap.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
		keyMap.Add(KeyKeys.EC2_X.AsCBOR(), CBORObject.FromObject(publicKeyX));
		if (publicKeyY != null)
			keyMap.Add(KeyKeys.EC2_Y.AsCBOR(), CBORObject.FromObject(publicKeyY));
		if (privateKey != null)
			keyMap.Add(KeyKeys.EC2_D.AsCBOR(), CBORObject.FromObject(privateKey));

		OneKey key = null;
		try {
			key = new OneKey(keyMap);
		} catch (CoseException e) {
			System.err.println("Failed to generate COSE OneKey: " + e);
		}

		return key;
	}

	/**
	 * Takes an ECDSA_256 X coordinate and computes a valid Y value for that X.
	 * Will only only return one of the possible Y values.
	 * 
	 * Resources:
	 * https://github.com/conz27/crypto-test-vectors/blob/master/ecdh.py
	 * https://crypto.stackexchange.com/questions/8914/ecdsa-compressed-public-key-point-back-to-uncompressed-public-key-point
	 * https://asecuritysite.com/encryption/js08
	 * https://bitcoin.stackexchange.com/questions/44024/get-uncompressed-public-key-from-compressed-form
	 * http://www-cs-students.stanford.edu/~tjw/jsbn/ecdh.html
	 * https://tools.ietf.org/html/rfc6090#appendix-C
	 * https://math.stackexchange.com/questions/464253/square-roots-in-finite-fields-i-e-mod-pm
	 * http://hg.openjdk.java.net/jdk/jdk/rev/752e57845ad2#l1.97
	 * jdk.crypto.ec/sun.security.ec.ECDHKeyAgreement
	 * https://www.secg.org/sec1-v2.pdf
	 * 
	 * @param publicKeyX the public key X coordinate
	 * @param signY the sign of the Y coordinate to return
	 * 
	 * @return the recomputed Y value for that X
	 * @throws CoseException if recomputation fails
	 */
	static byte[] recomputeEcdsa256YFromX(byte[] publicKeyX, boolean signY) throws CoseException {

		BigInteger x = new BigInteger(1, publicKeyX);

		// secp256r1
		// y^2 = x^3 + ax + b -> y = +- sqrt(a x + b + x^3)
		BigInteger prime = new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
		BigInteger A = new BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16);
		BigInteger B = new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);
		BigInteger three = new BigInteger("3");
		BigInteger two = new BigInteger("2");
		BigInteger zero = new BigInteger("0");
		BigInteger one = new BigInteger("1");

		BigInteger xPow3 = x.modPow(three, prime);
		BigInteger ax = (A.multiply(x)).mod(prime);
		BigInteger partial = ax.add(B).mod(prime);
		BigInteger combined = partial.add(xPow3).mod(prime);

		BigInteger root1 = squareMod(combined, prime);
		BigInteger root2 = root1.negate().mod(prime);

		// System.out.println("Root1: " +
		// StringUtil.byteArray2HexString(root1.toByteArray()));
		// System.out.println("Root2: " +
		// StringUtil.byteArray2HexString(root2.toByteArray()));

		byte[] root1Bytes = root1.toByteArray();
		byte[] root2Bytes = root2.toByteArray();

		if (root1Bytes.length == 33) {
			root1Bytes = Arrays.copyOfRange(root1Bytes, 1, 33);
		}
		if (root2Bytes.length == 33) {
			root2Bytes = Arrays.copyOfRange(root2Bytes, 1, 33);
		}

		byte[] xBytes = x.toByteArray();
		if (xBytes.length == 33) {
			xBytes = Arrays.copyOfRange(xBytes, 1, 33);
		}

		// Now build 2 keys from the potential Y values
		OneKey possibleKey1 = null;
		OneKey possibleKey2 = null;
		try {
			possibleKey1 = SharedSecretCalculation.buildEcdsa256OneKey(null, xBytes, root1Bytes);
		} catch (Exception e) {
			// Failed to build key with this Y, so it won't be used
		}
		try {
			possibleKey2 = SharedSecretCalculation.buildEcdsa256OneKey(null, xBytes, root2Bytes);
		} catch (Exception e) {
			// Failed to build key with this Y, so it won't be used
		}

		// Check if on point (first y)
		// jdk.crypto.ec/sun.security.ec.ECDHKeyAgreement
		ECPublicKey keyToTest;
		BigInteger keyX;
		BigInteger keyY;
		BigInteger p = prime;
		EllipticCurve curve;
		BigInteger rhs;
		BigInteger lhs;

		if (possibleKey1 != null
				&& ((root1.mod(two).equals(zero) && signY == false) || (root1.mod(two).equals(one) && signY == true))) {
			keyToTest = (ECPublicKey) possibleKey1.AsPublicKey();
			keyX = keyToTest.getW().getAffineX();
			keyY = keyToTest.getW().getAffineY();
			p = prime;
			curve = keyToTest.getParams().getCurve();
			rhs = keyX.modPow(BigInteger.valueOf(3), p).add(curve.getA().multiply(x)).add(curve.getB()).mod(p);
			lhs = keyY.modPow(BigInteger.valueOf(2), p).mod(p);
			if (!rhs.equals(lhs)) {
				System.out.println("Key using first Y not on curve!");
			} else {
				return possibleKey1.get(KeyKeys.EC2_Y).GetByteString();
			}
		}

		// Check if on point (second y)
		if (possibleKey2 != null) {
			keyToTest = (ECPublicKey) possibleKey2.AsPublicKey();
			keyX = keyToTest.getW().getAffineX();
			keyY = keyToTest.getW().getAffineY();
			curve = keyToTest.getParams().getCurve();
			rhs = keyX.modPow(BigInteger.valueOf(3), p).add(curve.getA().multiply(x)).add(curve.getB()).mod(p);
			lhs = keyY.modPow(BigInteger.valueOf(2), p).mod(p);
			if (!rhs.equals(lhs)) {
				System.out.println("Key using second Y not on curve!");
			} else {
				return possibleKey2.get(KeyKeys.EC2_Y).GetByteString();
			}
		}
		System.out.println("Found no fitting Y value.");
		return null;
	}

	/**
	 * Takes an ECDSA_384 X coordinate and computes a valid Y value for that X.
	 * Will only only return one of the possible Y values.
	 * 
	 * https://neuromancer.sk/std/secg/secp384r1
	 * 
	 * @param publicKeyX the public key X coordinate
	 * @param signY the sign of the Y coordinate to return
	 * 
	 * @return the recomputed Y value for that X
	 * @throws CoseException if recomputation fails
	 */
	static byte[] recomputeEcdsa384YFromX(byte[] publicKeyX, boolean signY) throws CoseException {

		BigInteger x = new BigInteger(1, publicKeyX);

		// secp384r1
		// y^2 = x^3 + ax + b -> y = +- sqrt(a x + b + x^3)
		BigInteger prime = new BigInteger(
				"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16);
		BigInteger A = new BigInteger(
				"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc", 16);
		BigInteger B = new BigInteger(
				"b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16);
		BigInteger three = new BigInteger("3");
		BigInteger two = new BigInteger("2");
		BigInteger zero = new BigInteger("0");
		BigInteger one = new BigInteger("1");

		BigInteger xPow3 = x.modPow(three, prime);
		BigInteger ax = (A.multiply(x)).mod(prime);
		BigInteger partial = ax.add(B).mod(prime);
		BigInteger combined = partial.add(xPow3).mod(prime);

		BigInteger root1 = squareMod(combined, prime);
		BigInteger root2 = root1.negate().mod(prime);

		byte[] root1Bytes = root1.toByteArray();
		byte[] root2Bytes = root2.toByteArray();

		if (root1Bytes.length == 49) {
			root1Bytes = Arrays.copyOfRange(root1Bytes, 1, 49);
		}
		if (root2Bytes.length == 49) {
			root2Bytes = Arrays.copyOfRange(root2Bytes, 1, 49);
		}

		byte[] xBytes = x.toByteArray();
		if (xBytes.length == 49) {
			xBytes = Arrays.copyOfRange(xBytes, 1, 49);
		}

		// System.out.println("Root1: " + StringUtil.byteArray2HexString(root1Bytes));
		// System.out.println("Root2: " + StringUtil.byteArray2HexString(root2Bytes));
		// System.out.println("X: " + StringUtil.byteArray2HexString(xBytes));
		
		// Now build 2 keys from the potential Y values
		OneKey possibleKey1 = null;
		OneKey possibleKey2 = null;
		try {
			possibleKey1 = SharedSecretCalculation.buildEcdsa384OneKey(null, xBytes, root1Bytes);
		} catch (Exception e) {
			// Failed to build key with this Y, so it won't be used
		}
		try {
			possibleKey2 = SharedSecretCalculation.buildEcdsa384OneKey(null, xBytes, root2Bytes);
		} catch (Exception e) {
			// Failed to build key with this Y, so it won't be used
		}

		// Check if on point (first y)
		// jdk.crypto.ec/sun.security.ec.ECDHKeyAgreement
		ECPublicKey keyToTest;
		BigInteger keyX;
		BigInteger keyY;
		BigInteger p = prime;
		EllipticCurve curve;
		BigInteger rhs;
		BigInteger lhs;

		if (possibleKey1 != null
				&& ((root1.mod(two).equals(zero) && signY == false) || (root1.mod(two).equals(one) && signY == true))) {
			keyToTest = (ECPublicKey) possibleKey1.AsPublicKey();
			keyX = keyToTest.getW().getAffineX();
			keyY = keyToTest.getW().getAffineY();
			p = prime;
			curve = keyToTest.getParams().getCurve();
			rhs = keyX.modPow(BigInteger.valueOf(3), p).add(curve.getA().multiply(x)).add(curve.getB()).mod(p);
			lhs = keyY.modPow(BigInteger.valueOf(2), p).mod(p);
			if (!rhs.equals(lhs)) {
				System.out.println("Key using first Y not on curve!");
			} else {
				return possibleKey1.get(KeyKeys.EC2_Y).GetByteString();
			}
		}

		// Check if on point (second y)
		if (possibleKey2 != null) {
			keyToTest = (ECPublicKey) possibleKey2.AsPublicKey();
			keyX = keyToTest.getW().getAffineX();
			keyY = keyToTest.getW().getAffineY();
			curve = keyToTest.getParams().getCurve();
			rhs = keyX.modPow(BigInteger.valueOf(3), p).add(curve.getA().multiply(x)).add(curve.getB()).mod(p);
			lhs = keyY.modPow(BigInteger.valueOf(2), p).mod(p);
			if (!rhs.equals(lhs)) {
				System.out.println("Key using second Y not on curve!");
			} else {
				return possibleKey2.get(KeyKeys.EC2_Y).GetByteString();
			}
		}
		System.out.println("Found no fitting Y value.");
		return null;
	}

    /**
     * Calculates prime roots in a field. Only works if p congruent 3 mod 4.
     * 
     * https://math.stackexchange.com/questions/464253/square-roots-in-finite-fields-i-e-mod-pm
     * 
     * @param val the value to square
     * @return one of the square roots
     */
	static BigInteger squareMod(BigInteger val, BigInteger prime) {

		BigInteger three = new BigInteger("3");
		BigInteger four = new BigInteger("4");
		if (!prime.mod(four).equals(three)) {
			System.err.println("Invalid prime! p must be congruent 3 mod 4");
		}

		BigInteger power = prime.add(BigInteger.ONE).divide(new BigInteger("4"));

		return val.modPow(power, prime);

	}

	/**
	 * Generates a shared secret for EdDSA (Ed25519) or ECDSA.
	 * 
	 * TODO: Add X448 support? (Would need a dedicated X448 method or
	 * modification of the existing)
	 * 
	 * @param privateKey the public/private key of the sender
	 * @param publicKey the public key of the recipient
	 * 
	 * @return the shared secret, or null in case of error
	 */
	static byte[] generateSharedSecret(OneKey privateKey, OneKey publicKey) {

		if (privateKey == null || publicKey == null) {
			System.err.println("Public key and/or private key not found.");
			return null;
		}
		
		// EC2 keys (P-256)
		
		CBORObject privateCurve = privateKey.get(KeyKeys.EC2_Curve);
		CBORObject publicCurve = publicKey.get(KeyKeys.EC2_Curve);

		if (privateCurve != publicCurve) {
			System.err.println("Public and private keys use different curves.");
			return null;
		}

		if (privateCurve == KeyKeys.EC2_P256 /*|| privateCurve == KeyKeys.EC2_P384 || privateCurve == KeyKeys.EC2_P521*/) {
			return generateSharedSecretECDSA(privateKey, publicKey);
		}

		
		// OKP keys (Curve25519)

		privateCurve = privateKey.get(KeyKeys.OKP_Curve);
		publicCurve = publicKey.get(KeyKeys.OKP_Curve);

		if (privateCurve != publicCurve) {
			System.err.println("Public and private keys use different curves.");
			return null;
		}

		// FIXME?: D is seed, not the private scalar
		byte[] privateScalar = privateKey.get(KeyKeys.OKP_D).GetByteString();
		// Take X value as U coordinate
		byte[] publicUCoordinate = publicKey.get(KeyKeys.OKP_X).GetByteString();

		if (privateCurve == KeyKeys.OKP_X25519 /*|| privateCurve == KeyKeys.OKP_X448*/) {
			// Use X25519 directly
			return X25519(privateScalar, publicUCoordinate);
		}

		
		System.err.println("Failed to generate shared secret.");

		return null;
		
	}

	/**
	 * Takes an input COSE OneKey and converts it from using Ed25519 to
	 * Curve25519 for X25519. Note that this new key will not have correct Java
	 * keys internally.
	 * 
	 * @return the generated COSE OneKey
	 * 
	 * @throws CoseException
	 */
	static OneKey convertEd25519ToCurve25519(OneKey initialKey) throws CoseException {

		FieldElement y = null;
		try {
			// Extract the y coordinate
			y = KeyRemapping.extractCOSE_y(initialKey);
		} catch (CoseException e) {
			System.err.println("Failed to generate Curve25519 key: " + e);
		}

		// Calculate the corresponding Curve25519 u coordinate
		FieldElement u = KeyRemapping.calcCurve25519_u(y);

		// Build the COSE OneKey

		OneKey key = new OneKey();
		
		// The private key
		if (initialKey.AsPrivateKey() != null) {
			EdDSAPrivateKey initialPrivKey = (EdDSAPrivateKey) initialKey.AsPrivateKey();
			byte[] privateHash = initialPrivKey.getH();
			byte[] privateScalar = Arrays.copyOf(privateHash, 32);
			byte[] rgbD = privateScalar;

			// System.out.println("D good: " + StringUtil.byteArray2HexString(rgbD));
			
			key.add(KeyKeys.OKP_D, CBORObject.FromObject(rgbD));
		}

		// The X value is the value of the u coordinate
		byte[] rgbX = u.toByteArray();

		key.add(KeyKeys.KeyType, KeyKeys.KeyType_OKP);
		key.add(KeyKeys.OKP_Curve, KeyKeys.OKP_X25519);
		key.add(KeyKeys.OKP_X, CBORObject.FromObject(rgbX));

		return key;
	}

	/**
	 * Generate a COSE OneKey using Curve25519 for X25519. Note that this key
	 * will be lacking the Java keys internally.
	 * 
	 * This method uses Ed25519 keys as a starting point.
	 * 
	 * @return the generated COSE OneKey
	 * @throws CoseException
	 */
	@Deprecated
	static OneKey generateCurve25519KeyOld() throws CoseException {

		// Start by generating a Ed25519 key pair
		OneKey initialKey = null;
		try {
			initialKey = OneKey.generateKey(KeyKeys.OKP_Ed25519);
		} catch (CoseException e) {
			System.err.println("Failed to generate Curve25519 key: " + e);
		}

		// Convert and return it as an Curve25519 key
		return convertEd25519ToCurve25519(initialKey);
	}

	/**
	 * Generate a shared secret when using ECDSA.
	 * 
	 * @param senderPrivateKey the public/private key of the sender
	 * @param recipientPublicKey the public key of the recipient
	 * @return the shared secret
	 */
	private static byte[] generateSharedSecretECDSA(OneKey senderPrivateKey, OneKey recipientPublicKey) {

		byte[] sharedSecret = null;

		try {
			ECPublicKey recipientPubKey = (ECPublicKey) recipientPublicKey.AsPublicKey();
			ECPrivateKey senderPrivKey = (ECPrivateKey) senderPrivateKey.AsPrivateKey();

			KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
			keyAgreement.init(senderPrivKey);
			keyAgreement.doPhase(recipientPubKey, true);

			sharedSecret = keyAgreement.generateSecret();
		} catch (InvalidKeyException | NoSuchAlgorithmException | CoseException e) {
			System.err.println("Could not generate the shared secret: " + e);
		}

		return sharedSecret;
	}

	/**
	 * Generate a shared secret when using EdDSA.
	 * 
	 * @param senderPrivateKey the public/private key of the sender
	 * @param recipientPublicKey the public key of the recipient
	 * @return the shared secret
	 */
	private static byte[] generateSharedSecretEdDSA(OneKey senderPrivateKey, OneKey recipientPublicKey) {

		byte[] sharedSecret = null;
		try {
			sharedSecret = SharedSecretCalculation.calculateSharedSecret(recipientPublicKey, senderPrivateKey);
		} catch (CoseException e) {
			System.err.println("Could not generate the shared secret: " + e);
		}

		return sharedSecret;
	}

	/**
	 * Calculate the shared secret from a COSE OneKey using EdDSA. It is first
	 * converted to Montgomery coordinates and after that the X25519 function is
	 * used to perform the shared secret calculation.
	 * 
	 * TODO: Update to handle both Ed25519 and Curve25519 already here?
	 * 
	 * @param publicKey the public key (of the other party)
	 * @param privateKey the private key (your own)
	 * @return the shared secret calculated
	 * @throws CoseException on failure
	 */
	private static byte[] calculateSharedSecret(OneKey publicKey, OneKey privateKey) throws CoseException {

		/* Check that the keys are as expected (using Ed25519) */
		if (publicKey.get(KeyKeys.OKP_Curve) != KeyKeys.OKP_Ed25519
				|| privateKey.get(KeyKeys.OKP_Curve) != KeyKeys.OKP_Ed25519) {
			System.err.println(
					"Error: Keys for EdDSA shared secret calculation are not using Ed25519. Use X25519 directly.");
			return null;
		}
		
		/* Calculate u coordinate from public key */

		FieldElement public_y = KeyRemapping.extractCOSE_y(publicKey);
		FieldElement public_u = KeyRemapping.calcCurve25519_u(public_y);
		byte[] public_u_array = public_u.toByteArray();

		/* Get private scalar from private key */

		byte[] private_hash = ((EdDSAPrivateKey) privateKey.AsPrivateKey()).getH();
		byte[] private_scalar = Arrays.copyOf(private_hash, 32);

		/* -- Calculated shared secret -- */
		// secret = X25519(my private scalar, your public key U)

		byte[] sharedSecret = X25519(private_scalar, public_u_array);

		return sharedSecret;
	}

	/**
	 * Wrapper for the X25519 function
	 * 
	 * @param k the private scalar k
	 * @param u the public u coordinate
	 * @return the shared secret
	 */
	static byte[] X25519(byte[] k, byte[] u) {

		k = k.clone(); // Needed?
		u = u.clone(); // Needed?

		BigInteger kn = decodeScalar(k);
		BigInteger un = decodeUCoordinate(u);

		BigIntegerFieldElement kn_bif = new BigIntegerFieldElement(ed25519Field, kn);
		BigIntegerFieldElement un_bif = new BigIntegerFieldElement(ed25519Field, un);

		FieldElement res = X25519_calculate(kn_bif, un_bif);

		BigInteger res_bi = new BigInteger(invertArray(res.toByteArray()));

		return encodeUCoordinate(res_bi);

	}

	/**
	 * Implements the XX25519 function.
	 * 
	 * See https://tools.ietf.org/html/rfc7748#section-5
	 */
	private static FieldElement X25519_calculate(FieldElement k, FieldElement u) {

		// Set bits
		// https://tools.ietf.org/html/rfc7748#page-7
		int bits = 255;

		// Initialize starting values
		FieldElement x_1 = u;
		FieldElement x_2 = new BigIntegerFieldElement(ed25519Field, new BigInteger("1"));

		FieldElement z_2 = new BigIntegerFieldElement(ed25519Field, new BigInteger("0"));

		FieldElement x_3 = u;
		FieldElement z_3 = new BigIntegerFieldElement(ed25519Field, new BigInteger("1"));

		BigInteger swap = new BigInteger("0");

		// https://tools.ietf.org/html/rfc7748#page-8
		FieldElement a24 = new BigIntegerFieldElement(ed25519Field, new BigInteger("121665"));

		// Uninitialized variables used in loop

		FieldElement A;
		FieldElement AA;
		FieldElement B;
		FieldElement BB;
		FieldElement E;
		FieldElement C;
		FieldElement D;
		FieldElement DA;
		FieldElement CB;

		// For loop here
		for (int t = bits - 1; t >= 0; t--) {

			// Swap step

			BigInteger k_bi = new BigInteger(invertArray(k.toByteArray()));
			// k_t = (k >> t) & 1
			BigInteger k_t = (k_bi.shiftRight(t)).and(BigInteger.ONE);

			swap = swap.xor(k_t); // swap ^= k_t

			// Swapping
			Tuple result = cswap(swap, x_2, x_3);
			x_2 = result.a;
			x_3 = result.b;
			// End swapping

			// Swapping
			Tuple result2 = cswap(swap, z_2, z_3);
			z_2 = result2.a;
			z_3 = result2.b;
			// End swapping

			swap = k_t; // swap = k_t

			// Calculation step

			A = x_2.add(z_2); // A = x_2 + z_2

			AA = A.multiply(A); // AA = A^2

			B = x_2.subtract(z_2); // B = x_2 - z_2

			BB = B.multiply(B); // B = B^2

			E = AA.subtract(BB); // E = AA - BB

			C = x_3.add(z_3); // C = x_3 + z_3

			D = x_3.subtract(z_3); // D = x_3 - z_3

			DA = D.multiply(A); // DA = D * A

			CB = C.multiply(B); // CB = C * B

			FieldElement DA_a_CB = DA.add(CB);
			x_3 = DA_a_CB.multiply(DA_a_CB); // x_3 = (DA + CB)^2

			FieldElement DA_s_CB = DA.subtract(CB);
			FieldElement DA_s_CB__x__DA_s_CB = DA_s_CB.multiply(DA_s_CB);
			z_3 = x_1.multiply(DA_s_CB__x__DA_s_CB); // z_3 = x_1 * (DA - CB)^2

			x_2 = AA.multiply(BB); // x_2 = AA * BB

			FieldElement a24_x_E = a24.multiply(E);
			FieldElement AA__a__a24_x_E = AA.add(a24_x_E);
			z_2 = E.multiply(AA__a__a24_x_E); // z_2 = E * (AA + a24 * E)
		}

		// Final swap step

		// Swapping
		Tuple result = cswap(swap, x_2, x_3);
		x_2 = result.a;
		x_3 = result.b;
		// End swapping

		// Swapping
		Tuple result2 = cswap(swap, z_2, z_3);
		z_2 = result2.a;
		z_3 = result2.b;
		// End swapping

		// Return step

		// Calculate p
		BigInteger pow = new BigInteger("2").pow(255);
		BigInteger p_bi = pow.subtract(new BigInteger("19"));
		FieldElement p = new BigIntegerFieldElement(ed25519Field, p_bi);

		// Calculate p minus 2
		FieldElement p_s_2 = p.subtractOne().subtractOne();

		// Calculate z_2^(p - 2)
		BigInteger z_2_bi = new BigInteger(invertArray(z_2.toByteArray()));
		BigIntegerFieldElement z_2_bif = new BigIntegerFieldElement(ed25519Field, z_2_bi);
		FieldElement val = z_2_bif.pow(p_s_2);

		// Calculate return vale
		FieldElement ret = x_2.multiply(val);

		return ret;

	}

	static BigInteger decodeLittleEndian(byte[] b, int bits) {

		byte[] cutArray = Arrays.copyOf(b, (bits + 7) / 8);

		BigInteger res = new BigInteger(1, invertArray(cutArray));

		return res;

	}

	static BigInteger decodeScalar(byte[] b) {

		b[0] &= 248;
		b[31] &= 127;
		b[31] |= 64;

		return decodeLittleEndian(b, 255);

	}

	static BigInteger decodeUCoordinate(byte[] u) {

		int bits = 255;

		for (int i = 0; i < u.length; i++) {
			if ((u[i] % 8) != 0) {
				u[u.length - 1] &= (1 << (bits % 8)) - 1;
			}
		}

		return decodeLittleEndian(u, bits);
	}

	// TODO: Optimize
	static byte[] encodeUCoordinate(BigInteger u) {

		int bits = 255;

		BigInteger pow = new BigInteger("2").pow(255);
		BigInteger p_bi = pow.subtract(new BigInteger("19"));

		u = u.mod(p_bi); // u = u % p

		byte[] res = new byte[(bits + 7) / 8];

		for (int i = 0; i < ((bits + 7) / 8); i++) {
			BigInteger temp = u.shiftRight(8 * i);
			byte[] temp2 = temp.toByteArray();

			res[i] = temp2[temp2.length - 1];
		}

		return res;
	}

	// TODO: Do I really need to make new objects?
	static class Tuple {

		public FieldElement a;
		public FieldElement b;

		Tuple(FieldElement a, FieldElement b) {

			BigInteger a_bi = new BigInteger(invertArray(a.toByteArray()));
			BigInteger b_bi = new BigInteger(invertArray(b.toByteArray()));

			this.a = new BigIntegerFieldElement(ed25519Field, a_bi);
			this.b = new BigIntegerFieldElement(ed25519Field, b_bi);
		}

	}

	// TODO: Make constant time
	static Tuple cswap(BigInteger swap, FieldElement a, FieldElement b) {

		if (swap.equals(BigInteger.ONE)) {
			return new Tuple(b, a);
		} else {
			return new Tuple(a, b);
		}

	}

	/**
	 * Invert a byte array
	 * 
	 * Needed to handle endianness
	 * 
	 * @param input the input byte array
	 * @return the inverted byte array
	 */
	private static byte[] invertArray(byte[] input) {
		byte[] output = input.clone();
		for (int i = 0; i < input.length; i++) {
			output[i] = input[input.length - i - 1];
		}
		return output;
	}

}
