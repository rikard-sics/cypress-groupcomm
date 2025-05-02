/*******************************************************************************
 * Copyright (c) 2023 RISE SICS and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Rikard Höglund (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore.group;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.Base64;
import org.eclipse.californium.elements.util.StringUtil;

import com.upokecenter.cbor.CBORObject;

import net.i2p.crypto.eddsa.Utils;

/**
 * Various functions for decoding OneKeys that can be useful for interop
 * testing.
 * 
 */
public class OneKeyDecoder {

	/**
	 * Create OneKey from raw bytes representing a public key. This is what one
	 * party had during the last interop test.
	 * 
	 * @param alg the algorithm used
	 * @param publicKey the bytes of the public key
	 * 
	 * @return the built OneKey object
	 */
	public static OneKey fromRawPublicBytes(AlgorithmID alg, byte[] publicKey) {

		switch (alg) {
		case EDDSA:
			String keyStringStart = "{1: 1, -2: h'";
			String keyStringEnd = "', -1: 6, 3: -8}";
			String publicKeyString = Utils.bytesToHex(publicKey);
			String fullKeyString = keyStringStart + publicKeyString + keyStringEnd;
			return parseDiagnostic(fullKeyString);
		default:
			System.err.println("Conversion using this algorithm not supported.");
			return null;
		}
	}

	/**
	 * As below but returns a CBOR Object.
	 * 
	 * @param keyString string representing a OneKey in diagnostic notation
	 * @return a CBOR object built from the string
	 */
	public static CBORObject parseDiagnosticToCbor(String keyString) {
		return parseDiagnostic(keyString).AsCBOR();
	}

	/**
	 * As below but returns a Base64 encoded string.
	 * 
	 * @param keyString string representing a OneKey in diagnostic notation
	 * @return a base 64 encoded representation built from the string
	 */
	public static String parseDiagnosticToBase64(String keyString) {

		OneKey key = parseDiagnostic(keyString);
		byte[] keyObjectBytes = key.EncodeToBytes();
		String base64Encoded = Base64.encodeBytes(keyObjectBytes);

		return base64Encoded;
	}

	/**
	 * Parse a string representing a COSE OneKey in diagnostic notation. This
	 * method first builds a CBOR Object from the values in the string. A COSE
	 * OneKey is then created from that CBOR Object.
	 * 
	 * @param keyString string representing a OneKey in diagnostic notation
	 * @return a OneKey object built from the string
	 */
	public static OneKey parseDiagnostic(String keyString) {

		// Add algorithm to key if missing
		boolean addAlgorithm = false;

		// Change alternative version of single quotes
		keyString = keyString.replace("’", "'");

		// Convert to lower case
		keyString = keyString.toLowerCase();

		// Remove { and } characters
		keyString = keyString.replace("{", "");
		keyString = keyString.replace("}", "");
		// Remove spaces
		keyString = keyString.replace(" ", "");

		// Split the string into sections at the , and : character
		String[] segments = keyString.split("[,:]");

		// Build CBOR Object from the segments
		CBORObject keyCbor = CBORObject.NewMap();

		for (int i = 0; i < segments.length; i += 2) {
			int key = Integer.parseInt(segments[i]);
			String value = segments[i + 1];

			// Handle byte array values
			if (value.length() >= 2 && value.substring(0, 2).equals("h'")) {
				String arrayString = value.replace("h'", "").replace("'", "");
				byte[] array = StringUtil.hex2ByteArray(arrayString);
				keyCbor.Add(key, array);
			} else {
				// Handle integer values
				int valueInt = Integer.parseInt(value);
				keyCbor.Add(key, valueInt);
			}
		}

		// Set the algorithm if missing (which it sometimes is) TODO: Needed?
		if (addAlgorithm && keyCbor.get(KeyKeys.Algorithm.AsCBOR()) == null) {

			// System.out.println("AlgorithmID in diagnostic string is null,
			// setting it.");

			AlgorithmID countersignAlg = OneKeyDecoder.getAlgFromCurve(keyCbor);
			keyCbor.set(KeyKeys.Algorithm.AsCBOR(), countersignAlg.AsCBOR());
		}

		// Create a COSE key from CBOR Object
		OneKey key = null;
		try {
			key = new OneKey(keyCbor);
		} catch (CoseException e) {
			System.err.println("Error: Failed to decode COSE OneKey from diagnostic notation.");
			e.printStackTrace();
		}

		return key;
	}

	/**
	 * Get the algorithm used from the curve information in a OneKey
	 * 
	 * @param key the OneKey to check
	 * @return the algorithm used
	 */
	public static AlgorithmID getAlgFromCurve(OneKey key) {
		CBORObject ec2Curve = null;
		CBORObject okpCurve = null;

		try {
			okpCurve = key.get(KeyKeys.OKP_Curve.AsCBOR());
			ec2Curve = key.get(KeyKeys.EC2_Curve.AsCBOR());
		} catch (CoseException e) {
			System.err.println("Failed to identify algorithm used from curve.");
			e.printStackTrace();
		}

		// Checks and returns the algorithm by looking at the curve used
		if (ec2Curve == KeyKeys.EC2_P256) {
			// ECDSA 256
			return AlgorithmID.ECDSA_256;
		} else if (ec2Curve == KeyKeys.EC2_P384) {
			// ECDSA 384
			return AlgorithmID.ECDSA_384;
		} else if (ec2Curve == KeyKeys.EC2_P521) {
			// ECDSA 512
			return AlgorithmID.ECDSA_256;
		} else if (okpCurve == KeyKeys.OKP_Ed25519) {
			// EdDSA
			return AlgorithmID.EDDSA;
		} else {
			return null;
		}
	}

	/**
	 * Get the algorithm used from the curve information in a CBOR Object
	 * 
	 * @param key the CBOR Object to check
	 * @return the algorithm used
	 */
	public static AlgorithmID getAlgFromCurve(CBORObject key) {
		CBORObject ec2Curve = key.get(KeyKeys.EC2_Curve.AsCBOR());
		CBORObject okpCurve = key.get(KeyKeys.OKP_Curve.AsCBOR());

		// Checks and returns the algorithm by looking at the curve used
		if (ec2Curve == KeyKeys.EC2_P256) {
			// ECDSA 256
			return AlgorithmID.ECDSA_256;
		} else if (ec2Curve == KeyKeys.EC2_P384) {
			// ECDSA 384
			return AlgorithmID.ECDSA_384;
		} else if (ec2Curve == KeyKeys.EC2_P521) {
			// ECDSA 512
			return AlgorithmID.ECDSA_256;
		} else if (okpCurve == KeyKeys.OKP_Ed25519) {
			// EdDSA
			return AlgorithmID.EDDSA;
		} else {
			return null;
		}
	}

}
