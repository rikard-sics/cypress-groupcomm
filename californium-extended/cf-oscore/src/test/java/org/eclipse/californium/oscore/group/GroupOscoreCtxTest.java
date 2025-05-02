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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.Attribute;
import org.eclipse.californium.cose.EncryptMessage;
import org.eclipse.californium.cose.HeaderKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.cose.Recipient;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.ByteId;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSException;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

/**
 * Test class for Group OSCORE context derivation. It also tests some of the
 * functionality from COSE.
 * 
 *
 */
public class GroupOscoreCtxTest {

	String uriLocal = "coap://localhost";
	AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	// Group OSCORE specific values for the countersignature (EdDSA)
	AlgorithmID algCountersign = AlgorithmID.EDDSA;

	// Encryption algorithm for when using signatures
	AlgorithmID algSignEnc = AlgorithmID.AES_CCM_16_64_128;

	// Algorithm for key agreement
	AlgorithmID algKeyAgreement = AlgorithmID.ECDH_SS_HKDF_256;

	// test vector OSCORE draft Appendix C.1.2
	byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
			0x10 };
	byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23, (byte) 0x78, (byte) 0x63,
			(byte) 0x40 };

	final int REPLAY_WINDOW = 32;

	byte[] gm_public_key_bytes = StringUtil.hex2ByteArray(
			"A501781A636F6170733A2F2F6D79736974652E6578616D706C652E636F6D026C67726F75706D616E6167657203781A636F6170733A2F2F646F6D61696E2E6578616D706C652E6F7267041AAB9B154F08A101A4010103272006215820CDE3EFD3BC3F99C9C9EE210415C6CBA55061B5046E963B8A58C9143A61166472");

	byte[] sid = new byte[] { 0x52 };
	byte[] sid_public_key_bytes = StringUtil.hex2ByteArray(
			"A501781A636F6170733A2F2F7365727665722E6578616D706C652E636F6D026673656E64657203781A636F6170733A2F2F636C69656E742E6578616D706C652E6F7267041A70004B4F08A101A401010327200621582077EC358C1D344E41EE0E87B8383D23A2099ACD39BDF989CE45B52E887463389B");
	byte[] sid_private_key_bytes = new byte[] { (byte) 0x85, 0x7E, (byte) 0xB6, 0x1D, 0x3F, 0x6D, 0x70, (byte) 0xA2,
			0x78, (byte) 0xA3, 0x67, 0x40, (byte) 0xD1, 0x32, (byte) 0xC0, (byte) 0x99, (byte) 0xF6, 0x28, (byte) 0x80,
			(byte) 0xED, 0x49, 0x7E, 0x27, (byte) 0xBD, (byte) 0xFD, 0x46, (byte) 0x85, (byte) 0xFA, 0x1A, 0x30, 0x4F,
			0x26 };

	byte[] rid1 = new byte[] { 0x25 };
	byte[] rid1_public_key_bytes = StringUtil.hex2ByteArray(
			"A501781B636F6170733A2F2F746573746572312E6578616D706C652E636F6D02666D796E616D6503781A636F6170733A2F2F68656C6C6F312E6578616D706C652E6F7267041A70004B4F08A101A4010103272006215820069E912B83963ACC5941B63546867DEC106E5B9051F2EE14F3BC5CC961ACD43A");

	byte[] group_identifier = new byte[] { 0x44, 0x61, 0x6c }; // GID

	/**
	 * Test Group OSCORE context derivation and verification of its contents.
	 * 
	 * @throws OSException on test failure
	 */
	@Test
	public void testContextDerivation() throws OSException {

		// Install cryptographic providers
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);

		HashMapCtxDB db = new HashMapCtxDB();

		// Set sender & receiver keys for countersignatures
		MultiKey sid_private_key = new MultiKey(sid_public_key_bytes, sid_private_key_bytes);
		MultiKey rid1_public_key = new MultiKey(rid1_public_key_bytes);

		byte[] gmPublicKey = gm_public_key_bytes;

		// Test context generation
		GroupCtx commonCtx = new GroupCtx(master_secret, master_salt, alg, kdf, group_identifier, algCountersign,
				algSignEnc, algKeyAgreement, gmPublicKey);
		commonCtx.addSenderCtxCcs(sid, sid_private_key);
		commonCtx.addRecipientCtxCcs(rid1, REPLAY_WINDOW, rid1_public_key);

		db.addContext(uriLocal, commonCtx);

		// Verify contents

		assertEquals("Incorrect size of countersignature length", 64, commonCtx.getCountersignatureLen());
		assertEquals("Incorrect amount of recipient contexts", 1, commonCtx.getRecipientContexts().size());
		assertArrayEquals("Incorrect GM public key", gm_public_key_bytes, commonCtx.getGmPublicKey());
		assertArrayEquals("Incorrect master secret", master_secret, commonCtx.getSenderCtx().getMasterSecret());

		byte[] correctGroupEncryptionKey = StringUtil.hex2ByteArray("b2a2df8dca9627613f8a2a9ec7a256c6");
		assertArrayEquals("Incorrect group encryption key", correctGroupEncryptionKey,
				commonCtx.getGroupEncryptionKey());

		// Check sender and recipient contents
		byte[] correctSenderKey = StringUtil.hex2ByteArray("6511e11b210c2f0a89d06c667123fe7f");
		assertArrayEquals(correctSenderKey, commonCtx.getSenderCtx().getSenderKey());
		assertEquals(64, commonCtx.getSenderCtx().getCountersignatureLen());
		assertArrayEquals(sid_private_key.getCoseKey().PublicKey().AsCBOR().EncodeToBytes(),
				commonCtx.getSenderCtx().getPrivateKey().PublicKey().AsCBOR().EncodeToBytes());

		byte[] correctRecipientKey = StringUtil.hex2ByteArray("2f99604a9be876ce3267aa2806cad220");
		assertArrayEquals(correctRecipientKey,
				commonCtx.getRecipientContexts().get(new ByteId(rid1)).getRecipientKey());
		assertEquals(REPLAY_WINDOW, commonCtx.getRecipientContexts().get(new ByteId(rid1)).getRecipientReplaySize());
		assertEquals(0, commonCtx.getRecipientContexts().get(new ByteId(rid1)).getRecipientReplayWindow());
		assertArrayEquals(rid1, commonCtx.getRecipientContexts().get(new ByteId(rid1)).getRecipientId());
		assertEquals(-1, commonCtx.getRecipientContexts().get(new ByteId(rid1)).getReceiverSeq());
		assertEquals(64, commonCtx.getRecipientContexts().get(new ByteId(rid1)).getCountersignatureLen());
	}

	/**
	 * Test Group OSCORE context derivation and verification of its contents.
	 * Uses SHA512 as HKDF algorithm instead of default SHA256.
	 * 
	 * @throws OSException on test failure
	 */
	@Test
	public void testContextDerivationSha512() throws OSException {

		AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_512;

		// Install cryptographic providers
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);

		HashMapCtxDB db = new HashMapCtxDB();

		byte[] rid0 = new byte[] { (byte) 0x99 };

		// Set sender & receiver keys for countersignatures
		MultiKey sid_private_key = new MultiKey(sid_public_key_bytes, sid_private_key_bytes);
		MultiKey rid1_public_key = new MultiKey(rid1_public_key_bytes);

		byte[] gmPublicKey = gm_public_key_bytes;

		// Test context generation
		GroupCtx commonCtx = new GroupCtx(master_secret, master_salt, alg, kdf, group_identifier, algCountersign,
				algSignEnc, algKeyAgreement, gmPublicKey);
		commonCtx.addSenderCtxCcs(sid, sid_private_key);
		commonCtx.addRecipientCtxCcs(rid0, REPLAY_WINDOW, null);
		commonCtx.addRecipientCtxCcs(rid1, REPLAY_WINDOW, rid1_public_key);

		db.addContext(uriLocal, commonCtx);

		// Verify contents

		assertEquals("Incorrect size of countersignature length", 64, commonCtx.getCountersignatureLen());
		assertEquals("Incorrect amount of recipient contexts", 2, commonCtx.getRecipientContexts().size());
		assertArrayEquals("Incorrect GM public key", gmPublicKey, commonCtx.getGmPublicKey());
		assertArrayEquals("Incorrect master secret", master_secret, commonCtx.getSenderCtx().getMasterSecret());

		byte[] correctGroupEncryptionKey = StringUtil.hex2ByteArray("eaedbbcd9dd887cbe2294fd05b08b43c");

		assertArrayEquals("Incorrect group encryption key", correctGroupEncryptionKey,
				commonCtx.getGroupEncryptionKey());

		// Check sender and recipient contents
		byte[] correctSenderKey = StringUtil.hex2ByteArray("07328e19f9245c1d758e81c4bbe7b32d");
		assertArrayEquals(correctSenderKey, commonCtx.getSenderCtx().getSenderKey());
		assertEquals(64, commonCtx.getSenderCtx().getCountersignatureLen());
		assertArrayEquals(sid_private_key.getCoseKey().PublicKey().AsCBOR().EncodeToBytes(),
				commonCtx.getSenderCtx().getPrivateKey().PublicKey().AsCBOR().EncodeToBytes());

		byte[] correctRecipientKey = StringUtil.hex2ByteArray("5a75eb1ee4950928d6c443e9ac3787f7");
		assertArrayEquals(correctRecipientKey,
				commonCtx.getRecipientContexts().get(new ByteId(rid1)).getRecipientKey());
		assertEquals(REPLAY_WINDOW, commonCtx.getRecipientContexts().get(new ByteId(rid1)).getRecipientReplaySize());
		assertEquals(0, commonCtx.getRecipientContexts().get(new ByteId(rid1)).getRecipientReplayWindow());
		assertArrayEquals(rid1, commonCtx.getRecipientContexts().get(new ByteId(rid1)).getRecipientId());
		assertEquals(-1, commonCtx.getRecipientContexts().get(new ByteId(rid1)).getReceiverSeq());
		assertEquals(64, commonCtx.getRecipientContexts().get(new ByteId(rid1)).getCountersignatureLen());
	}

	/**
	 * Test COSE functionality for EncryptMessage, Recipient and OneKey.
	 * 
	 * @throws IllegalStateException on test failure
	 * @throws Exception on test failure
	 */
	@Test
	public void testCose() throws IllegalStateException, Exception {

		/*
		 * Diagnostic notation of recipientBytes: [h'
		 * A5666865616465726970726F746563746564636B7479636F6374636B69646A6F75722D7365637265746375736563656E63616B76684A7458495A3275534E356B6251666274544E576267
		 * ', {"header": "unprotected", "content": "test123"},
		 * h'656E63727970746564']
		 * 
		 * Note that the first byte string is itself a CBOR object.
		 */

		// Install cryptographic providers
		Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);

		byte[] recipientBytes = StringUtil.hex2ByteArray(
				"83584AA5666865616465726970726F746563746564636B7479636F6374636B69646A6F75722D7365637265746375736563656E63616B76684A7458495A3275534E356B6251666274544E576267A2666865616465726B756E70726F74656374656467636F6E74656E74677465737431323349656E63727970746564");
		CBORObject recipientCbor = CBORObject.DecodeFromBytes(recipientBytes);
		Recipient recipient = new Recipient();
		recipient.DecodeFromCBORObject(recipientCbor);
		CBORObject keyCbor = CBORObject.DecodeFromBytes(StringUtil.hex2ByteArray(
				"a501022001215820f4bd3ca2cd0134db71d6d42d3c3e5666d4c64ea5dc98f447a717cc781b99698e2258201f0d091f00a4129ee52709921aa340b7caf4d62b8fe15ecc2b4558634fd65fe7235820222d42677a757940fef2b8d9302f6407276a761be7ccfa35340bfaa4ee0f08ae"));
		OneKey key = new OneKey(keyCbor);
		recipient.SetKey(key);
		recipient.SetSenderKey(OneKey.generateKey(AlgorithmID.ECDSA_256));
		recipient.addAttribute(HeaderKeys.Algorithm, AlgorithmID.ECDH_ES_HKDF_256.AsCBOR(),
				Attribute.DO_NOT_SEND);

		// Test key rebuilding
		OneKey newKey = new OneKey(key.AsPublicKey(), key.AsPrivateKey());
		assertArrayEquals(key.AsCBOR().EncodeToBytes(), newKey.AsCBOR().EncodeToBytes());

		// Test Recipient and EncryptMessage
		byte[] confidential = "ciphertext".getBytes();
		byte[] aad = "aad_data".getBytes();
		byte[] partialIV = StringUtil.hex2ByteArray("01020304050607080910111213");
		byte[] nonce = StringUtil.hex2ByteArray("11121314151617181920212223");
		byte[] kid = new byte[] { 0x00 };
		AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;

		EncryptMessage enc = new EncryptMessage();
		enc.SetContent(confidential);
		enc.addAttribute(HeaderKeys.PARTIAL_IV, CBORObject.FromObject(partialIV), Attribute.UNPROTECTED);
		enc.addAttribute(HeaderKeys.KID, CBORObject.FromObject(kid), Attribute.UNPROTECTED);
		enc.setExternal(aad);
		enc.addAttribute(HeaderKeys.IV, CBORObject.FromObject(nonce), Attribute.DO_NOT_SEND);
		enc.addAttribute(HeaderKeys.Algorithm, alg.AsCBOR(), Attribute.DO_NOT_SEND);

		enc.addRecipient(recipient);
		enc.encrypt();

		// Check contents after encryption
		assertArrayEquals(aad, enc.getExternal());
		assertArrayEquals(confidential, enc.GetContent());
		assertEquals(18, enc.getEncryptedContent().length);
		assertArrayEquals(StringUtil.hex2ByteArray(
				"c083584aa5616b76684a7458495a3275534e356b6251666274544e576267636b69646a6f75722d736563726574636b7479636f63746375736563656e63666865616465726970726f746563746564a320a401022001215820"),
				Arrays.copyOf(enc.getRecipientList().get(0).EncodeToBytes(), 88));
		assertEquals(16, enc.getRecipientList().get(0).GetContent().length);
		assertArrayEquals(StringUtil.hex2ByteArray(""), enc.getRecipientList().get(0).getExternal());
		assertArrayEquals(StringUtil.hex2ByteArray("a320a401022001215820"),
				Arrays.copyOf(enc.getRecipientList().get(0).getUnprotectedAttributes().EncodeToBytes(), 10));
		assertArrayEquals(
				StringUtil.hex2ByteArray("666865616465726b756e70726f74656374656467636f6e74656e746774657374313233"),
				Arrays.copyOfRange(enc.getRecipientList().get(0).getUnprotectedAttributes().EncodeToBytes(), 77, 112));

		// Check decrypted contents
		byte[] decrypted = enc.decrypt(recipient);
		assertArrayEquals(confidential, decrypted);

		// Try encryption / decryption with multiple algorithms
		List<AlgorithmID> algsList = new ArrayList<AlgorithmID>();
		algsList.add(AlgorithmID.ECDH_ES_HKDF_256);
		algsList.add(AlgorithmID.ECDH_ES_HKDF_512);
		algsList.add(AlgorithmID.ECDH_SS_HKDF_256);
		algsList.add(AlgorithmID.ECDH_SS_HKDF_512);
		algsList.add(AlgorithmID.Direct);
		algsList.add(AlgorithmID.HKDF_HMAC_SHA_256);
		algsList.add(AlgorithmID.HKDF_HMAC_SHA_512);

		for (AlgorithmID theAlg : algsList) {

			partialIV = StringUtil.hex2ByteArray("010203040506070809101112");
			nonce = StringUtil.hex2ByteArray("111213141516171819202122");
			alg = AlgorithmID.AES_GCM_128;
			enc.addAttribute(HeaderKeys.Algorithm, alg.AsCBOR(), Attribute.DO_NOT_SEND);
			enc.addAttribute(HeaderKeys.PARTIAL_IV, CBORObject.FromObject(partialIV), Attribute.UNPROTECTED);
			enc.addAttribute(HeaderKeys.IV, CBORObject.FromObject(nonce), Attribute.DO_NOT_SEND);

			recipient.addAttribute(HeaderKeys.Algorithm, theAlg.AsCBOR(), Attribute.DO_NOT_SEND);

			if (!theAlg.toString().contains("ECDH")) {
				keyCbor = CBORObject.DecodeFromBytes(StringUtil.hex2ByteArray(
						"A5010420509F7227CEBB894A46707F82ACCB6C56E2215820F4BD3CA2CD0134DB71D6D42D3C3E5666D4C64EA5DC98F447A717CC781B99698E2258201F0D091F00A4129EE52709921AA340B7CAF4D62B8FE15ECC2B4558634FD65FE7235820222D42677A757940FEF2B8D9302F6407276A761BE7CCFA35340BFAA4EE0F08AE"));
				key = new OneKey(keyCbor);

				recipient.SetKey(key);
				recipient.SetSenderKey(key);
			}

			enc.encrypt();
			decrypted = enc.decrypt(recipient);
			assertArrayEquals(confidential, decrypted);
		}

	}
}
