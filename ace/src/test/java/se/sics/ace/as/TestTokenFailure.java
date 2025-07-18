/*******************************************************************************
 * Copyright (c) 2025, RISE AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, 
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/
package se.sics.ace.as;

import java.io.IOException;
import java.sql.SQLException;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.MessageTag;
import org.eclipse.californium.cose.OneKey;
import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.DBHelper;
import se.sics.ace.Message;
import se.sics.ace.examples.KissPDP;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.LocalMessage;
import se.sics.ace.examples.SQLConnector;

/**
 * Test the token endpoint class for specific failure cases.
 * 
 * @author Ludwig Seitz, Marco Tiloca & Rikard Höglund
 *
 */
public class TestTokenFailure {

	private static OneKey publicKey;
	private static OneKey privateKey;
	private static byte[] key128 = { 'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
	private static SQLConnector db = null;
	private static Token t = null;
	private static String ctiStr1;
	private static String ctiStr2;
	private static KissPDP pdp = null;

	private static KissTime time;

	/**
	 * Set up tests.
	 * 
	 * @throws AceException on failure
	 * @throws SQLException on failure
	 * @throws IOException on failure
	 * @throws CoseException on failure
	 */
	@BeforeClass
	public static void setUp() throws AceException, SQLException, IOException, CoseException {

		DBHelper.setUpDB();
		db = DBHelper.getSQLConnector();

		privateKey = OneKey.generateKey(AlgorithmID.ECDSA_256);
		publicKey = privateKey.PublicKey();
		publicKey.add(KeyKeys.KeyId, CBORObject.FromObject("myKey".getBytes(Constants.charset)));

		CBORObject keyData = CBORObject.NewMap();
		keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
		keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128));
		OneKey skey = new OneKey(keyData);

		// Setup RS entries
		Set<String> profiles = new HashSet<>();
		profiles.add("coap_dtls");
		profiles.add("coap_oscore");

		Set<String> scopes = new HashSet<>();
		scopes.add("temp");
		scopes.add("co2");

		Set<String> auds = new HashSet<>();
		auds.add("actuators");

		Set<String> keyTypes = new HashSet<>();
		keyTypes.add("PSK");
		keyTypes.add("RPK");

		Set<Short> tokenTypes = new HashSet<>();
		tokenTypes.add(AccessTokenFactory.CWT_TYPE);
		tokenTypes.add(AccessTokenFactory.REF_TYPE);

		Set<COSEparams> cose = new HashSet<>();
		COSEparams coseP = new COSEparams(MessageTag.Sign1, AlgorithmID.ECDSA_256, AlgorithmID.Direct);
		cose.add(coseP);

		long expiration = 1000000L;

		db.addRS("rs1", profiles, scopes, auds, keyTypes, tokenTypes, cose, expiration, skey, skey, publicKey);

		profiles.remove("coap_oscore");
		scopes.clear();
		auds.clear();
		auds.add("sensors");
		auds.add("failTokenType");
		keyTypes.remove("PSK");
		tokenTypes.remove(AccessTokenFactory.REF_TYPE);
		expiration = 300000L;
		db.addRS("rs2", profiles, scopes, auds, keyTypes, tokenTypes, cose, expiration, skey, skey, null);

		profiles.clear();
		profiles.add("coap_oscore");
		scopes.add("co2");
		auds.clear();
		auds.add("actuators");
		auds.add("failTokenType");
		keyTypes.clear();
		keyTypes.add("PSK");
		keyTypes.add("RPK");
		tokenTypes.clear();
		tokenTypes.add(AccessTokenFactory.REF_TYPE);
		cose.clear();
		coseP = new COSEparams(MessageTag.MAC0, AlgorithmID.HMAC_SHA_256, AlgorithmID.Direct);
		cose.add(coseP);
		expiration = 30000L;
		db.addRS("rs3", profiles, scopes, auds, keyTypes, tokenTypes, cose, expiration, null, null, publicKey);

		profiles.clear();
		profiles.add("coap_dtls");
		auds.clear();
		auds.add("failProfile");
		scopes.add("failProfile");
		keyTypes.clear();
		keyTypes.add("PSK");
		tokenTypes.clear();
		tokenTypes.add(AccessTokenFactory.REF_TYPE);
		cose.clear();
		coseP = new COSEparams(MessageTag.MAC0, AlgorithmID.HMAC_SHA_256, AlgorithmID.Direct);
		cose.add(coseP);
		expiration = 30000L;
		db.addRS("rs4", profiles, scopes, auds, keyTypes, tokenTypes, cose, expiration, null, null, publicKey);

		profiles.clear();
		profiles.add("coap_dtls");
		scopes.add("co2");
		auds.clear();
		auds.add("failTokenNotImplemented");
		keyTypes.clear();
		keyTypes.add("PSK");
		tokenTypes.clear();
		tokenTypes.add(AccessTokenFactory.TEST_TYPE);
		cose.clear();
		coseP = new COSEparams(MessageTag.MAC0, AlgorithmID.HMAC_SHA_256, AlgorithmID.Direct);
		cose.add(coseP);
		expiration = 30000L;
		db.addRS("rs5", profiles, scopes, auds, keyTypes, tokenTypes, cose, expiration, null, null, publicKey);

		profiles.clear();
		profiles.add("coap_oscore");
		scopes.add("co2");
		auds.clear();
		auds.add("aud6");
		keyTypes.clear();
		keyTypes.add("TST");
		tokenTypes.clear();
		tokenTypes.add(AccessTokenFactory.REF_TYPE);
		cose.clear();
		coseP = new COSEparams(MessageTag.MAC0, AlgorithmID.HMAC_SHA_256, AlgorithmID.Direct);
		cose.add(coseP);
		expiration = 30000L;
		db.addRS("rs6", profiles, scopes, auds, keyTypes, tokenTypes, cose, expiration, null, null, publicKey);

		profiles.clear();
		profiles.add("coap_oscore");
		scopes.add("co2");
		auds.clear();
		auds.add("failCWTpar");
		keyTypes.clear();
		keyTypes.add("PSK");
		tokenTypes.clear();
		tokenTypes.add(AccessTokenFactory.CWT_TYPE);
		cose.clear();
		coseP = new COSEparams(MessageTag.MAC0, AlgorithmID.HMAC_SHA_256, AlgorithmID.Direct);
		cose.add(coseP);
		expiration = 30000L;
		db.addRS("rs7", profiles, scopes, auds, keyTypes, tokenTypes, cose, expiration, null, null, publicKey);

		// Setup client entries
		profiles.clear();
		profiles.add("coap_dtls");
		keyTypes.clear();
		keyTypes.add("RPK");
		db.addClient("clientA", profiles, null, null, keyTypes, null, publicKey);

		profiles.clear();
		profiles.add("coap_oscore");
		keyTypes.clear();
		keyTypes.add("PSK");
		db.addClient("clientB", profiles, "co2", "rs1", keyTypes, skey, null);

		profiles.clear();
		profiles.add("coap_oscore");
		keyTypes.clear();
		keyTypes.add("TST");
		db.addClient("clientC", profiles, "co2", "sensors", keyTypes, skey, null);

		profiles.clear();
		profiles.add("coap_dtls");
		keyTypes.clear();
		keyTypes.add("RPK");
		keyTypes.add("PSK");
		db.addClient("clientD", profiles, null, null, keyTypes, skey, null);

		profiles.clear();
		profiles.add("coap_dtls");
		profiles.add("coap_oscore");
		keyTypes.clear();
		keyTypes.add("RPK");
		keyTypes.add("PSK");
		db.addClient("clientE", profiles, null, null, keyTypes, skey, publicKey);

		RawPublicKeyIdentity rpkid = new RawPublicKeyIdentity(publicKey.AsPublicKey());
		profiles.clear();
		profiles.add("coap_oscore");
		keyTypes.clear();
		keyTypes.add("RPK");
		db.addClient(rpkid.getName(), profiles, null, null, keyTypes, skey, publicKey);

		time = new KissTime();

		// Setup token entries
		byte[] cti = new byte[] { 0x00 };
		ctiStr1 = Base64.getEncoder().encodeToString(cti);
		Map<Short, CBORObject> claims = new HashMap<>();
		claims.put(Constants.SCOPE, CBORObject.FromObject("co2"));
		claims.put(Constants.AUD, CBORObject.FromObject("sensors"));
		claims.put(Constants.EXP, CBORObject.FromObject(time.getCurrentTime() + 1000000L));
		claims.put(Constants.AUD, CBORObject.FromObject("actuators"));
		claims.put(Constants.CTI, CBORObject.FromObject(cti));
		db.addToken(ctiStr1, claims);

		cti = new byte[] { 0x01 };
		ctiStr2 = Base64.getEncoder().encodeToString(cti);
		claims.clear();
		claims.put(Constants.SCOPE, CBORObject.FromObject("temp"));
		claims.put(Constants.AUD, CBORObject.FromObject("actuators"));
		claims.put(Constants.EXP, CBORObject.FromObject(time.getCurrentTime() + 2000000L));
		claims.put(Constants.CTI, CBORObject.FromObject(cti));
		db.addToken(ctiStr2, claims);

		pdp = new KissPDP(db);
		pdp.addTokenAccess("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w");
		pdp.addTokenAccess(rpkid.getName());
		pdp.addTokenAccess("clientA");
		pdp.addTokenAccess("clientB");
		pdp.addTokenAccess("clientC");
		pdp.addTokenAccess("clientD");
		pdp.addTokenAccess("clientE");

		pdp.addAccess(rpkid.getName(), "rs3", "rw_valve");
		pdp.addAccess("clientA", "rs1", "r_temp");
		pdp.addAccess("clientA", "rs1", "rw_config");
		pdp.addAccess("clientA", "rs2", "r_light");
		pdp.addAccess("clientA", "rs5", "failTokenNotImplemented");

		pdp.addAccess("clientB", "rs1", "r_temp");
		pdp.addAccess("clientB", "rs1", "co2");
		pdp.addAccess("clientB", "rs2", "r_light");
		pdp.addAccess("clientB", "rs2", "r_config");
		pdp.addAccess("clientB", "rs2", "failTokenType");
		pdp.addAccess("clientB", "rs3", "rw_valve");
		pdp.addAccess("clientB", "rs3", "r_pressure");
		pdp.addAccess("clientB", "rs3", "failTokenType");
		pdp.addAccess("clientB", "rs4", "failProfile");
		pdp.addAccess("clientB", "rs6", "co2");
		pdp.addAccess("clientB", "rs7", "co2");

		pdp.addAccess("clientC", "rs3", "r_valve");
		pdp.addAccess("clientC", "rs3", "r_pressure");
		pdp.addAccess("clientC", "rs6", "r_valve");

		pdp.addAccess("clientD", "rs1", "r_temp");
		pdp.addAccess("clientD", "rs1", "rw_config");
		pdp.addAccess("clientD", "rs2", "r_light");
		pdp.addAccess("clientD", "rs5", "failTokenNotImplemented");
		pdp.addAccess("clientD", "rs1", "r_temp");

		pdp.addAccess("clientE", "rs3", "rw_valve");
		pdp.addAccess("clientE", "rs3", "r_pressure");
		pdp.addAccess("clientE", "rs3", "failTokenType");

		t = new Token("AS", pdp, db, time, privateKey, null);
	}

	/**
	 * Deletes the test DB after the tests
	 * 
	 * @throws Exception on failure
	 */
	@AfterClass
	public static void tearDown() throws Exception {
		pdp.close();

		DBHelper.tearDownDB();
	}

	/**
	 * Test the token endpoint. The request should fail since the message does
	 * not contain a Sender ID.
	 * 
	 */
	@Test
	public void testFailMissingId() {
		Map<Short, CBORObject> params = new HashMap<>();
		params.put(Constants.GRANT_TYPE, Token.clientCredentials);
		params.put(Constants.AUDIENCE, CBORObject.FromObject("rs1"));
		Message msg = new LocalMessage(-1, null, "TestAS", params);

		Message response = t.processMessage(msg);
		assert (response.getMessageCode() == Message.FAIL_UNAUTHORIZED);

		CBORObject cbor = CBORObject.NewMap();
		cbor.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
		Assert.assertArrayEquals(cbor.EncodeToBytes(), response.getRawPayload());
	}

	/**
	 * Test the token endpoint. The request should fail since the grant type is
	 * unsupported
	 * 
	 */
	@Test
	public void testUnsupportedGrantType() {
		Map<Short, CBORObject> params = new HashMap<>();
		CBORObject grantType = CBORObject.FromObject(10);
		params.put(Constants.GRANT_TYPE, grantType);
		params.put(Constants.AUDIENCE, CBORObject.FromObject("rs1"));
		Message msg = new LocalMessage(-1, "clientB", "TestAS", params);

		Message response = t.processMessage(msg);
		assert (response.getMessageCode() == Message.FAIL_BAD_REQUEST);

		CBORObject cbor = CBORObject.NewMap();
		cbor.Add(Constants.ERROR, Constants.UNSUPPORTED_GRANT_TYPE);
		Assert.assertArrayEquals(cbor.EncodeToBytes(), response.getRawPayload());
	}

	/**
	 * Test the token endpoint. The request should fail since the scope is of an
	 * invalid type
	 * 
	 */
	@Test
	public void testInvalidScope() {
		Map<Short, CBORObject> params = new HashMap<>();
		params.put(Constants.GRANT_TYPE, Token.clientCredentials);
		params.put(Constants.AUDIENCE, CBORObject.FromObject("rs1"));
		CBORObject scope = CBORObject.NewMap();
		params.put(Constants.SCOPE, scope);
		Message msg = new LocalMessage(-1, "clientB", "TestAS", params);

		Message response = t.processMessage(msg);
		assert (response.getMessageCode() == Message.FAIL_BAD_REQUEST);

		CBORObject cbor = CBORObject.NewMap();
		cbor.Add(Constants.ERROR, Constants.INVALID_REQUEST);
		cbor.Add(Constants.ERROR_DESCRIPTION, "Invalid datatype for scope");
		Assert.assertArrayEquals(cbor.EncodeToBytes(), response.getRawPayload());
	}

	/**
	 * Test the token endpoint. The request should fail since the audience is
	 * malformed
	 * 
	 */
	@Test
	public void testMalformedAudience() {
		Map<Short, CBORObject> params = new HashMap<>();
		params.put(Constants.GRANT_TYPE, Token.clientCredentials);
		CBORObject audience = CBORObject.FromObject(100);
		params.put(Constants.AUDIENCE, audience);
		Message msg = new LocalMessage(-1, "clientB", "TestAS", params);

		Message response = t.processMessage(msg);
		assert (response.getMessageCode() == Message.FAIL_BAD_REQUEST);

		CBORObject cbor = CBORObject.NewMap();
		cbor.Add(Constants.ERROR, Constants.INVALID_REQUEST);
		cbor.Add(Constants.ERROR_DESCRIPTION, "Audience malformed");
		Assert.assertArrayEquals(cbor.EncodeToBytes(), response.getRawPayload());
	}

	/**
	 * Test the token endpoint. The request should fail since the cnf is
	 * malformed
	 * 
	 */
	@Test
	public void testMalformedCnf() {
		Map<Short, CBORObject> params = new HashMap<>();
		params.put(Constants.GRANT_TYPE, Token.clientCredentials);
		params.put(Constants.SCOPE, CBORObject.FromObject("r_pressure"));
		params.put(Constants.AUDIENCE, CBORObject.FromObject("rs3"));
		CBORObject cnf = CBORObject.NewMap();
		CBORObject keyType = CBORObject.FromObject(100);
		cnf.Add(keyType, publicKey.get(KeyKeys.KeyId));
		params.put(Constants.REQ_CNF, cnf);

		Message msg = new LocalMessage(-1, "clientE", "TestAS", params);
		Message response = t.processMessage(msg);
		assert (response.getMessageCode() == Message.FAIL_BAD_REQUEST);

		CBORObject cbor = CBORObject.NewMap();
		cbor.Add(Constants.ERROR, Constants.INVALID_REQUEST);
		cbor.Add(Constants.ERROR_DESCRIPTION, "Malformed 'cnf' parameter in request");
		Assert.assertArrayEquals(cbor.EncodeToBytes(), response.getRawPayload());
	}

	/**
	 * Test the token endpoint. The request should fail since the kid within the
	 * cnf is malformed
	 * 
	 */
	@Test
	public void testMalformedCnfKid() {
		Map<Short, CBORObject> params = new HashMap<>();
		params.put(Constants.GRANT_TYPE, Token.clientCredentials);
		params.put(Constants.SCOPE, CBORObject.FromObject("r_pressure"));
		params.put(Constants.AUDIENCE, CBORObject.FromObject("rs3"));
		CBORObject cnf = CBORObject.NewMap();
		CBORObject kidInt = CBORObject.FromObject(1);
		cnf.Add(Constants.COSE_KID_CBOR, kidInt);
		params.put(Constants.REQ_CNF, cnf);

		Message msg = new LocalMessage(-1, "clientE", "TestAS", params);
		Message response = t.processMessage(msg);
		assert (response.getMessageCode() == Message.FAIL_BAD_REQUEST);

		CBORObject cbor = CBORObject.NewMap();
		cbor.Add(Constants.ERROR, Constants.INVALID_REQUEST);
		cbor.Add(Constants.ERROR_DESCRIPTION, "Malformed kid in 'cnf' parameter");
		Assert.assertArrayEquals(cbor.EncodeToBytes(), response.getRawPayload());
	}

	/**
	 * Test the token endpoint. The request should fail since the key within the
	 * cnf is malformed
	 * 
	 */
	@Test
	public void testMalformedCnfKey() {
		Map<Short, CBORObject> params = new HashMap<>();
		params.put(Constants.GRANT_TYPE, Token.clientCredentials);
		params.put(Constants.SCOPE, CBORObject.FromObject("r_pressure"));
		params.put(Constants.AUDIENCE, CBORObject.FromObject("rs3"));
		CBORObject cnf = CBORObject.NewMap();
		CBORObject key = CBORObject.FromObject(new byte[] { 11, 22 });
		cnf.Add(Constants.COSE_KEY_CBOR, key);
		params.put(Constants.REQ_CNF, cnf);

		Message msg = new LocalMessage(-1, "clientE", "TestAS", params);
		Message response = t.processMessage(msg);
		assert (response.getMessageCode() == Message.FAIL_INTERNAL_SERVER_ERROR);

		Assert.assertNull(response.getRawPayload());
	}

	/**
	 * Test the token endpoint. The request should fail since the key within the
	 * cnf is invalid
	 * 
	 * @throws CoseException on failure
	 * 
	 */
	@Test
	public void testInvalidCnfKey() throws CoseException {
		Map<Short, CBORObject> params = new HashMap<>();
		params.put(Constants.GRANT_TYPE, Token.clientCredentials);
		params.put(Constants.SCOPE, CBORObject.FromObject("r_pressure"));
		params.put(Constants.AUDIENCE, CBORObject.FromObject("rs3"));
		CBORObject cnf = CBORObject.NewMap();
		CBORObject key = CBORObject.FromObject(OneKey.generateKey(AlgorithmID.ECDSA_256));
		cnf.Add(Constants.COSE_KEY_CBOR, key);
		params.put(Constants.REQ_CNF, cnf);

		Message msg = new LocalMessage(-1, "clientE", "TestAS", params);
		Message response = t.processMessage(msg);
		assert (response.getMessageCode() == Message.FAIL_INTERNAL_SERVER_ERROR);

		Assert.assertNull(response.getRawPayload());
	}

	/**
	 * Test the token endpoint. The request should fail since the key within the
	 * cnf uses unauthenticated RPK
	 * 
	 * @throws CoseException on failure
	 * 
	 */
	@Test
	public void testInvalidCnfUnauthenticatedRpk() throws CoseException {
		Map<Short, CBORObject> params = new HashMap<>();
		params.put(Constants.GRANT_TYPE, Token.clientCredentials);
		params.put(Constants.SCOPE, CBORObject.FromObject("r_pressure"));
		params.put(Constants.AUDIENCE, CBORObject.FromObject("rs3"));
		CBORObject cnf = CBORObject.NewMap();
		CBORObject key = OneKey.generateKey(AlgorithmID.ECDSA_256).AsCBOR();
		cnf.Add(Constants.COSE_KEY_CBOR, key);
		params.put(Constants.REQ_CNF, cnf);

		Message msg = new LocalMessage(-1, "clientE", "TestAS", params);
		Message response = t.processMessage(msg);
		assert (response.getMessageCode() == Message.FAIL_BAD_REQUEST);

		CBORObject cbor = CBORObject.NewMap();
		cbor.Add(Constants.ERROR, Constants.UNSUPPORTED_POP_KEY);
		Assert.assertArrayEquals(cbor.EncodeToBytes(), response.getRawPayload());
	}

	/**
	 * Test the token endpoint. The request should fail since the key within the
	 * cnf will fail to decrypt
	 * 
	 * @throws CoseException on failure
	 * 
	 */
	@Test
	public void testFailCnfKeyDecryption() throws CoseException {
		Map<Short, CBORObject> params = new HashMap<>();
		params.put(Constants.GRANT_TYPE, Token.clientCredentials);
		params.put(Constants.SCOPE, CBORObject.FromObject("r_pressure"));
		params.put(Constants.AUDIENCE, CBORObject.FromObject("rs3"));
		CBORObject cnf = CBORObject.NewMap();
		CBORObject key = OneKey.generateKey(AlgorithmID.ECDSA_256).AsCBOR();
		cnf.Add(Constants.COSE_ENCRYPTED_CBOR, key);
		params.put(Constants.REQ_CNF, cnf);

		Message msg = new LocalMessage(-1, "clientE", "TestAS", params);
		Message response = t.processMessage(msg);
		assert (response.getMessageCode() == Message.FAIL_INTERNAL_SERVER_ERROR);

		Assert.assertNull(response.getRawPayload());
	}

	/**
	 * Test the token endpoint. The request should fail since the key within the
	 * cnf is a PSK
	 * 
	 * @throws CoseException on failure
	 * 
	 */
	@Test
	public void testFailCnfKeyPsk() throws CoseException {
		Map<Short, CBORObject> params = new HashMap<>();
		params.put(Constants.GRANT_TYPE, Token.clientCredentials);
		params.put(Constants.SCOPE, CBORObject.FromObject("r_pressure"));
		params.put(Constants.AUDIENCE, CBORObject.FromObject("rs3"));
		CBORObject cnf = CBORObject.NewMap();
		CBORObject key = OneKey.generateKey(AlgorithmID.ECDSA_256).AsCBOR();
		byte[] dummyPsk = new byte[] { 11, 22 };
		key.set(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
		key.set(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(dummyPsk));
		cnf.Add(Constants.COSE_KEY_CBOR, key);
		params.put(Constants.REQ_CNF, cnf);

		Message msg = new LocalMessage(-1, "clientE", "TestAS", params);
		Message response = t.processMessage(msg);
		assert (response.getMessageCode() == Message.FAIL_BAD_REQUEST);

		CBORObject cbor = CBORObject.NewMap();
		cbor.Add(Constants.ERROR, Constants.INVALID_REQUEST);
		cbor.Add(Constants.ERROR_DESCRIPTION, "Client tried to provide cnf PSK");
		Assert.assertArrayEquals(cbor.EncodeToBytes(), response.getRawPayload());
	}

}
