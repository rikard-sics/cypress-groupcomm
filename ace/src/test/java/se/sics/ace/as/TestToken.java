/*******************************************************************************
 * Copyright (c) 2019, RISE AB
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

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.Attribute;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.Encrypt0Message;
import org.eclipse.californium.cose.HeaderKeys;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.MessageTag;
import org.eclipse.californium.cose.OneKey;
import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.DBHelper;
import se.sics.ace.Message;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissPDP;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.LocalMessage;
import se.sics.ace.examples.SQLConnector;

/**
 * Test the token endpoint class.
 * 
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class TestToken {
    
    private static OneKey publicKey;
    private static OneKey privateKey; 
    private static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static SQLConnector db = null;
    private static Token t = null;
    private static String ctiStr1;
    private static String ctiStr2;
    private static KissPDP pdp = null;
    
    private static KissTime time;
    
    /**
     * Set up tests.
     * @throws AceException 
     * @throws SQLException 
     * @throws IOException 
     * @throws CoseException 
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
        
        //Setup RS entries
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
        COSEparams coseP = new COSEparams(MessageTag.Sign1, 
                AlgorithmID.ECDSA_256, AlgorithmID.Direct);
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
        
        //Setup client entries
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
        
        
        //Setup token entries
        byte[] cti = new byte[] {0x00};
        ctiStr1 = Base64.getEncoder().encodeToString(cti);
        Map<Short, CBORObject> claims = new HashMap<>();
        claims.put(Constants.SCOPE, CBORObject.FromObject("co2"));
        claims.put(Constants.AUD,  CBORObject.FromObject("sensors"));
        claims.put(Constants.EXP, CBORObject.FromObject(time.getCurrentTime() + 1000000L));
        claims.put(Constants.AUD,  CBORObject.FromObject("actuators"));
        claims.put(Constants.CTI, CBORObject.FromObject(cti));
        db.addToken(ctiStr1, claims);
        
        cti = new byte[]{0x01};
        ctiStr2 = Base64.getEncoder().encodeToString(cti);
        claims.clear();
        claims.put(Constants.SCOPE, CBORObject.FromObject("temp"));
        claims.put(Constants.AUD,  CBORObject.FromObject("actuators"));
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
     * @throws Exception 
     */
    @AfterClass
    public static void tearDown() throws Exception {
        pdp.close();

        DBHelper.tearDownDB();
    }
    
    
    /**
     * Test the token endpoint. Request should fail since it is unauthorized.
     * 
     * @throws Exception
     */
    @Test
    public void testFailUnauthorized() throws Exception {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        LocalMessage msg = new LocalMessage(-1, "client_1", "TestAS", params); 
        Message response = t.processMessage(msg);
        assert(response.getMessageCode() == Message.FAIL_UNAUTHORIZED);
        
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
        Assert.assertArrayEquals(cbor.EncodeToBytes(), response.getRawPayload());
    }
    

    /**
     * Test the token endpoint. Request should fail since the scope is missing.
     * 
     * 
     * @throws Exception
     */
    @Test
    public void testFailMissingScope() throws Exception {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        LocalMessage msg = new LocalMessage(-1, "clientA", "TestAS", params);
        Message response = t.processMessage(msg);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        cbor.Add(Constants.ERROR_DESCRIPTION, "No scope found for message");
        Assert.assertArrayEquals(cbor.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test the token endpoint. 
     * Request should fail since the audience is missing.
     * 
     * 
     * @throws Exception
     */
    @Test
    public void testFailMissingAudience() throws Exception {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.SCOPE, CBORObject.FromObject("blah"));
        LocalMessage msg = new LocalMessage(-1, "clientA","TestAS", params);
        Message response = t.processMessage(msg);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        cbor.Add(Constants.ERROR_DESCRIPTION, "No audience found for message");
        Assert.assertArrayEquals(cbor.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test the token endpoint. 
     * Request should fail since the scope is not allowed.
     * 
     * 
     * @throws Exception
     */
    @Test
    public void testFailForbidden() throws Exception {  
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.SCOPE, CBORObject.FromObject("blah"));
        params.put(Constants.AUDIENCE, CBORObject.FromObject("blubb"));
        Message msg = new LocalMessage(-1, "clientA", "TestAS", params);
        Message response = t.processMessage(msg);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, Constants.INVALID_SCOPE);
        Assert.assertArrayEquals(cbor.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test the token endpoint. 
     * Request should fail since the audience does not support
     * a common token type.
     * 
     * 
     * @throws Exception
     */
    @Test
    public void testFailIncompatibleTokenType() throws Exception { 
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.AUDIENCE, CBORObject.FromObject("failTokenType"));
        params.put(Constants.SCOPE, CBORObject.FromObject("failTokenType"));
        Message msg = new LocalMessage(-1, "clientB", "TestAS", params);
        Message response = t.processMessage(msg);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, "Audience incompatible on token type");
        Assert.assertArrayEquals(cbor.EncodeToBytes(), response.getRawPayload());
    } 
    
    /**
     * Test the token endpoint. 
     * Request should fail since the audience does not support
     * a common profile.
     * 
     * 
     * @throws Exception
     */
    @Test
    public void testFailIncompatibleProfile() throws Exception {
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.AUDIENCE, CBORObject.FromObject("failProfile"));
        params.put(Constants.SCOPE, CBORObject.FromObject("failProfile"));
        Message msg = new LocalMessage(-1, "clientB", "TestAS", params);
        Message response = t.processMessage(msg);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, Constants.INCOMPATIBLE_PROFILES);        
        Assert.assertArrayEquals(response.getRawPayload(), cbor.EncodeToBytes());
    }
    
    /**
     * Test the token endpoint. 
     * Request should fail since the audience supports
     * an unknown token type.
     *  
     * @throws Exception
     */
    @Test
    public void testFailUnsupportedTokenType() throws Exception { 
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs5"));
        params.put(Constants.SCOPE, CBORObject.FromObject("failTokenNotImplemented"));
        Message msg = new LocalMessage(-1, "clientA", "TestAS", params);
        Message response = t.processMessage(msg);      
        assert(response.getMessageCode() == Message.FAIL_NOT_IMPLEMENTED);
        
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, "Unsupported token type");
        Assert.assertArrayEquals(cbor.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test the token endpoint. 
     * Request should fail since the audience does not support PSK
     * 
     * @throws Exception
     */
    @Test
    public void testFailPskNotSupported() throws Exception { 
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs2"));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_light"));
        Message msg = new LocalMessage(-1, "clientD", "TestAS", params);
        Message response = t.processMessage(msg);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, Constants.UNSUPPORTED_POP_KEY);
        Assert.assertArrayEquals(cbor.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test the token endpoint. 
     * Request should fail since the client provided an
     * unknown key type. 
     * 
     * @throws Exception
     */
    @Test
    public void testFailUnknownKeyType() throws Exception {
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs6"));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_valve"));
        Message msg = new LocalMessage(-1, "clientC", "TestAS", params);
        Message response = t.processMessage(msg);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, Constants.UNSUPPORTED_POP_KEY);
        Assert.assertArrayEquals(cbor.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test the token endpoint. 
     * Request should fail since the audience does not
     * have a common CwtCryptoCtx
     * 
     * @throws Exception
     */
    @Test
    public void testFailIncompatibleCwt() throws Exception { 
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.AUDIENCE, CBORObject.FromObject("failCWTpar"));
        params.put(Constants.SCOPE, CBORObject.FromObject("co2"));
        Message msg = new LocalMessage(-1, "clientB", "TestAS", params);
        Message response = t.processMessage(msg);
        assert(response.getMessageCode() == Message.FAIL_INTERNAL_SERVER_ERROR);
        
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.ERROR, "No common security context found for audience");
        Assert.assertArrayEquals(cbor.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test the token endpoint. 
     * Request should succeed with default scope.
     * 
     * @throws Exception
     */
    @Test
    public void testSucceedDefaultScope() throws Exception { 
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs1"));
        Message msg = new LocalMessage(-1, "clientB", "TestAS", params);
        Message response = t.processMessage(msg);
        CBORObject rparams = CBORObject.DecodeFromBytes(response.getRawPayload());
        params = Constants.getParams(rparams);
        assert(response.getMessageCode() == Message.CREATED);
        
        CBORObject token = params.get(Constants.ACCESS_TOKEN);
        CWT cwt = CWT.processCOSE(CBORObject.DecodeFromBytes(token.GetByteString()).EncodeToBytes(),
        						  CwtCryptoCtx.sign1Verify(publicKey, AlgorithmID.ECDSA_256.AsCBOR()));
        assert(cwt.getClaim(Constants.AUD).AsString().equals("rs1"));
    }
    
    /**
     * Test the token endpoint. 
     * Request should succeed with default audience.
     * 
     * @throws Exception
     */
    @Test
    public void testSucceedDefaultAud() throws Exception { 
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.SCOPE, CBORObject.FromObject("co2"));
        Message msg = new LocalMessage(-1, "clientB", "TestAS", params);
        Message response = t.processMessage(msg);
        CBORObject rparams = CBORObject.DecodeFromBytes(response.getRawPayload());
        params = Constants.getParams(rparams);
        assert(response.getMessageCode() == Message.CREATED);
        
        CBORObject token = params.get(Constants.ACCESS_TOKEN);
        CWT cwt = CWT.processCOSE(CBORObject.DecodeFromBytes(token.GetByteString()).EncodeToBytes(), 
                				  CwtCryptoCtx.sign1Verify(publicKey, AlgorithmID.ECDSA_256.AsCBOR()));
        assert(cwt.getClaim(Constants.SCOPE).AsString().equals("co2"));
    }
    
    /**
     * Test the token endpoint, creating a REF token with multiple scopes, one
     * of which is not allowed. Request should succeed, but not give access to
     * scope "foobar"
     * 
     * @throws Exception
     */
    @Test
    public void testSucceed() throws Exception { 
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.SCOPE, CBORObject.FromObject("rw_valve r_pressure foobar"));
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs3"));
        Message msg = new LocalMessage(-1, "clientB", "TestAS", params);
        Message response = t.processMessage(msg);
        CBORObject rparams = CBORObject.DecodeFromBytes(response.getRawPayload());
        params = Constants.getParams(rparams);
        assert(response.getMessageCode() == Message.CREATED);
        
        CBORObject token = params.get(Constants.ACCESS_TOKEN);
        String ctiStr = Base64.getEncoder().encodeToString(
        			    CBORObject.DecodeFromBytes(token.GetByteString()).GetByteString());
        Map<Short, CBORObject> claims = db.getClaims(ctiStr);
        assert(claims.get(Constants.SCOPE).AsString().contains("rw_valve"));
        assert(claims.get(Constants.SCOPE).AsString().contains("r_pressure"));
        assert(!claims.get(Constants.SCOPE).AsString().contains("foobar"));
        assert(!params.containsKey(Constants.PROFILE));    
    }
    
    
    /**
     * Test with COSE_Encrypt in cnf parameter
     *
     * @throws AceException 
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     */
    @Test
    public void testSucceedCE() throws AceException, CoseException, 
            IllegalStateException, InvalidCipherTextException {
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.SCOPE, CBORObject.FromObject("rw_valve"));
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs3"));
        CBORObject rpk = CBORObject.NewMap();
        
        Encrypt0Message enc = new Encrypt0Message();
        enc.addAttribute(HeaderKeys.Algorithm, AlgorithmID.AES_CCM_16_128_128.AsCBOR(), Attribute.PROTECTED);
        enc.SetContent(publicKey.EncodeToBytes());
        enc.encrypt(key128);
        rpk.Add(Constants.COSE_ENCRYPTED_CBOR, enc.EncodeToCBORObject());
        
        params.put(Constants.CNF, rpk);
        RawPublicKeyIdentity rpkid = new RawPublicKeyIdentity(publicKey.AsPublicKey());
        Message msg = new LocalMessage(-1, rpkid.getName(), "TestAS", params);
        Message response = t.processMessage(msg);
        CBORObject rparams = CBORObject.DecodeFromBytes(response.getRawPayload());
        params = Constants.getParams(rparams);
        assert(response.getMessageCode() == Message.CREATED);
        
        CBORObject token = params.get(Constants.ACCESS_TOKEN);
        String ctiStr = Base64.getEncoder().encodeToString(
        				CBORObject.DecodeFromBytes(token.GetByteString()).GetByteString());
        Map<Short, CBORObject> claims = db.getClaims(ctiStr);
        assert(claims.get(Constants.SCOPE).AsString().contains("rw_valve"));
    }
    
    /**
     * Test the token endpoint. Test purging expired tokens.
     * 
     * @throws Exception
     */
    @Test
    public void testPurge() throws Exception {
        Map<Short, CBORObject> claims = db.getClaims(ctiStr1);
        assert(!claims.isEmpty());
        
        db.purgeExpiredTokens(time.getCurrentTime() + 1000001L);
        claims = db.getClaims(ctiStr1);
        assert(claims.isEmpty());
    }
    
    /**
     * Test the token endpoint. Test removing a specific token.
     * 
     * @throws Exception
     */
    @Test
    public void testRemoveToken() throws Exception { 
        Map<Short, CBORObject> claims = db.getClaims(ctiStr2);
        assert(!claims.isEmpty());
        
        db.deleteToken(ctiStr2);
        claims = db.getClaims(ctiStr2);
        assert(claims.isEmpty());
    }
    
    /**
     * Test the token endpoint by requesting multiple tokens and
     * checking that the cti counter is correctly adjusted.
     * This uses default audience and scope.
     * 
     * @throws Exception
     */
    @Test
    public void testMultiRequest() throws Exception {
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        Message msg = new LocalMessage(-1, "clientB", "TestAS", params);
        t.processMessage(msg);
        Long ctiCtrStart = db.getCtiCounter();
        for (int i=0; i<10; i++) {
            t.processMessage(msg);
        }
        Long ctiCtrEnd = db.getCtiCounter();
        
        // This is consistent with the fact that the Authorization Server includes the 'exi' claim
        // in every issued Access Token. Thus, the per-RS Exi Sequence Numbers are incremented and
        // persisted in the database, while the single global counter used as 'cti' for issued
        // Access Tokens without the 'exi' claim is never used and incremented.
        assert(ctiCtrEnd == ctiCtrStart);
        
    }
    
    /**
     * Test the token endpoint by requesting multiple tokens and
     * checking that the cti counter is correctly adjusted.
     * This uses default audience and scope.
     * 
     * @throws Exception
     */
    @Test
    public void testTokenConfig() throws Exception {
        Set<Short> tokenConfig = new HashSet<>();
        tokenConfig.add(Constants.CTI);
        t = new Token("testAS2", pdp, db, new KissTime(), privateKey, tokenConfig, false, null);
        
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.SCOPE, CBORObject.FromObject("r_pressure"));
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs3"));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KID_CBOR, publicKey.get(KeyKeys.KeyId));
        params.put(Constants.CNF, cnf);
        
        Message msg = new LocalMessage(-1, "clientE", "TestAS", params);
        Message response = t.processMessage(msg);
        CBORObject rparams = CBORObject.DecodeFromBytes(response.getRawPayload());
        params = Constants.getParams(rparams);
        assert(response.getMessageCode() == Message.CREATED);
        
        CBORObject token = params.get(Constants.ACCESS_TOKEN);
        String ctiStr = Base64.getEncoder().encodeToString(
                		CBORObject.DecodeFromBytes(token.GetByteString()).GetByteString());
        Map<Short, CBORObject> claims = db.getClaims(ctiStr);
        assert(claims.containsKey(Constants.CTI));
        assert(claims.size() == 1);
        
        db.deleteToken(ctiStr);
        t = new Token("AS", pdp, db, new KissTime(), privateKey, null); 
    }
    
    /**
     * Test the grant flow.
     * 
     * @throws Exception
     */
    @Test
    public void testGrant() throws Exception {
        //Create the grant
        byte[] ctiB = new byte[] {0x00, 0x01};
        String cti = Base64.getEncoder().encodeToString(ctiB);
        
        Map<Short, CBORObject> claims = new HashMap<>();
        claims.put(Constants.AUD, CBORObject.FromObject("rs1"));
        claims.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        claims.put(Constants.CTI, CBORObject.FromObject(ctiB));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KID_CBOR, publicKey.get(KeyKeys.KeyId));
        claims.put(Constants.CNF, cnf);
        
        CWT cwt = new CWT(claims);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, AlgorithmID.AES_CCM_16_64_128.AsCBOR());
        CBORObject cwtCB = cwt.encode(ctx);
        Map<Short, CBORObject> rsInfo = new HashMap<>(); 
        rsInfo.put(Constants.ACCESS_TOKEN, CBORObject.FromObject(cwtCB.EncodeToBytes()));
        rsInfo.put(Constants.CNF, cnf);
        db.addGrant("testGrant", cti, claims, rsInfo);
        
        //Prepare the request
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.authzCode);
        params.put(Constants.CODE, CBORObject.FromObject("testGrant"));
        Message msg = new LocalMessage(-1, "clientA", "TestAS", params);
        Message response = t.processMessage(msg);
        CBORObject rparams = CBORObject.DecodeFromBytes(response.getRawPayload());
        params = Constants.getParams(rparams);
        assert(response.getMessageCode() == Message.CREATED);
        
        CBORObject token = params.get(Constants.ACCESS_TOKEN);
        CWT cwt2 = CWT.processCOSE(CBORObject.DecodeFromBytes(token.GetByteString()).EncodeToBytes(), ctx);
        claims = cwt2.getClaims();
        assert(claims.get(Constants.SCOPE).AsString().contains("r_temp"));
        assert(claims.get(Constants.AUD).AsString().contains("rs1"));     
    }
    
    /**
     * Test issuing an OSCORE cnf
     * 
     * @throws Exception
     */
    @Test
    public void testOscoreCnf() throws Exception {
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.SCOPE, CBORObject.FromObject("rw_valve r_pressure foobar"));
        params.put(Constants.AUDIENCE, CBORObject.FromObject("rs3"));
        Message msg = new LocalMessage(-1, "clientB", "TestAS", params);
        Message response = t.processMessage(msg);
        CBORObject rparams = CBORObject.DecodeFromBytes(response.getRawPayload());
        params = Constants.getParams(rparams);
        assert(response.getMessageCode() == Message.CREATED);
        
        CBORObject token = params.get(Constants.ACCESS_TOKEN);
        String ctiStr = Base64.getEncoder().encodeToString(
                	    CBORObject.DecodeFromBytes(token.GetByteString()).GetByteString());
        Map<Short, CBORObject> claims = db.getClaims(ctiStr);
        CBORObject cnf = claims.get(Constants.CNF);
        assert(cnf.getType().equals(CBORType.Map));
        assert(cnf.ContainsKey(CBORObject.FromObject(Constants.OSCORE_Input_Material)));
        
        CBORObject osctx = cnf.get(CBORObject.FromObject(Constants.OSCORE_Input_Material));
        assert(osctx.getType().equals(CBORType.Map));
        assert(osctx.ContainsKey(CBORObject.FromObject(Constants.OS_MS)));
    }
    
}
