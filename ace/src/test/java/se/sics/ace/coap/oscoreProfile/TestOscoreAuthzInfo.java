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
package se.sics.ace.coap.oscoreProfile;

import java.io.File;
import java.io.IOException;
import java.security.SecureRandom;
import java.sql.SQLException;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import org.eclipse.californium.oscore.OSException;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
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
import se.sics.ace.TestConfig;
import se.sics.ace.Util;
import se.sics.ace.as.AccessTokenFactory;
import se.sics.ace.as.Introspect;
import se.sics.ace.coap.CoapReq;
import se.sics.ace.coap.rs.oscoreProfile.OscoreAuthzInfo;
import se.sics.ace.coap.rs.oscoreProfile.OscoreCtxDbSingleton;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissPDP;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.KissValidator;
import se.sics.ace.examples.LocalMessage;
import se.sics.ace.examples.SQLConnector;
import se.sics.ace.rs.AuthzInfo;
import se.sics.ace.rs.IntrospectionException;
import se.sics.ace.rs.IntrospectionHandler4Tests;
import se.sics.ace.rs.TokenRepository;

/**
 * 
 * @author Ludwig Seitz and Marco Tiloca
 */
public class TestOscoreAuthzInfo {
    
    static OneKey publicKey;
    static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static byte[] key128a = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static SQLConnector db = null;

    private static AuthzInfo ai = null;
    private static Introspect i; 
    private static KissPDP pdp = null;
    
    private final static int MAX_UNFRAGMENTED_SIZE = 4096;
    
    /**
     * Set up tests.
     * @throws SQLException 
     * @throws AceException 
     * @throws IOException 
     * @throws CoseException 
     */
    @BeforeClass
    public static void setUp() 
            throws SQLException, AceException, IOException, CoseException {

        DBHelper.setUpDB();
        db = DBHelper.getSQLConnector();

        OneKey key = OneKey.generateKey(AlgorithmID.ECDSA_256);
        publicKey = key.PublicKey();

        
        OneKey sharedKey = new OneKey();
        sharedKey.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        sharedKey.add(KeyKeys.KeyId, CBORObject.FromObject(new byte[]{0x74, 0x11}));
        sharedKey.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));

        Set<String> profiles = new HashSet<>();
        profiles.add("coap_dtls");
        Set<String> keyTypes = new HashSet<>();
        keyTypes.add("PSK");
        db.addClient("client1", profiles, null, null, keyTypes, null, publicKey);
        db.addClient("client2", profiles, null, null, keyTypes, sharedKey, publicKey);

        
        String rsId = "rs1";
        
        Set<String> scopes = new HashSet<>();
        scopes.add("temp");
        scopes.add("co2");
        Set<String> auds = new HashSet<>();
        auds.add("aud1");
        auds.add("actuators");
        Set<Short> tokenTypes = new HashSet<>();
        tokenTypes.add(AccessTokenFactory.CWT_TYPE);
        tokenTypes.add(AccessTokenFactory.REF_TYPE);
        Set<COSEparams> cose = new HashSet<>();
        COSEparams coseP = new COSEparams(MessageTag.Sign1, AlgorithmID.ECDSA_256, AlgorithmID.Direct);
        cose.add(coseP);
        long expiration = 1000000L;
        CBORObject keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128));
        OneKey psk = new OneKey(keyData);
        db.addRS(rsId, profiles, scopes, auds, keyTypes, tokenTypes, cose, expiration, psk, psk, publicKey);
                
        
        Set<Short> actions = new HashSet<>();
        actions.add(Constants.GET);
        Map<String, Set<Short>> myResource = new HashMap<>();
        myResource.put("temp", actions);
        Map<String, Map<String, Set<Short>>> myScopes = new HashMap<>();
        myScopes.put("r_temp", myResource);
        
        actions = new HashSet<>();
        actions.add(Constants.GET);
        actions.add(Constants.POST);
        myResource = new HashMap<>();
        myResource.put("co2", actions);
        myScopes.put("r_co2", myResource);
        
        KissValidator valid = new KissValidator(Collections.singleton("aud1"), myScopes);
        coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());

        String tokenFile = TestConfig.testFilePath + "tokens.json";
        //Delete lingering token file from old test runs
        new File(TestConfig.testFilePath + "tokens.json").delete();
        
        pdp = new KissPDP(db);
        pdp.addIntrospectAccess("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w");
        pdp.addIntrospectAccess(rsId);
        
        i = new Introspect(pdp, db, new KissTime(), key, null);
        
        ai = new OscoreAuthzInfo(Collections.singletonList("TestAS"), 
                new KissTime(),  new IntrospectionHandler4Tests(i, "rs1", "TestAS"),
                rsId, valid, ctx, tokenFile, valid, false);
    }
    
    /**
     * Cleanup before each individual test.
     */
    @Before
    public void cleanOscoreCtxDB() {
        OscoreCtxDbSingleton.getInstance().purge();
    }
    
    /**
     * Deletes the test DB after the tests
     * @throws Exception 
     */
    @AfterClass
    public static void tearDown() throws Exception {
        DBHelper.tearDownDB();
        pdp.close();
        i.close();
        ai.close();
        new File(TestConfig.testFilePath + "tokens.json").delete();
    }
    
    /**
     * Test invalid payload submission to OscoreAuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testInvalidPayload() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Request r = Request.newPost();
        CoapReq request = CoapReq.getInstance(r);
        request.getOptions().setContentFormat(Constants.APPLICATION_ACE_CBOR);
        Message response = ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST); 
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, "Invalid payload");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test no-map CBOR submission to OscoreAuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testNoMapPayload() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Request r = Request.newPost();
        CBORObject foo = CBORObject.FromObject("bar");
        r.setPayload(foo.EncodeToBytes());
        CoapReq request = CoapReq.getInstance(r);
        request.getOptions().setContentFormat(Constants.APPLICATION_ACE_CBOR);
        Message response = ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST); 
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, "Payload to authz-info must be a CBOR map");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test map with no ACCESS_TOKEN
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testNoAccessTokenPayload() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Request r = Request.newPost();
        CBORObject foo = CBORObject.NewMap();
        foo.Add(Constants.OSCORE_Input_Material, "bar");
        byte[] n1 = new byte[8];
        new SecureRandom().nextBytes(n1);
        foo.Add(Constants.NONCE1, n1);
        byte[] id1  = new byte[] {0x00};
        foo.Add(Constants.ACE_CLIENT_RECIPIENTID, id1);
        r.setPayload(foo.EncodeToBytes());
        CoapReq request = CoapReq.getInstance(r);
        request.getOptions().setContentFormat(Constants.APPLICATION_ACE_CBOR);
        Message response = ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST); 
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, "Missing mandatory parameter 'access_token'");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test fail in superclass AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testFailInAuthzInfo() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        CBORObject bogusToken = CBORObject.NewMap();
        bogusToken.Add(Constants.ACCESS_TOKEN, CBORObject.FromObject("bogus token"));
        byte[] n1 = new byte[8];
        new SecureRandom().nextBytes(n1);
        bogusToken.Add(Constants.NONCE1, n1);
        byte[] id1  = new byte[] {0x00};
        bogusToken.Add(Constants.ACE_CLIENT_RECIPIENTID, id1);
        LocalMessage request = new LocalMessage(0, null, null, bogusToken);
                
        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST); 
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, "Unknown token format");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test nonce1 != byte string
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testFailNonce1NotByteString() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x01}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourKey";
        CBORObject kid = CBORObject.FromObject(kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x01});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(new byte[]{0x01}), params);
        db.addCti2Client(ctiStr, "client1");  
        
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());
        
        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx).EncodeToBytes());
        payload.Add(Constants.NONCE1, "blah");
        LocalMessage request = new LocalMessage(0, null, null, payload);
                
        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, "Malformed or missing parameter 'nonce1'");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test nonce1  == null
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testFailNullNonce1() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x02}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourKey";
        CBORObject kid = CBORObject.FromObject(kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x02});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(new byte[]{0x02}), params);
        db.addCti2Client(ctiStr, "client1");
        
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());
        
        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx).EncodeToBytes());
        payload.Add(Constants.NONCE1, null);
        LocalMessage request = new LocalMessage(0, null, null, payload);
                
        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, "Malformed or missing parameter 'nonce1'");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
    }
  
    /**
     * Test OSCORE_Input_Material  == null
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testFailNullOsc() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {

        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x03}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.OSCORE_Input_Material, null);
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x03});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(new byte[]{0x03}), params);
        db.addCti2Client(ctiStr, "client1");  

        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());

        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx).EncodeToBytes());
        byte[] n1 = new byte[8];
        new SecureRandom().nextBytes(n1);
        payload.Add(Constants.NONCE1, n1);
        byte[] id1  = new byte[] {0x00};
        payload.Add(Constants.ACE_CLIENT_RECIPIENTID, id1);
        LocalMessage request = new LocalMessage(0, null, null, payload);

        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, "invalid/missing OSCORE_Input_Material");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test OSCORE_Input_Material  != Map
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testFailOscNoMap() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x04}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.OSCORE_Input_Material, "blah");
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x04});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(new byte[]{0x04}), params);
        db.addCti2Client(ctiStr, "client1");  

        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());

        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx).EncodeToBytes());
        byte[] n1 = new byte[8];
        new SecureRandom().nextBytes(n1);
        payload.Add(Constants.NONCE1, n1);
        byte[] id1  = new byte[] {0x00};
        payload.Add(Constants.ACE_CLIENT_RECIPIENTID, id1);
        LocalMessage request = new LocalMessage(0, null, null, payload);

        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, "invalid/missing OSCORE_Input_Material");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload()); 
    }
    
    /**
     * Test alg  != AlgorithmID
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testFailAlgWrongType() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x05}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CBORObject cbor = CBORObject.NewMap();
        CBORObject osc = CBORObject.NewMap();
        osc.Add(Constants.OS_ALG, "blah");
        cbor.Add(Constants.OSCORE_Input_Material, osc);
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x05});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(new byte[]{0x05}), params);
        db.addCti2Client(ctiStr, "client1");  

        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());

        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx).EncodeToBytes());
        byte[] n1 = new byte[8];
        new SecureRandom().nextBytes(n1);
        payload.Add(Constants.NONCE1, n1);
        byte[] id1  = new byte[] {0x00};
        payload.Add(Constants.ACE_CLIENT_RECIPIENTID, id1);
        LocalMessage request = new LocalMessage(0, null, null, payload);

        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, "Malformed algorithm Id in OSCORE security context");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload()); 
    }
    
    /**
     * Test kdf  != AlgorithmID
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testFailKdfWrongType() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x06}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        
        CBORObject osc = CBORObject.NewMap();
        CBORObject cbor = CBORObject.NewMap();
        osc.Add(Constants.OS_HKDF, "blah");
        cbor.Add(Constants.OSCORE_Input_Material, osc);
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x06});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(new byte[]{0x06}), params);
        db.addCti2Client(ctiStr, "client1");  

        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());

        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx).EncodeToBytes());
        byte[] n1 = new byte[8];
        new SecureRandom().nextBytes(n1);
        payload.Add(Constants.NONCE1, n1);
        byte[] id1  = new byte[] {0x00};
        payload.Add(Constants.ACE_CLIENT_RECIPIENTID, id1);
        LocalMessage request = new LocalMessage(0, null, null, payload);

        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);          
        map.Add(Constants.ERROR_DESCRIPTION, "Malformed KDF in OSCORE security context");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());  
    } 
    
    /**
     * Test master_secret == null
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testFailMsNull() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x07}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        
        CBORObject osc = CBORObject.NewMap();
        CBORObject cbor = CBORObject.NewMap();
        osc.Add(Constants.OS_MS, null);
        cbor.Add(Constants.OSCORE_Input_Material, osc);
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x07});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(new byte[]{0x07}), params);
        db.addCti2Client(ctiStr, "client1");  

        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());

        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx).EncodeToBytes());
        byte[] n1 = new byte[8];
        new SecureRandom().nextBytes(n1);
        payload.Add(Constants.NONCE1, n1);
        byte[] id1  = new byte[] {0x00};
        payload.Add(Constants.ACE_CLIENT_RECIPIENTID, id1);
        LocalMessage request = new LocalMessage(0, null, null, payload);

        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);  
        map.Add(Constants.ERROR_DESCRIPTION, "malformed or missing master" + " secret in OSCORE security context");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());   
    } 
    
    /**
     * Test master_secret != byte string
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testFailMsNotBytestring() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x08}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        
        CBORObject osc = CBORObject.NewMap();
        CBORObject cbor = CBORObject.NewMap();
        osc.Add(Constants.OS_MS, "very secret");
        cbor.Add(Constants.OSCORE_Input_Material, osc);
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x08});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(new byte[]{0x08}), params);
        db.addCti2Client(ctiStr, "client1");  

        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());

        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx).EncodeToBytes());
        byte[] n1 = new byte[8];
        new SecureRandom().nextBytes(n1);
        payload.Add(Constants.NONCE1, n1);
        byte[] id1  = new byte[] {0x00};
        payload.Add(Constants.ACE_CLIENT_RECIPIENTID, id1);
        LocalMessage request = new LocalMessage(0, null, null, payload);

        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);  
        map.Add(Constants.ERROR_DESCRIPTION, "malformed or missing master secret in OSCORE security context");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());    
    } 
    
    
    /**
     * Test salt != byte string
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testFailSaltNotBytestring() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x09}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
   
        CBORObject osc = CBORObject.NewMap();
        CBORObject cbor = CBORObject.NewMap();
        osc.Add(Constants.OS_MS, key128a);
        osc.Add(Constants.OS_SALT, "NaCl");
        osc.Add(Constants.OS_ID, Util.intToBytes(0));
        cbor.Add(Constants.OSCORE_Input_Material, osc);
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x09});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(new byte[]{0x09}), params);
        db.addCti2Client(ctiStr, "client1");  

        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());

        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx).EncodeToBytes());
        byte[] n1 = new byte[8];
        new SecureRandom().nextBytes(n1);
        payload.Add(Constants.NONCE1, n1);
        byte[] id1  = new byte[] {0x00};
        payload.Add(Constants.ACE_CLIENT_RECIPIENTID, id1);
        LocalMessage request = new LocalMessage(0, null, null, payload);

        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);  
        map.Add(Constants.ERROR_DESCRIPTION, "malformed master salt in OSCORE security context");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());  
    } 
            
    
    /**
     * Test id == null
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testFailIdNull() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x0b}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        
        CBORObject osc = CBORObject.NewMap();
        CBORObject cbor = CBORObject.NewMap();
        osc.Add(Constants.OS_MS, key128a);
        osc.Add(Constants.OS_ID, null);
        cbor.Add(Constants.OSCORE_Input_Material, osc);
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x0b});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(new byte[]{0x0b}), params);
        db.addCti2Client(ctiStr, "client1");  

        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());


        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx).EncodeToBytes());
        byte[] n1 = new byte[8];
        new SecureRandom().nextBytes(n1);
        payload.Add(Constants.NONCE1, n1);
        byte[] id1  = new byte[] {0x00};
        payload.Add(Constants.ACE_CLIENT_RECIPIENTID, id1);
        LocalMessage request = new LocalMessage(0, null, null, payload);

        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);  
        map.Add(Constants.ERROR_DESCRIPTION, "malformed or missing input material identifier in OSCORE security context");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());  
    } 
    
    
    /**
     * Test id != byte string
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testFailIdNotBytestring() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x0c}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

        CBORObject osc = CBORObject.NewMap();
        CBORObject cbor = CBORObject.NewMap();
        osc.Add(Constants.OS_MS, key128a);
        osc.Add(Constants.OS_ID, "emil");
        cbor.Add(Constants.OSCORE_Input_Material, osc);
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x0c});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(new byte[]{0x0c}), params);
        db.addCti2Client(ctiStr, "client1");  

        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());


        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx).EncodeToBytes());
        byte[] n1 = new byte[8];
        new SecureRandom().nextBytes(n1);
        payload.Add(Constants.NONCE1, n1);
        byte[] id1  = new byte[] {0x00};
        payload.Add(Constants.ACE_CLIENT_RECIPIENTID, id1);
        LocalMessage request = new LocalMessage(0, null, null, payload);

        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);  
        map.Add(Constants.ERROR_DESCRIPTION, "malformed or missing input material identifier in OSCORE security context");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());  
    }
    
    /**
     * Test failed OSCORE context creation exception
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testFailOscoreCtx() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x0d}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

        CBORObject osc = CBORObject.NewMap();
        CBORObject cbor = CBORObject.NewMap();
        osc.Add(Constants.OS_MS, key128a);
        osc.Add(Constants.OS_HKDF, AlgorithmID.HKDF_HMAC_AES_128.AsCBOR());
        osc.Add(Constants.OS_ID, Util.intToBytes(0));
        cbor.Add(Constants.OSCORE_Input_Material, osc);
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x0d});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(new byte[]{0x0d}), params);
        db.addCti2Client(ctiStr, "client1");  

        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());

        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx).EncodeToBytes());
        byte[] n1 = new byte[8];
        new SecureRandom().nextBytes(n1);
        byte[] id1 = {0x00};
        payload.Add(Constants.NONCE1, n1);
        payload.Add(Constants.ACE_CLIENT_RECIPIENTID, id1);
        LocalMessage request = new LocalMessage(0, null, null, payload);

        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);  
        map.Add(Constants.ERROR_DESCRIPTION, "Error while creating OSCORE security context: HKDF algorithm not supported");
        CBORObject rC = CBORObject.DecodeFromBytes(response.getRawPayload());
        System.out.println(rC);
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());  
    }
    
    /**
     * Test successful submission to AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     * @throws OSException 
     * @throws IntrospectionException 
     */
    @Test
    public void testSuccess() throws IllegalStateException, InvalidCipherTextException,
    								 CoseException, AceException, OSException, IntrospectionException {
    	
    	/* PART 1 */
    	
    	// Prepare and POST a first Token, through an unprotected request.
    	// Then establish a new OSCORE Security Context
    	
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x0e}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        
        byte[] kidContext = null; // To possibly include the Id Context
        kidContext = new byte[] {0x00, 0x01};
        
        CBORObject osc = CBORObject.NewMap();
        CBORObject cbor = CBORObject.NewMap();
        osc.Add(Constants.OS_MS, key128a);
        osc.Add(Constants.OS_ID, Util.intToBytes(0));
        if (kidContext != null) {
        	osc.Add(Constants.OS_CONTEXTID, kidContext);
        }
        cbor.Add(Constants.OSCORE_Input_Material, osc);
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x0e});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(new byte[]{0x0e}), params);
        db.addCti2Client(ctiStr, "client1");  

        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());

        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx).EncodeToBytes());
        byte[] n1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        byte[] id1 = {0x00};
        payload.Add(Constants.NONCE1, n1);
        payload.Add(Constants.ACE_CLIENT_RECIPIENTID, id1);
        LocalMessage request = new LocalMessage(0, null, null, payload);

        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.CREATED);
        
        OSCoreCtxDB ctxDB = OscoreCtxDbSingleton.getInstance();
        
        CBORObject authzInfoResponse = CBORObject.DecodeFromBytes(response.getRawPayload());        
        byte[] id2 = authzInfoResponse.get(Constants.ACE_SERVER_RECIPIENTID).GetByteString();
        OSCoreCtx osctx = ctxDB.getContext(id2);
        OSCoreCtx osctx2 = new OSCoreCtx(key128a, true, null, id1, id2, null, null, null, kidContext, MAX_UNFRAGMENTED_SIZE);
        
        assert(osctx.equals(osctx2));
        
        // Test that the token is there and that responses are as expected
        //
        // The identities are strings with format ["A" + ":" +] "B", where A and B are
        // the base64 encoding of the ContextID (if present) and of the SenderID.
    	String subjectId = "";
    	String kidContextStr = null;
    	String kidStr = Base64.getEncoder().encodeToString(id2);

    	if (kidContext != null && kidContext.length != 0) {    		
    		kidContextStr = Base64.getEncoder().encodeToString(kidContext);
    		subjectId = (new StringBuilder()).append(kidContextStr).append(":").toString();
    	}
    	subjectId = (new StringBuilder()).append(subjectId).append(kidStr).toString();
    	
    	// Consistently with the Token Repository, the kid coincides with the subjectId
		Assert.assertEquals(TokenRepository.OK,
		         TokenRepository.getInstance().canAccess(subjectId, subjectId, "temp", Constants.GET, null));
	       Assert.assertEquals(TokenRepository.METHODNA,
	               TokenRepository.getInstance().canAccess(subjectId, subjectId, "temp", Constants.POST, null));   
	       Assert.assertEquals(TokenRepository.FORBID,
	               TokenRepository.getInstance().canAccess(subjectId, subjectId, "co2", Constants.POST, null));
        
	    
	    /* PART 2 */
	       
	    // Resubmit the same token through an unprotected message,
	    // triggering the establishment of a new OSCORE Security Context.
	    //
	    // Then try again the same accesses as above.
	    	       
        payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx).EncodeToBytes());
        n1 = new byte[]{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}; // Offer a new nonce N1
        id1 = new byte[]{0x03}; // Offer a new ID1 for the server to use as its own Sender ID
        payload.Add(Constants.NONCE1, n1);
        payload.Add(Constants.ACE_CLIENT_RECIPIENTID, id1);
        request = new LocalMessage(0, null, null, payload);

        response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.CREATED);
        
        authzInfoResponse = CBORObject.DecodeFromBytes(response.getRawPayload());        
        id2 = authzInfoResponse.get(Constants.ACE_SERVER_RECIPIENTID).GetByteString();
        osctx = ctxDB.getContext(id2);
        osctx2 = new OSCoreCtx(key128a, true, null, id1, id2, null, null, null, kidContext, MAX_UNFRAGMENTED_SIZE);
        
        assert(osctx.equals(osctx2));
        
        subjectId = "";
    	kidContextStr = null;    	
    	kidStr = Base64.getEncoder().encodeToString(id2);
    	
    	if (kidContext != null && kidContext.length != 0) {    		
    		kidContextStr = Base64.getEncoder().encodeToString(kidContext);
    		subjectId = (new StringBuilder()).append(kidContextStr).append(":").toString();
    	}
    	subjectId = (new StringBuilder()).append(subjectId).append(kidStr).toString();
    	
    	// Consistently with the Token Repository, the kid coincides with the subjectId
		Assert.assertEquals(TokenRepository.OK,
		         TokenRepository.getInstance().canAccess(subjectId, subjectId, "temp", Constants.GET, null));
	    Assert.assertEquals(TokenRepository.METHODNA,
	             TokenRepository.getInstance().canAccess(subjectId, subjectId, "temp", Constants.POST, null));   
	    Assert.assertEquals(TokenRepository.FORBID,
	             TokenRepository.getInstance().canAccess(subjectId, subjectId, "co2", Constants.POST, null));
	       
    }
    
    
    /**
     * Test successful submission to AuthzInfo, followed by an attempt to
     * update access rights by posting a new Access Token over OSCORE
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     * @throws OSException 
     * @throws IntrospectionException 
     */
    @Test
    public void testSuccessUpdateAccessRights() throws IllegalStateException,  InvalidCipherTextException,
    											CoseException, AceException, OSException, IntrospectionException {
    	
	    /* PART 1 */
    	
    	// Prepare and POST a first Token, through an unprotected request.
    	// Then establish a new OSCORE Security Context
    	
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x0f}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        
        byte[] kidContext = null; // To possibly include the Id Context
        kidContext = new byte[] {0x00, 0x01};
        
        CBORObject osc = CBORObject.NewMap();
        CBORObject cbor = CBORObject.NewMap();
        osc.Add(Constants.OS_MS, key128a);
        osc.Add(Constants.OS_ID, Util.intToBytes(0));
        if (kidContext != null) {
        	osc.Add(Constants.OS_CONTEXTID, kidContext);
        }
        cbor.Add(Constants.OSCORE_Input_Material, osc);
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x0f});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(new byte[]{0x0f}), params);
        db.addCti2Client(ctiStr, "client1");  

        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());

        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx).EncodeToBytes());
        byte[] n1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        byte[] id1 = {0x00};
        payload.Add(Constants.NONCE1, n1);
        payload.Add(Constants.ACE_CLIENT_RECIPIENTID, id1);
        LocalMessage request = new LocalMessage(0, null, null, payload);

        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.CREATED);
        
        OSCoreCtxDB ctxDB = OscoreCtxDbSingleton.getInstance();
        
        CBORObject authzInfoResponse = CBORObject.DecodeFromBytes(response.getRawPayload());
        byte[] id2 = authzInfoResponse.get(Constants.ACE_SERVER_RECIPIENTID).GetByteString();
        OSCoreCtx osctx = ctxDB.getContext(id2);
        OSCoreCtx osctx2 = new OSCoreCtx(key128a, true, null, id1, id2, null, null, null, kidContext, MAX_UNFRAGMENTED_SIZE);
        
        assert(osctx.equals(osctx2));

        //Test that the token is there and that responses are as expected
        
        // The identities are strings with format ["A" + ":" +] "B", where A and B are
        // the base64 encoding of the ContextID (if present) and of the SenderID.
    	String subjectId = "";
    	String kidContextStr = null;
    	String kidStr = Base64.getEncoder().encodeToString(id2);
    	
    	if (kidContext != null && kidContext.length != 0) {
    		kidContextStr = Base64.getEncoder().encodeToString(kidContext);
    		subjectId = (new StringBuilder()).append(kidContextStr).append(":").toString();
    	}
    	subjectId = (new StringBuilder()).append(subjectId).append(kidStr).toString();
    	
    	// Consistently with the Token Repository, the kid coincides with the subjectId
		Assert.assertEquals(TokenRepository.OK,
		         TokenRepository.getInstance().canAccess(subjectId, subjectId, "temp", Constants.GET, null));
	       Assert.assertEquals(TokenRepository.METHODNA,
	               TokenRepository.getInstance().canAccess(subjectId, subjectId, "temp", Constants.POST, null));   
	       Assert.assertEquals(TokenRepository.FORBID,
	               TokenRepository.getInstance().canAccess(subjectId, subjectId, "co2", Constants.POST, null));
        
	    /* PART 2 */
    
	    // Resubmit the same token through an unprotected message,
	    // triggering the establishment of a new OSCORE Security Context.
	    //
	    // Then try again the same accesses as above.
	    	       
        payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx).EncodeToBytes());
        n1 = new byte[]{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}; // Offer a new nonce N1
        id1 = new byte[]{0x03}; // Offer a new ID1 for the server to use as its own Sender ID
        payload.Add(Constants.NONCE1, n1);
        payload.Add(Constants.ACE_CLIENT_RECIPIENTID, id1);
        request = new LocalMessage(0, null, null, payload);

        response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.CREATED);
        
        authzInfoResponse = CBORObject.DecodeFromBytes(response.getRawPayload());        
        id2 = authzInfoResponse.get(Constants.ACE_SERVER_RECIPIENTID).GetByteString();
        osctx = ctxDB.getContext(id2);
        osctx2 = new OSCoreCtx(key128a, true, null, id1, id2, null, null, null, kidContext, MAX_UNFRAGMENTED_SIZE);
        
        assert(osctx.equals(osctx2));
        
        subjectId = "";
    	kidContextStr = null;
       	kidStr = Base64.getEncoder().encodeToString(id2);
    	
    	if (kidContext != null && kidContext.length != 0) {
    		kidContextStr = Base64.getEncoder().encodeToString(kidContext);
    		subjectId = (new StringBuilder()).append(kidContextStr).append(":").toString();
    	}
    	subjectId = (new StringBuilder()).append(subjectId).append(kidStr).toString();
    	
    	// Consistently with the Token Repository, the kid coincides with the subjectId
		Assert.assertEquals(TokenRepository.OK,
		         TokenRepository.getInstance().canAccess(subjectId, subjectId, "temp", Constants.GET, null));
	       Assert.assertEquals(TokenRepository.METHODNA,
	               TokenRepository.getInstance().canAccess(subjectId, subjectId, "temp", Constants.POST, null));   
	       Assert.assertEquals(TokenRepository.FORBID,
	               TokenRepository.getInstance().canAccess(subjectId, subjectId, "co2", Constants.POST, null));   
	       
	       
		/* PART 3 */
	       
        // Build a new Token for updating access rights, with a different 'scope'
        
        params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{(byte) 0xa0}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_co2"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        
        // Now the 'cnf' claim includes only a 'kid' with value the 'id'
        // used in the first Token and identifying the OSCORE_Input_Material
        cbor = CBORObject.NewMap();
        cbor.Add(Constants.COSE_KID_CBOR, Util.intToBytes(0));
        params.put(Constants.CNF, cbor);
        ctiStr = Base64.getEncoder().encodeToString(new byte[]{(byte) 0xa0});
        
        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(new byte[]{(byte) 0xa0}), params);
        db.addCti2Client(ctiStr, "client1");  

        token = new CWT(params);

        // Include only the Token now. If Id1 and Nonce1 were
        // included here too, the RS would silently ignore them
        payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx).EncodeToBytes());
        
        // Posting the Token through an unprotected request.
        // This fails since such a Token needs to include the
        // full-fledged OSCORE_Input_Material object
        request = new LocalMessage(0, null, null, payload);
        response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        
        // In fact, this has to be a protected POST to /authz-info
        // The identity of the client is the string <ID Context>:<Sender ID>,
        // or simply <Sender ID> in case no ID Context is used with OSCORE
        request = new LocalMessage(0, subjectId, null, payload);
        response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.CREATED);
        
        // ... and in fact nothings is expected to be returned as response
        assert(response.getRawPayload() == null);
        
        // Test that the new token is there, and both GET and POST
        // are consistently authorized on the "co2" resource
        //
        // The subjectId (used also as kid) has not changed, since the
        // same OSCORE Master Secret is bound also to the new token
        Assert.assertEquals(TokenRepository.OK, 
                TokenRepository.getInstance().canAccess(subjectId, subjectId, "co2", Constants.GET, null));
        Assert.assertEquals(TokenRepository.OK, 
                TokenRepository.getInstance().canAccess(subjectId, subjectId, "co2", Constants.POST, null));
        Assert.assertEquals(TokenRepository.METHODNA, 
                TokenRepository.getInstance().canAccess(subjectId, subjectId, "co2", Constants.DELETE, null));
        
        // ... and that access to the "temp" resource is not allowed anymore
        Assert.assertEquals(TokenRepository.FORBID, 
                TokenRepository.getInstance().canAccess(subjectId, subjectId, "temp", Constants.GET, null));
        
    }
    
}
