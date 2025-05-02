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
package se.sics.ace.rs;

import java.io.File;
import java.io.IOException;
import java.sql.SQLException;
import java.util.Base64;
import java.util.Collections;
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
import se.sics.ace.ReferenceToken;
import se.sics.ace.TestConfig;
import se.sics.ace.as.AccessTokenFactory;
import se.sics.ace.as.Introspect;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissPDP;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.KissValidator;
import se.sics.ace.examples.LocalMessage;
import se.sics.ace.examples.SQLConnector;

/**
 * 
 * @author Ludwig Seitz and Marco Tiloca
 */
public class TestAuthzInfo {
    
    static OneKey publicKey;
    static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static byte[] key128a = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static SQLConnector db = null;

    private static AuthzInfo ai = null;
    private static AuthzInfo ai2 = null;
    private static Introspect i; 
    private static KissPDP pdp = null;
    
    private static String rsId = "rs1";
    
    /**
     * Set up tests.
     * @throws SQLException 
     * @throws AceException 
     * @throws IOException 
     * @throws CoseException 
     */
    @BeforeClass
    public static void setUp() throws SQLException, AceException, IOException, CoseException {
        //Delete lingering old token file
        new File(TestConfig.testFilePath + "tokens.json").delete();
        
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
        
        Map<String, Set<Short>> myResource2 = new HashMap<>();
        myResource2.put("co2", actions);
        myScopes.put("r_co2", myResource2);
        
        KissValidator valid = new KissValidator(Collections.singleton("aud1"), myScopes);

        String tokenFile = TestConfig.testFilePath + "tokens.json";      
        coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());

        pdp = new KissPDP(db);
        pdp.addIntrospectAccess("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w");
        pdp.addIntrospectAccess(rsId);
        
        i = new Introspect(pdp, db, new KissTime(), key, null);
        
        ai = new AuthzInfo(Collections.singletonList("TestAS"), new KissTime(),
		                   new IntrospectionHandler4Tests(i, rsId, "TestAS"), rsId,
		                   valid, ctx, null, 0, tokenFile, valid, false);
        
        
        // A separate authz-info endpoint is required for each Resource Server, here "rs2",
        // due to the interface of the IntrospectionHandler4Tests taking exactly one RS as second argument.
        
    	// This endpoint does not perform introspection, thus enabling some of the tests below
    	// to focus on error conditions and achieve the expected outcomes.
        
        // Set a separate authz-info endpoint that does not perform introspection, which always
        // expects Access Tokens stored at the AS and possible to introspect to specify an audience.
        // This enables some of the tests below to focus on error conditions and achieve the expected outcomes.
        ai2 = new AuthzInfo(Collections.singletonList("TestAS"), new KissTime(),
        					null, rsId, valid, ctx, null, 0, tokenFile, valid, false);
        
    }

    
    /**
     * Deletes the test DB after the tests
     * @throws Exception 
     */
    @AfterClass
    public static void tearDown() throws Exception {
        DBHelper.tearDownDB();
        pdp.close();
        ai.close();
        i.close();
        new File(TestConfig.testFilePath + "tokens.json").delete();
    }
    
    /**
     * Test inactive reference token submission to AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException 
     */
    @Test
    public void testRefInactive() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        ReferenceToken token = new ReferenceToken(20);
        LocalMessage request = new LocalMessage(0, null, "rs1", CBORObject.FromObject(token.encode().EncodeToBytes()));
                
        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_UNAUTHORIZED);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
        map.Add(Constants.ERROR_DESCRIPTION, "Token is not active");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test CWT with a scope claim that is overwritten by introspection
     * 
     * @throws AceException 
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     * @throws IntrospectionException 
     */
    @Test
    public void testCwtIntrospect() throws AceException, IllegalStateException,
            InvalidCipherTextException, CoseException, IntrospectionException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.SCOPE, CBORObject.FromObject("r_co2"));
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x01}));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, publicKey.AsCBOR());
        params.put(Constants.CNF, cnf);
        
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x01});
        //Make introspection succeed
        db.addToken(ctiStr, params);
        db.addCti2Client(ctiStr, "client1");
        
        //this overwrites the scope
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        CBORObject kid = CBORObject.FromObject(new byte[]{0x00, 0x01});
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cbor);
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());
        
        LocalMessage request = new LocalMessage(0, null, "rs1", token.encode(ctx));
        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.CREATED);
        
        CBORObject resP = CBORObject.DecodeFromBytes(response.getRawPayload());
        CBORObject cti = resP.get(CBORObject.FromObject(Constants.CTI));
        Assert.assertArrayEquals(cti.GetByteString(), new byte[]{0x01});
        
        String rpk = new RawPublicKeyIdentity(publicKey.AsPublicKey()).getName();
        String kidStr = Base64.getEncoder().encodeToString(rpk.getBytes());
        assert(1 == TokenRepository.getInstance().canAccess(kidStr, null, "co2", Constants.GET, null));
        
        db.deleteToken(ctiStr);
    }
    
    /**
     * Test CWT with invalid MAC submission to AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testInvalidCWT() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> claims = new HashMap<>();
        claims.put(Constants.ISS, CBORObject.FromObject("coap://as.example.com"));
        claims.put(Constants.AUD, CBORObject.FromObject("coap://light.example.com"));
        claims.put(Constants.EXP, CBORObject.FromObject(1444064944));
        claims.put(Constants.NBF, CBORObject.FromObject(1443944944));
        claims.put(Constants.IAT, CBORObject.FromObject(1443944944));
        byte[] cti = {0x02};
        claims.put(Constants.CTI, CBORObject.FromObject(cti));
        claims.put(Constants.CNF, publicKey.AsCBOR());
        claims.put(Constants.SCOPE, CBORObject.FromObject("r+/s/light rwx+/a/led w+/dtls"));
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128a, AlgorithmID.AES_CCM_16_64_128.AsCBOR());
        CWT cwt = new CWT(claims);

        LocalMessage request = new LocalMessage(0, null , "rs1", cwt.encode(ctx));
                
        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
        map.Add(Constants.ERROR_DESCRIPTION, "Token is invalid");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test an invalid token format submission to AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testInvalidTokenFormat() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        CBORObject token = CBORObject.False;
        LocalMessage request = new LocalMessage(0, "client1", "rs1", token);
                
        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, "Unknown token format");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test expired CWT submission to AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testExpiredCWT() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> claims = new HashMap<>();
        byte[] cti = {0x03};
        claims.put(Constants.CTI, CBORObject.FromObject(cti));
        claims.put(Constants.AUD, CBORObject.FromObject("aud1"));        
        claims.put(Constants.CNF, publicKey.AsCBOR());
        claims.put(Constants.SCOPE, CBORObject.FromObject("r+/s/light rwx+/a/led w+/dtls")); 
        claims.put(Constants.ISS, CBORObject.FromObject("coap://as.example.com"));
        claims.put(Constants.AUD, CBORObject.FromObject("coap://light.example.com"));
        claims.put(Constants.NBF, CBORObject.FromObject(1443944944));
        claims.put(Constants.IAT, CBORObject.FromObject(1443944944));        
        claims.put(Constants.EXP, CBORObject.FromObject(10000));
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, AlgorithmID.AES_CCM_16_64_128.AsCBOR());
        CWT cwt = new CWT(claims);
        
        LocalMessage request = new LocalMessage(0, null, "rs1", cwt.encode(ctx));
                
        LocalMessage response = (LocalMessage)ai2.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_UNAUTHORIZED);
        
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
        map.Add(Constants.ERROR_DESCRIPTION, "Token is expired");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
        
    }
    
    
    /**
     * Test submission of CWT without security wrapper
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testInsecureCWT() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> claims = new HashMap<>();
        byte[] cti = {0x13};
        claims.put(Constants.CTI, CBORObject.FromObject(cti));
        String ctiStr = Base64.getEncoder().encodeToString(cti);
        
        //Make introspection succeed
        db.addToken(ctiStr, claims);
        db.addCti2Client(ctiStr, "client1");
        
        claims.put(Constants.CNF, publicKey.AsCBOR());
        claims.put(Constants.SCOPE, CBORObject.FromObject("r+/s/light rwx+/a/led w+/dtls")); 
        claims.put(Constants.ISS, CBORObject.FromObject("coap://as.example.com"));
        claims.put(Constants.AUD, CBORObject.FromObject("coap://light.example.com"));
        claims.put(Constants.NBF, CBORObject.FromObject(1443944944));
        claims.put(Constants.IAT, CBORObject.FromObject(1443944944));        
        claims.put(Constants.EXP, CBORObject.FromObject(10000));
        CWT cwt = new CWT(claims);
        
        LocalMessage request = new LocalMessage(0, null, "rs1", cwt.encode());
                
        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, "Unknown token format");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
        db.deleteToken(ctiStr);
    }
    
    /**
     * Test CWT with unrecognized issuer submission to AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException 
     */
    @Test
    public void testIssuerNotRecognized() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x05}));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, publicKey.AsCBOR());
        params.put(Constants.CNF, cnf);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x05});
        
        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(new byte[]{0x05}), params);
        db.addCti2Client(ctiStr, "client1");
        
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.ISS, CBORObject.FromObject("FalseAS"));
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());
        LocalMessage request = new LocalMessage(0, null, "rs1", token.encode(ctx));
                
        LocalMessage response = (LocalMessage)ai.processMessage(request);  
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, "Token issuer unknown");
        assert(response.getMessageCode() == Message.FAIL_UNAUTHORIZED);
        
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
        db.deleteToken(ctiStr);
    }
    
    /**
     * Test CWT without audience submission to AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException 
     */
    @Test
    public void testNoAudience() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x06}));
                
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());
        LocalMessage request = new LocalMessage(0, null, "rs1", token.encode(ctx));
                
        LocalMessage response = (LocalMessage)ai2.processMessage(request);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, "Token has no audience");
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
        
    }
    
    /**
     * Test CWT with audience that does not match RS submission to AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException 
     */
    @Test
    public void testNoAudienceMatch() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x07}));
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x07});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(new byte[]{0x07}), params);
        db.addCti2Client(ctiStr, "client1");
        
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("blah"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());
        LocalMessage request = new LocalMessage(0, null, "rs1", token.encode(ctx));
                
        LocalMessage response = (LocalMessage)ai2.processMessage(request);  
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
        map.Add(Constants.ERROR_DESCRIPTION, "Audience does not apply");
        assert(response.getMessageCode() == Message.FAIL_FORBIDDEN);
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
        
        db.deleteToken(ctiStr);
    }  
    
    /**
     * Test CWT without scope submission to AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testNoScope() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x08}));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x08});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(new byte[]{0x08}), params);
        db.addCti2Client(ctiStr, "client1");
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());
        
        LocalMessage request = new LocalMessage(0, null, "rs1", token.encode(ctx));
        LocalMessage response = (LocalMessage)ai.processMessage(request);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_SCOPE);
        map.Add(Constants.ERROR_DESCRIPTION, "Token has no scope");
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
        
        db.deleteToken(ctiStr);
    }
    
    /**
     * Test successful submission to AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testSuccess() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x09}));
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
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x09});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(new byte[]{0x09}), params);
        db.addCti2Client(ctiStr, "client1");  

        
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());
        LocalMessage request = new LocalMessage(0, null, "rs1", token.encode(ctx));
                
        LocalMessage response = (LocalMessage)ai.processMessage(request);
        System.out.println(response.toString());
        assert(response.getMessageCode() == Message.CREATED);
        CBORObject resP = CBORObject.DecodeFromBytes(response.getRawPayload());
        CBORObject cti = resP.get(CBORObject.FromObject(Constants.CTI));
        Assert.assertArrayEquals(cti.GetByteString(), new byte[]{0x09});
        
        db.deleteToken(ctiStr);
    }    
    
    /**
     * Test successful submission to AuthzInfo with an EXI claim
     * 
     * @throws AceException  
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     * @throws IntrospectionException 
     */
    @Test
    public void testExi() throws AceException, IllegalStateException, 
            InvalidCipherTextException, CoseException, IntrospectionException {
        Map<Short, CBORObject> params = new HashMap<>();
        
        // Since the 'exi' claim is included, the 'cti' claim must
        // also be included andi it must have a specific format
        int exiSeqNum = 1;
        String rawCti = new String(rsId + String.valueOf(exiSeqNum));
		byte[] ctiB = rawCti.getBytes(Constants.charset);
        params.put(Constants.CTI, CBORObject.FromObject(ctiB));
        
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.EXI, CBORObject.FromObject(20000L));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourKey";
        CBORObject kid = CBORObject.FromObject(kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(ctiB);

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(ctiB), params);
        db.addCti2Client(ctiStr, "client1");  

        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());
        LocalMessage request = new LocalMessage(0, null, "rs1", token.encode(ctx));     
        LocalMessage response = (LocalMessage)ai.processMessage(request);
        System.out.println(response.toString());
        assert(response.getMessageCode() == Message.CREATED);
        
        CBORObject resP = CBORObject.DecodeFromBytes(response.getRawPayload());
        CBORObject cti = resP.get(CBORObject.FromObject(Constants.CTI));
        
        Assert.assertArrayEquals(cti.GetByteString(), ctiB);
        
        // The Token Repository stores as 'kid' the base64 encoding of
        // the binary content from the 'kid' field of the 'cnf' claim.
        String storedKid = Base64.getEncoder().encodeToString(kidStr.getBytes(Constants.charset));
        Assert.assertEquals(1, TokenRepository.getInstance().canAccess(
                				storedKid, "client1", "temp", Constants.GET, null));
        
        db.deleteToken(ctiStr);
        
        
        // Post a new Access Token, similar to the previous one,
        // but with a lower Sequence Number in the 'cti' claim.
        // This test must fail, since such Sequence Number values
        // can only strictly grow on the same Resource Server.
        exiSeqNum = 0;
        rawCti = new String(rsId + String.valueOf(exiSeqNum));
		ctiB = rawCti.getBytes(Constants.charset);
        params.put(Constants.CTI, CBORObject.FromObject(ctiB));
        ctiStr = Base64.getEncoder().encodeToString(ctiB);
        
        db.addToken(Base64.getEncoder().encodeToString(ctiB), params);
        db.addCti2Client(ctiStr, "client1");
        
        token = new CWT(params);
        request = new LocalMessage(0, null, "rs1", token.encode(ctx));     
        response = (LocalMessage)ai.processMessage(request);
        System.out.println(response.toString());
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        
    }
}
