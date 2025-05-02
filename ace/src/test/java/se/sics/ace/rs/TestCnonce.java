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
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.Request;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.upokecenter.cbor.CBORObject;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.MessageTag;
import org.eclipse.californium.cose.OneKey;

import org.junit.AfterClass;
import org.junit.Assert;
import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.Message;
import se.sics.ace.TestConfig;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.KissValidator;
import se.sics.ace.examples.LocalMessage;

/**
 * Tests for the cnonce mechanism
 * 
 * @author Ludwig Seitz
 *
 */
public class TestCnonce {

      
    private static CBORObject pskCnf;
    private static CwtCryptoCtx ctx;
    private static OneKey symmetricKey;
    private static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static AuthzInfo ai;
    
    /**
     * Expected exception
     */
    @Rule
    public ExpectedException thrown = ExpectedException.none();
    
    /**
     * Set up tests.
     * @throws IOException 
     * @throws AceException 
     * @throws CoseException 
     */
    @BeforeClass
    public static void setUp() throws IOException, AceException, CoseException  {
        
        
        Set<Short> actions = new HashSet<>();
        actions.add(Constants.GET);
        Map<String, Set<Short>> myResource = new HashMap<>();
        myResource.put("temp", actions);
        Map<String, Map<String, Set<Short>>> myScopes = new HashMap<>();
        myScopes.put("r_temp", myResource);
        
        Map<String, Set<Short>> otherResource = new HashMap<>();
        otherResource.put("co2", actions);
        myScopes.put("r_co2", otherResource);
        
        KissValidator valid = new KissValidator(Collections.singleton("aud1"), myScopes);
        
        String rsId = "rs1";
        
        String tokenFile = TestConfig.testFilePath + "tokens.json";
        //Delete lingering old token file
        new File(tokenFile).delete();
        
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());
       
        ai = new AuthzInfo(Collections.singletonList("TestAS"), new KissTime(),
        				   null, rsId, valid, ctx, null, 0, tokenFile, valid, true);
        
        CBORObject keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.KeyId.AsCBOR(), "ourKey".getBytes(Constants.charset));
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), key128);
        symmetricKey = new OneKey(keyData);  
        pskCnf = CBORObject.NewMap();
        pskCnf.Add(Constants.COSE_KEY_CBOR, symmetricKey.AsCBOR());
    }
    
    /**
     * Deletes the test file after the tests
     * @throws AceException 
     */
    @AfterClass
    public static void tearDown() throws AceException {
        ai.close();
        new File(TestConfig.testFilePath + "tokens.json").delete();
    }   

    /**
     * Test a successful round-trip with cnonce
     * 
     * @throws AceException 
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeyException 
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     */
    @Test
    public void testSuccess() throws AceException, InvalidKeyException,
            NoSuchAlgorithmException, IllegalStateException, 
            InvalidCipherTextException, CoseException {
       AsRequestCreationHints hints = new AsRequestCreationHints(
               "coaps://example.as.com/token", null, false, true);

       Request req = new Request(Code.GET);
       req.setURI("coap://localhost/temp");       
       CBORObject hintsCBOR = hints.getHints(req, null);
       CBORObject cnonce = hintsCBOR.get(CBORObject.FromObject(Constants.CNONCE));
       System.out.println("client nonce: " + cnonce);
       Assert.assertNotNull(cnonce);
       
       Map<Short, CBORObject> params = new HashMap<>(); 
       params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
       params.put(Constants.AUD, CBORObject.FromObject("aud1"));
       params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
       params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
       params.put(Constants.CNF, pskCnf);
       params.put(Constants.CNONCE, CBORObject.FromObject(cnonce));

       CWT token = new CWT(params);
       LocalMessage request = new LocalMessage(0, null, "rs1", token.encode(ctx));
       Message response = ai.processMessage(request);
       assert(response.getMessageCode() == Message.CREATED);
 
    }

    /**
     * Test adding a token with missing cnonce claim
     * 
     * @throws AceException 
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     */
    @Test
    public void testMissingCnonce() throws AceException, 
            IllegalStateException, InvalidCipherTextException, CoseException {
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, pskCnf);
        CWT token = new CWT(params);
        LocalMessage request = new LocalMessage(0, "clientA", "rs1", token.encode(ctx));

        Message response = ai.processMessage(request);   
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, "cnonce expected but not found");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());       
    }

    /**
     * Test adding a token with unknown cnonce claim with wrong length
     * 
     * @throws AceException 
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     */
    @Test
    public void testInvalidLengthCnonce() throws AceException, 
            IllegalStateException, InvalidCipherTextException, CoseException {
        byte[] otherNonce = {0x00, 0x01, 0x02};

        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.CTI, CBORObject.FromObject("token2".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, pskCnf);
        params.put(Constants.CNONCE, CBORObject.FromObject(otherNonce));
        CWT token = new CWT(params);
        LocalMessage request = new LocalMessage(0, "clientA", "rs1", token.encode(ctx));

        Message response = ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, "Invalid cnonce length");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());   
    }

    /**
     * Test adding a token with unknown cnonce claim with right length
     * 
     * @throws AceException 
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     */
    @Test
    public void testInvalidCnonce() throws AceException, IllegalStateException,
            InvalidCipherTextException, CoseException {
        byte[] otherNonce = new byte[36];
        new SecureRandom().nextBytes(otherNonce);

        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.CTI, CBORObject.FromObject("token3".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, pskCnf);
        params.put(Constants.CNONCE, CBORObject.FromObject(otherNonce));
        CWT token = new CWT(params);
        LocalMessage request = new LocalMessage(0, "clientA", "rs1", token.encode(ctx));
        
        Message response = ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, "cnonce invalid");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());  
    }
    
    /**
     * Test adding a token with invalid cnonce type
     * 
     * @throws AceException 
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     */
    @Test
    public void testInvalidCnonceType() throws AceException, 
            IllegalStateException, InvalidCipherTextException, CoseException {
        String otherNonce = "nonce";
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.CTI, CBORObject.FromObject("token4".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, pskCnf);
        params.put(Constants.CNONCE, CBORObject.FromObject(otherNonce));
        CWT token = new CWT(params);
        LocalMessage request = new LocalMessage(0, "clientA", "rs1", token.encode(ctx));
        Message response = ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, "Invalid cnonce type");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());       
    }

    /**
     * Test adding a token with expired cnonce
     * 
     * @throws AceException 
     * @throws InterruptedException 
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeyException 
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     */
    @Test
    public void testExpiredCnonce() throws AceException, InterruptedException,
            InvalidKeyException, NoSuchAlgorithmException, IllegalStateException, InvalidCipherTextException, CoseException {
        AsRequestCreationHints hints = new AsRequestCreationHints(
                "coaps://example.as.com/token", null, false, true);

        Request req = new Request(Code.GET);
        req.setURI("coap://localhost/temp");       
        CBORObject hintsCBOR = hints.getHints(req, null);
        CBORObject cnonce = hintsCBOR.get(
                CBORObject.FromObject(Constants.CNONCE));
        System.out.println("client nonce: " + cnonce);
        Assert.assertNotNull(cnonce);

        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.CTI, CBORObject.FromObject("token5".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, pskCnf);

        for (int i=0; i<36; i++) {//"expire" cnonce
            CBORObject dummyH = hints.getHints(req, null);
            CBORObject dummyC = dummyH.get(CBORObject.FromObject(Constants.CNONCE));
            params.put(Constants.CTI, CBORObject.FromObject(new String("" + i).getBytes(Constants.charset)));
            params.put(Constants.CNONCE, CBORObject.FromObject(dummyC));
            CWT token = new CWT(params);
            LocalMessage request = new LocalMessage(0, "clientA", "rs1", token.encode(ctx));
            ai.processMessage(request);      
        }
        params.put(Constants.CNONCE, CBORObject.FromObject(cnonce));
        CWT token = new CWT(params);
        LocalMessage request = new LocalMessage(0, "clientA", "rs1", token.encode(ctx));

        Message response = ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, "cnonce expired");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());       
    }

    /**
     * Test replaying a nonce
     * 
     * @throws AceException 
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeyException 
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     */
    @Test
    public void testReplay() throws AceException, InvalidKeyException,
            NoSuchAlgorithmException, IllegalStateException, 
            InvalidCipherTextException, CoseException {
       AsRequestCreationHints hints = new AsRequestCreationHints(
               "coaps://example.as.com/token", null, false, true);

       Request req = new Request(Code.GET);
       req.setURI("coap://localhost/temp");       
       CBORObject hintsCBOR = hints.getHints(req, null);
       CBORObject cnonce = hintsCBOR.get(CBORObject.FromObject(Constants.CNONCE));
       System.out.println("client nonce: " + cnonce);
       Assert.assertNotNull(cnonce);
       
       Map<Short, CBORObject> params = new HashMap<>(); 
       params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
       params.put(Constants.AUD, CBORObject.FromObject("aud1"));
       params.put(Constants.CTI, CBORObject.FromObject("token6".getBytes(Constants.charset)));
       params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
       params.put(Constants.CNF, pskCnf);
       params.put(Constants.CNONCE, CBORObject.FromObject(cnonce));
       CWT token = new CWT(params);
       LocalMessage request = new LocalMessage(0, "clientA", "rs1", token.encode(ctx));
       ai.processMessage(request);
       
       params.put(Constants.CTI, CBORObject.FromObject("token7".getBytes(Constants.charset)));
       CWT token2 = new CWT(params);
       LocalMessage request2 = new LocalMessage(0, "clientA", "rs1", token2.encode(ctx));

       ai.processMessage(request2);
       Message response = ai.processMessage(request2);
       assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
       
       CBORObject map = CBORObject.NewMap();
       map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
       map.Add(Constants.ERROR_DESCRIPTION, "cnonce replayed");
       Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());      
    }
}
