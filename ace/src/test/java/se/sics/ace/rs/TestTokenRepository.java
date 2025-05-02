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
import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.upokecenter.cbor.CBORObject;

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
import se.sics.ace.TestConfig;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.KissValidator;

/**
 * Tests for the TokenRepository class.
 * 
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class TestTokenRepository {
    
    static OneKey asymmetricKey;
    static OneKey symmetricKey;
    static OneKey otherKey;
    static CwtCryptoCtx ctx;
    static byte[] key128a = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static TokenRepository tr; 
    private static CBORObject pskCnf;
    private static CBORObject rpkCnf;
    private static String ourKey = "ourKey";
    private static String rpk = "ni:///sha-256;-QCjSk6ojWX8-YaHwQMOkewLD7p89aFF2eh8shWDmKE";
    
    /**
     * Converter for generating byte arrays from int
     */
    private static ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
    
    /**
     * Expected exception
     */
    @Rule
    public ExpectedException thrown = ExpectedException.none();
    
    /**
     * Set up tests.
     *
     * @throws AceException 
     * @throws CoseException 
     * @throws IOException 
     */
    @BeforeClass
    public static void setUp() throws AceException, CoseException, IOException {

        asymmetricKey = OneKey.generateKey(AlgorithmID.ECDSA_256);
        
        byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
               
        CBORObject keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.KeyId.AsCBOR(), "ourKey".getBytes(Constants.charset));
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), key128);
        symmetricKey = new OneKey(keyData);
        
        CBORObject otherKeyData = CBORObject.NewMap();
        otherKeyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        otherKeyData.Add(KeyKeys.KeyId.AsCBOR(), "otherKey".getBytes(Constants.charset));
        otherKeyData.Add(KeyKeys.Octet_K.AsCBOR(), key128a);
        otherKey = new OneKey(otherKeyData);
        
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
        
        createTR(valid);
        tr = TokenRepository.getInstance();
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());
        
        pskCnf = CBORObject.NewMap();
        pskCnf.Add(Constants.COSE_KEY_CBOR, symmetricKey.AsCBOR());
        
        rpkCnf = CBORObject.NewMap();
        rpkCnf.Add(Constants.COSE_KEY_CBOR, asymmetricKey.PublicKey().AsCBOR()); 
       
    }
    
    /**
     * Create the Token repository if not already created,
     * if already create ignore.
     * 
     * @param valid 
     * @throws IOException 
     * 
     */
    private static void createTR(KissValidator valid) throws IOException {
    	String rsId = "rs1";
    	
        try {
            TokenRepository.create(valid, TestConfig.testFilePath + "tokens.json",
            					   null, null, 0, new KissTime(), rsId);
        } catch (AceException e) {
            System.err.println(e.getMessage());
            try {
                TokenRepository tr = TokenRepository.getInstance();
                tr.close();
                new File(TestConfig.testFilePath + "tokens.json").delete();
                TokenRepository.create(valid, TestConfig.testFilePath + "tokens.json",
                					   null, null, 0, new KissTime(), rsId);
            } catch (AceException e2) {
               throw new RuntimeException(e2);
            } 
        }
    }
    
    /**
     * Deletes the test file after the tests
     * @throws AceException 
     */
    @AfterClass
    public static void tearDown() throws AceException {
        tr.close();
        new File(TestConfig.testFilePath + "tokens.json").delete();
    }
    
    /**
     * Test add token without scope
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenNoScope() throws AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, pskCnf);
        this.thrown.expect(AceException.class);
        this.thrown.expectMessage("Token has no scope");
        tr.addToken(null, params, ctx, null, -1);
    }
    
    /**
     * Test add token without cti
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenNoCti() throws AceException {
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, pskCnf);
        tr.addToken(null, params, ctx, null, -1);
        params.remove(Constants.CTI); //Gets added by tr.addToken()
        CBORObject cticb = CBORObject.FromObject(buffer.putInt(0, params.hashCode()).array());
        String cti = Base64.getEncoder().encodeToString(cticb.GetByteString());
        Assert.assertNotNull(tr.getPoP(cti));
    }
    
    /**
     * Test add token with invalid cti
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenInvalidCti() throws AceException {
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, pskCnf);
        params.put(Constants.CTI, CBORObject.FromObject("token1"));
        this.thrown.expect(AceException.class);
        this.thrown.expectMessage("Cti has invalid format");
        tr.addToken(null, params, ctx, null, -1);
    }
    
    /**
     * Test add token with duplicate cti
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenDuplicateCti() throws AceException {
        this.thrown.expect(AceException.class);
        this.thrown.expectMessage("Duplicate cti");
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, pskCnf);
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        tr.addToken(null, params, ctx, null, -1);
        
        params.clear();
        params.put(Constants.SCOPE, CBORObject.FromObject("r_co2"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, rpkCnf);
        tr.addToken(null, params, ctx, null, -1);
    }
    
    /**
     * Test add token without cnf
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenNoCnf() throws AceException {
        this.thrown.expect(AceException.class);
        this.thrown.expectMessage("Token has no cnf");
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        tr.addToken(null, params, ctx, null, -1);
    }
    
    /**
     * Test add token with unknown kid
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenUnknownKid() throws AceException {
        this.thrown.expect(AceException.class);
        this.thrown.expectMessage("Token refers to unknown kid");
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KID_CBOR, CBORObject.FromObject("blah".getBytes(Constants.charset)));
        params.put(Constants.CNF, cnf);
        tr.addToken(null, params, ctx, null, -1);
    }
    
    /**
     * Test add token with invalid cnf
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenInvalidCnf() throws AceException {
        this.thrown.expect(AceException.class);
        this.thrown.expectMessage("Malformed cnf claim in token");
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add("blah", "blah".getBytes(Constants.charset));
        cnf.Add("blubb", CBORObject.FromObject("blah".getBytes(Constants.charset)));
        params.put(Constants.CNF, cnf);
        tr.addToken(null, params, ctx, null, -1);
    }
    
    /**
     * Test add token with invalid Encrypt0
     * 
     * @throws AceException 
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     */
    @Test
    public void testTokenCnfInvalidEncrypt0() throws AceException, CoseException,
            IllegalStateException, InvalidCipherTextException {
        this.thrown.expect(AceException.class);
        this.thrown.expectMessage("Error while decrypting a cnf claim");
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        CBORObject cnf = CBORObject.NewMap();
        Encrypt0Message enc = new Encrypt0Message();
        enc.addAttribute(HeaderKeys.Algorithm, ctx.getAlg(), Attribute.PROTECTED);
        enc.SetContent(symmetricKey.EncodeToBytes());
        enc.encrypt(key128a);
        cnf.Add(Constants.COSE_ENCRYPTED_CBOR, enc.EncodeToCBORObject());
        
        params.put(Constants.CNF, cnf);
        tr.addToken(null, params, ctx, null, -1);
    }
    
    
    /**
     * Test add token with cnf without kid
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenNoKid() throws AceException {
        this.thrown.expect(AceException.class);
        this.thrown.expectMessage("Malformed cnf claim in token");
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add("blubb", CBORObject.FromObject("blah".getBytes(Constants.charset)));
        params.put(Constants.CNF, cnf);
        tr.addToken(null, params, ctx, null, -1);
    }
    
    
    /**
     * Test add token with cnf with invalid kid
     * 
     * @throws AceException 
     */
    @Test
    public void testTokenInvalidKid() throws AceException {
        this.thrown.expect(AceException.class);
        this.thrown.expectMessage("cnf contains invalid kid");
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KID_CBOR, CBORObject.FromObject("blah"));
        params.put(Constants.CNF, cnf);
        tr.addToken(null, params, ctx, null, -1);
    }
    
    
    /**
     * Test add token with cnf containing COSE_Key
     *
     * @throws AceException 
     * @throws IntrospectionException 
     * @throws CoseException 
     */
    @Test
    public void testTokenCnfCoseKey() throws AceException, IntrospectionException, CoseException {
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, pskCnf);
        tr.addToken(null, params, ctx, null, -1);
        
        params.clear();
        params.put(Constants.SCOPE, CBORObject.FromObject("r_co2"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.CTI, CBORObject.FromObject("token2".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, rpkCnf);
        tr.addToken(null, params, ctx, null, -1);
        
        rpk = new RawPublicKeyIdentity(asymmetricKey.AsPublicKey()).getName();
        
        // The Token Repository stores as 'kid' the base64 encoding of
        // the binary content from the 'kid' field of the 'cnf' claim.
        String kid = Base64.getEncoder().encodeToString(rpk.getBytes());
        
        String kid2 = Base64.getEncoder().encodeToString(ourKey.getBytes(Constants.charset));
        
        Assert.assertEquals(TokenRepository.OK, tr.canAccess(kid, null, "co2", Constants.GET, null));
        Assert.assertEquals(TokenRepository.METHODNA, tr.canAccess(kid, null, "co2", Constants.POST, null));
        Assert.assertEquals(TokenRepository.FORBID, tr.canAccess(kid2, null, "co2", Constants.POST, null));
        Assert.assertEquals(TokenRepository.OK, tr.canAccess(kid2, null, "temp", Constants.GET, null));
        Assert.assertEquals(TokenRepository.UNAUTHZ, tr.canAccess("otherKey", null, "temp", Constants.GET, null));
    }
    
    
    /**
     * Test add token with cnf containing known kid
     *
     * @throws AceException 
     * @throws IntrospectionException 
     */
    @Test
    public void testTokenCnfKid() throws AceException, IntrospectionException {
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, pskCnf);
        tr.addToken(null, params, ctx, null, -1);
        
        params.clear();
        params.put(Constants.SCOPE, CBORObject.FromObject("r_co2"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));        
        params.put(Constants.CTI, CBORObject.FromObject("token2".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KID_CBOR, CBORObject.FromObject("ourKey".getBytes(Constants.charset)));
        params.put(Constants.CNF, cnf);
        tr.addToken(null, params, ctx, null, -1);
        
        // The Token Repository stores as 'kid' the base64 encoding of
        // the binary content from the 'kid' field of the 'cnf' claim.
        String kidStr = Base64.getEncoder().encodeToString(ourKey.getBytes(Constants.charset));
        
        Assert.assertEquals(TokenRepository.OK, tr.canAccess(kidStr, null, "co2", Constants.GET, null));
        Assert.assertEquals(TokenRepository.UNAUTHZ, tr.canAccess(rpk, null, "co2", Constants.POST, null));
        Assert.assertEquals(TokenRepository.UNAUTHZ, tr.canAccess(rpk, null, "co2", Constants.POST, null));
        Assert.assertEquals(TokenRepository.OK, tr.canAccess(kidStr, null, "temp", Constants.GET, null));
        Assert.assertEquals(TokenRepository.UNAUTHZ, tr.canAccess("otherKey", null, "temp", Constants.GET, null));
    }
    
    /**
     * Test add token with cnf containing valid Encrypt0
     *
     * @throws AceException 
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     * @throws IntrospectionException 
     */
    @Test
    public void testTokenCnfEncrypt0() throws AceException, CoseException,
            IllegalStateException, InvalidCipherTextException, IntrospectionException {
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        CBORObject cnf = CBORObject.NewMap();
        Encrypt0Message enc = new Encrypt0Message();
        enc.addAttribute(HeaderKeys.Algorithm, ctx.getAlg(), Attribute.PROTECTED);
        enc.SetContent(symmetricKey.EncodeToBytes());
        enc.encrypt(symmetricKey.get(KeyKeys.Octet_K).GetByteString());
        cnf.Add(Constants.COSE_ENCRYPTED_CBOR, enc.EncodeToCBORObject());
        params.put(Constants.CNF, cnf);
        tr.addToken(null, params, ctx, null, -1);

        // The Token Repository stores as 'kid' the base64 encoding of
        // the binary content from the 'kid' field of the 'cnf' claim.
        String kidStr = Base64.getEncoder().encodeToString(ourKey.getBytes(Constants.charset));
        
        Assert.assertEquals(TokenRepository.FORBID, tr.canAccess(kidStr, null, "co2", Constants.GET, null));
        Assert.assertEquals(TokenRepository.UNAUTHZ, tr.canAccess(rpk, null, "co2", Constants.POST, null));
        Assert.assertEquals(TokenRepository.UNAUTHZ, tr.canAccess(rpk, null, "co2", Constants.POST, null));
        Assert.assertEquals(TokenRepository.OK, tr.canAccess(kidStr, null, "temp", Constants.GET, null));
        Assert.assertEquals(TokenRepository.UNAUTHZ, tr.canAccess("otherKey", null, "temp", Constants.GET, null));
    }
    
    
    /**
     * Test pollTokens()
     *
     * @throws AceException 
     */
    @Test
    public void testPollToken() throws AceException {
        KissTime time = new KissTime();
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, pskCnf);
        params.put(Constants.EXP, CBORObject.FromObject(time.getCurrentTime()-1000));
        tr.addToken(null, params, ctx, null, -1);
        
        params.clear();
        params.put(Constants.SCOPE, CBORObject.FromObject("r_co2"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.CTI, CBORObject.FromObject("token2".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KID_CBOR, CBORObject.FromObject("ourKey".getBytes(Constants.charset)));
        params.put(Constants.CNF, cnf);
        params.put(Constants.EXP, CBORObject.FromObject(time.getCurrentTime()+1000000));
        tr.addToken(null, params, ctx, null, -1);
        
        OneKey key1 = tr.getPoP("dG9rZW4x");
        OneKey key2 = tr.getPoP("dG9rZW4y");

        key1 = tr.getPoP("dG9rZW4x");
        key2 = tr.getPoP("dG9rZW4y");
        
        Assert.assertNull(key1);
        Assert.assertNotNull(key2);
    }
    
    /**
     * Test loading an existing token file
     * 
     * @throws AceException
     * @throws IOException 
     * @throws IntrospectionException 
     */
    @Test
    public void testLoad() throws AceException, IOException, IntrospectionException {
        Set<String> resources = new HashSet<>();
        resources.add("temp");
        resources.add("co2");
        
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
        
        TokenRepository tr2 = new TokenRepository(valid, TestConfig.testFilePath + "testTokens.json",
        										  ctx, null, 0, new KissTime(), rsId);

        // The Token Repository stores as 'kid' the base64 encoding of
        // the binary content from the 'kid' field of the 'cnf' claim.
        String kidStr = Base64.getEncoder().encodeToString(ourKey.getBytes(Constants.charset));
        
        Assert.assertEquals(TokenRepository.OK, tr2.canAccess(kidStr, null, "temp", Constants.GET, null));  
        Assert.assertEquals(TokenRepository.UNAUTHZ, tr2.canAccess("otherKey", null, "co2", Constants.GET, null));
        Assert.assertEquals(TokenRepository.METHODNA, tr2.canAccess(kidStr, null, "temp", Constants.POST, null)); 
        Assert.assertEquals(TokenRepository.FORBID, tr2.canAccess(kidStr, null, "co2", Constants.GET, null)); 
        tr2.close();

        //re-create the original TR
        createTR(valid);
    }
    
    
    /**
     * Test getPoP()
     *
     * @throws AceException 
     */
    @Test
    public void testGetPoP() throws AceException {
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, pskCnf);
        tr.addToken(null, params, ctx, null, -1);
        
        params.clear();
        params.put(Constants.SCOPE, CBORObject.FromObject("r_co2"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.CTI, CBORObject.FromObject("token2".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        params.put(Constants.CNF, rpkCnf);
        tr.addToken(null, params, ctx, null, -1);
        
        OneKey key1 = tr.getPoP("dG9rZW4x");
        OneKey key2 = tr.getPoP("dG9rZW4y");
        
        Assert.assertArrayEquals(symmetricKey.EncodeToBytes(), key1.EncodeToBytes());
        Assert.assertArrayEquals(asymmetricKey.PublicKey().EncodeToBytes(), key2.EncodeToBytes());
    }
    
    
    /**
     * Remove lingering token entries
     * @throws AceException 
     */
    @After
    public void cleanup() throws AceException {
        tr.removeToken("dG9rZW4x");
        tr.removeToken("dG9rZW4y");
    }
    
}
