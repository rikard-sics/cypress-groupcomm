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
package se.sics.ace.coap.dtlsProfile;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executor;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.auth.PreSharedKeyIdentity;
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
import se.sics.ace.Message;
import se.sics.ace.TestConfig;
import se.sics.ace.coap.rs.CoapAuthzInfo;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.KissValidator;
import se.sics.ace.examples.LocalMessage;
import se.sics.ace.rs.AuthzInfo;
import se.sics.ace.rs.IntrospectionException;
import se.sics.ace.rs.TokenRepository;

/**
 * Test the DTLSProfileAuthzInfo class.
 * 
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class TestDtlspAuthzInfo {

    private static byte[] key128a = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static CwtCryptoCtx ctx;
    private static AuthzInfo ai;
    private static CoapAuthzInfo dai;
    private static CBORObject payload;
    private static CBORObject payload2;
    
    /**
     * Set up the necessary objects.
     * 
     * @throws CoseException
     * @throws AceException
     * @throws IOException
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     */
    @BeforeClass
    public static void setUp() 
            throws CoseException, AceException, IOException, 
            IllegalStateException, InvalidCipherTextException {
        
        //Set up DTLSProfileTokenRepository
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
        myScopes.put("rw_co2", myResource);
        
        String rsId = "rs1";
        
        KissValidator valid = new KissValidator(Collections.singleton("aud1"), myScopes);  
        
        String tokenFile = TestConfig.testFilePath + "tokens.json";
        new File(tokenFile).delete(); 
        
        //Set up COSE parameters
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        ctx = CwtCryptoCtx.encrypt0(key128a, coseP.getAlg().AsCBOR());
        
        //Set up the inner Authz-Info library
        ai = new AuthzInfo(Collections.singletonList("TestAS"), 
                new KissTime(), null, rsId, valid, ctx, null, 0, tokenFile, valid,
                false);
        
        //Set up the DTLS authz-info resource
        dai = new CoapAuthzInfo(ai);
        
        //Set up a token to use
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x00}));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        CBORObject kid = CBORObject.FromObject(new byte[] {0x01, 0x02});
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        payload = token.encode(ctx);
        
        
        // Set up one more token to use, for testing the update of access rights
        Map<Short, CBORObject> params2 = new HashMap<>(); 
        params2.put(Constants.SCOPE, CBORObject.FromObject("rw_co2"));
        params2.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params2.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x01}));
        params2.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CBORObject keyData  = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.KeyId.AsCBOR(), kid);
        CBORObject cnf2 = CBORObject.NewMap();
        cnf2.Add(Constants.COSE_KEY_CBOR, keyData); // The specified 'COSE_Key' includes only key type and kid
        params2.put(Constants.CNF, cnf2);
        CWT token2 = new CWT(params2);
        payload2 = token2.encode(ctx);
        
    }
    
    /**
     * Test a POST to /authz-info
     * @throws AceException 
     * @throws IntrospectionException 
     * @throws IOException 
     */
    @Test
    public void testPOSTtoken() 
            throws AceException, IntrospectionException, IOException {
        Request req = new Request(Code.POST);
        req.setPayload(payload.EncodeToBytes());
        AddressEndpointContext destCtx = new AddressEndpointContext(
                new InetSocketAddress(
                InetAddress.getLocalHost(), CoAP.DEFAULT_COAP_PORT),
                new PreSharedKeyIdentity("psk"));
        req.setDestinationContext(destCtx);
        

        req.setType(Type.NON);
        req.setAcknowledged(false);
        AddressEndpointContext srcCtx = new AddressEndpointContext(
                new InetSocketAddress(InetAddress.getLocalHost(),
                        CoAP.DEFAULT_COAP_PORT));
        req.setSourceContext(srcCtx);
        
        req.setToken(new byte[]{0x01});
        CoapEndpoint cep = new CoapEndpoint.Builder().build();
        cep.start();
        Exchange iex = new Exchange(req, null, Origin.REMOTE, new TestSynchroneExecutor());
        iex.setEndpoint(cep);
        CoapExchange ex = new CoapExchange(iex, dai);      
        dai.handlePOST(ex);
      
        byte[] kidBytes = new byte[]{0x01, 0x02};
        String kid = Base64.getEncoder().encodeToString(kidBytes);
        
        //Test that the PoP key was stored
        Assert.assertArrayEquals(key128,
                TokenRepository.getInstance().getKey(kid).get(
                        KeyKeys.Octet_K).GetByteString());
               
       //Test that the token is there
        Assert.assertEquals(TokenRepository.OK, 
                TokenRepository.getInstance().canAccess(
                        kid, kid, "temp", Constants.GET, null));
    }
    
    /**
     * Test a POST to /authz-info, followed by an attempt to update
     * access rights by posting a new Access Token over DTLS
     * 
     * @throws AceException 
     * @throws IntrospectionException 
     * @throws IOException 
     */
    @Test
    public void testPOSTtokenUpdateAccessRights() 
            throws AceException, IntrospectionException, IOException {
    	
        Request req = new Request(Code.POST);
        req.setPayload(payload.EncodeToBytes());
        AddressEndpointContext destCtx = new AddressEndpointContext(
                new InetSocketAddress(
                InetAddress.getLocalHost(), CoAP.DEFAULT_COAP_PORT),
                new PreSharedKeyIdentity("psk"));
        req.setDestinationContext(destCtx);
        
        req.setType(Type.NON);
        req.setAcknowledged(false);
        AddressEndpointContext srcCtx = new AddressEndpointContext(
                new InetSocketAddress(InetAddress.getLocalHost(),
                        CoAP.DEFAULT_COAP_PORT));
        req.setSourceContext(srcCtx);
        
        req.setToken(new byte[]{0x02});
        CoapEndpoint cep = new CoapEndpoint.Builder().build();
        cep.start();
        Exchange iex = new Exchange(req, null, Origin.REMOTE, new TestSynchroneExecutor());
        iex.setEndpoint(cep);
        CoapExchange ex = new CoapExchange(iex, dai);      
        dai.handlePOST(ex);
      
        byte[] kidBytes = new byte[]{0x01, 0x02};
        String kid = Base64.getEncoder().encodeToString(kidBytes);
        
        //Test that the PoP key was stored
        Assert.assertArrayEquals(key128,
                TokenRepository.getInstance().getKey(kid).get(
                        KeyKeys.Octet_K).GetByteString());
               
       //Test that the token is there and that responses are as expected
       Assert.assertEquals(TokenRepository.OK,
                TokenRepository.getInstance().canAccess(
                        kid, null, "temp", Constants.GET, null));
       
       Assert.assertEquals(TokenRepository.METHODNA,
               TokenRepository.getInstance().canAccess(
                       kid, null, "temp", Constants.POST, null));
       
       Assert.assertEquals(TokenRepository.FORBID,
               TokenRepository.getInstance().canAccess(
                       kid, null, "co2", Constants.POST, null));
        
        
       // Build a new Token for updating access rights, with a different 'scope'
        
      // Posting the Token through an unprotected request.
      // This fails since such a Token needs to include
      // a 'cnf' claim transporting also the actual key 'k'
      LocalMessage req2 = new LocalMessage(0, null, null, payload2);
      req2 = new LocalMessage(0, null, null, payload2);
      LocalMessage resp2 = (LocalMessage)ai.processMessage(req2);
      assert(resp2.getMessageCode() == Message.FAIL_BAD_REQUEST);
      
	  req2 = new LocalMessage(0, kid, null, payload2);
	  resp2 = (LocalMessage)ai.processMessage(req2);
	  assert(resp2.getMessageCode() == Message.CREATED);
	  
      // Test that the new token is there, and both GET and POST
      // are consistently authorized on the "co2" resource
      //
      // The 'kid' has not changed, since the same PoP key
      // with the same 'kid' is bound also to the new token
      Assert.assertEquals(TokenRepository.OK, 
              TokenRepository.getInstance().canAccess(
                      kid, kid, "co2", Constants.GET, null));
      Assert.assertEquals(TokenRepository.OK, 
              TokenRepository.getInstance().canAccess(
                      kid, kid, "co2", Constants.POST, null));
      Assert.assertEquals(TokenRepository.METHODNA, 
              TokenRepository.getInstance().canAccess(
                      kid, kid, "co2", Constants.DELETE, null));
      
      // ... and that access to the "temp" resource is not allowed anymore
      Assert.assertEquals(TokenRepository.FORBID, 
              TokenRepository.getInstance().canAccess(
                      kid, kid, "temp", Constants.GET, null));
        
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
     * Synchronous Executor.
     * 
     * Executes command synchronous to simplify unit tests.
     * 
     * @since 3.0 (replaces SyncSerialExecutor)
     */
    private class TestSynchroneExecutor implements Executor {
        /**
         * Synchronous executor.
         * 
         * For unit tests.
         */
        private TestSynchroneExecutor() {
        }

        /**
         * Execute the job synchronous.
         */
        @Override
        public void execute(final Runnable command) {
            command.run();
        }
    }
}
