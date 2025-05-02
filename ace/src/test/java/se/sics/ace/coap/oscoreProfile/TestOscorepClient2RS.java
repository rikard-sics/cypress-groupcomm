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
package se.sics.ace.coap.oscoreProfile;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import org.eclipse.californium.oscore.OSException;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.MessageTag;
import org.eclipse.californium.elements.util.Bytes;

import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.Util;
import se.sics.ace.coap.client.OSCOREProfileRequests;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;

/**
 * A test case for the OSCORE profile interactions between client and server.
 * 
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class TestOscorepClient2RS {

    /**
     * The cnf keys used in these tests as OSCORE Master Secrets
     */
    private static byte[] keyCnf = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static byte[] keyCnf2 = {'a', 'b', 'd', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    /**
     * The OSCORE Master Salts used in these tests
     */
    private static byte[] salt = {'a', 'b', 'e', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static byte[] salt2 = {'a', 'b', 'f', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    
    /**
     * The OSCORE ID Contexts used in these tests
     */
    private static byte[] kidContext = {'a', 'b'};
    
    /**
     * The AS <-> RS key used in these tests
     */
    private static byte[] keyASRS = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static RunTestServer srv = null;
    private static OSCoreCtx osctx;
    
    private static OSCoreCtxDB ctxDB;
    
    private final static int MAX_UNFRAGMENTED_SIZE = 4096;
    
	// Each set of the list refers to a different size of Recipient IDs.
	// The element with index 0 includes as elements Recipient IDs with size 1 byte.
	private static List<Set<Integer>> usedRecipientIds = new ArrayList<Set<Integer>>();
    
    private static class RunTestServer implements Runnable {
        
        public RunTestServer() {
           //Do nothing
        }

        /**
         * Stop the server
         * @throws Exception 
         */
        public void stop() throws Exception {
            OscoreRSTestServer.stop();
        }
        
        @Override
        public void run() {
            try {
                OscoreRSTestServer.main(null);
            } catch (final Throwable t) {
                System.err.println(t.getMessage());
                try {
                    OscoreRSTestServer.stop();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        
    }
    
    /**
     * This sets up everything for the tests including the server
     * @throws OSException 
     */
    @BeforeClass
    public static void setUp() throws OSException {
        srv = new RunTestServer();
        srv.run();
        
        //Initialize a fake context        
        byte[] senderId  = new byte[] {(byte) 0xff, (byte) 0xff, (byte) 0xff};
        byte[] recipientId  = new byte[] {(byte) 0xff, (byte) 0xff, (byte) 0xfe};
        osctx = new OSCoreCtx(keyCnf, true, null, 
        		senderId,
        		recipientId,
                null, null, null, null, MAX_UNFRAGMENTED_SIZE);
        
        
        
        ctxDB = new org.eclipse.californium.oscore.HashMapCtxDB();
        
    	for (int i = 0; i < 4; i++) {
        	// Empty sets of assigned Sender IDs; one set for each possible Sender ID size in bytes.
        	// The set with index 0 refers to Sender IDs with size 1 byte
    		usedRecipientIds.add(new HashSet<Integer>());
    	}
    }
    
    /**
     * Deletes the test DB after the tests
     * @throws Exception 
     */
    @AfterClass
    public static void tearDown() throws Exception {
        srv.stop();
    }
    
    /**
     * Test successful submission of a token to the RS with subsequent
     * access based on the token
     * 
     * @throws Exception 
     */
    @Test
    public void testSuccess() throws Exception {
        //Generate a token
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx 
            = CwtCryptoCtx.encrypt0(keyASRS, coseP.getAlg().AsCBOR());
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_helloWorld"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.CTI, CBORObject.FromObject("token2".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

        CBORObject osc = CBORObject.NewMap();
        
        osc.Add(Constants.OS_MS, keyCnf);
        osc.Add(Constants.OS_SALT, salt);
        osc.Add(Constants.OS_CONTEXTID, kidContext);
        byte[] id = Util.intToBytes(1);
        osc.Add(Constants.OS_ID, id);
        
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.OSCORE_Input_Material, osc);
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx).EncodeToBytes());
        payload.Add(Constants.CNF, cnf);
        Response asRes = new Response(CoAP.ResponseCode.CREATED);
        asRes.setPayload(payload.EncodeToBytes());
        
        Response rsRes = OSCOREProfileRequests.postToken("coap://localhost/authz-info", asRes, ctxDB, usedRecipientIds);

        assert(rsRes.getCode().equals(CoAP.ResponseCode.CREATED));
        
        //Check that the OSCORE context has been created:
        Assert.assertNotNull(ctxDB.getContext("coap://localhost/helloWorld"));

        
       //Submit a request

       CoapClient c = OSCOREProfileRequests.getClient(new InetSocketAddress(
               "coap://localhost/helloWorld", CoAP.DEFAULT_COAP_PORT), ctxDB);
       
       Request helloReq = new Request(CoAP.Code.GET);
       helloReq.getOptions().setOscore(new byte[0]);
       CoapResponse helloRes = c.advanced(helloReq);
       
       Assert.assertEquals("Hello World!", helloRes.getResponseText());
       
       
       //Submit a forbidden request
       
       CoapClient c2 = OSCOREProfileRequests.getClient(new InetSocketAddress(
               "coap://localhost/temp", CoAP.DEFAULT_COAP_PORT), ctxDB);
       
       Request getTemp = new Request(CoAP.Code.GET);
       getTemp.getOptions().setOscore(new byte[0]);
       CoapResponse getTempRes = c2.advanced(getTemp);
       assert(getTempRes.getCode().equals(CoAP.ResponseCode.FORBIDDEN));
       
       //Submit a request with unallowed method
       Request deleteHello = new Request(CoAP.Code.DELETE);
       deleteHello.getOptions().setOscore(new byte[0]);
       CoapResponse deleteHelloRes = c.advanced(deleteHello);
       assert(deleteHelloRes.getCode().equals(CoAP.ResponseCode.METHOD_NOT_ALLOWED));
    }
    
    /**
     * Test unauthorized access to the RS
     * 
     * @throws Exception 
     */
    @Test
    public void testNoAccess() throws Exception {
    	
    	ctxDB.addContext("coap://localhost/helloWorld", osctx);

        CoapClient c = OSCOREProfileRequests.getClient(
                 new InetSocketAddress(
                        "coap://localhost/helloWorld", CoAP.DEFAULT_COAP_PORT), ctxDB);

        CoapResponse res = c.get();
        assert(res.getCode().equals(CoAP.ResponseCode.UNAUTHORIZED));
    }
    
    
    /**
     * Test successful submission of a token to the RS with subsequent
     * access based on the token, followed by the submission of a new token
     * to update access rights with subsequent access based on the new token
     * 
     * @throws Exception 
     */
    @Test
    public void testSuccessUpdateAccessRights() throws Exception {
        //Generate a token
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx 
            = CwtCryptoCtx.encrypt0(keyASRS, coseP.getAlg().AsCBOR());
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_helloWorld"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.CTI, CBORObject.FromObject("token3".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

        CBORObject osc = CBORObject.NewMap();
        CBORObject cbor = CBORObject.NewMap();
        
        osc.Add(Constants.OS_MS, keyCnf2);
        osc.Add(Constants.OS_SALT, salt2);
        osc.Add(Constants.OS_CONTEXTID, kidContext);
        byte[] id = Util.intToBytes(2);
        osc.Add(Constants.OS_ID, id);

        cbor.Add(Constants.OSCORE_Input_Material, osc);
        params.put(Constants.CNF, cbor);
        CWT token = new CWT(params);
        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx).EncodeToBytes());
        payload.Add(Constants.CNF, cbor);
        Response asRes = new Response(CoAP.ResponseCode.CREATED);
        asRes.setPayload(payload.EncodeToBytes());

        Response rsRes = OSCOREProfileRequests.postToken("coap://localhost/authz-info", asRes, ctxDB, usedRecipientIds);

        assert(rsRes.getCode().equals(CoAP.ResponseCode.CREATED));
        //Check that the OSCORE context has been created:
        
       Assert.assertNotNull(ctxDB.getContext("coap://localhost/helloWorld"));

       //Submit a request
       
       CoapClient c = OSCOREProfileRequests.getClient(new InetSocketAddress(
               "coap://localhost/helloWorld", CoAP.DEFAULT_COAP_PORT), ctxDB);
       
       Request helloReq = new Request(CoAP.Code.GET);
       helloReq.getOptions().setOscore(new byte[0]);
       CoapResponse helloRes = c.advanced(helloReq);
       Assert.assertEquals("Hello World!", helloRes.getResponseText());
       
       //Submit a forbidden request
       
       CoapClient c2 = OSCOREProfileRequests.getClient(new InetSocketAddress(
               "coap://localhost/temp", CoAP.DEFAULT_COAP_PORT), ctxDB);
       
       Request getTemp = new Request(CoAP.Code.GET);
       getTemp.getOptions().setOscore(new byte[0]);
       CoapResponse getTempRes = c2.advanced(getTemp);
       assert(getTempRes.getCode().equals(CoAP.ResponseCode.FORBIDDEN));
       
       //Submit a request with unallowed method
       Request deleteHello = new Request(CoAP.Code.DELETE);
       deleteHello.getOptions().setOscore(new byte[0]);
       CoapResponse deleteHelloRes = c.advanced(deleteHello);
       assert(deleteHelloRes.getCode().equals(CoAP.ResponseCode.METHOD_NOT_ALLOWED));
     
       
       // Build a new Token for updating access rights, with a different 'scope'
       
       params = new HashMap<>(); 
       params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
       params.put(Constants.AUD, CBORObject.FromObject("aud1"));
       params.put(Constants.CTI, CBORObject.FromObject("token4".getBytes(Constants.charset)));
       params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

       // Now the 'cnf' claim includes only a 'kid' with value the 'id'
       // used in the first Token and identifying the OSCORE_Input_Material
       cbor = CBORObject.NewMap();
       cbor.Add(Constants.COSE_KID_CBOR, Util.intToBytes(2));
       params.put(Constants.CNF, cbor);
       token = new CWT(params);
       
       // Include only the Token now. If Id1 and Nonce1 were
       // included here too, the RS would silently ignore them
       payload = CBORObject.NewMap();
       payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx).EncodeToBytes());
       
       asRes = new Response(CoAP.ResponseCode.CREATED);
       asRes.setPayload(payload.EncodeToBytes());
        
	   // Posting the Token through an OSCORE-protected request
       // 
       // Normally, a client understands that the Token is indeed for updating access rights,
       // since the response from the AS does not include the 'cnf' parameter.
       CoapResponse rsRes2 = OSCOREProfileRequests.postTokenUpdate("coap://localhost/authz-info", asRes, ctxDB);
       assert(rsRes2.getCode() == CoAP.ResponseCode.CREATED);
       // ... and in fact no payload is expected in the response
       assert (rsRes2.getPayload() == null || rsRes2.getPayload() == Bytes.EMPTY);
       
       //Check that the OSCORE context created before is still present
       Assert.assertNotNull(ctxDB.getContext("coap://localhost/helloWorld"));
       
       // Perform new requests to the RS, under the latest posted Token
       
       // This should now fail - Access to this resource is not granted anymore
       helloReq = new Request(CoAP.Code.GET);
       helloReq.getOptions().setOscore(new byte[0]);
       helloRes = c.advanced(helloReq);
       assert(helloRes.getCode().equals(CoAP.ResponseCode.FORBIDDEN));
       
       // This should now fail with FORBIDDEN, not with METHOD NOT ALLOWED
       deleteHello = new Request(CoAP.Code.DELETE);
       deleteHello.getOptions().setOscore(new byte[0]);
       deleteHelloRes = c.advanced(deleteHello);
       assert(deleteHelloRes.getCode().equals(CoAP.ResponseCode.FORBIDDEN));
       
       // This should now succeed - Access to this resource is now granted by the latest posted Token
       getTemp = new Request(CoAP.Code.GET);
       getTemp.getOptions().setOscore(new byte[0]);
       getTempRes = c2.advanced(getTemp);
       assert(getTempRes.getCode().equals(CoAP.ResponseCode.CONTENT));
       Assert.assertEquals("19.0 C", getTempRes.getResponseText());
       
       // This should fail with METHOD NOT ALLOWED, since the latest posted Token grants access to this resource with GET
       Request deleteTemp = new Request(CoAP.Code.DELETE);
       deleteTemp.getOptions().setOscore(new byte[0]);
       CoapResponse deleteTempRes = c2.advanced(deleteTemp);
       assert(deleteTempRes.getCode().equals(CoAP.ResponseCode.METHOD_NOT_ALLOWED));
       
    }
    

}
