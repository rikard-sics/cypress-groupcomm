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

import java.util.Map;

import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import org.eclipse.californium.oscore.OSException;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

import se.sics.ace.Constants;
import se.sics.ace.client.GetToken;
import se.sics.ace.coap.client.OSCOREProfileRequests;

/**
 * Test the DTLSProfileRequests class C->AS
 *  
 * NOTE: This will automatically start an AS in another thread 
 * 
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class TestOscorepClient2AS {
    
    private final static int MAX_UNFRAGMENTED_SIZE = 4096;
	
    /**
     * The Master Secret of the AS <-> C OSCORE Security Context
     */
    private static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};    
    private static RunTestServer srv = null;
    private static OSCoreCtx ctx;
    
    private static OSCoreCtxDB ctxDB;
    
    private static class RunTestServer implements Runnable {
        
        public RunTestServer() {
           //Do nothing
        }

        /**
         * Stop the server
         * @throws Exception 
         */
        public void stop() throws Exception {
            OscoreASTestServer.stop();
        }
        
        @Override
        public void run() {
            try {
                OscoreASTestServer.main(null);
            } catch (final Throwable t) {
                System.err.println(t.getMessage());
                try {
                    OscoreASTestServer.stop();
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
    	
    	ctx = new OSCoreCtx(key128, true, null, 
    			new byte[] {0x01},
    			new byte[] {0x00},
                null, null, null, null, MAX_UNFRAGMENTED_SIZE);
        
        ctxDB = new org.eclipse.californium.oscore.HashMapCtxDB();
        
        srv = new RunTestServer();
        srv.run();
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
     * Test successful retrieval of a token over OSCORE
     * 
     * @throws Exception 
     */
    @Test
    public void testSuccess() throws Exception { 	
        CBORObject params = GetToken.getClientCredentialsRequest(
                CBORObject.FromObject("rs1"),
                CBORObject.FromObject("r_temp rw_config foobar"), null);
        
        Response response = OSCOREProfileRequests.getToken(
                "coap://localhost/token", params, ctx, ctxDB);
        
        CBORObject res = CBORObject.DecodeFromBytes(response.getPayload());
        Map<Short, CBORObject> map = Constants.getParams(res);
        System.out.println(map);
        assert(map.containsKey(Constants.ACCESS_TOKEN));
        assert(!map.containsKey(Constants.PROFILE)); //Profile is implicit
        assert(map.containsKey(Constants.CNF));
        assert(map.containsKey(Constants.SCOPE));
        assert(map.get(Constants.SCOPE).AsString().equals("r_temp rw_config"));
    }

    /**
     * Test successful retrieval of a token over OSCORE, followed
     * by a second request for a new access token to update access rights
     * 
     * @throws Exception 
     */
    @Test
    public void testSuccessUpdateAccessRights() throws Exception { 	
        CBORObject params = GetToken.getClientCredentialsRequest(
                CBORObject.FromObject("rs2"),
                CBORObject.FromObject("r_temp rw_config foobar"), null);
        
        Response response = OSCOREProfileRequests.getToken(
                "coap://localhost/token", params, ctx, ctxDB);
        
        CBORObject res = CBORObject.DecodeFromBytes(response.getPayload());
        Map<Short, CBORObject> map = Constants.getParams(res);
        System.out.println(map);
        assert(map.containsKey(Constants.ACCESS_TOKEN));
        assert(!map.containsKey(Constants.PROFILE)); //Profile is implicit
        assert(map.containsKey(Constants.CNF));
        assert(map.containsKey(Constants.SCOPE));
        assert(map.get(Constants.SCOPE).AsString().equals("r_temp rw_config"));
        
        // Ask for a new Token for updating access rights, with a different 'scope'
        
       CBORObject myKid = map.get(Constants.CNF).get(Constants.OSCORE_Input_Material).get(Constants.OS_ID);
       CBORObject myCnf = CBORObject.NewMap();
       myCnf.Add(Constants.COSE_KID_CBOR, myKid);
        
        params = GetToken.getClientCredentialsRequest(
                CBORObject.FromObject("rs2"),
                CBORObject.FromObject("r_temp rw_config rw_light foobar"), myCnf);
        
        response = OSCOREProfileRequests.getToken(
                "coap://localhost/token", params, ctx, ctxDB);
        
        res = CBORObject.DecodeFromBytes(response.getPayload());
        map = Constants.getParams(res);
        System.out.println(map);
        assert(map.containsKey(Constants.ACCESS_TOKEN));
        assert(!map.containsKey(Constants.PROFILE)); //Profile is implicit
        assert(!map.containsKey(Constants.CNF)); // The 'cnf' parameter must not be present here
        assert(map.containsKey(Constants.SCOPE));
        assert(map.get(Constants.SCOPE).AsString().equals("r_temp rw_config rw_light"));
        
    }
    
}

