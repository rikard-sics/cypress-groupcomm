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

import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

import se.sics.ace.Constants;
import se.sics.ace.coap.rs.oscoreProfile.OscoreIntrospection;

/**
 * Test for the OscoreIntrospection class. 
 * 
 *  NOTE: This will automatically start a server in another thread
 * 
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class TestOscoreIntrospection {

    static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    static RunTestServer srv = null;
    
    private static OSCoreCtxDB ctxDB;
    
    private final static int MAX_UNFRAGMENTED_SIZE = 4096;

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
     */
    @BeforeClass
    public static void setUp() {
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
     * Test OscoreIntrospection using OSCORE
     * 
     * @throws Exception
     */
    @Test
    public void testCoapIntrospect() throws Exception {
    	
        byte[] senderId = new byte[] {0x11};
        byte[] recipientId = new byte[] {0x00};
        OSCoreCtx ctx = new OSCoreCtx(key128, true, null, senderId, recipientId, null, null, null, null, MAX_UNFRAGMENTED_SIZE);
                
        OscoreIntrospection i = new OscoreIntrospection(ctx, "coap://localhost/introspect", ctxDB);
        Map<Short, CBORObject> map =  i.getParams(new byte[]{0x00});     
        assert(map.containsKey(Constants.AUD));
        assert(map.get(Constants.AUD).AsString().equals("actuators"));
        assert(map.containsKey(Constants.SCOPE));
        assert(map.get(Constants.SCOPE).AsString().equals("co2"));
        assert(map.containsKey(Constants.ACTIVE));
        assert(map.get(Constants.ACTIVE).isTrue());
        assert(map.containsKey(Constants.CTI));
        assert(map.containsKey(Constants.EXP));

    }
}
