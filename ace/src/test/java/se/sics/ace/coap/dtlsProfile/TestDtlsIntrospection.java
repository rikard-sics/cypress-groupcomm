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

import java.net.InetSocketAddress;
import java.util.Base64;
import java.util.Map;

import org.eclipse.californium.core.coap.CoAP;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

import org.eclipse.californium.cose.OneKey;

import se.sics.ace.Constants;
import se.sics.ace.TestConfig;
import se.sics.ace.coap.BksStore;
import se.sics.ace.coap.rs.dtlsProfile.DtlspIntrospection;

/**
 * Test for the DtlspIntrospection class. 
 * 
 *  NOTE: This will automatically start a server in another thread
 * 
 * @author Ludwig Seitz
 *
 */
public class TestDtlsIntrospection {

    static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static byte[] key256 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,28, 29, 30, 31, 32};

    static String aKey = "piJYICg7PY0o/6Wf5ctUBBKnUPqN+jT22mm82mhADWecE0foI1ghAKQ7qn7SL/Jpm6YspJmTWbFG8GWpXE5GAXzSXrialK0pAyYBAiFYIBLW6MTSj4MRClfSUzc8rVLwG8RH5Ak1QfZDs4XhecEQIAE=";
    
    static RunTestServer srv = null;

    private static class RunTestServer implements Runnable {

        public RunTestServer() {
            //Do nothing
        }

        /**
         * Stop the server
         * @throws Exception 
         */
        public void stop() throws Exception {
            DtlsASTestServer.stop();
        }

        @Override
        public void run() {
            try {
                DtlsASTestServer.main(null);
            } catch (final Throwable t) {
                System.err.println(t.getMessage());
                try {
                    DtlsASTestServer.stop();
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
     * Test CoapIntrospect using RPK
     * 
     * @throws Exception
     */
    @Test
    public void testCoapIntrospect() throws Exception {
        OneKey key = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(aKey)));
        DtlspIntrospection i = new DtlspIntrospection(key, "coaps://localhost/introspect");
        Map<Short, CBORObject> map = i.getParams(new byte[]{0x00});     
        assert(map.containsKey(Constants.AUD));
        assert(map.get(Constants.AUD).AsString().equals("actuators"));
        assert(map.containsKey(Constants.SCOPE));
        assert(map.get(Constants.SCOPE).AsString().equals("temp"));
        assert(map.containsKey(Constants.ACTIVE));
        assert(map.get(Constants.ACTIVE).isTrue());
        assert(map.containsKey(Constants.CTI));
        assert(map.containsKey(Constants.EXP));

    }

    /**
     * Test CoapIntrospect using PSK
     * 
     * @throws Exception
     */
    @Test
    public void testCoapIntrospectPSK() throws Exception {
        BksStore.init( TestConfig.testFilePath + "IntrospectTestKeyStore.bks", "password",
                TestConfig.testFilePath + "IntrospectTestAddr2id.cfg"); 
          
        BksStore keystore = new BksStore(TestConfig.testFilePath + "IntrospectTestKeyStore.bks", "password",
                TestConfig.testFilePath + "IntrospectTestAddr2id.cfg");
        
        keystore.addKey(key128, "rs1");
        keystore.addAddress(new InetSocketAddress("localhost", 
                CoAP.DEFAULT_COAP_SECURE_PORT), "rs1");
        
        DtlspIntrospection i = new DtlspIntrospection(
                key128, "rs1", 
                TestConfig.testFilePath + "IntrospectTestKeyStore.bks",
                "password",
                TestConfig.testFilePath + "IntrospectTestAddr2id.cfg",
                "coaps://localhost/introspect");
        
        Map<Short, CBORObject> map =  i.getParams(new byte[]{0x01});     
        assert(map.containsKey(Constants.AUD));
        assert(map.get(Constants.AUD).AsString().equals("aud1"));
        assert(map.containsKey(Constants.SCOPE));
        assert(map.get(Constants.SCOPE).AsString().equals("co2"));
        assert(map.containsKey(Constants.ACTIVE));
        assert(map.get(Constants.ACTIVE).isTrue());
        assert(map.containsKey(Constants.CTI));
        assert(map.containsKey(Constants.EXP));

    }

}
