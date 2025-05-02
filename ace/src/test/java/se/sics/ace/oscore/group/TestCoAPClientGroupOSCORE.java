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
package se.sics.ace.oscore.group;

import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.CoapEndpoint.Builder;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedSinglePskStore;
import org.eclipse.californium.scandium.dtls.x509.AsyncNewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.dtls.x509.SingleCertificateProvider;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.config.Configuration;

import se.sics.ace.Constants;
import se.sics.ace.ReferenceToken;
import se.sics.ace.Util;
import se.sics.ace.as.Token;

/**
 * Test the coap classes.
 * 
 * NOTE: This will automatically start a server in another thread
 * 
 * @author Marco Tiloca
 *
 */
public class TestCoAPClientGroupOSCORE {
    
    static byte[] key256 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,28, 29, 30, 31, 32};
    static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static String aKey = "piJYICg7PY0o/6Wf5ctUBBKnUPqN+jT22mm82mhADWecE0foI1ghAKQ7qn7SL/Jpm6YspJmTWbFG8GWpXE5GAXzSXrialK0pAyYBAiFYIBLW6MTSj4MRClfSUzc8rVLwG8RH5Ak1QfZDs4XhecEQIAE=";
    
	// Asymmetric key pair of the Client
	// ECDSA with P-256
	private static String cX_ECDSA = "12D6E8C4D28F83110A57D253373CAD52F01BC447E4093541F643B385E179C110";
	private static String cY_ECDSA = "283B3D8D28FFA59FE5CB540412A750FA8DFA34F6DA69BCDA68400D679C1347E8";
	private static String cD_ECDSA = "00A43BAA7ED22FF2699BA62CA4999359B146F065A95C4E46017CD25EB89A94AD29";
	static OneKey cRPK = null;
    
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
            CoapASTestServerGroupOSCORE.stop();
        }
        
        @Override
        public void run() {
            try {
                CoapASTestServerGroupOSCORE.main(null);
            } catch (final Throwable t) {
                System.err.println(t.getMessage());
                try {
                    CoapASTestServerGroupOSCORE.stop();
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
    
    // @Ignore
    /**
     * Test connecting with RPK without authenticating the client.
     * The Server should reject that.
     * 
     * @throws Exception 
     */
    /*
    @Test
    public void testNoClientAuthN() throws Exception {
        DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
        builder.setAddress(new InetSocketAddress(0));
        builder.setSupportedCipherSuites(new CipherSuite[]{
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8});
        builder.setClientOnly();
        builder.setRpkTrustAll();
        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
        Builder ceb = new Builder();
        ceb.setConnector(dtlsConnector);
        ceb.setConfiguration(Configuration.getStandard());
        CoapEndpoint e = ceb.build();
        CoapClient client = new CoapClient("coaps://localhost/introspect");
        client.setEndpoint(e);
        dtlsConnector.start();

        ReferenceToken at = new ReferenceToken(new byte[]{0x00});
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.TOKEN, at.encode());
        try {
            client.post(
                Constants.getCBOR(params).EncodeToBytes(), 
                Constants.APPLICATION_ACE_CBOR);
        } catch (IOException ex) {
            Object cause = ex.getCause();
            if (cause instanceof HandshakeException) {
                HandshakeException he = (HandshakeException)cause;
                System.out.println(he.getAlert().toString());
                //Everything ok
                return;
            }
        }
        
        Assert.fail("Server should not accept DTLS connection");
  
    }
    */
    
    /**
     * Test CoapToken using PSK
     * 
     * @throws Exception 
     */
    @Test
    public void testCoapToken() throws Exception {
        Configuration dtlsConfig = Configuration.getStandard();
        dtlsConfig.set(DtlsConfig.DTLS_CIPHER_SUITES, Arrays.asList(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8));
        
        DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(dtlsConfig);
        builder.setAddress(new InetSocketAddress(0));

        AdvancedSinglePskStore pskStore = new AdvancedSinglePskStore("clientA", key128);
        builder.setAdvancedPskStore(pskStore);

        CBORObject rpkData = CBORObject.NewMap();
        rpkData = Util.buildRpkData(KeyKeys.EC2_P256.AsInt32(), cX_ECDSA, cY_ECDSA, cD_ECDSA);
        cRPK = new OneKey(rpkData);
        String keyId = new RawPublicKeyIdentity(cRPK.AsPublicKey()).getName();
        cRPK.add(KeyKeys.KeyId, CBORObject.FromObject(keyId.getBytes(Constants.charset)));

        builder.setCertificateIdentityProvider(
                new SingleCertificateProvider(cRPK.AsPrivateKey(), cRPK.AsPublicKey()));

        ArrayList<CertificateType> certTypes = new ArrayList<CertificateType>();
        certTypes.add(CertificateType.RAW_PUBLIC_KEY);
        certTypes.add(CertificateType.X_509);
        AsyncNewAdvancedCertificateVerifier verifier = new AsyncNewAdvancedCertificateVerifier(
                                                            new X509Certificate[0],
                                                            new RawPublicKeyIdentity[0],
                                                            certTypes);
        builder.setAdvancedCertificateVerifier(verifier);
        
        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
        Builder ceb = new Builder();
        ceb.setConnector(dtlsConnector);
        ceb.setConfiguration(Configuration.getStandard());
        CoapEndpoint e = ceb.build();
        CoapClient client = new CoapClient("coaps://localhost/token");
        client.setEndpoint(e);
        dtlsConnector.start();

        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp rw_config foobar"));
        params.put(Constants.AUDIENCE, CBORObject.FromObject("aud1"));
        CoapResponse response = client.post(Constants.getCBOR(params).EncodeToBytes(), Constants.APPLICATION_ACE_CBOR);    
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
     * Test CoapToken using PSK, for asking access to an
     * OSCORE group with a single role, using a REF token.
     * 
     * @throws Exception
     */
    @Test
    public void testGroupOSCORESingleRoleREFToken() throws Exception { 
        
    	String gid = new String("feedca570000");
        String gid2 = new String("feedca570001");
    	
        Configuration dtlsConfig = Configuration.getStandard();
        dtlsConfig.set(DtlsConfig.DTLS_CIPHER_SUITES, Arrays.asList(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8));
        
        DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(dtlsConfig);
        builder.setAddress(new InetSocketAddress(0));

        AdvancedSinglePskStore pskStore = new AdvancedSinglePskStore("clientF", key128);
        builder.setAdvancedPskStore(pskStore);

        CBORObject rpkData = CBORObject.NewMap();
        rpkData = Util.buildRpkData(KeyKeys.EC2_P256.AsInt32(), cX_ECDSA, cY_ECDSA, cD_ECDSA);
        cRPK = new OneKey(rpkData);
        String keyId = new RawPublicKeyIdentity(cRPK.AsPublicKey()).getName();
        cRPK.add(KeyKeys.KeyId, CBORObject.FromObject(keyId.getBytes(Constants.charset)));

        builder.setCertificateIdentityProvider(
                new SingleCertificateProvider(cRPK.AsPrivateKey(), cRPK.AsPublicKey()));

        ArrayList<CertificateType> certTypes = new ArrayList<CertificateType>();
        certTypes.add(CertificateType.RAW_PUBLIC_KEY);
        certTypes.add(CertificateType.X_509);
        AsyncNewAdvancedCertificateVerifier verifier = new AsyncNewAdvancedCertificateVerifier(
                                                            new X509Certificate[0],
                                                            new RawPublicKeyIdentity[0],
                                                            certTypes);
        builder.setAdvancedCertificateVerifier(verifier);
        
        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
        Builder ceb = new Builder();
        ceb.setConnector(dtlsConnector);
        ceb.setConfiguration(Configuration.getStandard());
        CoapEndpoint e = ceb.build();
        CoapClient client = new CoapClient("coaps://localhost/token");
        client.setEndpoint(e);
        dtlsConnector.start();
    	
        // The scope is a CBOR Array encoded as a CBOR byte string
    	
    	// The requested role is allowed in the specified group
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        CBORObject cborArrayScope = CBORObject.NewArray();
        CBORObject cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        
    	int myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayEntry.Add(myRoles);
    	
        cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
    	
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUDIENCE, CBORObject.FromObject("aud2"));
        
        CoapResponse response = client.post(Constants.getCBOR(params).EncodeToBytes(), 
                							Constants.APPLICATION_ACE_CBOR);    
        CBORObject res = CBORObject.DecodeFromBytes(response.getPayload());
        
        Map<Short, CBORObject> map = Constants.getParams(res);
        
        assert(map.containsKey(Constants.ACCESS_TOKEN));
        assert(!map.containsKey(Constants.PROFILE)); //Profile is implicit
        assert(map.containsKey(Constants.CNF));
        assert(!map.containsKey(Constants.SCOPE)); // The originally requested scope is implicitly confirmed
        
        
        // The requested role is allowed in the specified group
        params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        
    	myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_MONITOR);
    	cborArrayEntry.Add(myRoles);
    	        
        cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUDIENCE, CBORObject.FromObject("aud2"));
        
        response = client.post(Constants.getCBOR(params).EncodeToBytes(), 
                			   Constants.APPLICATION_ACE_CBOR);    
        res = CBORObject.DecodeFromBytes(response.getPayload());
        
        map = Constants.getParams(res);
        
        assert(map.containsKey(Constants.ACCESS_TOKEN));
        assert(!map.containsKey(Constants.PROFILE)); //Profile is implicit
        assert(map.containsKey(Constants.CNF));
        assert(!map.containsKey(Constants.SCOPE)); // The originally requested scope is implicitly confirmed
        
        
        // Access to the specified group is not allowed
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid2);
        
    	myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayEntry.Add(myRoles);
    	
        byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
       params.put(Constants.AUDIENCE, CBORObject.FromObject("aud2"));
        
        response = client.post(Constants.getCBOR(params).EncodeToBytes(), 
                			   Constants.APPLICATION_ACE_CBOR);
        
        res = CBORObject.DecodeFromBytes(response.getPayload());
        
        map = Constants.getParams(res);
        
        assert(map.size() == 1);
        assert(map.containsKey(Constants.ERROR));
        assert(map.get(Constants.ERROR).AsNumber().ToInt16Checked() == Constants.INVALID_SCOPE);
        
        
        // The requested role is not allowed in the specified group
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        
    	myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(myRoles);
    	        
        cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUDIENCE, CBORObject.FromObject("aud3"));
        
        response = client.post(Constants.getCBOR(params).EncodeToBytes(), 
                			   Constants.APPLICATION_ACE_CBOR);
        
        res = CBORObject.DecodeFromBytes(response.getPayload());
        
        map = Constants.getParams(res);
        
        assert(map.size() == 1);
        assert(map.containsKey(Constants.ERROR));
        assert(map.get(Constants.ERROR).AsNumber().ToInt16Checked() == Constants.INVALID_SCOPE);
        
        
        // The requested role is not allowed in the specified group
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        
    	myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, (short)10);
    	cborArrayEntry.Add(myRoles);
    	 
        cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUDIENCE, CBORObject.FromObject("aud2"));
        
        response = client.post(Constants.getCBOR(params).EncodeToBytes(), 
                			   Constants.APPLICATION_ACE_CBOR);
        
        res = CBORObject.DecodeFromBytes(response.getPayload());
        
        map = Constants.getParams(res);
        
        assert(map.size() == 1);
        assert(map.containsKey(Constants.ERROR));
        assert(map.get(Constants.ERROR).AsNumber().ToInt16Checked() == Constants.INVALID_SCOPE);
        
    }
    

    /**
     * Test CoapToken using PSK, for asking access to an
     * OSCORE group with multiple roles, using a REF token.
     * 
     * @throws Exception
     */
    @Test
    public void testGroupOSCOREMultipleRolesREFToken() throws Exception { 
        
    	String gid = new String("feedca570000");
        String gid2 = new String("feedca570001");
    	
        Configuration dtlsConfig = Configuration.getStandard();
        dtlsConfig.set(DtlsConfig.DTLS_CIPHER_SUITES, Arrays.asList(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8));
        
        DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(dtlsConfig);
        builder.setAddress(new InetSocketAddress(0));

        AdvancedSinglePskStore pskStore = new AdvancedSinglePskStore("clientF", key128);
        builder.setAdvancedPskStore(pskStore);

        CBORObject rpkData = CBORObject.NewMap();
        rpkData = Util.buildRpkData(KeyKeys.EC2_P256.AsInt32(), cX_ECDSA, cY_ECDSA, cD_ECDSA);
        cRPK = new OneKey(rpkData);
        String keyId = new RawPublicKeyIdentity(cRPK.AsPublicKey()).getName();
        cRPK.add(KeyKeys.KeyId, CBORObject.FromObject(keyId.getBytes(Constants.charset)));

        builder.setCertificateIdentityProvider(
                new SingleCertificateProvider(cRPK.AsPrivateKey(), cRPK.AsPublicKey()));

        ArrayList<CertificateType> certTypes = new ArrayList<CertificateType>();
        certTypes.add(CertificateType.RAW_PUBLIC_KEY);
        certTypes.add(CertificateType.X_509);
        AsyncNewAdvancedCertificateVerifier verifier = new AsyncNewAdvancedCertificateVerifier(
                                                            new X509Certificate[0],
                                                            new RawPublicKeyIdentity[0],
                                                            certTypes);
        builder.setAdvancedCertificateVerifier(verifier);
        
        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
        Builder ceb = new Builder();

        ceb.setConnector(dtlsConnector);
        ceb.setConfiguration(Configuration.getStandard());
        CoapEndpoint e = ceb.build();
        CoapClient client = new CoapClient("coaps://localhost/token");
        client.setEndpoint(e);
        dtlsConnector.start();
    	
    	
        // The scope is a CBOR Array encoded as a CBOR byte string
    	
        // Both requested roles are allowed in the specified group
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        CBORObject cborArrayScope = CBORObject.NewArray();
        CBORObject cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        
    	int myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(myRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
    	
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUDIENCE, CBORObject.FromObject("aud2"));
        
        CoapResponse response = client.post(Constants.getCBOR(params).EncodeToBytes(), 
                							Constants.APPLICATION_ACE_CBOR);    
        CBORObject res = CBORObject.DecodeFromBytes(response.getPayload());
        
        Map<Short, CBORObject> map = Constants.getParams(res);
        
        assert(map.containsKey(Constants.ACCESS_TOKEN));
        assert(!map.containsKey(Constants.PROFILE)); //Profile is implicit
        assert(map.containsKey(Constants.CNF));
        assert(!map.containsKey(Constants.SCOPE)); // The originally requested scope is implicitly confirmed
        
        
        // Access to the specified group is not allowed
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid2);
        
        myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_MONITOR);
    	cborArrayEntry.Add(myRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUDIENCE, CBORObject.FromObject("aud2"));
        
        response = client.post(Constants.getCBOR(params).EncodeToBytes(), 
                			   Constants.APPLICATION_ACE_CBOR);
        
        res = CBORObject.DecodeFromBytes(response.getPayload());
        
        map = Constants.getParams(res);
        
        assert(map.size() == 1);
        assert(map.containsKey(Constants.ERROR));
        assert(map.get(Constants.ERROR).AsNumber().ToInt16Checked() == Constants.INVALID_SCOPE);
        
        
        // Only one role out of the two requested ones is allowed in the specified group
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
    	
        myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(myRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUDIENCE, CBORObject.FromObject("aud3"));
        
        response = client.post(Constants.getCBOR(params).EncodeToBytes(), 
                			   Constants.APPLICATION_ACE_CBOR);
        
        res = CBORObject.DecodeFromBytes(response.getPayload());
        
        map = Constants.getParams(res);
        
        assert(map.containsKey(Constants.ACCESS_TOKEN));
        assert(!map.containsKey(Constants.PROFILE)); //Profile is implicit
        assert(map.containsKey(Constants.CNF));
        assert(map.containsKey(Constants.SCOPE)); // The granted scope differs from the original requested one
        assert(map.get(Constants.SCOPE).getType().equals(CBORType.ByteString));
        
        byte[] receivedScope = map.get(Constants.SCOPE).GetByteString();
        CBORObject receivedArrayScope = CBORObject.DecodeFromBytes(receivedScope);
        assert(receivedArrayScope.getType().equals(CBORType.Array));
        assert(receivedArrayScope.size() == 1);
        assert(receivedArrayScope.get(0).getType().equals(CBORType.Array));
        assert(receivedArrayScope.get(0).size() == 2);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        
        int expectedRoles = 0;
        expectedRoles = Util.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayEntry.Add(expectedRoles);
    	
        cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
    	Assert.assertArrayEquals(receivedScope, byteStringScope);
        
    }


    /**
     * Test CoapToken using PSK, for asking access to an
     * OSCORE group with multiple roles, using a REF token.
     * (Alternative version with different client)
     * 
     * @throws Exception
     */
    @Test
    public void testGroupOSCOREAltClientREFToken() throws Exception { 
        
    	String gid = new String("feedca570000");
    	
        Configuration dtlsConfig = Configuration.getStandard();
        dtlsConfig.set(DtlsConfig.DTLS_CIPHER_SUITES, Arrays.asList(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8));
    	
        DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(dtlsConfig);
        builder.setAddress(new InetSocketAddress(0));

        AdvancedSinglePskStore pskStore = new AdvancedSinglePskStore("clientG", key128);
        builder.setAdvancedPskStore(pskStore);

        CBORObject rpkData = CBORObject.NewMap();
        rpkData = Util.buildRpkData(KeyKeys.EC2_P256.AsInt32(), cX_ECDSA, cY_ECDSA, cD_ECDSA);
        cRPK = new OneKey(rpkData);
        String keyId = new RawPublicKeyIdentity(cRPK.AsPublicKey()).getName();
        cRPK.add(KeyKeys.KeyId, CBORObject.FromObject(keyId.getBytes(Constants.charset)));

        builder.setCertificateIdentityProvider(
                new SingleCertificateProvider(cRPK.AsPrivateKey(), cRPK.AsPublicKey()));

        ArrayList<CertificateType> certTypes = new ArrayList<CertificateType>();
        certTypes.add(CertificateType.RAW_PUBLIC_KEY);
        certTypes.add(CertificateType.X_509);
        AsyncNewAdvancedCertificateVerifier verifier = new AsyncNewAdvancedCertificateVerifier(
                                                            new X509Certificate[0],
                                                            new RawPublicKeyIdentity[0],
                                                            certTypes);
        builder.setAdvancedCertificateVerifier(verifier);
        
        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
        Builder ceb = new Builder();
        ceb.setConnector(dtlsConnector);
        ceb.setConfiguration(Configuration.getStandard());
        CoapEndpoint e = ceb.build();
        CoapClient client = new CoapClient("coaps://localhost/token");
        client.setEndpoint(e);
        dtlsConnector.start();
    	
    	
        // The scope is a CBOR Array encoded as a CBOR byte string
    	
        // The requested role is not allowed in the specified group
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        CBORObject cborArrayScope = CBORObject.NewArray();
        CBORObject cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        
    	int myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(myRoles);
        
        cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUDIENCE, CBORObject.FromObject("aud3"));
        
        CoapResponse response = client.post(Constants.getCBOR(params).EncodeToBytes(), 
                							Constants.APPLICATION_ACE_CBOR);    
        CBORObject res = CBORObject.DecodeFromBytes(response.getPayload());
        
        Map<Short, CBORObject> map = Constants.getParams(res);
        
        assert(map.size() == 1);
        assert(map.containsKey(Constants.ERROR));
        assert(map.get(Constants.ERROR).AsNumber().ToInt16Checked() == Constants.INVALID_SCOPE);

        
        // Only one role out of the two requested ones is allowed in the specified group
        params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        
        myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(myRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
    	
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUDIENCE, CBORObject.FromObject("aud2"));
        
        response = client.post(Constants.getCBOR(params).EncodeToBytes(), 
                			   Constants.APPLICATION_ACE_CBOR);    
        res = CBORObject.DecodeFromBytes(response.getPayload());
        
        map = Constants.getParams(res);
        
        assert(map.containsKey(Constants.ACCESS_TOKEN));
        assert(!map.containsKey(Constants.PROFILE)); //Profile is implicit
        assert(map.containsKey(Constants.CNF));
        assert(map.containsKey(Constants.SCOPE)); // The granted scope differs from the original requested one
        assert(map.get(Constants.SCOPE).getType().equals(CBORType.ByteString));
        
        byte[] receivedScope = map.get(Constants.SCOPE).GetByteString();
        CBORObject receivedArrayScope = CBORObject.DecodeFromBytes(receivedScope);
        assert(receivedArrayScope.getType().equals(CBORType.Array));
        assert(receivedArrayScope.size() == 1);
        assert(receivedArrayScope.get(0).getType().equals(CBORType.Array));
        assert(receivedArrayScope.get(0).size() == 2);
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(gid);
        
        int expectedRoles = 0;
        expectedRoles = Util.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayEntry.Add(expectedRoles);
    	
        cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
    	Assert.assertArrayEquals(receivedScope, byteStringScope);
            	
    }
    
    
    /**
     * Test CoapIntrospect using RPK
     * 
     * @throws Exception
     */
    @Test
    public void testCoapIntrospect() throws Exception {
        OneKey key = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(aKey)));
        
        Configuration dtlsConfig = Configuration.getStandard();
        dtlsConfig.set(DtlsConfig.DTLS_CIPHER_SUITES, Arrays.asList(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8));
        
        DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(dtlsConfig);
        builder.setAddress(new InetSocketAddress(0));
        builder.setCertificateIdentityProvider(
                new SingleCertificateProvider(key.AsPrivateKey(), key.AsPublicKey()));

        ArrayList<CertificateType> certTypes = new ArrayList<CertificateType>();
        certTypes.add(CertificateType.RAW_PUBLIC_KEY);
        certTypes.add(CertificateType.X_509);
        AsyncNewAdvancedCertificateVerifier verifier = new AsyncNewAdvancedCertificateVerifier(new X509Certificate[0],
                new RawPublicKeyIdentity[0], certTypes);
        builder.setAdvancedCertificateVerifier(verifier);

        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());

        Builder ceb = new Builder();
        ceb.setConnector(dtlsConnector);
        ceb.setConfiguration(Configuration.getStandard());
        CoapEndpoint e = ceb.build();
        CoapClient client = new CoapClient("coaps://localhost/introspect");
        client.setEndpoint(e);
        dtlsConnector.start();
       
        ReferenceToken at = new ReferenceToken(new byte[]{0x00});
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.TOKEN, CBORObject.FromObject(at.encode().EncodeToBytes()));
        CoapResponse response = client.post(Constants.getCBOR(params).EncodeToBytes(), 
                							Constants.APPLICATION_ACE_CBOR);
        CBORObject res = CBORObject.DecodeFromBytes(response.getPayload());
        Map<Short, CBORObject> map = Constants.getParams(res);
        System.out.println(map);
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
