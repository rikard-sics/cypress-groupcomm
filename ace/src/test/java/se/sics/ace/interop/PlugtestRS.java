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
package se.sics.ace.interop;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import org.apache.log4j.BasicConfigurator;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.elements.config.CertificateAuthenticationMode;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.x509.SingleCertificateProvider;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.MessageTag;
import org.eclipse.californium.cose.OneKey;

import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.TestConfig;
import se.sics.ace.coap.rs.CoapAuthzInfo;
import se.sics.ace.coap.rs.CoapDeliverer;
import se.sics.ace.coap.rs.dtlsProfile.DtlspPskStore;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.KissValidator;
import se.sics.ace.rs.AsRequestCreationHints;
import se.sics.ace.rs.AuthzInfo;
import se.sics.ace.rs.TokenRepository;

/**
 * Server for testing the DTLSProfileDeliverer class. 
 * 
 * The Junit tests are in TestDtlspClient, 
 * which will automatically start this server.
 * 
 * @author Ludwig Seitz
 *
 */
public class PlugtestRS {

    private static byte[] rs1 = {(byte)0xa1, (byte)0xa2, (byte)0xa3, 0x04, 
            0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10};
    
    private static byte[] rs2 = {(byte)0xb1, (byte)0xb2, (byte)0xb3, 0x04, 
            0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10};
   
    private static String rsX 
        = "73B7D755827D5D59D73FD4015D47B445762F7CDB59799CD966714AB2727F1BA5";
    private static String rsY 
        = "1A84F5C82797643D33F7E6E6AFCF016522238CE430E1BF21A218E6B4DEEAC37A";
    private static String rsD 
        = "00EA086573C683477D74EB7A0C63A6D031D5DEB10F3CC2876FDA6D3400CAA4E507";
  
    /**
     * Definition of the Hello-World Resource
     */
    public static class HelloWorldResource extends CoapResource {
        
        /**
         * Constructor
         */
        public HelloWorldResource() {
            
            // set resource identifier
            super("helloWorld");
            
            // set display name
            getAttributes().setTitle("Hello-World Resource");
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            
            // respond to the request
            exchange.respond(ResponseCode.CONTENT,"Hello World!", 
                    MediaTypeRegistry.TEXT_PLAIN);
        }
    }
    
    /**
     * Definition of the Lock Resource
     */
    public static class LockResource extends CoapResource {
        
        private boolean locked = true;
        
        /**
         * Constructor
         */
        public LockResource() {
            
            // set resource identifier
            super("lock");
            
            // set display name
            getAttributes().setTitle("Lock Resource");
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            exchange.respond(ResponseCode.CONTENT, this.locked 
                    ? CBORObject.True.EncodeToBytes() :
                            CBORObject.False.EncodeToBytes(),
                            MediaTypeRegistry.APPLICATION_CBOR);
        }
        
        @Override
        public void handlePUT(CoapExchange exchange) {
            if (exchange.getRequestPayload() != null) {
                CBORObject newState = CBORObject.DecodeFromBytes(
                        exchange.getRequestPayload());
                if (newState.getType().equals(CBORType.Boolean)) {
                    this.locked = newState.AsBoolean();
                    exchange.respond(ResponseCode.CHANGED);
                }
            }
            exchange.respond(ResponseCode.BAD_REQUEST);
        }
    }
    
    private static TokenRepository tr = null;
    
    private static AuthzInfo ai = null;
    
    private static CoapServer rs = null;
    
    private static CoapDeliverer dpd = null;
    
    private static CwtCryptoCtx ctx = null;
    
    private static OneKey rpk = null;
       
    /**
     * The CoAPs server for testing, run this before running the Junit tests.
     *  
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        //Set logging for slf4/blah
        BasicConfigurator.configure();

        //Set java.util.logging
        Logger rootLogger = LogManager.getLogManager().getLogger("");
        rootLogger.setLevel(Level.FINEST);
        for (Handler h : rootLogger.getHandlers()) {
            h.setLevel(Level.FINEST);
        }
        
        //Try to delete the previous tokens config
        new File("tokens.json").delete();
        
        if (args.length != 1) { 
            System.out.println("Need 1 argument: 1 for RS1 and 2 for RS2");
            return;
        }
        int testcase = Integer.parseInt(args[0]);     
        


        switch (testcase) {

        case 1 : 
            startRS1();
            break;

        case 2 :
            startRS2();
            break;
            
        default :
            stop();
            throw new RuntimeException("Unknown RS number: " + testcase);
        }
        
    }
    
    private static void startRS2() 
            throws CoseException, IOException, AceException {
        CBORObject rpkData = CBORObject.NewMap();
        rpkData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
        rpkData.Add(KeyKeys.Algorithm.AsCBOR(), 
                AlgorithmID.ECDSA_256.AsCBOR());
        rpkData.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
        CBORObject x = CBORObject.FromObject(PlugtestAS.hexString2byteArray(rsX));
        CBORObject y = CBORObject.FromObject(PlugtestAS.hexString2byteArray(rsY));
        CBORObject d = CBORObject.FromObject(PlugtestAS.hexString2byteArray(rsD));
        rpkData.Add(KeyKeys.EC2_X.AsCBOR(), x);
        rpkData.Add(KeyKeys.EC2_Y.AsCBOR(), y);
        rpkData.Add(KeyKeys.EC2_D.AsCBOR(), d);
        rpk = new OneKey(rpkData); 

        
        
        //Set up DTLSProfileTokenRepository
        Set<Short> r = new HashSet<>();
        r.add(Constants.GET);
        
        Set<Short> rw = new HashSet<>();
        rw.add(Constants.GET);
        rw.add(Constants.PUT);
        
        Map<String, Set<Short>> helloWorldResource = new HashMap<>();
        helloWorldResource.put("ace/helloWorld", r);
        Map<String, Map<String, Set<Short>>> myScopes = new HashMap<>();
        myScopes.put("HelloWorld", helloWorldResource);
        
        Map<String, Set<Short>> rLockResource = new HashMap<>();
        rLockResource.put("ace/lock", r);
        myScopes.put("r_Lock", rLockResource);
 
        Map<String, Set<Short>> rwLockResource = new HashMap<>();
        rwLockResource.put("ace/lock", rw);
        myScopes.put("rw_Lock", rwLockResource);
        
        //Set up COSE parameters
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        ctx = CwtCryptoCtx.encrypt0(rs2, coseP.getAlg().AsCBOR());     
        
        AsRequestCreationHints archm = new AsRequestCreationHints(
                "coaps://31.133.132.127:5689/token", null, false, false);
        Resource hello = new HelloWorldResource();
        Resource lock = new LockResource();
        KissValidator valid = new KissValidator(Collections.singleton("RS2"),
                myScopes);
        
        String rsId = "RS2";
        
        String tokenFile = "tokens.json";
        //Delete lingering old token file
        new File(tokenFile).delete();
      
        //Set up the inner Authz-Info library
        ai = new AuthzInfo( Collections.singletonList("AS"), 
                new KissTime(), null, rsId, valid, ctx, null, 0, tokenFile, valid, false);
        Resource authzInfo = new CoapAuthzInfo(ai);
        rs = new CoapServer();
        Resource ace = new CoapResource("ace");
        ace.add(hello);
        ace.add(lock);
        rs.add(ace);
        rs.add(authzInfo);

        Configuration dtlsConfig = Configuration.getStandard();
        dtlsConfig.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NEEDED);
        dtlsConfig.set(DtlsConfig.DTLS_CIPHER_SUITES, Arrays.asList(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, CipherSuite.TLS_PSK_WITH_AES_128_CCM_8));
        
        DtlsConnectorConfig.Builder config 
        = new DtlsConnectorConfig.Builder(dtlsConfig).setAddress(
                new InetSocketAddress(CoAP.DEFAULT_COAP_SECURE_PORT));

        DtlspPskStore psk = new DtlspPskStore(ai);
		config.setPskStore(psk);
        config.setCertificateIdentityProvider(
                new SingleCertificateProvider(rpk.AsPrivateKey(), rpk.AsPublicKey()));
 
        DTLSConnector connector = new DTLSConnector(config.build());
        CoapEndpoint cep = new CoapEndpoint.Builder().setConnector(connector)
                .setConfiguration(Configuration.getStandard()).build();
        rs.addEndpoint(cep);
        //Add a CoAP (no 's') endpoint for authz-info
        CoapEndpoint aiep = new CoapEndpoint.Builder().setInetSocketAddress(
                new InetSocketAddress(CoAP.DEFAULT_COAP_PORT)).build();
        rs.addEndpoint(aiep);
        
        dpd = new CoapDeliverer(rs.getRoot(), null, archm, cep);
        rs.setMessageDeliverer(dpd);
        
        rs.start();
        System.out.println("Server starting");
    }
    
    private static void startRS1() 
            throws IOException, AceException {
     //Set up DTLSProfileTokenRepository
     Set<Short> r = new HashSet<>();
     r.add(Constants.GET);
     
     Set<Short> rw = new HashSet<>();
     rw.add(Constants.GET);
     rw.add(Constants.PUT);
     
     Map<String, Set<Short>> helloWorldResource = new HashMap<>();
     helloWorldResource.put("ace/helloWorld", r);
     Map<String, Map<String, Set<Short>>> myScopes = new HashMap<>();
     myScopes.put("HelloWorld", helloWorldResource);
     
     Map<String, Set<Short>> rLockResource = new HashMap<>();
     rLockResource.put("ace/lock", r);
     myScopes.put("r_Lock", rLockResource);

     Map<String, Set<Short>> rwLockResource = new HashMap<>();
     rwLockResource.put("ace/lock", rw);
     myScopes.put("rw_Lock", rwLockResource);
     
     //Set up COSE parameters
     COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
             AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
     CwtCryptoCtx ctx 
         = CwtCryptoCtx.encrypt0(rs1, coseP.getAlg().AsCBOR());     
     
     AsRequestCreationHints archm = new AsRequestCreationHints(
             "coaps://31.133.145.200:5689/token", null, false, false);
     Resource hello = new HelloWorldResource();
     Resource lock = new LockResource();
     KissValidator valid = new KissValidator(Collections.singleton("RS1"),
             myScopes);
    
     String rsId = "RS1";
     
     String tokenFile = "tokens.json";
     //Delete lingering old token file
     new File(tokenFile).delete();
   
     //Set up the inner Authz-Info library
     ai = new AuthzInfo(Collections.singletonList("AS"), 
             new KissTime(), null, rsId, valid, ctx, null, 0, tokenFile, valid, false);
     Resource authzInfo = new CoapAuthzInfo(ai);
     rs = new CoapServer();
     Resource ace = new CoapResource("ace");
     ace.add(hello);
     ace.add(lock);
     rs.add(ace);
     rs.add(authzInfo);

     Configuration dtlsConfig = Configuration.getStandard();
     dtlsConfig.set(DtlsConfig.DTLS_CIPHER_SUITES, Arrays.asList(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8));
     
     DtlsConnectorConfig.Builder config 
     = new DtlsConnectorConfig.Builder(dtlsConfig).setAddress(
             new InetSocketAddress(CoAP.DEFAULT_COAP_SECURE_PORT));

     DtlspPskStore psk = new DtlspPskStore(ai);
		config.setPskStore(psk);
     DTLSConnector connector = new DTLSConnector(config.build());
     CoapEndpoint cep = new CoapEndpoint.Builder().setConnector(connector)
             .setConfiguration(Configuration.getStandard()).build();
     rs.addEndpoint(cep);
     //Add a CoAP (no 's') endpoint for authz-info
     CoapEndpoint aiep = new CoapEndpoint.Builder().setInetSocketAddress(
             new InetSocketAddress(CoAP.DEFAULT_COAP_PORT)).build();
     rs.addEndpoint(aiep);
     
     dpd = new CoapDeliverer(rs.getRoot(), null, archm, cep); 
     rs.setMessageDeliverer(dpd);
     
     rs.start();
     System.out.println("Server starting");
    }

    /**
     * Stops the server
     * 
     * @throws IOException 
     * @throws AceException 
     */
    public static void stop() throws IOException, AceException {
        rs.stop();
        ai.close();
        tr.close();
        new File(TestConfig.testFilePath + "tokens.json").delete();
    }
}
