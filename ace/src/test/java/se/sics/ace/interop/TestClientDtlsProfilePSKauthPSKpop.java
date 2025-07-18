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

import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.CoapEndpoint.Builder;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.SinglePskStore;

import com.upokecenter.cbor.CBORObject;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.MessageTag;
import org.eclipse.californium.cose.OneKey;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.as.Token;
import se.sics.ace.coap.client.DTLSProfileRequests;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;

/**
 * Test the coap classes.
 * 
 * NOTE: This will automatically start a server in another thread
 * 
 * @author Marco Tiloca
 *
 */
public class TestClientDtlsProfilePSKauthPSKpop {
    
	static {
	    CoapConfig.register();
	    DtlsConfig.register();
	}
	
	/* START LIST OF KEYS */
	
	// PSK authentication key for the client (clientA on the AS)
    private static byte[] key128_client_A = {(byte)0x61, (byte)0x62, (byte)0x63, (byte)0x04, (byte)0x05, (byte)0x06,
    										 (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c,
    										 (byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10};

    
	// PSK to encrypt access tokens issued for Resource Server rs1
    // (Enabling to show the access token content at the client, for debug purposes)
    private static byte[] key128_token_rs1 = {(byte)0xa1, (byte)0xa2, (byte)0xa3, (byte)0x04, (byte)0x05, (byte)0x06,
    										  (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c,
    										  (byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10};
    
    /* END LIST OF KEYS */
    
    
    // Needed to show the access token content, for debug purposes
    private static CwtCryptoCtx ctx = null;
    

    private static int portNumberAS = 5689;
    private static String uriAS = "coaps://127.0.0.1:" + portNumberAS;
    private static String pathTokenEndpoint = "token";
    
    private static int portNumberNoSecRS = 5690;
    private static int portNumberSecRS = 5691;
    private static String addressRS = "127.0.0.1";
    private static String uriNoSecRS = "coap://" + addressRS + ":" + portNumberNoSecRS;
    private static String uriSecRS = "coaps://" + addressRS + ":" + portNumberSecRS;
    private static String pathAuthzinfoEndpoint = "authz-info";

    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(TestClientDtlsProfilePSKauthPSKpop.class.getName()); 
    
    /**
     * @param args
     * @throws Exception 
     */
    public static void main(String[] args) throws Exception {

        // Set COSE context to protect issued access tokens, for debug purposes
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_64_128, AlgorithmID.Direct);
        ctx = CwtCryptoCtx.encrypt0(key128_token_rs1, coseP.getAlg().AsCBOR());
        
        
        // Setup the DTLS client towards the AS
        
        Configuration dtlsConfig = Configuration.getStandard();
        dtlsConfig.set(DtlsConfig.DTLS_CIPHER_SUITES, Arrays.asList(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8));
        
        DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(dtlsConfig);
        builder.setAddress(new InetSocketAddress(0));

        // Set the authentication PSK of the client (ClientA on the AS)
        SinglePskStore pskStore = new SinglePskStore("clientA", key128_client_A);
        builder.setPskStore(pskStore);

        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
        Builder ceb = new Builder();
        ceb.setConnector(dtlsConnector);
        ceb.setConfiguration(Configuration.getStandard());
        CoapEndpoint e = ceb.build();
        CoapClient client = new CoapClient(uriAS + "/" + pathTokenEndpoint);
        client.setEndpoint(e);
        dtlsConnector.start();
        
        // Send a token request to the AS, asking for an access token with symmetric proof-of-possession key
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.GRANT_TYPE, Token.clientCredentials);
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp rw_config foobar"));
        params.put(Constants.AUDIENCE, CBORObject.FromObject("aud1"));
        
        CoapResponse response = client.post(Constants.getCBOR(params).EncodeToBytes(), 
                							Constants.APPLICATION_ACE_CBOR);
        printResponseFromAS(response);
        
        // Upload the access token to the Resource Server
        
        CBORObject resCBOR = CBORObject.DecodeFromBytes(response.getPayload());
        CBORObject token = CBORObject.DecodeFromBytes(resCBOR.get(Constants.ACCESS_TOKEN).GetByteString());
        
        response = DTLSProfileRequests.postToken(uriNoSecRS + "/" + pathAuthzinfoEndpoint, token, null);
        System.out.println("\nPosted access token to the RS");
        System.out.println("Response from the RS : " + response.getCode().toString());
        
        
        // Perform the DTLS handshake with the Resource Server
        
        CBORObject cnf = resCBOR.get(Constants.CNF);
        OneKey key = new OneKey(cnf.get(Constants.COSE_KEY_CBOR));
        byte[] kid = key.get(KeyKeys.KeyId).GetByteString();
        		
        CoapClient c = DTLSProfileRequests.getPskClient(
        				 new InetSocketAddress(addressRS, portNumberSecRS), kid, key);

        
        // Send requests to the Resource Server
        
        // Expected 4.03 (Forbidden)
        c.setURI(uriSecRS + "/helloWorld");
        response = c.get();
        System.out.println("\nGET request to the RS at " + uriSecRS + "/helloWorld");
        System.out.println("Response from the RS : " + response.getCode().toString());
        System.out.println("Response content : " + CBORObject.DecodeFromBytes(response.getPayload()).toString());
        
        // Expected 2.05 (Content)
        c.setURI(uriSecRS + "/temp");
        response = c.get();
        System.out.println("\nGET request to the RS at " + uriSecRS + "/temp");
        System.out.println("Response from the RS : " + response.getCode().toString());
        System.out.println("Response content : " + new String(response.getPayload()));
        
        // Expected 4.05 (Method not allowed)
        c.setURI(uriSecRS + "/temp");
        String value = Integer.toString(5);
        response = c.post(value.getBytes(Constants.charset), MediaTypeRegistry.APPLICATION_OCTET_STREAM);
        System.out.println("\nPOST request to the RS at " + uriSecRS + "/temp");
        System.out.println("Response from the RS : " + response.getCode().toString());
        System.out.println("Response content : " + CBORObject.DecodeFromBytes(response.getPayload()).toString());
        
        // Expected 2.05 (Content)
        c.setURI(uriSecRS + "/temp");
        response = c.get();
        System.out.println("\nGET request to the RS at " + uriSecRS + "/temp");
        System.out.println("Response from the RS : " + response.getCode().toString());
        System.out.println("Response content : " + new String(response.getPayload()));
        
        // Expected 2.05 (Content)
        c.setURI(uriSecRS + "/config");
        response = c.get();
        System.out.println("\nGET request to the RS at " + uriSecRS + "/config");
        System.out.println("Response from the RS : " + response.getCode().toString());
        System.out.println("Response content : " + new String(response.getPayload()));

        // Expected 2.04 (Changed)
        c.setURI(uriSecRS + "/config");
        value = new String("Custom");
        response = c.post(value, MediaTypeRegistry.TEXT_PLAIN);
        System.out.println("\nPOST request to the RS at " + uriSecRS + "/config");
        System.out.println("Response from the RS : " + response.getCode().toString());
        
        // Expected 2.05 (Content)
        c.setURI(uriSecRS + "/config");
        response = c.get();
        System.out.println("\nGET request to the RS at " + uriSecRS + "/config");
        System.out.println("Response from the RS : " + response.getCode().toString());
        System.out.println("Response content : " + new String(response.getPayload()));
        
    }
    
    private static void printResponseFromAS(CoapResponse res) throws Exception {
        if (res != null) {
        	System.out.println("*** Response from the AS *** ");
            System.out.print(res.getCode().codeClass + "." + "0" + res.getCode().codeDetail);
            System.out.println(" " + res.getCode().name());

            CBORObject resCBOR = null;
            if (res.getPayload() != null) {
            	resCBOR = CBORObject.DecodeFromBytes(res.getPayload());
                System.out.println(resCBOR.toString());
            }
            
            // Decrypt and print the access token
            // This is just for debug purposes! The access token is opaque to the client
            if (res.getCode().isSuccess()) {
	            CBORObject token = CBORObject.DecodeFromBytes(resCBOR.get(Constants.ACCESS_TOKEN).GetByteString());
	    	    CWT cwt = CWT.processCOSE(token.EncodeToBytes(), ctx);
	    	    //Check if we can introspect this token
	    	    Map<Short, CBORObject> claims = cwt.getClaims();
	    	    System.out.println("Token content: " + claims.toString());
            }
            
        } else {
        	System.out.println("*** The response from the AS is null!");
            System.out.print("No response received");
        }
    }

}
