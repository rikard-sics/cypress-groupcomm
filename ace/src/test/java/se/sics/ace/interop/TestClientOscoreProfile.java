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
package se.sics.ace.interop;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreCtxDB;

import com.upokecenter.cbor.CBORObject;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.MessageTag;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.client.GetToken;
import se.sics.ace.coap.client.OSCOREProfileRequests;
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
public class TestClientOscoreProfile {
    
	private static OSCoreCtxDB ctxDB;
	
	// OSCORE Context ID used to communicate with Clients and Resource Server (it can be null)
    private static byte[] idContext = null;

    private static List<Set<Integer>> usedRecipientIds = new ArrayList<Set<Integer>>();
    
    
	/* START LIST OF KEYS */
    
	// OSCORE Security Context with clientA
	
	// Master Secret
    private static byte[] msecret_with_AS = {(byte)0x61, (byte)0x62, (byte)0x63, (byte)0x04, (byte)0x05, (byte)0x06,
    									     (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c,
    									     (byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10};

    
    // Sender ID: 0x55
    private static byte[] senderIdWithAS = new byte[] {0x55};
    
    // Recipient ID: 0x00
    private static byte[] recipientIdWithAS = new byte[] {0x00};
    
    
	// PSK to encrypt access tokens issued for Resource Server rs1
    // (Enabling to show the access token content at the client, for debug purposes)
    private static byte[] key128_token_rs1 = {(byte)0xa1, (byte)0xa2, (byte)0xa3, (byte)0x04, (byte)0x05, (byte)0x06,
    										  (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c,
    										  (byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10};
    
    /* END LIST OF KEYS */
    
    
    // Needed to show the access token content, for debug purposes
    private static CwtCryptoCtx ctx = null;
    

    private static int portNumberAS = 5689;
    private static String uriAS = "coap://127.0.0.1:" + portNumberAS;
    private static String pathTokenEndpoint = "token";
    
    private static int portNumberRS = 5690;
    private static String addressRS = "127.0.0.1";
    private static String uriRS = "coap://" + addressRS + ":" + portNumberRS;
    private static String pathAuthzinfoEndpoint = "authz-info";

    private final static int MAX_UNFRAGMENTED_SIZE = 4096;
    
    
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
        
        
        // Initialize the set of assigned Sender IDs as empty
    	for (int i = 0; i < 4; i++) {
        	// Empty sets of assigned Sender IDs; one set for each possible Sender ID size in bytes.
        	// The set with index 0 refers to Sender IDs with size 1 byte
    		usedRecipientIds.add(new HashSet<Integer>());
    	}
        
        
        // Setup the OSCORE client towards the AS
        
        OSCoreCtx ctx = new OSCoreCtx(msecret_with_AS, true, null, 
        							  senderIdWithAS, recipientIdWithAS,
    								  null, null, null, idContext, MAX_UNFRAGMENTED_SIZE);
        
        ctxDB = new org.eclipse.californium.oscore.HashMapCtxDB();
        
        
        
        // Send a token request to the AS, asking for an access token
        CBORObject params = GetToken.getClientCredentialsRequest(CBORObject.FromObject("aud1"),
        														 CBORObject.FromObject("r_temp rw_config foobar"),
        														 null);
        
        Response response = OSCOREProfileRequests.getToken(uriAS + "/" + pathTokenEndpoint, params, ctx, ctxDB);
        printResponseFromAS(response);
        
        
        // Upload the access token to the Resource Server
        
        CBORObject resCBOR = CBORObject.DecodeFromBytes(response.getPayload());
        CBORObject token = CBORObject.DecodeFromBytes(resCBOR.get(Constants.ACCESS_TOKEN).GetByteString());
        
        // response = DTLSProfileRequests.postToken(uriNoSecRS + "/" + pathAuthzinfoEndpoint, token, null);
        
        
        Response rsRes = OSCOREProfileRequests.postToken(uriRS + "/" + pathAuthzinfoEndpoint, response, ctxDB, usedRecipientIds);
        
        System.out.println("\nPosted access token to the RS");
        System.out.println("Response from the RS : " + rsRes.getCode().toString());
        
                
        // Setup the OSCORE client towards the Resource Server rs1
        CoapClient c = OSCOREProfileRequests.getClient(new InetSocketAddress(uriRS + "/helloWorld", portNumberRS), ctxDB);
        
        
        // Send requests to the Resource Server
        
        // Expected 4.03 (Forbidden)
        Request req = new Request(CoAP.Code.GET);
        req.getOptions().setOscore(new byte[0]);
        CoapResponse res = c.advanced(req);
        System.out.println("\nGET request to the RS at " + uriRS + "/helloWorld");
        System.out.println("Response from the RS : " + res.getCode().toString());
        System.out.println("Response content : " + CBORObject.DecodeFromBytes(res.getPayload()).toString());
        
        // Expected 2.05 (Content)
        c.setURI(uriRS + "/temp");
        req = new Request(CoAP.Code.GET);
        req.getOptions().setOscore(new byte[0]);
        res = c.advanced(req);
        System.out.println("\nGET request to the RS at " + uriRS + "/temp");
        System.out.println("Response from the RS : " + res.getCode().toString());
        System.out.println("Response content : " + new String(res.getPayload()));
        
        // Expected 4.05 (Method not allowed)
        req = new Request(CoAP.Code.POST);
        req.getOptions().setOscore(new byte[0]);
        req.getOptions().setContentFormat(MediaTypeRegistry.APPLICATION_OCTET_STREAM);
        String value = Integer.toString(5);
        req.setPayload(value.getBytes(Constants.charset));
        res = c.advanced(req);
        System.out.println("\nPOST request to the RS at " + uriRS + "/temp");
        System.out.println("Response from the RS : " + res.getCode().toString());
        System.out.println("Response content : " + CBORObject.DecodeFromBytes(res.getPayload()).toString());

        // Expected 2.05 (Content)
        req = new Request(CoAP.Code.GET);
        req.getOptions().setOscore(new byte[0]);
        res = c.advanced(req);
        System.out.println("\nGET request to the RS at " + uriRS + "/temp");
        System.out.println("Response from the RS : " + res.getCode().toString());
        System.out.println("Response content : " + new String(res.getPayload()));
        
        // Expected 2.05 (Content)
        c.setURI(uriRS + "/config");
        req = new Request(CoAP.Code.GET);
        req.getOptions().setOscore(new byte[0]);
        res = c.advanced(req);
        System.out.println("\nGET request to the RS at " + uriRS + "/config");
        System.out.println("Response from the RS : " + res.getCode().toString());
        System.out.println("Response content : " + new String(res.getPayload()));
        
        // Expected 2.04 (Changed)
        req = new Request(CoAP.Code.POST);
        req.getOptions().setOscore(new byte[0]);
        value = new String("Custom");
        req.setPayload(value);
        req.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
        res = c.advanced(req);
        System.out.println("\nPOST request to the RS at " + uriRS + "/config");
        System.out.println("Response from the RS : " + res.getCode().toString());
        
        // Expected 2.05 (Content)
        req = new Request(CoAP.Code.GET);
        req.getOptions().setOscore(new byte[0]);
        res = c.advanced(req);
        System.out.println("\nGET request to the RS at " + uriRS + "/config");
        System.out.println("Response from the RS : " + res.getCode().toString());
        System.out.println("Response content : " + new String(res.getPayload()));
        
    }
    
    private static void printResponseFromAS(Response res) throws Exception {
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
