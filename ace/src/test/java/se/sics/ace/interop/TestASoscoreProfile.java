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

import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.upokecenter.cbor.CBORObject;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.MessageTag;
import org.eclipse.californium.cose.OneKey;

import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.DBHelper;
import se.sics.ace.as.AccessTokenFactory;
import se.sics.ace.coap.as.CoapDBConnector;
import se.sics.ace.coap.as.OscoreAS;
import se.sics.ace.examples.KissPDP;
import se.sics.ace.examples.KissTime;

/**
 * The server to run the client tests against.
 * 
 * The Junit tests are in TestCoAPClient, 
 * which will automatically start this server.
 * 
 * @author Marco Tiloca
 *
 */
public class TestASoscoreProfile
{
	
    private static String myName = "AS";
	
    // The map has as key the name of a Client or Resource Server,
    // and as value the OSCORE identity of that peer with the AS.
    //
    // The identities are strings with format ["A" + ":" +] "B", where A and B are
    // the base64 encoding of the ContextID (if present) and of the SenderID.
    private static Map<String, String> peerNamesToIdentities = new HashMap<>();
    
    
    // The map has as key the OSCORE identity of the Client or Resource Server,
    // and as value the name of that peer with the AS.
    //
    // The identities are strings with format ["A" + ":" +] "B", where A and B are
    // the base64 encoding of the ContextID (if present) and of the SenderID.
    private static Map<String, String> peerIdentitiesToNames = new HashMap<>();
    
    
    // The inner map has as key the name of a Client or Resource Server, and
    // as value the OSCORE identity that this specific AS has with that peer.
    //
    // The identities are strings with format ["A" + ":" +] "B", where A and B are
    // the base64 encoding of the ContextID (if present) and of the SenderID.
    private static Map<String, String> myIdentities = new HashMap<>();
  
    
	/* START LIST OF KEYS */
    
    // OSCORE Context ID used to communicate with Clients and Resource Server (it can be null)
    private static byte[] idContext = null;

	
	// OSCORE Security Context with clientA
	
	// Master Secret
    private static byte[] msecret_with_clientA = {(byte)0x61, (byte)0x62, (byte)0x63, (byte)0x04, (byte)0x05, (byte)0x06,
    									     (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c,
    									     (byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10};
    
    // Sender ID: 0x00
    private static String identity_with_clientA = buildOscoreIdentity(new byte[] {0x00}, idContext);
    
    // Recipient ID: 0x55
    private static String identity_of_clientA = buildOscoreIdentity(new byte[] {0x55}, idContext);
    
    
	// OSCORE Security Context with the Resource Server rs1
	
	// Master Secret
    private static byte[] msecret_with_rs1 = {(byte)0x51, (byte)0x52, (byte)0x53, (byte)0x04, (byte)0x05, (byte)0x06,
						    			(byte)0x07, (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c,
						    			(byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10};
    
    // Sender ID: 0x01
    private static String identity_with_rs1 = buildOscoreIdentity(new byte[] {0x01}, idContext);
    
    // Recipient ID: 0x77
    private static String identity_of_rs1 = buildOscoreIdentity(new byte[] {0x77}, idContext);
    
    
	// PSK to encrypt access tokens issued for Resource Server rs1
    private static byte[] key128_token_rs1 = {(byte)0xa1, (byte)0xa2, (byte)0xa3, (byte)0x04, (byte)0x05, (byte)0x06,
    										  (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c,
    										  (byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10};
    
    
    /* END LIST OF KEYS */
	
    
    private static CoapDBConnector db = null;
    private static OscoreAS as = null;
    private static KissPDP pdp = null;
    
    private static int portNumber = 5689;
  
    /**
     * The CoAPs server for testing, run this before running the Junit tests.
     *  
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        DBHelper.setUpDB();
        db = DBHelper.getCoapDBConnector();

        // Setup the OSCORE Master Secret for clientA
        CBORObject keyData = CBORObject.NewMap();
        String kidStr = "PSK_clientA";
        byte[] kidBytes = kidStr.getBytes(Constants.charset);
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(msecret_with_clientA));
        keyData.Add(KeyKeys.KeyId.AsCBOR(), kidBytes);
        OneKey msecret_clientA = new OneKey(keyData);
        
        
        // Setup the OSCORE Master Secret for the Resource Server rs1
        keyData = CBORObject.NewMap();
        kidStr = "PSK_rs1";
        kidBytes = kidStr.getBytes(Constants.charset);
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(msecret_with_rs1));
        OneKey msecret_rs1 = new OneKey(keyData);

        
        // Setup the PSK to encrypt access tokens issued for Resource Server rs1
        keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128_token_rs1));
        OneKey tokenPsk_rs1 = new OneKey(keyData);
       
        
        // Set supported ACE profiles
        Set<String> profiles = new HashSet<>();
        profiles.add("coap_oscore");
        
        // Set supported types of proof-of-possession keys
        Set<String> keyTypes = new HashSet<>();
        keyTypes.add("PSK");
        
        
        // Register the Resource Server rs1
        
        // Set supported scopes
        Set<String> scopes = new HashSet<>();
        scopes.add("r_temp");
        scopes.add("r_config");
        scopes.add("rw_config");
        scopes.add("foobar");
        
        // Set audiences
        Set<String> auds = new HashSet<>();
        auds.add("aud1");

        // Set supported types of access tokens
        Set<Short> tokenTypes = new HashSet<>();
        tokenTypes.add(AccessTokenFactory.CWT_TYPE);
        
        // Set COSE context to protect issued access tokens
        Set<COSEparams> cose = new HashSet<>();
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_64_128, AlgorithmID.Direct);
        cose.add(coseP);
        
        // Set lifetime for issued access tokens
        long expiration = 30000L;        
        
        db.addRS("rs1", profiles, scopes, auds, keyTypes, tokenTypes,
        		 cose, expiration, msecret_rs1, tokenPsk_rs1, null);
        peerNamesToIdentities.put("rs1", identity_of_rs1);
        peerIdentitiesToNames.put(identity_of_rs1, "rs1");
        myIdentities.put("rs1", identity_with_rs1);
        

        // Register the client clientA

        db.addClient("clientA", profiles, null, null, keyTypes, msecret_clientA, null);
        peerNamesToIdentities.put("clientA", identity_of_clientA);
        peerIdentitiesToNames.put(identity_of_clientA, "clientA");
        myIdentities.put("clientA", identity_with_clientA);
        
        
        //Setup time provider
        KissTime time = new KissTime();
                
        //Initialize data in PDP
        pdp = new KissPDP(db);
        
        // Allow accesses to the /introspect endpoint
        pdp.addIntrospectAccess("rs1");

        // Allow accesses to the /token endpoint
        pdp.addTokenAccess("clientA");

        // Configure access policies for clientA
        pdp.addAccess("clientA", "rs1", "r_temp");
        pdp.addAccess("clientA", "rs1", "rw_config");
        
        
        // Create and start the AS
        as = new OscoreAS(myName, db, pdp, time, null, "token", "introspect",
        				  portNumber, null, false, (short)1, true,
        				  peerNamesToIdentities, peerIdentitiesToNames, myIdentities);
        as.start();
        System.out.println("Server starting");
    }
    
    /**
     * Stops the server
     * @throws Exception 
     */
    public static void stop() throws Exception {
        as.stop();
        pdp.close();
        DBHelper.tearDownDB();
    }
    
    /**
     * Reads the keys and transforms to bytes from Strings.
     * 
     * @param hex  the hex String representation of a key
     * @return  the byte array representation
     */
    public static byte[] hexString2byteArray(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }
    
    private static String buildOscoreIdentity(byte[] senderId, byte[] contextId) {
    	
    	if (senderId == null)
    		return null;
    	
    	String identity = "";
    	
    	if (contextId != null) {
    		identity += Base64.getEncoder().encodeToString(contextId);
    		identity += ":";
    	}
    	
    	identity += Base64.getEncoder().encodeToString(senderId);
    	
    	return identity;
    	
    }
    
}
