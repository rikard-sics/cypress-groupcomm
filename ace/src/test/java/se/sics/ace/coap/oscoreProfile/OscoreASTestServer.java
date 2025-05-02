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

import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.eclipse.californium.core.coap.CoAP;

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
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class OscoreASTestServer
{
    static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static byte[] key256 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,28, 29, 30, 31, 32};
    
    private static CoapDBConnector db = null;
    private static OscoreAS as = null;
    private static KissPDP pdp = null;
    
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
  
    // OSCORE Context ID used to communicate with Clients and Resource Server (it can be null)
    private static byte[] idContext = null;
    
    /**
     * The OSCORE AS for testing, autostarted by tests needing this.
     *  
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        DBHelper.setUpDB();
        db = DBHelper.getCoapDBConnector();

        CBORObject keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key256));
        OneKey tokenPsk = new OneKey(keyData);
        
        keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128));
        OneKey authPsk = new OneKey(keyData);
        
        String myName = "AS";
        String myIdentity = buildOscoreIdentity(new byte[] {0x00}, idContext);
        String peerIdentity;
        
        //Setup RS entries
        Set<String> profiles = new HashSet<>();
        profiles.add("coap_oscore");
        Set<String> auds = new HashSet<>();
        auds.add("aud1");
        auds.add("actuators");
        Set<String> keyTypes = new HashSet<>();
        keyTypes.add("PSK");
        Set<Short> tokenTypes = new HashSet<>();
        tokenTypes.add(AccessTokenFactory.CWT_TYPE);
        Set<COSEparams> cose = new HashSet<>();
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_256, AlgorithmID.Direct);
        cose.add(coseP);
        long expiration = 30000L;
        
        Set<String> scopes = new HashSet<>();
        scopes.add("r_temp");
        scopes.add("rw_config");
        scopes.add("co2");
        db.addRS("rs1", profiles, scopes, auds, keyTypes, tokenTypes, cose, expiration, authPsk, tokenPsk, null);
        peerIdentity = buildOscoreIdentity(new byte[] {0x11}, idContext);
        peerNamesToIdentities.put("rs1", peerIdentity);
        peerIdentitiesToNames.put(peerIdentity, "rs1");
        myIdentities.put("rs1", myIdentity);
        
        scopes = new HashSet<>();
        scopes.add("r_temp");
        scopes.add("rw_config");
        scopes.add("rw_light");
        scopes.add("failTokenType");
        auds.clear();
        auds.add("aud2");
        db.addRS("rs2", profiles, scopes, auds, keyTypes, tokenTypes, cose, expiration, authPsk, tokenPsk, null);
        peerIdentity = buildOscoreIdentity(new byte[] {0x12}, idContext);
        peerNamesToIdentities.put("rs2", peerIdentity);
        peerIdentitiesToNames.put(peerIdentity, "rs2");
        myIdentities.put("rs2", myIdentity);
        
        
        profiles.clear();
        profiles.add("coap_oscore");
        keyTypes.clear();
        keyTypes.add("PSK");        
        db.addClient("clientA", profiles, null, null, keyTypes, authPsk, null);
        peerIdentity = buildOscoreIdentity(new byte[] {0x01}, idContext);
        peerNamesToIdentities.put("clientA", peerIdentity);
        peerIdentitiesToNames.put(peerIdentity, "clientA");
        myIdentities.put("clientA", myIdentity);
        
        
        KissTime time = new KissTime();
        
        // Add a Token to successfully test introspection
        //
        // Note that this Token is not including everything expected in a Token
        // for the OSCORE profile, especially the 'cnf' claim requiring specific
        // preparation in the /token endpoint
        String cti = Base64.getEncoder().encodeToString(new byte[]{0x00});
        Map<Short, CBORObject> claims = new HashMap<>();
        claims.put(Constants.SCOPE, CBORObject.FromObject("co2"));
        claims.put(Constants.EXP, CBORObject.FromObject(time.getCurrentTime()+1000000L));   
        claims.put(Constants.AUD,  CBORObject.FromObject("actuators"));
        claims.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x00}));
        db.addToken(cti, claims);       
        db.addCti2Client(cti, "clientA");  
        
        
        OneKey asymmKey = OneKey.generateKey(AlgorithmID.ECDSA_256);
        pdp = new KissPDP(db);
        
        //Initialize data in PDP
        pdp.addTokenAccess("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w");
        pdp.addTokenAccess("clientA");
        pdp.addTokenAccess("clientB");
        pdp.addTokenAccess("clientC");
        pdp.addTokenAccess("clientD");
        pdp.addTokenAccess("clientE");
        pdp.addIntrospectAccess("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w");
        pdp.addIntrospectAccess("rs1");
        pdp.addIntrospectAccess("rs2");
        pdp.addIntrospectAccess("rs3");
        pdp.addIntrospectAccess("rs5");
        pdp.addIntrospectAccess("rs6");
        pdp.addIntrospectAccess("rs7");

        pdp.addAccess("clientA", "rs1", "r_temp");
        pdp.addAccess("clientA", "rs1", "rw_config");
        pdp.addAccess("clientA", "rs2", "r_temp");
        pdp.addAccess("clientA", "rs2", "rw_config");
        pdp.addAccess("clientA", "rs2", "rw_light");
        pdp.addAccess("clientA", "rs5", "failTokenNotImplemented");
        
        pdp.addAccess("clientB", "rs1", "r_temp");
        pdp.addAccess("clientB", "rs1", "co2");
        pdp.addAccess("clientB", "rs2", "rw_light");
        pdp.addAccess("clientB", "rs2", "rw_config");
        pdp.addAccess("clientB", "rs2", "failTokenType");
        pdp.addAccess("clientB", "rs3", "rw_valve");
        pdp.addAccess("clientB", "rs3", "r_pressure");
        pdp.addAccess("clientB", "rs3", "failTokenType");
        pdp.addAccess("clientB", "rs3", "failProfile");
        pdp.addAccess("clientB", "rs4", "failProfile");
        pdp.addAccess("clientB", "rs6", "co2");
        pdp.addAccess("clientB", "rs7", "co2");
        
        pdp.addAccess("clientC", "rs3", "r_valve");
        pdp.addAccess("clientC", "rs3", "r_pressure");
        pdp.addAccess("clientC", "rs6", "r_valve");

        pdp.addAccess("clientD", "rs1", "r_temp");
        pdp.addAccess("clientD", "rs1", "rw_config");
        pdp.addAccess("clientD", "rs2", "rw_light");
        pdp.addAccess("clientD", "rs5", "failTokenNotImplemented");        

        pdp.addAccess("clientE", "rs3", "rw_valve");
        pdp.addAccess("clientE", "rs3", "r_pressure");
        pdp.addAccess("clientE", "rs3", "failTokenType");
        pdp.addAccess("clientE", "rs3", "failProfile");
        
        as = new OscoreAS(myName, db, pdp, time, asymmKey,"token", "introspect",
                          CoAP.DEFAULT_COAP_PORT, null, false, (short)1, true,
                          peerNamesToIdentities, peerIdentitiesToNames, myIdentities);
        
        as.start();
        System.out.println("Server starting");
    }
    
    /**
     * Stops the server
     * @throws Exception 
     */
    public static void stop() throws Exception {
        DBHelper.tearDownDB();
        as.stop();
        pdp.close();
      
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
