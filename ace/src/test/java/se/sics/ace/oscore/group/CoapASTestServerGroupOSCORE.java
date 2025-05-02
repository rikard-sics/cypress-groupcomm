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

import java.util.Base64;
import java.util.Collections;
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
import se.sics.ace.coap.as.DtlsAS;
import se.sics.ace.examples.KissTime;
import se.sics.ace.oscore.as.GroupOSCOREJoinPDP;

/**
 * The server to run the client tests against.
 * 
 * The Junit tests are in TestCoAPClient, 
 * which will automatically start this server.
 * 
 * @author Marco Tiloca
 *
 */
public class CoapASTestServerGroupOSCORE
{
    static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static byte[] key256 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,28, 29, 30, 31, 32};
    static String aKey = "piJYICg7PY0o/6Wf5ctUBBKnUPqN+jT22mm82mhADWecE0foI1ghAKQ7qn7SL/Jpm6YspJmTWbFG8GWpXE5GAXzSXrialK0pAyYBAiFYIBLW6MTSj4MRClfSUzc8rVLwG8RH5Ak1QfZDs4XhecEQIAE=";
    
    private static CoapDBConnector db = null;
    private static DtlsAS as = null;
    private static GroupOSCOREJoinPDP pdp = null;
  
    /**
     * The CoAPs server for testing, run this before running the Junit tests.
     *  
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        DBHelper.setUpDB();
        db = DBHelper.getCoapDBConnector();

        OneKey akey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(aKey)));

        CBORObject keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key256));
        OneKey tokenPsk = new OneKey(keyData);
        
        keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128));
        OneKey authPsk = new OneKey(keyData);
        
    	final String groupName = "feedca570000";
        
        //Setup RS entries
        Set<String> profiles = new HashSet<>();
        profiles.add("coap_oscore");
        Set<String> scopes = new HashSet<>();
        scopes.add("rw_valve");
        scopes.add("r_pressure");
        scopes.add("foobar");
        Set<String> auds = new HashSet<>();
        auds.add("aud1");
        Set<String> keyTypes = new HashSet<>();
        keyTypes.add("PSK");
        keyTypes.add("RPK");
        Set<Short> tokenTypes = new HashSet<>();
        tokenTypes.add(AccessTokenFactory.CWT_TYPE);
        Set<COSEparams> cose = new HashSet<>();
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_256, AlgorithmID.Direct);
        cose.add(coseP);
        long expiration = 30000L;
        db.addRS("rs1", profiles, scopes, auds, keyTypes, tokenTypes, cose,
        		 expiration, authPsk, tokenPsk, akey);
        
        auds.clear();
        auds.add("actuators");
        db.addRS("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w", profiles, scopes,
        		 auds, keyTypes, tokenTypes, cose, expiration, authPsk, tokenPsk, akey);
        
        
        // Add a further resource server "rs2" acting as OSCORE Group Manager
        // This resource server uses only REF Tokens
        profiles.clear();
        profiles.add("coap_dtls");
        scopes.clear();
        scopes.add(groupName + "_requester");
        scopes.add(groupName + "_responder");
        scopes.add(groupName + "_monitor");
        scopes.add(groupName + "_requester_responder");
        auds.clear();
        auds.add("aud2");
        keyTypes.clear();
        keyTypes.add("PSK");
        tokenTypes.clear();
        tokenTypes.add(AccessTokenFactory.REF_TYPE);
        cose.clear();
        coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_256, AlgorithmID.Direct);
        cose.add(coseP);
        expiration = 1000000L;
        db.addRS("rs2", profiles, scopes, auds, keyTypes, tokenTypes, cose,
                 expiration, authPsk, tokenPsk, akey);
        
        // Add the resource server rs2 and its OSCORE Group Manager audience
        // to the table OSCORE GroupManagers in the Database
        db.addOSCOREGroupManagers("rs2", auds);
        
        // Add a further resource server "rs3" acting as OSCORE Group Manager
        // This resource server uses only REF Tokens
        profiles.clear();
        profiles.add("coap_dtls");
        scopes.clear();
        scopes.add(groupName + "_requester");
        scopes.add(groupName + "_responder");
        scopes.add(groupName + "_monitor");
        scopes.add(groupName + "_requester_responder");
        auds.clear();
        auds.add("aud3");
        keyTypes.clear();
        keyTypes.add("PSK");
        tokenTypes.clear();
        tokenTypes.add(AccessTokenFactory.REF_TYPE);
        cose.clear();
        coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_256, AlgorithmID.Direct);
        cose.add(coseP);
        expiration = 1000000L;
        db.addRS("rs3", profiles, scopes, auds, keyTypes, tokenTypes, cose,
                 expiration, authPsk, tokenPsk, akey);
        
        // Add the resource server rs3 and its OSCORE Group Manager audience
        // to the table OSCORE GroupManagers in the Database
        db.addOSCOREGroupManagers("rs3", auds);
        
        // Add a further resource server "rs4" acting as OSCORE Group Manager
        // This resource server uses only CWT Tokens
        profiles.clear();
        profiles.add("coap_dtls");
        scopes.clear();
        scopes.add(groupName + "_requester");
        scopes.add(groupName + "_responder");
        scopes.add(groupName + "_monitor");
        scopes.add(groupName + "_requester_responder");
        auds.clear();
        auds.add("aud4");
        keyTypes.clear();
        keyTypes.add("PSK");
        tokenTypes.clear();
        tokenTypes.add(AccessTokenFactory.CWT_TYPE);
        cose.clear();
        coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_256, AlgorithmID.Direct);
        cose.add(coseP);
        expiration = 1000000L;
        db.addRS("rs4", profiles, scopes, auds, keyTypes, tokenTypes, cose,
                 expiration, authPsk, tokenPsk, akey);
        
        // Add the resource server rs4 and its OSCORE Group Manager audience
        // to the table OSCORE GroupManagers in the Database
        db.addOSCOREGroupManagers("rs4", auds);
        
        
        profiles.clear();
        profiles.add("coap_oscore");
        keyTypes.clear();
        keyTypes.add("PSK");        
        db.addClient("clientA", profiles, null, null, keyTypes, authPsk, null);        
        
        // Add a further client "clientF" as a joining node of an OSCORE group
        profiles.clear();
        profiles.add("coap_dtls");
        keyTypes.clear();
        keyTypes.add("PSK");        
        db.addClient("clientF", profiles, null, null, keyTypes, authPsk, null);
        
        // Add a further client "clientG" as a joining node of an OSCORE group
        profiles.clear();
        profiles.add("coap_dtls");
        keyTypes.clear();
        keyTypes.add("PSK");        
        db.addClient("clientG", profiles, null, null, keyTypes, authPsk, null);
        
        
        KissTime time = new KissTime();
        String cti = Base64.getEncoder().encodeToString(new byte[]{0x00});
        Map<Short, CBORObject> claims = new HashMap<>();
        claims.put(Constants.SCOPE, CBORObject.FromObject("co2"));
        claims.put(Constants.EXP, CBORObject.FromObject(time.getCurrentTime()+1000000L));   
        claims.put(Constants.AUD,  CBORObject.FromObject("actuators"));
        claims.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x00}));
        db.addToken(cti, claims);       
        db.addCti2Client(cti, "clientA");
        
        OneKey asymmKey = OneKey.generateKey(AlgorithmID.ECDSA_256);
        pdp = new GroupOSCOREJoinPDP(db);
        
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
        pdp.addIntrospectAccess("rs4");
        
        // Add also client "clientF" as a joining node of an OSCORE group.
        pdp.addTokenAccess("clientF");
        // Add also client "clientG" as a joining node of an OSCORE group.
        pdp.addTokenAccess("clientG");

        pdp.addAccess("clientA", "rs1", "r_temp");
        pdp.addAccess("clientA", "rs1", "rw_config");
        pdp.addAccess("clientA", "rs2", "r_light");
        
        pdp.addAccess("clientB", "rs1", "r_temp");
        pdp.addAccess("clientB", "rs1", "co2");
        pdp.addAccess("clientB", "rs2", "r_light");
        pdp.addAccess("clientB", "rs2", "r_config");
        pdp.addAccess("clientB", "rs2", "failTokenType");
        pdp.addAccess("clientB", "rs3", "rw_valve");
        pdp.addAccess("clientB", "rs3", "r_pressure");
        pdp.addAccess("clientB", "rs3", "failTokenType");
        pdp.addAccess("clientB", "rs3", "failProfile");
        
        pdp.addAccess("clientC", "rs3", "r_valve");
        pdp.addAccess("clientC", "rs3", "r_pressure");

        pdp.addAccess("clientD", "rs1", "r_temp");
        pdp.addAccess("clientD", "rs1", "rw_config");
        pdp.addAccess("clientD", "rs2", "r_light");
        

        pdp.addAccess("clientE", "rs3", "rw_valve");
        pdp.addAccess("clientE", "rs3", "r_pressure");
        pdp.addAccess("clientE", "rs3", "failTokenType");
        pdp.addAccess("clientE", "rs3", "failProfile");
        
        // Specify access right also for client "clientF" as a joining node of an OSCORE group.
        // On this Group Manager, this client is allowed to be requester, responder, requester+responder or monitor.
        pdp.addAccess("clientF", "rs2", groupName + "_requester_monitor_responder");
        // On this Group Manager, this client is allowed to be requester or monitor.
        pdp.addAccess("clientF", "rs3", groupName + "_requester_monitor");
        
        // Specify access right also for client "clientG" as a joining node of an OSCORE group.
        // On this Group Manager, this client is allowed to be requester.
        pdp.addAccess("clientG", "rs2", groupName + "_requester");
        
        // Add the resource servers rs2 and rs3 and their OSCORE Group Manager
        // audience to the table OSCOREGroupManagersTable in the PDP
        Set<String> aud2 = Collections.singleton("aud2");
        pdp.addOSCOREGroupManagers("rs2", aud2);
        Set<String> aud3 = Collections.singleton("aud3");
        pdp.addOSCOREGroupManagers("rs3", aud3);
        
        as = new DtlsAS("AS", db, pdp, time, asymmKey);
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
    
}
