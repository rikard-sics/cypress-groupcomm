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
package se.sics.ace.interopGroupOSCORE;

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
import se.sics.ace.Util;
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
public class PlugtestASGroupOSCORE
{
	
	/* START LIST OF KEYS */
	
	// For old tests
    private static byte[] key128_client_A = {0x61, 0x62, 0x63, 0x04, 0x05, 0x06, 0x07, 0x08,
    										 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    
    // More PSKs if needed
    /*
    private static byte[] key128_client_B = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    										 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    private static byte[] key128_client_D = {0x51, 0x52, 0x53, 0x04, 0x05, 0x06, 0x07, 0x08,
    										 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    */
    
    // For group joining tests (rs2, rs3 and rs4 are Group Managers)
    private static byte[] key128_client_F = {0x61, 0x62, 0x63, 0x04, 0x05, 0x06, 0x07, 0x08,
    										 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x11};
    private static byte[] key128_client_G = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    										 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x12};
    
	// For old tests
    private static byte[] key128_rs1 = {0x51, 0x52, 0x53, 0x04, 0x05, 0x06, 0x07, 0x08,
    									0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    
    // For group joining tests (rs2, rs3 and rs4 are Group Managers)
    private static byte[] key128_rs2 = {0x51, 0x52, 0x53, 0x04, 0x05, 0x06, 0x07, 0x08,
    									0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x11};
    private static byte[] key128_rs3 = {0x51, 0x52, 0x53, 0x04, 0x05, 0x06, 0x07, 0x08,
    									0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x12};
    private static byte[] key128_rs4 = {0x51, 0x52, 0x53, 0x04, 0x05, 0x06, 0x07, 0x08,
    									0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x13};

	// For old tests - PSK to encrypt the token
    private static byte[] key128_token_rs1 = {(byte)0xa1, (byte)0xa2, (byte)0xa3, 0x04, 0x05, 0x06, 0x07,
    										  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    
    // For group joining tests - PSK to encrypt the token (rs2, rs3 and rs4 are Group Managers)
    private static byte[] key128_token_rs2 = {(byte)0xb1, (byte)0xa2, (byte)0xa3, 0x04, 0x05, 0x06, 0x07,
    										  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10};
    private static byte[] key128_token_rs3 = {(byte)0xb1, (byte)0xb2, (byte)0xb3, 0x04, 0x05, 0x06, 0x07,
    										  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x11};
    private static byte[] key128_token_rs4 = {(byte)0xb1, (byte)0xb2, (byte)0xb3, 0x04, 0x05, 0x06, 0x07,
    										  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x12};
    
    // Asymmetric key of the AS
    private static String asX = "058F35F3C0D34D3DF50DEBC82208CDA9BE373AF7B8F7AAC381577B144D5FA781";
    private static String asY = "364269649744067D4600A529AE12076750D90C5EFCD9835137DB1AE2B4BACCB8";
	private static String asD = "0089A92D07B34F1D806FABFF444AF6507C5F18F47BB2CCFAA7FBEC447303790D53";
    
	// Public key of a RS (same for all the RSs)
    private static String rsX = "73B7D755827D5D59D73FD4015D47B445762F7CDB59799CD966714AB2727F1BA5";
    private static String rsY = "1A84F5C82797643D33F7E6E6AFCF016522238CE430E1BF21A218E6B4DEEAC37A";

	// Public key of a Client (clientC)
    private static String cX = "12D6E8C4D28F83110A57D253373CAD52F01BC447E4093541F643B385E179C110";
    private static String cY = "283B3D8D28FFA59FE5CB540412A750FA8DFA34F6DA69BCDA68400D679C1347E8";
    /* END LIST OF KEYS */
	
	// OLD SETUP
	/*
    static byte[] key128_client1 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static byte[] key256_gm = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,28, 29, 30, 31, 32};
    static String publicKey_gm = "piJYICg7PY0o/6Wf5ctUBBKnUPqN+jT22mm82mhADWecE0foI1ghAKQ7qn7SL/Jpm6YspJmTWbFG8GWpXE5GAXzSXrialK0pAyYBAiFYIBLW6MTSj4MRClfSUzc8rVLwG8RH5Ak1QfZDs4XhecEQIAE=";
    */
    
    
    private static CoapDBConnector db = null;
    private static DtlsAS as = null;
    private static GroupOSCOREJoinPDP pdp = null;
    
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

        // Setup PSKs for Clients
        CBORObject keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128_client_A));
        OneKey authPsk_clientA = new OneKey(keyData);
        
        // More PSKs if needed
        /*
        keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128_client_B));
        OneKey authPsk_clientB = new OneKey(keyData);
        
        keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128_client_D));
        OneKey authPsk_clientD = new OneKey(keyData);
        */
        
        keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128_client_F));
        OneKey authPsk_clientF = new OneKey(keyData);
        
        keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128_client_G));
        OneKey authPsk_clientG = new OneKey(keyData);
        
        // Setup PSKs for RSs
        keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128_rs1));
        OneKey authPsk_rs1 = new OneKey(keyData);
        
        keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128_rs2));
        OneKey authPsk_rs2 = new OneKey(keyData);
        
        keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128_rs3));
        OneKey authPsk_rs3 = new OneKey(keyData);
        
        keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128_rs4));
        OneKey authPsk_rs4 = new OneKey(keyData);
        
        // Setup symmetric keys to protect the Access Tokens
        keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128_token_rs1));
        OneKey tokenPsk_rs1 = new OneKey(keyData);
        
        keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128_token_rs2));
        OneKey tokenPsk_rs2 = new OneKey(keyData);
        
        keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128_token_rs3));
        OneKey tokenPsk_rs3 = new OneKey(keyData);
        
        keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128_token_rs4));
        OneKey tokenPsk_rs4 = new OneKey(keyData);

        CBORObject rpkData = null;
        
        // Build the RS public key (the same one for all the RSs)
        rpkData = CBORObject.NewMap();
        rpkData = Util.buildRpkData(KeyKeys.EC2_P256.AsInt32(), rsX, rsY, null);
        OneKey akey_rs = new OneKey(rpkData);
        
        // Build the AS asymmetric key pair
        rpkData = CBORObject.NewMap();
        rpkData = Util.buildRpkData(KeyKeys.EC2_P256.AsInt32(), asX, asY, asD);
        OneKey asRPK = new OneKey(rpkData);  

        
    	final String groupName = "feedca570000";
        
        //Setup RS entries
        Set<String> profiles = new HashSet<>();
        profiles.add("coap_oscore");
        Set<String> scopes = new HashSet<>();
        scopes.add("r_temp");
        scopes.add("rw_config");
        scopes.add("foobar");
        Set<String> auds = new HashSet<>();
        auds.add("aud1");        
        Set<String> keyTypes = new HashSet<>();
        keyTypes.add("PSK");
        keyTypes.add("RPK");
        Set<Short> tokenTypes = new HashSet<>();
        tokenTypes.add(AccessTokenFactory.CWT_TYPE);
        Set<COSEparams> cose = new HashSet<>();
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_64_128, AlgorithmID.Direct);
        cose.add(coseP);
        long expiration = 30000L;        
        
        db.addRS("rs1", profiles, scopes, auds, keyTypes, tokenTypes,
        		 cose, expiration, authPsk_rs1, tokenPsk_rs1, akey_rs);
        
        
        // Add a further resource server "rs2" acting as OSCORE Group Manager
        // This resource server uses only REF Tokens
        profiles.clear();
        profiles.add("coap_dtls");
        scopes.clear();
        scopes.add(groupName + "_requester_responder_monitor");
        auds.clear();
        auds.add("aud2");
        keyTypes.clear();
        keyTypes.add("PSK");
        tokenTypes.clear();
        tokenTypes.add(AccessTokenFactory.REF_TYPE);
        expiration = 1000000L;
        db.addRS("rs2", profiles, scopes, auds, keyTypes, tokenTypes,
        		 cose, expiration, authPsk_rs2, tokenPsk_rs2, akey_rs);
        
        // Add the resource server rs2 and its OSCORE Group Manager audience to the table OSCORE GroupManagers in the Database
        db.addOSCOREGroupManagers("rs2", auds);
        
        
        // Add a further resource server "rs3" acting as OSCORE Group Manager
        // This resource server uses only REF Tokens
        profiles.clear();
        profiles.add("coap_dtls");
        scopes.clear();
        scopes.add(groupName + "_requester_responder_monitor");
        auds.clear();
        auds.add("aud3");
        keyTypes.clear();
        keyTypes.add("PSK");
        tokenTypes.clear();
        tokenTypes.add(AccessTokenFactory.REF_TYPE);
        expiration = 1000000L;
        db.addRS("rs3", profiles, scopes, auds, keyTypes, tokenTypes,
        		 cose, expiration, authPsk_rs3, tokenPsk_rs3, akey_rs);
        
        // Add the resource server rs3 and its OSCORE Group Manager audience
        // to the table OSCORE GroupManagers in the Database
        db.addOSCOREGroupManagers("rs3", auds);
        
        
        // Add a further resource server "rs4" acting as OSCORE Group Manager
        // This resource server uses only CWT Tokens
        profiles.clear();
        profiles.add("coap_dtls");
        scopes.clear();
        scopes.add(groupName + "_requester_responder_monitor");
        auds.clear();
        auds.add("aud4");
        keyTypes.clear();
        keyTypes.add("PSK");
        tokenTypes.clear();
        tokenTypes.add(AccessTokenFactory.CWT_TYPE);
        expiration = 1000000L;
        db.addRS("rs4", profiles, scopes, auds, keyTypes, tokenTypes,
        		 cose, expiration, authPsk_rs4, tokenPsk_rs4, akey_rs);
        
        // Add the resource server rs4 and its OSCORE Group Manager audience
        // to the table OSCORE GroupManagers in the Database
        db.addOSCOREGroupManagers("rs4", auds);
        
        auds.clear();
        auds.add("aud5");
        db.addRS("ni:///sha-256;sU09Kz-RXT8izVvD3n7v3d5vHVGF1NcYShZZ-oczcVE", profiles, scopes, auds, keyTypes, tokenTypes,
       		 cose, expiration, authPsk_rs4, tokenPsk_rs4, akey_rs);
        
        profiles.clear();
        profiles.add("coap_oscore");
        keyTypes.clear();
        keyTypes.add("PSK");        
        db.addClient("clientA", profiles, null, null, keyTypes, authPsk_clientA, null);        
        
        // Add a further client "clientF" as a joining node of an OSCORE group
        profiles.clear();
        profiles.add("coap_dtls");
        keyTypes.clear();
        keyTypes.add("PSK");        
        db.addClient("clientF", profiles, null, null, keyTypes, authPsk_clientF, null);
        
        // Add a further client "clientG" as a joining node of an OSCORE group
        profiles.clear();
        profiles.add("coap_dtls");
        keyTypes.clear();
        keyTypes.add("PSK");        
        db.addClient("clientG", profiles, null, null, keyTypes, authPsk_clientG, null);
        
        
        KissTime time = new KissTime();
        String cti = Base64.getEncoder().encodeToString(new byte[]{0x00});
        Map<Short, CBORObject> claims = new HashMap<>();
        claims.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        claims.put(Constants.AUD,  CBORObject.FromObject("aud5"));
        claims.put(Constants.EXP, CBORObject.FromObject(time.getCurrentTime()+1000000L));
        claims.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x00}));
        db.addToken(cti, claims);       
        db.addCti2Client(cti, "clientA");
        
        pdp = new GroupOSCOREJoinPDP(db);
        
        //Initialize data in PDP
        
        // For the public key build from 'publicKey_gm' in base64
        // pdp.addIntrospectAccess("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w");
        
        pdp.addIntrospectAccess("ni:///sha-256;sU09Kz-RXT8izVvD3n7v3d5vHVGF1NcYShZZ-oczcVE");
        pdp.addIntrospectAccess("rs1");
        pdp.addIntrospectAccess("rs2");
        pdp.addIntrospectAccess("rs3");
        pdp.addIntrospectAccess("rs4");
        
        
        // For the public key build from 'publicKey_gm' in base64
        // pdp.addTokenAccess("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w");
        
        pdp.addTokenAccess("ni:///sha-256;sU09Kz-RXT8izVvD3n7v3d5vHVGF1NcYShZZ-oczcVE");
        pdp.addTokenAccess("clientA");

        // Add also client "clientF" as a joining node of an OSCORE group.
        pdp.addTokenAccess("clientF");
        // Add also client "clientG" as a joining node of an OSCORE group.
        pdp.addTokenAccess("clientG");
        
        
        pdp.addAccess("clientA", "rs1", "r_temp");
        pdp.addAccess("clientA", "rs1", "rw_config");
        
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
        
        as = new DtlsAS("AS", db, pdp, time, asRPK, portNumber);
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
    
}
