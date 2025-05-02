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

import java.util.HashSet;
import java.util.Set;

import org.apache.log4j.BasicConfigurator;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;

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
import se.sics.ace.examples.KissPDP;
import se.sics.ace.examples.KissTime;

/**
 * The server to run the client tests against.
 * 
 * The Junit tests are in TestCoAPClient, 
 * which will automatically start this server.
 * 
 * @author Ludwig Seitz
 *
 */
public class PlugtestAS {

    private static byte[] client1 = {0x61, 0x62, 0x63, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    
    private static byte[] client2 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    
    private static byte[] client4 = {0x51, 0x52, 0x53, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    
 
    private static byte[] rs1 = {(byte)0xa1, (byte)0xa2, (byte)0xa3, 0x04, 
            0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10};
    
    private static byte[] rs2 = {(byte)0xb1, (byte)0xb2, (byte)0xb3, 0x04, 
            0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10};
    
    private static String asX 
        = "058F35F3C0D34D3DF50DEBC82208CDA9BE373AF7B8F7AAC381577B144D5FA781";
    private static String asY 
        = "364269649744067D4600A529AE12076750D90C5EFCD9835137DB1AE2B4BACCB8";
    private static String asD 
        = "0089A92D07B34F1D806FABFF444AF6507C5F18F47BB2CCFAA7FBEC447303790D53";
                     
    private static String rsX 
        = "73B7D755827D5D59D73FD4015D47B445762F7CDB59799CD966714AB2727F1BA5";
    private static String rsY 
        = "1A84F5C82797643D33F7E6E6AFCF016522238CE430E1BF21A218E6B4DEEAC37A";
    
    private static String cX 
        = "12D6E8C4D28F83110A57D253373CAD52F01BC447E4093541F643B385E179C110";
    private static String cY 
        = "283B3D8D28FFA59FE5CB540412A750FA8DFA34F6DA69BCDA68400D679C1347E8";

    
    private static CoapDBConnector db = null;
    private static DtlsAS as = null; 
    private static KissPDP pdp = null;
  
    /**
     * The CoAPs server for testing, run this before running the Junit tests.
     *  
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        BasicConfigurator.configure();
        
        //Setup PSKs
        CBORObject keyDataC1 = CBORObject.NewMap();
        keyDataC1.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyDataC1.Add(KeyKeys.Octet_K.AsCBOR(), 
                CBORObject.FromObject(client1));
        OneKey client1PSK = new OneKey(keyDataC1);
        
        CBORObject keyDataC2 = CBORObject.NewMap();
        keyDataC2.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyDataC2.Add(KeyKeys.Octet_K.AsCBOR(), 
                CBORObject.FromObject(client2));
        OneKey client2PSK = new OneKey(keyDataC2);
        
        CBORObject keyDataC4 = CBORObject.NewMap();
        keyDataC4.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyDataC4.Add(KeyKeys.Octet_K.AsCBOR(), 
                CBORObject.FromObject(client4));
        OneKey client4PSK = new OneKey(keyDataC4);
        
        CBORObject keyDataRS1 = CBORObject.NewMap();
        keyDataRS1.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyDataRS1.Add(KeyKeys.Octet_K.AsCBOR(), 
                CBORObject.FromObject(rs1));
        OneKey rs1PSK = new OneKey(keyDataRS1);
        
        CBORObject keyDataRS2 = CBORObject.NewMap();
        keyDataRS2.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyDataRS2.Add(KeyKeys.Octet_K.AsCBOR(), 
                CBORObject.FromObject(rs2));
        OneKey rs2PSK = new OneKey(keyDataRS2);
        
        //Setup RPKs
        CBORObject asRpkData = CBORObject.NewMap();
        asRpkData = Util.buildRpkData(KeyKeys.EC2_P256.AsInt32(), asX, asY, asD);
        OneKey asRPK = new OneKey(asRpkData);  
        
        CBORObject rsRpkData = CBORObject.NewMap();
        rsRpkData = Util.buildRpkData(KeyKeys.EC2_P256.AsInt32(), rsX, rsY, null);
        OneKey rsRPK = new OneKey(rsRpkData);
        
        CBORObject cRpkData = CBORObject.NewMap();
        cRpkData = Util.buildRpkData(KeyKeys.EC2_P256.AsInt32(), cX, cY, null);
        OneKey cRPK = new OneKey(cRpkData);
        String clientId = new RawPublicKeyIdentity(
                cRPK.AsPublicKey()).getName();
        
        //Just to be sure no old test pollutes the DB
        DBHelper.setUpDB();
        db = DBHelper.getCoapDBConnector();
        
        //Setup common RS parameters
        Set<String> profiles = new HashSet<>();
        profiles.add("coap_dtls");
        Set<COSEparams> cose = new HashSet<>();
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_64_128, AlgorithmID.Direct);
        cose.add(coseP);        
        Set<String> scopes = new HashSet<>();
        scopes.add("HelloWorld");
        scopes.add("r_Lock");
        scopes.add("rw_Lock");   
        Set<String> auds = new HashSet<>();
        Set<String> keyTypes = new HashSet<>();
        Set<Short> tokenTypes = new HashSet<>();
        tokenTypes.add(AccessTokenFactory.CWT_TYPE);
        long expiration = 30000L;
        
        //Setup RS1
        keyTypes.add("PSK");       
        db.addRS("RS1", profiles, scopes, auds, keyTypes, tokenTypes, cose,
                expiration, null, rs1PSK, null);
      
        //Setup RS2
        keyTypes.add("RPK");
        db.addRS("RS2", profiles, scopes, auds, keyTypes, tokenTypes, cose,
        expiration, rs2PSK, rs2PSK, rsRPK);
         
        //Setup C1 
        keyTypes.clear();
        keyTypes.add("RPK");
        db.addClient("client1", profiles, null, null, 
                keyTypes, client1PSK, cRPK);  
        
        //Setup C2
        keyTypes.clear();
        keyTypes.add("PSK");
        db.addClient("client2", profiles, null, null, 
                keyTypes, client2PSK, null);
        
        //Setup C3
        keyTypes.clear();
        keyTypes.add("PSK");
        keyTypes.add("RPK");
        db.addClient(clientId, profiles, null, null, 
                keyTypes, null, cRPK);
        
        //Setup C4
        keyTypes.clear();
        keyTypes.add("PSK");
        db.addClient("client4", profiles, null, null, 
                keyTypes, client4PSK, null);
        
        
        //Setup time provider
        KissTime time = new KissTime();
        
        //Setup PDP
        pdp = new KissPDP(db);
    
        //Initialize data in PDP
        pdp.addTokenAccess("client2");
        pdp.addTokenAccess(clientId); //client3
        pdp.addTokenAccess("client4");
        
        pdp.addAccess("client2", "RS1", "HelloWorld");
        pdp.addAccess("client2", "RS1", "r_Lock");
        pdp.addAccess("client2", "RS1", "rw_Lock");
        pdp.addAccess("client2", "RS2", "HelloWorld");
        pdp.addAccess("client2", "RS2", "r_Lock");
        pdp.addAccess("client2", "RS2", "rw_Lock");
        
        pdp.addAccess(clientId, "RS1", "HelloWorld");
        pdp.addAccess(clientId, "RS1", "r_Lock");
        pdp.addAccess(clientId, "RS1", "rw_Lock");
        pdp.addAccess(clientId, "RS2", "HelloWorld");
        pdp.addAccess(clientId, "RS2", "r_Lock");
        pdp.addAccess(clientId, "RS2", "rw_Lock");
        
        pdp.addAccess("client4", "RS1", "r_Lock");
        
        pdp.addIntrospectAccess("RS2");
        pdp.addIntrospectAccess("client2");
        
        //as = new CoapsAS("AS", db, pdp, time, asRPK);
        Set<Short> claims = new HashSet<>();
        claims.add(Constants.CTI);
        claims.add(Constants.AUD);
        claims.add(Constants.SCOPE);
        claims.add(Constants.CNF);
        claims.add(Constants.PROFILE);
        
        as = new DtlsAS("AS", db, pdp, time, asRPK, "token", "introspect",                
                5689, claims, true);
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
