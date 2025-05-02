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

import java.io.IOException;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.upokecenter.cbor.CBORObject;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.MessageTag;
import org.eclipse.californium.cose.OneKey;
import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.DBHelper;
import se.sics.ace.Util;
import se.sics.ace.as.AccessTokenFactory;
import se.sics.ace.as.PDP;
import se.sics.ace.examples.SQLConnector;
import se.sics.ace.oscore.as.GroupOSCOREJoinPDP;

/**
 * Test the GroupOSCOREJoinPDP class.
 * 
 * @author Marco Tiloca
 *
 */
public class TestGroupOSCOREJoinPDP {
    
    private static OneKey publicKey;
    private static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static SQLConnector db = null;
    private static GroupOSCOREJoinPDP pdp = null;

    /**
     * Tests for CWT code.
     */
    public TestGroupOSCOREJoinPDP() {
    }
 
    
    /**
     * Set up tests.
     * @throws AceException 
     * @throws SQLException 
     * @throws IOException 
     * @throws CoseException 
     */
    @BeforeClass
    public static void setUp() throws AceException, SQLException, IOException, CoseException {

        DBHelper.setUpDB();
        db = DBHelper.getSQLConnector();

        OneKey key = OneKey.generateKey(AlgorithmID.ECDSA_256);
        publicKey = key.PublicKey();
        
        CBORObject keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), 
                CBORObject.FromObject(key128));
        OneKey skey = new OneKey(keyData);
        
        //Setup RS entries
        Set<String> profiles = new HashSet<>();
        profiles.add("coap_dtls");
        profiles.add("coap_oscore");
        
        Set<String> scopes = new HashSet<>();
        scopes.add("temp");
        scopes.add("co2");
        
        Set<String> auds = new HashSet<>();
        auds.add("aud1");
        auds.add("sensors");
        auds.add("actuators");
        
        Set<String> keyTypes = new HashSet<>();
        keyTypes.add("PSK");
        keyTypes.add("RPK");
        
        Set<Short> tokenTypes = new HashSet<>();
        tokenTypes.add(AccessTokenFactory.CWT_TYPE);
        tokenTypes.add(AccessTokenFactory.REF_TYPE);
        
        Set<COSEparams> cose = new HashSet<>();
        COSEparams coseP = new COSEparams(MessageTag.Sign1, AlgorithmID.ECDSA_256, AlgorithmID.Direct);
        cose.add(coseP);
        
        long expiration = 1000000L;
       
        db.addRS("rs1", profiles, scopes, auds, keyTypes, tokenTypes, cose, expiration, skey, skey, publicKey);
        
        profiles.remove("coap_oscore");
        scopes.clear();
        scopes.add("light");
        scopes.add("config");
        auds.clear();
        auds.add("aud2");
        keyTypes.remove("PSK");
        tokenTypes.remove(AccessTokenFactory.REF_TYPE);
        expiration = 300000L;
        db.addRS("rs2", profiles, scopes, auds, keyTypes, tokenTypes, cose, expiration, skey, skey, null);
        
        profiles.clear();
        profiles.add("coap_oscore");
        scopes.add("co2");
        auds.clear();
        auds.add("aud3");
        keyTypes.clear();
        keyTypes.add("PSK");
        tokenTypes.clear();
        tokenTypes.add(AccessTokenFactory.CWT_TYPE);
        cose.clear();
        coseP = new COSEparams(MessageTag.MAC0, 
                AlgorithmID.HMAC_SHA_256, AlgorithmID.Direct);
        cose.add(coseP);
        expiration = 30000L;
        db.addRS("rs3", profiles, scopes, auds, keyTypes, tokenTypes, cose, expiration, null, null, publicKey);
        
        
        db.addRS("testRS1", profiles, scopes, auds, keyTypes, tokenTypes, cose, expiration, null, null, publicKey);
        db.addRS("testRS2", profiles, scopes, auds, keyTypes, tokenTypes, cose, expiration, null, null, publicKey);
        db.addRS("testRS3", profiles, scopes, auds, keyTypes, tokenTypes, cose, expiration, null, null, publicKey);
        
        // Add a further resource server "rs4" acting as OSCORE Group Manager
        profiles.clear();
        profiles.add("coap_dtls");
        scopes.clear();
        scopes.add("feedca570000_requester");
        scopes.add("feedca570000_responder");
        scopes.add("feedca570000_monitor");
        scopes.add("feedca570000_requester_responder");
        scopes.add("feedca570000_requester_monitor");
        auds.clear();
        auds.add("aud4");
        keyTypes.clear();
        keyTypes.add("PSK");
        tokenTypes.clear();
        tokenTypes.add(AccessTokenFactory.CWT_TYPE);
        cose.clear();
        coseP = new COSEparams(MessageTag.Sign1, AlgorithmID.ECDSA_256, AlgorithmID.Direct);
        cose.add(coseP);
        expiration = 1000000L;
        db.addRS("rs4", profiles, scopes, auds, keyTypes, tokenTypes, cose, expiration, skey, skey, publicKey);
        
        // Add the resource server rs4 and its OSCORE Group Manager
        // audience to the table OSCOREGroupManagers in the Database
        db.addOSCOREGroupManagers("rs4", auds);
        

        //Setup client entries
        profiles.clear();
        profiles.add("coap_dtls");
        keyTypes.clear();
        keyTypes.add("RPK");
        db.addClient("clientA", profiles, null, null, keyTypes, null, publicKey);
  
        profiles.clear();
        profiles.add("coap_oscore");
        keyTypes.clear();
        keyTypes.add("PSK");        
        db.addClient("clientB", profiles, "co2", "sensors", keyTypes, skey, null);
        
        // Add a further client "clientG" as a joining node of an OSCORE group
        profiles.clear();
        profiles.add("coap_dtls");
        keyTypes.clear();
        keyTypes.add("PSK");        
        db.addClient("clientG", profiles, null, null, keyTypes, skey, null);
        
        // Add a further client "clientH" as a joining node of an OSCORE group
        profiles.clear();
        profiles.add("coap_dtls");
        keyTypes.clear();
        keyTypes.add("PSK");        
        db.addClient("clientH", profiles, null, null, keyTypes, skey, null);
        
       pdp =  new GroupOSCOREJoinPDP(db);
       
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
       pdp.addIntrospectAccess("rs8", PDP.IntrospectAccessLevel.ACTIVE_ONLY);
       
       // Add also client "clientG" as a joining node of an OSCORE group.
       pdp.addTokenAccess("clientG");
       // Add also client "clientH" as a joining node of an OSCORE group.
       pdp.addTokenAccess("clientH");

       pdp.addAccess("clientA", "rs1", "r_temp");
       pdp.addAccess("clientA", "rs2", "r_light");

       pdp.addAccess("clientB", "rs1", "r_temp");
       pdp.addAccess("clientB", "rs1", "co2");
       pdp.addAccess("clientB", "rs2", "r_light");
       pdp.addAccess("clientB", "rs2", "r_config");

       pdp.addAccess("clientC", "rs1", "r_light");
       
       pdp.addAccess("clientG", "rs1", "r_light");
       pdp.addAccess("clientG", "rs2", "r_light");
       
       // Specify access right also for client "clientG" as a joining node of an OSCORE group.
       // On this Group Manager, this client is allowed to be
       // requester, responder, requester+responder, or monitor.
       pdp.addAccess("clientG", "rs4", "feedca570000_requester_monitor_responder");
       
       // Specify access right also for client "clientG" as a joining node of an OSCORE group.
       // This client is allowed to be requester.
       pdp.addAccess("clientH", "rs4", "feedca570000_monitor");
       
       // Add the resource server rs4 and its OSCORE Group Manager
       // audience to the table OSCOREGroupManagersTable in the PDP
       Set<String> aud4 = Collections.singleton("aud4");
       pdp.addOSCOREGroupManagers("rs4", aud4);
    }
    
    /**
     * Deletes the test DB after the tests
     * 
     * @throws Exception 
     */
    @AfterClass
    public static void tearDown() throws Exception {
        pdp.close();
        DBHelper.tearDownDB();
    }
    
    /**
     * 
     */
    @Rule
    public ExpectedException thrown = ExpectedException.none();

    /**
     * Test the basic example configuration with different access queries
     * 
     * @throws Exception 
     */
    @Test
    public void testBaseConfig() throws Exception {
    	assert(pdp.canAccessToken("clientA"));
    	Set<String> aud1 = Collections.singleton("rs1");
    	Set<String> aud2 = Collections.singleton("rs2");
    	assert(pdp.canAccess("clientA", aud2, "r_light").equals("r_light"));
    	assert(pdp.canAccess("clientC", aud1, "r_temp")==null);
    	assert(pdp.canAccess("clientA", aud1, "r_temp").equals("r_temp"));
    	assert(pdp.canAccess("clientB", aud1, "r_config")==null);
    	assert(pdp.getIntrospectAccessLevel("rs1").equals(PDP.IntrospectAccessLevel.ACTIVE_AND_CLAIMS));
        assert(pdp.getIntrospectAccessLevel("rs8").equals(PDP.IntrospectAccessLevel.ACTIVE_ONLY));
    	assert(!pdp.canAccessToken("clientF"));
    	assert(pdp.getIntrospectAccessLevel("rs4").equals(PDP.IntrospectAccessLevel.NONE));
    }
    
    /**
     * Test the basic example configuration with different access queries
     * 
     * Focus on a client interested to join an OSCORE group through the Group Manager
     * 
     * @throws Exception 
     */
    @Test
    public void testBaseConfiGroupOSCORE() throws Exception {
    	
    	assert(pdp.canAccessToken("clientG"));
    	assert(pdp.canAccessToken("clientH"));
    	
    	Set<String> aud1 = Collections.singleton("rs1");
    	Set<String> aud2 = Collections.singleton("rs2");
    	Set<String> aud4 = Collections.singleton("rs4");
    	assert(pdp.canAccess("clientG", aud1, "r_temp")==null);
    	assert(pdp.canAccess("clientG", aud2, "r_light").equals("r_light"));
    	
    	String gid = new String("feedca570000");
    	String gid2 = new String("feedca570001");
    	
    	// Tests for joining with a single role
    	// The scope is a CBOR Array encoded as a CBOR byte string
    	
    	// The requested role is allowed in the specified group
    	CBORObject cborArrayScope = CBORObject.NewArray();
    	CBORObject cborArrayEntry = CBORObject.NewArray();
    	cborArrayEntry.Add(gid);
    	
    	int myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayEntry.Add(myRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
    	assert(Arrays.equals((byte[])pdp.canAccess("clientG", aud4, byteStringScope), byteStringScope));
    	
    	// The requested role is allowed in the specified group
    	cborArrayScope = CBORObject.NewArray();
    	cborArrayEntry = CBORObject.NewArray();
    	cborArrayEntry.Add(gid);
    	
    	myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_MONITOR);
    	cborArrayEntry.Add(myRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
    	assert(Arrays.equals((byte[])pdp.canAccess("clientG", aud4, byteStringScope), byteStringScope));
    	
    	// The requested role is allowed in the specified group
    	cborArrayScope = CBORObject.NewArray();
    	cborArrayEntry = CBORObject.NewArray();
    	cborArrayEntry.Add(gid);
    	
    	myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_MONITOR);
    	cborArrayEntry.Add(myRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
    	assert(Arrays.equals((byte[])pdp.canAccess("clientH", aud4, byteStringScope), byteStringScope));

    	// Access to the specified group is not allowed
    	cborArrayScope = CBORObject.NewArray();
    	cborArrayEntry = CBORObject.NewArray();
    	cborArrayEntry.Add(gid2);
    	
    	myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_MONITOR);
    	cborArrayEntry.Add(myRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
    	assert(pdp.canAccess("clientG", aud4, byteStringScope)==null);
    	
    	// The requested role is not allowed in the specified group
    	cborArrayScope = CBORObject.NewArray();
    	cborArrayEntry = CBORObject.NewArray();
    	cborArrayEntry.Add(gid);
    	
    	myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayEntry.Add(myRoles);
    		
    	cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
    	assert(pdp.canAccess("clientH", aud4, byteStringScope)==null);
    	
    	// The requested role is not allowed in the specified group
    	cborArrayScope = CBORObject.NewArray();
    	cborArrayEntry = CBORObject.NewArray();
    	cborArrayEntry.Add(gid);
    	
    	myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, (short)10);
    	cborArrayEntry.Add(myRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
    	assert(pdp.canAccess("clientG", aud4, byteStringScope)==null);
    	
    	
    	// Tests for joining with multiple roles
    	// The scope is a CBOR Array encoded as a CBOR byte string
    	
    	// Both requested roles are allowed in the specified group
    	cborArrayScope = CBORObject.NewArray();
    	cborArrayEntry = CBORObject.NewArray();
    	cborArrayEntry.Add(gid);
    	
    	myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(myRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
    	
    	byte[] bysteStringScope2;
    	cborArrayScope = CBORObject.NewArray();
    	cborArrayEntry = CBORObject.NewArray();
    	cborArrayEntry.Add(gid);
    	
    	myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(myRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	bysteStringScope2 = cborArrayScope.EncodeToBytes();
    	
    	assert(Arrays.equals((byte[])pdp.canAccess("clientG", aud4, byteStringScope), byteStringScope) ||
    	       Arrays.equals((byte[])pdp.canAccess("clientG", aud4, byteStringScope), bysteStringScope2));
    	
    	// Access to the specified group is not allowed
    	cborArrayScope = CBORObject.NewArray();
    	cborArrayEntry = CBORObject.NewArray();
    	cborArrayEntry.Add(gid2);
    	
    	myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(myRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
    	
    	assert(pdp.canAccess("clientG", aud4, byteStringScope)==null);
    	    	

    	// Only one role out of the two requested ones is allowed in the specified group
    	cborArrayScope = CBORObject.NewArray();
    	cborArrayEntry = CBORObject.NewArray();
    	cborArrayEntry.Add(gid);
    	
    	myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_MONITOR);
    	cborArrayEntry.Add(myRoles);
    	    	
    	cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
    	
    	cborArrayScope = CBORObject.NewArray();
    	cborArrayEntry = CBORObject.NewArray();
    	cborArrayEntry.Add(gid);
    	
    	myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_MONITOR);
    	cborArrayEntry.Add(myRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	bysteStringScope2 = cborArrayScope.EncodeToBytes();
    	
    	assert(Arrays.equals((byte[])pdp.canAccess("clientH", aud4, byteStringScope), bysteStringScope2));
    	
    	
    	// None of the requested ones is allowed in the specified group
    	cborArrayScope = CBORObject.NewArray();
    	cborArrayEntry = CBORObject.NewArray();
    	cborArrayEntry.Add(gid);
    	
    	myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(myRoles);
    	
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
    	    	
    	assert(pdp.canAccess("clientH", aud4, byteStringScope)==null);
    	
    }
    
    /**
     * Test deleting and adding access
     * 
     * @throws Exception 
     */
    @Test
    public void testDeleteAdd() throws Exception {
        pdp.addTokenAccess("testC");
        assert(pdp.canAccessToken("testC"));
        
        pdp.addIntrospectAccess("testRS", PDP.IntrospectAccessLevel.ACTIVE_AND_CLAIMS);
        assert(pdp.getIntrospectAccessLevel("testRS").equals(PDP.IntrospectAccessLevel.ACTIVE_AND_CLAIMS));
        
        pdp.revokeTokenAccess("testC");
        assert(!pdp.canAccessToken("testC"));
        
        pdp.revokeIntrospectAccess("testRS");
        assert(pdp.getIntrospectAccessLevel("testRS").equals(PDP.IntrospectAccessLevel.NONE));
        
        pdp.addAccess("testC", "testRS1", "testScope1");
        pdp.addAccess("testC", "testRS1", "testScope2");
        pdp.addAccess("testC", "testRS2", "testScope3");
        pdp.addAccess("testC", "testRS3", "testScope4");
        assert(pdp.canAccess("testC", Collections.singleton("testRS1"), "testScope1").
        		equals("testScope1"));
        assert(pdp.canAccess("testC", Collections.singleton("testRS1"),"testScope1 testScope2 testScope3").
        		equals("testScope1 testScope2"));
        assert(pdp.canAccess("testC", Collections.singleton("testRS2"), "testScope3").
        		equals("testScope3"));
        assert(pdp.canAccess("testC", Collections.singleton("testRS3"), "testScope4").
        		equals("testScope4"));
        
        pdp.revokeAccess("testC", "testRS3", "testScope4");
        assert(pdp.canAccess("testC", Collections.singleton("testRS3"), "testScope4") == null);
        
        pdp.revokeAllRsAccess("testC", "testRS1");
        assert(pdp.canAccess("testC", Collections.singleton("testRS1"), "testScope1") == null);
        
        pdp.revokeAllAccess("testC");
        assert(pdp.canAccess("testC", Collections.singleton("testRS2"), "testScope3") == null);
    }
}
