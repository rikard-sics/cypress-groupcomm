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

import java.io.File;
import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.sql.SQLException;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.MessageTag;
import org.eclipse.californium.cose.OneKey;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.Utils;
import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.DBHelper;
import se.sics.ace.Message;
import se.sics.ace.ReferenceToken;
import se.sics.ace.TestConfig;
import se.sics.ace.Util;
import se.sics.ace.as.AccessTokenFactory;
import se.sics.ace.as.Introspect;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.LocalMessage;
import se.sics.ace.examples.SQLConnector;
import se.sics.ace.oscore.GroupInfo;
import se.sics.ace.oscore.as.GroupOSCOREJoinPDP;
import se.sics.ace.oscore.rs.AuthzInfoGroupOSCORE;
import se.sics.ace.oscore.rs.GroupOSCOREJoinValidator;
import se.sics.ace.rs.IntrospectionException;
import se.sics.ace.rs.IntrospectionHandler4Tests;
import se.sics.ace.rs.TokenRepository;

/**
 * 
 * @author Marco Tiloca
 */
public class TestAuthzInfoGroupOSCORE {
    
    static OneKey publicKey;
    static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static byte[] key128a = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static SQLConnector db = null;

    private static AuthzInfoGroupOSCORE ai = null;
    
    private static AuthzInfoGroupOSCORE ai2 = null;
    // Created a separate authz-info endpoint using a dedicated introspection handler
    // for the audience "aud2" (OSCORE Group Manager). An actual fix would be defining
    // a new introspection handler, whose constructor takes as input a list of audience
    // identifiers, rather than a single RS identifier.
    
    private static Introspect i; 
    private static GroupOSCOREJoinPDP pdp = null;
    
    // Up to 4 bytes, same for all the OSCORE Group of the Group Manager
    private final static int groupIdPrefixSize = 4;
    
    // Initial part of the node name for monitors, since they do not have a Sender ID
    private final static String prefixMonitorNames = "M";
    
    // For non-monitor members, separator between the two components of the node name
	private final static String nodeNameSeparator = "-";
    
    private static Map<String, GroupInfo> activeGroups = new HashMap<>();
    
	private static final String rootGroupMembershipResource = "ace-group";
    
    /**
     * Set up tests.
     * @throws SQLException 
     * @throws AceException 
     * @throws IOException 
     * @throws CoseException 
     */
    @BeforeClass
    public static void setUp() throws SQLException, AceException, IOException, CoseException {
    	
    	final Provider PROVIDER = new BouncyCastleProvider();
    	final Provider EdDSA = new EdDSASecurityProvider();
    	Security.insertProviderAt(PROVIDER, 2);
    	Security.insertProviderAt(EdDSA, 1);

        DBHelper.setUpDB();
        db = DBHelper.getSQLConnector();

    	final String groupName = "feedca570000";
        
        OneKey key = OneKey.generateKey(AlgorithmID.ECDSA_256);
        publicKey = key.PublicKey();
        
        OneKey sharedKey = new OneKey();
        sharedKey.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        sharedKey.add(KeyKeys.KeyId, CBORObject.FromObject(new byte[]{0x74, 0x11}));
        sharedKey.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));

        Set<String> profiles = new HashSet<>();
        profiles.add("coap_dtls");
        Set<String> keyTypes = new HashSet<>();
        keyTypes.add("PSK");
        db.addClient("client1", profiles, null, null, keyTypes, null, publicKey);
        db.addClient("client2", profiles, null, null, keyTypes, sharedKey, publicKey);
        
        
        String rsId = "rs1";
        
        Set<String> scopes = new HashSet<>();
        scopes.add("temp");
        scopes.add("co2");
        Set<String> auds = new HashSet<>();
        auds.add("aud1");
        auds.add("actuators");
        Set<Short> tokenTypes = new HashSet<>();
        tokenTypes.add(AccessTokenFactory.CWT_TYPE);
        tokenTypes.add(AccessTokenFactory.REF_TYPE);
        Set<COSEparams> cose = new HashSet<>();
        COSEparams coseP = new COSEparams(MessageTag.Sign1, AlgorithmID.ECDSA_256, AlgorithmID.Direct);
        cose.add(coseP);
        long expiration = 1000000L;
        CBORObject keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128));
        OneKey psk = new OneKey(keyData);
        db.addRS(rsId, profiles, scopes, auds, keyTypes, tokenTypes, cose, expiration, psk, psk, publicKey);
        
        
        rsId = "rs2";
        auds.clear();
        auds.add("aud2");
        db.addRS(rsId, profiles, scopes, auds, keyTypes, tokenTypes, cose, expiration, psk, psk, publicKey);
        
        
        Set<Short> actions = new HashSet<>();
        actions.add(Constants.GET);
        Map<String, Set<Short>> myResource = new HashMap<>();
        myResource.put("temp", actions);
        Map<String, Map<String, Set<Short>>> myScopes = new HashMap<>();
        myScopes.put("r_temp", myResource);
        
        Map<String, Set<Short>> myResource2 = new HashMap<>();
        myResource2.put("co2", actions);
        myScopes.put("r_co2", myResource2);
        
        // Adding the group-membership resource
        Set<Short> actions2 = new HashSet<>();
        actions2.add(Constants.POST);
        Map<String, Set<Short>> myResource3 = new HashMap<>();
        myResource3.put(rootGroupMembershipResource + "/" + groupName, actions2);
        myScopes.put(rootGroupMembershipResource + "/" + groupName, myResource3);
        
        auds = new HashSet<>();
        auds.add("aud1"); // Simple test audience
        auds.add("actuators"); // Simple test audience
        auds.add("aud2"); // OSCORE Group Manager (This audience expects scopes as Byte Strings)
        GroupOSCOREJoinValidator valid = new GroupOSCOREJoinValidator(auds, myScopes, rootGroupMembershipResource);
        
        // Include this audience in the list of audiences recognized as OSCORE Group Managers 
        valid.setGMAudiences(Collections.singleton("aud2"));
        
        // Include this resource as a group-membership resource for Group OSCORE.
        // The resource name is the name of the OSCORE group.
        valid.setJoinResources(Collections.singleton(rootGroupMembershipResource + "/" + groupName));
        
        // Create the OSCORE group
        final byte[] masterSecret = { (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
                					  (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08,
                					  (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C,
                					  (byte) 0x0D, (byte) 0x0E, (byte) 0x0F, (byte) 0x10 };

        final byte[] masterSalt =   { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22,
                					  (byte) 0x23, (byte) 0x78, (byte) 0x63, (byte) 0x40 };

        final AlgorithmID hkdf = AlgorithmID.HMAC_SHA_256;
        final int credFmt = Constants.COSE_HEADER_PARAM_CCS;
        
        int mode = Constants.GROUP_OSCORE_GROUP_MODE_ONLY;

        final AlgorithmID signEncAlg = AlgorithmID.AES_CCM_16_64_128;
        AlgorithmID signAlg = null;
        CBORObject algCapabilities = CBORObject.NewArray();
        CBORObject keyCapabilities = CBORObject.NewArray();
        CBORObject signParams = CBORObject.NewArray();
        
        // Uncomment to set ECDSA with curve P256 for countersignatures
        // int signKeyCurve = KeyKeys.EC2_P256.AsInt32();
        
        // Uncomment to set EDDSA with curve Ed25519 for countersignatures
        int signKeyCurve = KeyKeys.OKP_Ed25519.AsInt32();
        
        // ECDSA_256
        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            signAlg = AlgorithmID.ECDSA_256;
            algCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
            keyCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
            keyCapabilities.Add(KeyKeys.EC2_P256); // Curve
        }

        // EDDSA (Ed25519)
        if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            signAlg = AlgorithmID.EDDSA;
            algCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
            keyCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
            keyCapabilities.Add(KeyKeys.OKP_Ed25519); // Curve
        }

        signParams.Add(algCapabilities);
        signParams.Add(keyCapabilities); 
        
        // Prefix (4 byte) and Epoch (2 bytes) --- All Group IDs have the same prefix size, but can have different Epoch sizes
        // The current Group ID is: 0xfeedca57f05c, with Prefix 0xfeedca57 and current Epoch 0xf05c 
    	final byte[] groupIdPrefix = new byte[] { (byte) 0xfe, (byte) 0xed, (byte) 0xca, (byte) 0x57 };
    	byte[] groupIdEpoch = new byte[] { (byte) 0xf0, (byte) 0x5c }; // Up to 4 bytes
    	
    	
    	// Set the asymmetric key pair and public key of the Group Manager
    	
    	// Serialization of the COSE Key including both private and public part
    	byte[] gmKeyPairBytes = null;
    	    	
    	// The asymmetric key pair and public key of the Group Manager (ECDSA_256)
    	if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
    		gmKeyPairBytes = Utils.hexToBytes("a60102032620012158202236658ca675bb62d7b24623db0453a3b90533b7c3b221cc1c2c73c4e919d540225820770916bc4c97c3c46604f430b06170c7b3d6062633756628c31180fa3bb65a1b2358204a7b844a4c97ef91ed232aa564c9d5d373f2099647f9e9bd3fe6417a0d0f91ad");
    	}
    	    
    	// The asymmetric key pair and public key of the Group Manager (EDDSA - Ed25519)
    	if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
    		gmKeyPairBytes = Utils.hexToBytes("a5010103272006215820c6ec665e817bd064340e7c24bb93a11e8ec0735ce48790f9c458f7fa340b8ca3235820d0a2ce11b2ba614b048903b72638ef4a3b0af56e1a60c6fb6706b0c1ad8a14fb");
    	}

    	OneKey gmKeyPair = null;
    	gmKeyPair = new OneKey(CBORObject.DecodeFromBytes(gmKeyPairBytes));
    	

    	// Serialization of the public key, according to the format used in the group
    	byte[] gmPublicKey = null;
    	
    	/*
    	// Build the authentication credential according to the format used in the group
    	// Note: most likely, the result will NOT follow the required deterministic
    	//       encoding in byte lexicographic order, and it has to be adjusted offline
    	switch (credFmt) {
        case Constants.COSE_HEADER_PARAM_CCS:
            // A CCS including the public key
        	String subjectName = "";
            gmPublicKey = Util.oneKeyToCCS(gmKeyPair, subjectName);
            break;
        case Constants.COSE_HEADER_PARAM_CWT:
            // A CWT including the public key
            // TODO
            break;
        case Constants.COSE_HEADER_PARAM_X5CHAIN:
            // A certificate including the public key
            // TODO
            break;
    	}
    	*/
    	
    	switch (credFmt) {
	        case Constants.COSE_HEADER_PARAM_CCS:
	            // A CCS including the public key
	        	if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
	        		gmPublicKey = Utils.hexToBytes("A2026008A101A50102032620012158202236658CA675BB62D7B24623DB0453A3B90533B7C3B221CC1C2C73C4E919D540225820770916BC4C97C3C46604F430B06170C7B3D6062633756628C31180FA3BB65A1B");
	        	}
	        	if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
	        		gmPublicKey = Utils.hexToBytes("A2026008A101A4010103272006215820C6EC665E817BD064340E7C24BB93A11E8EC0735CE48790F9C458F7FA340B8CA3");
	        	}
	            break;
	        case Constants.COSE_HEADER_PARAM_CWT:
	            // A CWT including the public key
	            // TODO
	        	gmPublicKey = null;
	            break;
	        case Constants.COSE_HEADER_PARAM_X5CHAIN:
	            // A certificate including the public key
	            // TODO
	        	gmPublicKey = null;
	            break;
    	}
    	
    	
    	GroupInfo myGroup = new GroupInfo(groupName,
						                  masterSecret,
						                  masterSalt,
						                  groupIdPrefixSize,
						                  groupIdPrefix,
						                  groupIdEpoch.length,
						                  Util.bytesToInt(groupIdEpoch),
						                  prefixMonitorNames,
						                  nodeNameSeparator,
						                  hkdf,
						                  credFmt,
						                  mode,
						                  signEncAlg,
						                  signAlg,
						                  signParams,
						                  null,
						                  null,
						                  null,
    			                          null,
    			                          gmKeyPair,
    			                          gmPublicKey);
        
    	// Add this OSCORE group to the set of active groups
    	activeGroups.put(groupName, myGroup);
       
    	
        String tokenFile = TestConfig.testFilePath + "tokens.json";
        //Delete lingering old token files
        new File(tokenFile).delete();
        
        coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, 
                coseP.getAlg().AsCBOR());

        pdp = new GroupOSCOREJoinPDP(db);
        pdp.addIntrospectAccess("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w");
        pdp.addIntrospectAccess("rs1");
        pdp.addIntrospectAccess("rs2"); // Enabling introspection for the OSCORE Group Manager
        i = new Introspect(pdp, db, new KissTime(), key, null);
        
        
    	rsId = "rs1";
        // Tests on this Resource Server "rs1" are just the same as in TestAuthzInfo,
        // while using the endpoint AuthzInfoGroupOSCORE as for the Resource Server "rs2".
    	//
    	// This endpoint does not perform introspection, which always expects Access Tokens stored
    	// at the AS and possible to introspect to specify an audience. This enables some of the
    	// tests below to focus on error conditions and achieve the expected outcomes.
        ai = new AuthzInfoGroupOSCORE(Collections.singletonList("TestAS"), new KissTime(),
        							  null, rsId, valid, ctx, null, 0, tokenFile, valid, false);
        
        // Provide the authz-info endpoint with the set of active OSCORE groups
        ai.setActiveGroups(activeGroups);
        
        
    	rsId = "rs2";
        // A separate authz-info endpoint is required for each Resource Server, here "rs2",
        // due to the interface of the IntrospectionHandler4Tests taking exactly one RS as second argument.
        ai2 = new AuthzInfoGroupOSCORE(Collections.singletonList("TestAS"), 
						               new KissTime(), new IntrospectionHandler4Tests(i, "rs2", "TestAS"),
						               rsId, valid, ctx, null, 0, tokenFile, valid, false);
        
        // Provide the authz-info endpoint with the set of active OSCORE groups
        ai2.setActiveGroups(activeGroups);
        
    }
    
    /**
     * Deletes the test DB after the tests
     * @throws Exception 
     */
    @AfterClass
    public static void tearDown() throws Exception {
        DBHelper.tearDownDB();
        pdp.close();
        i.close();
        ai.close();
        new File(TestConfig.testFilePath + "tokens.json").delete();
    }
    
    /**
     * Test inactive reference token submission to AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException 
     */
    @Test
    public void testRefInactive() throws IllegalStateException,
    		InvalidCipherTextException, CoseException, AceException {
        ReferenceToken token = new ReferenceToken(20);
        LocalMessage request = new LocalMessage(0, null, "rs2", CBORObject.FromObject(token.encode().EncodeToBytes()));
                
        LocalMessage response = (LocalMessage)ai2.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_UNAUTHORIZED);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
        map.Add(Constants.ERROR_DESCRIPTION, "Token is not active");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test CWT with a scope claim that is overwritten by introspection
     * 
     * @throws AceException 
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     * @throws IntrospectionException 
     */
    @Test
    public void testCwtIntrospect() throws AceException, IllegalStateException,
            InvalidCipherTextException, CoseException, IntrospectionException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.SCOPE, CBORObject.FromObject("r_co2"));
        params.put(Constants.AUD, CBORObject.FromObject("aud2"));
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x01}));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, publicKey.AsCBOR());
        params.put(Constants.CNF, cnf);
        
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x01});
        //Make introspection succeed
        db.addToken(ctiStr, params);
        db.addCti2Client(ctiStr, "client1");
        
        //this overwrites the scope
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud2"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        CBORObject kid = CBORObject.FromObject(new byte[]{0x00, 0x01});
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cbor);
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());
        LocalMessage request = new LocalMessage(0, null, "rs2", token.encode(ctx));
        
        LocalMessage response = (LocalMessage)ai2.processMessage(request);
        assert(response.getMessageCode() == Message.CREATED);
        
        CBORObject resP = CBORObject.DecodeFromBytes(response.getRawPayload());
        CBORObject cti = resP.get(CBORObject.FromObject(Constants.CTI));
        Assert.assertArrayEquals(cti.GetByteString(), new byte[]{0x01});
        String rpk = new RawPublicKeyIdentity(publicKey.AsPublicKey()).getName();
        String kidStr = Base64.getEncoder().encodeToString(rpk.getBytes());
        assert(1 == TokenRepository.getInstance().canAccess(kidStr, null, "co2", Constants.GET, null));

    }
    
    /**
     * Test CWT with invalid MAC submission to AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testInvalidCWT() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> claims = new HashMap<>();
        claims.put(Constants.ISS, CBORObject.FromObject("coap://as.example.com"));
        claims.put(Constants.AUD, CBORObject.FromObject("coap://light.example.com"));
        claims.put(Constants.EXP, CBORObject.FromObject(1444064944));
        claims.put(Constants.NBF, CBORObject.FromObject(1443944944));
        claims.put(Constants.IAT, CBORObject.FromObject(1443944944));
        byte[] cti = {0x02};
        claims.put(Constants.CTI, CBORObject.FromObject(cti));
        claims.put(Constants.CNF, publicKey.AsCBOR());
        claims.put(Constants.SCOPE, CBORObject.FromObject("r+/s/light rwx+/a/led w+/dtls"));
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128a, AlgorithmID.AES_CCM_16_64_128.AsCBOR());
        CWT cwt = new CWT(claims);

        LocalMessage request = new LocalMessage(0, null, "rs1", cwt.encode(ctx));
                
        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
        map.Add(Constants.ERROR_DESCRIPTION, "Token is invalid");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test an invalid token format submission to AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testInvalidTokenFormat() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        CBORObject token = CBORObject.False;
        LocalMessage request = new LocalMessage(0, null, "rs1", token);
                
        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, "Unknown token format");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test expired CWT submission to AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testExpiredCWT() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> claims = new HashMap<>();
        byte[] cti = {0x03};
        claims.put(Constants.CTI, CBORObject.FromObject(cti));
        claims.put(Constants.AUD, CBORObject.FromObject("aud1"));
        String ctiStr = Base64.getEncoder().encodeToString(cti);
        
        //Make introspection succeed
        db.addToken(ctiStr, claims);
        db.addCti2Client(ctiStr, "client1");
        
        claims.put(Constants.CNF, publicKey.AsCBOR());
        claims.put(Constants.SCOPE, CBORObject.FromObject("r+/s/light rwx+/a/led w+/dtls")); 
        claims.put(Constants.ISS, CBORObject.FromObject("coap://as.example.com"));
        claims.put(Constants.AUD, CBORObject.FromObject("coap://light.example.com"));
        claims.put(Constants.NBF, CBORObject.FromObject(1443944944));
        claims.put(Constants.IAT, CBORObject.FromObject(1443944944));        
        claims.put(Constants.EXP, CBORObject.FromObject(10000));
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, AlgorithmID.AES_CCM_16_64_128.AsCBOR());
        CWT cwt = new CWT(claims);
        
        LocalMessage request = new LocalMessage(0, null, "rs1", cwt.encode(ctx));
                
        LocalMessage response = (LocalMessage)ai.processMessage(request);
        assert(response.getMessageCode() == Message.FAIL_UNAUTHORIZED);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
        map.Add(Constants.ERROR_DESCRIPTION, "Token is expired");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
        db.deleteToken(ctiStr);
    }
    
    /**
     * Test CWT with unrecognized issuer submission to AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException 
     */
    @Test
    public void testIssuerNotRecognized() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x05}));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, publicKey.AsCBOR());
        params.put(Constants.CNF, cnf);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x05});
        
        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(new byte[]{0x05}), params);
        db.addCti2Client(ctiStr, "client1");
        
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("FalseAS"));
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());
        LocalMessage request = new LocalMessage(0, null, "rs1", token.encode(ctx));
                
        LocalMessage response = (LocalMessage)ai.processMessage(request);  
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, "Token issuer unknown");
        assert(response.getMessageCode() == Message.FAIL_UNAUTHORIZED);
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test CWT without audience submission to AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException 
     */
    @Test
    public void testNoAudience() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x06}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());
        LocalMessage request = new LocalMessage(0, null, "rs1", token.encode(ctx));
                
        LocalMessage response = (LocalMessage)ai.processMessage(request);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, "Token has no audience");
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test CWT with audience that does not match RS submission to AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException 
     */
    @Test
    public void testNoAudienceMatch() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x07}));
        
        /*
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x07});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(
                new byte[]{0x07}), params);
        db.addCti2Client(ctiStr, "client1");
        */
        
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("blah"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());
        LocalMessage request = new LocalMessage(0, null, "rs1", token.encode(ctx));
                
        LocalMessage response = (LocalMessage)ai.processMessage(request);  
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
        map.Add(Constants.ERROR_DESCRIPTION, "Audience does not apply");
        assert(response.getMessageCode() == Message.FAIL_FORBIDDEN);
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());   
    }  
    
    /**
     * Test CWT without scope submission to AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testNoScope() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x08}));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());
        LocalMessage request = new LocalMessage(0, null, "rs1", token.encode(ctx));
        LocalMessage response = (LocalMessage)ai.processMessage(request);
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_SCOPE);
        map.Add(Constants.ERROR_DESCRIPTION, "Token has no scope");
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test successful submission to AuthzInfo
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testSuccess() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x09}));
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourKey";
        CBORObject kid = CBORObject.FromObject(kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cbor);
        
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());
        LocalMessage request = new LocalMessage(0, null, "rs1", token.encode(ctx));
                
        LocalMessage response = (LocalMessage)ai.processMessage(request);
        System.out.println(response.toString());
        assert(response.getMessageCode() == Message.CREATED);
        
        CBORObject resP = CBORObject.DecodeFromBytes(response.getRawPayload());
        CBORObject cti = resP.get(CBORObject.FromObject(Constants.CTI));
        Assert.assertArrayEquals(cti.GetByteString(), new byte[]{0x09});
    }    
    
    /**
     * Test successful submission to AuthzInfo, for
     * accessing an OSCORE group with a single role.
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testSuccessGroupOSCORESingleRole() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
    	
        Map<Short, CBORObject> params = new HashMap<>();
        
        String groupName = new String("feedca570000");
    	CBORObject cborArrayScope = CBORObject.NewArray();
    	CBORObject cborArrayEntry = CBORObject.NewArray();
    	cborArrayEntry.Add(groupName);
    	
    	int myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayEntry.Add(myRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
    	
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x12}));
        
        // The scope is a CBOR Array encoded as a CBOR byte string
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        
        // Note the usage of this particular audience "aud2" acting as OSCORE Group Manager
        params.put(Constants.AUD, CBORObject.FromObject("aud2"));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourKey";
        CBORObject kid = CBORObject.FromObject(kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x12});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(new byte[]{0x12}), params);
        db.addCti2Client(ctiStr, "client1");  
        
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());
        LocalMessage request = new LocalMessage(0, null, null, token.encode(ctx));
              
        // Note the usage of the dedicated authz-info endpoint for this audience "aud2"
        LocalMessage response = (LocalMessage)ai2.processMessage(request);
        System.out.println(response.toString());
        assert(response.getMessageCode() == Message.CREATED);
        
        CBORObject resP = CBORObject.DecodeFromBytes(response.getRawPayload());
        CBORObject cti = resP.get(CBORObject.FromObject(Constants.CTI));
        Assert.assertArrayEquals(cti.GetByteString(), new byte[]{0x12});
    }
    
    
    /**
     * Test successful submission to AuthzInfo, for
     * accessing an OSCORE group with multiple roles.
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testSuccessGroupOSCOREMultipleRoles() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
    	
        Map<Short, CBORObject> params = new HashMap<>();
        
        String groupName = new String("feedca570000");
    	CBORObject cborArrayScope = CBORObject.NewArray();
    	CBORObject cborArrayEntry = CBORObject.NewArray();
    	cborArrayEntry.Add(groupName);
    	
    	int myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(myRoles);
    		
    	cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
    	
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x13}));
        
        // The scope is a CBOR Array encoded as a CBOR byte string
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        
        // Note the usage of this particular audience "aud2" acting as OSCORE Group Manager
        params.put(Constants.AUD, CBORObject.FromObject("aud2"));
        
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourKey";
        CBORObject kid = CBORObject.FromObject(kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x13});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(new byte[]{0x13}), params);
        db.addCti2Client(ctiStr, "client1");  
        
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());
        LocalMessage request = new LocalMessage(0, null, null, token.encode(ctx));
              
        // Note the usage of the dedicated authz-info endpoint for this audience "aud2"
        LocalMessage response = (LocalMessage)ai2.processMessage(request);
        System.out.println(response.toString());        
        assert(response.getMessageCode() == Message.CREATED);   
        CBORObject resP = CBORObject.DecodeFromBytes(response.getRawPayload());
        CBORObject cti = resP.get(CBORObject.FromObject(Constants.CTI));
        Assert.assertArrayEquals(cti.GetByteString(), new byte[]{0x13});
    }

    /**
     * Test successful submission to AuthzInfo, for
     * accessing an OSCORE group with a single role.
     * 
     * Then post a new Access Token to update access rights,
     * for accessing the same OSCORE group with multiple roles.
     * 
     * @throws IllegalStateException 
     * @throws InvalidCipherTextException 
     * @throws CoseException 
     * @throws AceException  
     */
    @Test
    public void testSuccessGroupOSCORESingleRoleUpdateAccessRights() throws IllegalStateException, 
            InvalidCipherTextException, CoseException, AceException {
    	
        Map<Short, CBORObject> params = new HashMap<>();
        
        String groupName = new String("feedca570000");
    	CBORObject cborArrayScope = CBORObject.NewArray();
    	CBORObject cborArrayEntry = CBORObject.NewArray();
    	cborArrayEntry.Add(groupName);
    	
    	int myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayEntry.Add(myRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
    	
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x14}));
        
        // The scope is a CBOR Array encoded as a CBOR byte string
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        
        // Note the usage of this particular audience "aud2" acting as OSCORE Group Manager
        params.put(Constants.AUD, CBORObject.FromObject("aud2"));
        
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        String kidStr = "ourKey";
        CBORObject kid = CBORObject.FromObject(kidStr.getBytes(Constants.charset));
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cbor);
        String ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x14});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(new byte[]{0x14}), params);
        db.addCti2Client(ctiStr, "client1");  
        
        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128, coseP.getAlg().AsCBOR());
        LocalMessage request = new LocalMessage(0, null, null, token.encode(ctx));
              
        // Note the usage of the dedicated authz-info endpoint for this audience "aud"
        LocalMessage response = (LocalMessage)ai2.processMessage(request);
        System.out.println(response.toString());
        assert(response.getMessageCode() == Message.CREATED);        
        CBORObject resP = CBORObject.DecodeFromBytes(response.getRawPayload());
        CBORObject cti = resP.get(CBORObject.FromObject(Constants.CTI));
        Assert.assertArrayEquals(cti.GetByteString(), new byte[]{0x14});
        
        
        // Build a new Token for updating access rights, with a different 'scope'
         
    	cborArrayScope = CBORObject.NewArray();
    	cborArrayEntry = CBORObject.NewArray();
    	cborArrayEntry.Add(groupName);
    	
    	myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(myRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
    	
    	Map<Short, CBORObject> params2 = new HashMap<>();
        params2.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x15}));
        
        // The scope is a CBOR Array encoded as a CBOR byte string
        params2.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        
        // Note the usage of this particular audience "aud2" acting as OSCORE Group Manager
        params2.put(Constants.AUD, CBORObject.FromObject("aud2"));
        
        params2.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        
        CBORObject keyData  = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.KeyId.AsCBOR(), kid);
        CBORObject cnf2 = CBORObject.NewMap();
        cnf2.Add(Constants.COSE_KEY_CBOR, keyData); // The specified 'COSE_Key' includes only key type and kid
        params2.put(Constants.CNF, cnf2);
        ctiStr = Base64.getEncoder().encodeToString(new byte[]{0x15});

        //Make introspection succeed
        db.addToken(Base64.getEncoder().encodeToString(new byte[]{0x15}), params2);
        db.addCti2Client(ctiStr, "client1");  
        
        CWT token2 = new CWT(params2);
        
        // Posting the Token through an unprotected request.
        // This fails since such a Token needs to include the
        // a 'cnf' claim transporting also the actual key 'k'
        LocalMessage req2 = new LocalMessage(0, null, null, token2.encode(ctx));
        req2 = new LocalMessage(0, null, null, token.encode(ctx));
        LocalMessage resp2 = (LocalMessage)ai2.processMessage(req2);
        assert(resp2.getMessageCode() == Message.FAIL_BAD_REQUEST);
        
        String identityStr = Base64.getEncoder().encodeToString(kid.GetByteString());
  	    req2 = new LocalMessage(0, identityStr, null, token2.encode(ctx));
  	    
  	    resp2 = (LocalMessage)ai2.processMessage(req2);
  	    assert(resp2.getMessageCode() == Message.CREATED);
        
    }
    
}   

