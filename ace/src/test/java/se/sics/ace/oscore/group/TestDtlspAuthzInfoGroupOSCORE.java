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
package se.sics.ace.oscore.group;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.Provider;
import java.security.Security;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executor;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.CoapEndpoint.Builder;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.auth.PreSharedKeyIdentity;
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
import se.sics.ace.GroupcommParameters;
import se.sics.ace.Message;
import se.sics.ace.TestConfig;
import se.sics.ace.Util;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.LocalMessage;
import se.sics.ace.oscore.GroupInfo;
import se.sics.ace.oscore.rs.AuthzInfoGroupOSCORE;
import se.sics.ace.oscore.rs.CoapAuthzInfoGroupOSCORE;
import se.sics.ace.oscore.rs.GroupOSCOREValidator;
import se.sics.ace.rs.IntrospectionException;
import se.sics.ace.rs.TokenRepository;

/**
 * Test the DTLSProfileAuthzInfo class.
 * 
 * @author Marco Tiloca
 *
 */
public class TestDtlspAuthzInfoGroupOSCORE {

	static {
	    CoapConfig.register();
	}
	
    private static byte[] key128a = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static CwtCryptoCtx ctx;
    private static AuthzInfoGroupOSCORE ai;
    private static AuthzInfoGroupOSCORE ai2;
    private static CoapAuthzInfoGroupOSCORE dai;
    private static CoapAuthzInfoGroupOSCORE dai2;
    private static CBORObject payload;
    private static CBORObject payload2;
    private static CBORObject payload3;
    private static CBORObject payload4;
    
    // Up to 4 bytes, same for all the OSCORE Group of the Group Manager
    private final static int groupIdPrefixSize = 4;
    
    // Initial part of the node name for monitors, since they do not have a Sender ID
    private final static String prefixMonitorNames = "M";
    
    // For non-monitor members, separator between the two components of the node name
	private final static String nodeNameSeparator = "-";
    
	// The maximum number of sets of stale Sender IDs for the group
	// This value must be strictly greater than 1
	private final static int maxStaleIdsSets = 3;
	
    private static Map<String, GroupInfo> existingGroups = new HashMap<>();
    
	private static final String rootGroupMembershipResource = "ace-group";
	
	private final static String groupCollectionResourcePath = "manage";
    
    // The map key is the cryptographic curve; the map value is the hex string of the key pair
    private static Map<CBORObject, String> gmSigningKeyPairs = new HashMap<CBORObject, String>();
    
    // For the outer map, the map key is the type of authentication credential
    // For the inner map, the map key is the cryptographic curve, while the map value is the hex string of the authentication credential
    private static Map<Integer,  Map<CBORObject, String>> gmSigningPublicAuthCred = new HashMap<Integer, Map<CBORObject, String>>();
    
    // The map key is the cryptographic curve; the map value is the hex string of the key pair
    private static Map<CBORObject, String> gmKeyAgreementKeyPairs = new HashMap<CBORObject, String>();
    
    // For the outer map, the map key is the type of authentication credential
    // For the inner map, the map key is the cryptographic curve, while the map value is the hex string of the authentication credential
    private static Map<Integer,  Map<CBORObject, String>> gmKeyAgreementPublicAuthCred  = new HashMap<Integer, Map<CBORObject, String>>();
	
	
    /**
     * Set up the necessary objects.
     * 
     * @throws CoseException
     * @throws AceException
     * @throws IOException
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     */
    @BeforeClass
    public static void setUp() throws CoseException, AceException, IOException, 
        	IllegalStateException, InvalidCipherTextException {
        
    	final Provider PROVIDER = new BouncyCastleProvider();
    	final Provider EdDSA = new EdDSASecurityProvider();
    	Security.insertProviderAt(PROVIDER, 2);
    	Security.insertProviderAt(EdDSA, 1);
    	
        //Set up DTLSProfileTokenRepository
        Set<Short> actions = new HashSet<>();
        actions.add(Constants.GET);
        Map<String, Set<Short>> myResource = new HashMap<>();
        myResource.put("temp", actions);
        Map<String, Map<String, Set<Short>>> myScopes = new HashMap<>();
        myScopes.put("r_temp", myResource);
        
        Set<Short> actions2 = new HashSet<>();
        actions2.add(Constants.GET);
        actions2.add(Constants.POST);
        Map<String, Set<Short>> myResource2 = new HashMap<>();
        myResource2.put("co2", actions2);
        myScopes.put("rw_co2", myResource2);
        
        final String groupName = "feedca570000";
        
        // Adding the group-membership resource
        Set<Short> actions3 = new HashSet<>();
        actions3.add(Constants.POST);
        Map<String, Set<Short>> myResource3 = new HashMap<>();
        
        myResource3.put(rootGroupMembershipResource + "/" + groupName, actions3);
        myScopes.put(rootGroupMembershipResource + "/" + groupName, myResource3);
                
        Set<String> auds = new HashSet<>();
        auds.add("aud1"); // Simple test audience
        auds.add("aud2"); // OSCORE Group Manager (This audience expects scopes as Byte Strings)
        GroupOSCOREValidator valid = new GroupOSCOREValidator(auds, myScopes, rootGroupMembershipResource, groupCollectionResourcePath);
        
        // Include this audience in the list of audiences recognized as OSCORE Group Managers 
        valid.setGMAudiences(Collections.singleton("aud2"));
        
        // Include this resource as a group-membership resource for Group OSCORE.
        // The resource name is the name of the OSCORE group.
        valid.setGroupMembershipResources(Collections.singleton(rootGroupMembershipResource + "/" + groupName));
        
        
        // Create the OSCORE group
        final byte[] masterSecret = { (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
                					  (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08,
                					  (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C,
                					  (byte) 0x0D, (byte) 0x0E, (byte) 0x0F, (byte) 0x10 };

        final byte[] masterSalt =   { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22,
                					  (byte) 0x23, (byte) 0x78, (byte) 0x63, (byte) 0x40 };

        final AlgorithmID hkdf = AlgorithmID.HMAC_SHA_256;
        final int credFmt = Constants.COSE_HEADER_PARAM_KCCS;
        
        int mode = GroupcommParameters.GROUP_OSCORE_GROUP_MODE_ONLY;

        final AlgorithmID gpEncAlg = AlgorithmID.AES_CCM_16_64_128;
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
        
        // Prefix (4 byte) and Epoch (2 bytes)
        // All Group IDs have the same prefix size, but can have different Epoch sizes
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
    	

    	// Serialization of the authentication credential, according to the format used in the group
    	byte[] gmAuthenticationCredential = null;
    	
    	/*
    	// Build the authentication credential according to the format used in the group
    	// Note: most likely, the result will NOT follow the required deterministic
    	//       encoding in byte lexicographic order, and it has to be adjusted offline
    	switch (credFmt) {
        case Constants.COSE_HEADER_PARAM_KCCS:
            // A CCS including the public key
        	String subjectName = "";
            gmAuthenticationCredential = Util.oneKeyToCCS(gmKeyPair, subjectName);
            break;
        case Constants.COSE_HEADER_PARAM_KCWT:
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
	        case Constants.COSE_HEADER_PARAM_KCCS:
	            // A CCS including the public key
	        	if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
	        		gmAuthenticationCredential = Utils.hexToBytes("A2026008A101A50102032620012158202236658CA675BB62D7B24623DB0453A3B90533B7C3B221CC1C2C73C4E919D540225820770916BC4C97C3C46604F430B06170C7B3D6062633756628C31180FA3BB65A1B");
	        	}
	        	if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
	        		gmAuthenticationCredential = Utils.hexToBytes("A2026008A101A4010103272006215820C6EC665E817BD064340E7C24BB93A11E8EC0735CE48790F9C458F7FA340B8CA3");
	        	}
	            break;
	        case Constants.COSE_HEADER_PARAM_KCWT:
	            // A CWT including the public key
	            // TODO
	        	gmAuthenticationCredential = null;
	            break;
	        case Constants.COSE_HEADER_PARAM_X5CHAIN:
	            // A certificate including the public key
	            // TODO
	        	gmAuthenticationCredential = null;
	            break;
    	}
    	
    	GroupInfo myGroup = new GroupInfo(groupName,
						                  masterSecret,
						                  masterSalt,
						                  groupIdPrefixSize,
						                  groupIdPrefix,
						                  groupIdEpoch.length,
						                  Util.bytesToInt(groupIdEpoch),
						                  true,
						                  prefixMonitorNames,
						                  nodeNameSeparator,
						                  hkdf,
						                  credFmt,
						                  mode,
						                  gpEncAlg,
						                  signAlg,
						                  signParams,
						                  null,
						                  null,
						                  null,
    			                          null,
    			                          gmKeyPair,
    			                          gmAuthenticationCredential,
									      gmSigningKeyPairs,
									      gmSigningPublicAuthCred,
									      gmKeyAgreementKeyPairs,
									      gmKeyAgreementPublicAuthCred,
    			                          maxStaleIdsSets,
    			                          0);
        
    	// Add this OSCORE group to the set of existing OSCORE groups
    	existingGroups.put(groupName, myGroup);
        
        //Set up COSE parameters
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, 
                AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        ctx = CwtCryptoCtx.encrypt0(key128a, coseP.getAlg().AsCBOR());
        
        String rsId = "rs1";
        
        String tokenFile = TestConfig.testFilePath + "tokens.json";
        //Delete lingering token files
        new File(tokenFile).delete();
        
        //Set up the inner Authz-Info library
        ai = new AuthzInfoGroupOSCORE(Collections.singletonList("TestAS"), 
                new KissTime(), null, rsId, valid, ctx, null, 0, tokenFile, valid, false);
        
        // Provide the authz-info endpoint with the set of existing OSCORE groups
        ai.setExistingGroups(existingGroups);
        
        //Set up the DTLS authz-info resource
        dai = new CoapAuthzInfoGroupOSCORE(ai);
        
        // Tests on the audience "aud1" are just the same as in TestAuthzInfo,
        // while using the endpoint AuthzInfoGroupOSCORE as for audience "aud2".
        ai2 = new AuthzInfoGroupOSCORE(Collections.singletonList("TestAS"), 
                new KissTime(), null, rsId, valid, ctx, null, 0, tokenFile, valid, false);
        
        // Provide the authz-info endpoint with the set of existing OSCORE groups
        ai2.setExistingGroups(existingGroups);
        
        // A separate authz-info endpoint is required for each audience, here "aud2",
        // due to the interface of the IntrospectionHandler4Tests taking exactly
        // one RS as second argument.
        dai2 = new CoapAuthzInfoGroupOSCORE(ai2);
        
        //Set up a token to use
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));        
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x00}));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key = new OneKey();
        key.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        CBORObject kid = CBORObject.FromObject(new byte[] {0x01, 0x02}); 
        key.add(KeyKeys.KeyId, kid);
        key.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, key.AsCBOR());
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        payload = token.encode(ctx);
        
        //Set up a token to use, for joining an OSCORE group with a single role
        Map<Short, CBORObject> params2 = new HashMap<>();
    	CBORObject cborArrayScope = CBORObject.NewArray();
    	CBORObject cborArrayEntry = CBORObject.NewArray();
    	cborArrayEntry.Add(groupName);
    	
    	int myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
    	cborArrayEntry.Add(myRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        
        params2.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params2.put(Constants.AUD, CBORObject.FromObject("aud2"));
        params2.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x01}));
        params2.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key2 = new OneKey();
        key2.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        CBORObject kid2 = CBORObject.FromObject(new byte[] {0x03, 0x04}); 
        key2.add(KeyKeys.KeyId, kid2);
        key2.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cnf2 = CBORObject.NewMap();
        cnf2.Add(Constants.COSE_KEY_CBOR, key2.AsCBOR());
        params2.put(Constants.CNF, cnf2);
        CWT token2 = new CWT(params2);
        payload2 = token2.encode(ctx);
        
        //Set up a token to use, for joining an OSCORE group with multiple roles
        Map<Short, CBORObject> params3 = new HashMap<>();
    	cborArrayScope = CBORObject.NewArray();
    	cborArrayEntry = CBORObject.NewArray();
    	cborArrayEntry.Add(groupName);
    	
    	myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(myRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
        
        params3.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params3.put(Constants.AUD, CBORObject.FromObject("aud2"));        
        params3.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x03}));
        params3.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        OneKey key3 = new OneKey();
        key3.add(KeyKeys.KeyType, KeyKeys.KeyType_Octet);
        CBORObject kid3 = CBORObject.FromObject(new byte[] {0x05, 0x06}); 
        key3.add(KeyKeys.KeyId, kid3);
        key3.add(KeyKeys.Octet_K, CBORObject.FromObject(key128));
        CBORObject cnf3 = CBORObject.NewMap();
        cnf3.Add(Constants.COSE_KEY_CBOR, key3.AsCBOR());
        params3.put(Constants.CNF, cnf3);
        CWT token3 = new CWT(params3);
        payload3 = token3.encode(ctx);
        
        
        // Set up one more token to use, for testing the update of access rights
        Map<Short, CBORObject> params4 = new HashMap<>(); 
        params4.put(Constants.SCOPE, CBORObject.FromObject("rw_co2"));
        params4.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params4.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x04}));
        params4.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        CBORObject keyData  = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.KeyId.AsCBOR(), kid);
        CBORObject cnf4 = CBORObject.NewMap();
        cnf4.Add(Constants.COSE_KEY_CBOR, keyData); // The specified 'COSE_Key' includes only key type and kid
        params4.put(Constants.CNF, cnf4);
        CWT token4 = new CWT(params4);
        payload4 = token4.encode(ctx);
        
    }
    
    /**
     * Test a POST to /authz-info
     * @throws AceException 
     * @throws IntrospectionException 
     * @throws IOException 
     */
    @Test
    public void testPOSTtoken() throws AceException, IntrospectionException, IOException {
        Request req = new Request(Code.POST);
        req.setPayload(payload.EncodeToBytes());
        AddressEndpointContext destCtx = new AddressEndpointContext(
                new InetSocketAddress(InetAddress.getLocalHost(), CoAP.DEFAULT_COAP_PORT),
                new PreSharedKeyIdentity("psk"));
        req.setDestinationContext(destCtx);
        

        req.setType(Type.NON);
        req.setAcknowledged(false);
        AddressEndpointContext srcCtx = new AddressEndpointContext(
                new InetSocketAddress(InetAddress.getLocalHost(), CoAP.DEFAULT_COAP_PORT));
        req.setSourceContext(srcCtx);
        
        req.setToken(new byte[]{0x01});
        Exchange iex = new Exchange(req, null, Origin.REMOTE, new TestSynchroneExecutor());  
        CoapEndpoint cep = new Builder().build();
        cep.start();
        iex.setEndpoint(cep);
        CoapExchange ex = new CoapExchange(iex);
        dai.handlePOST(ex);
      
        byte[] kidBytes = new byte[]{0x01, 0x02};
        String kid = Base64.getEncoder().encodeToString(kidBytes);
        
        
        //Test that the PoP key was stored
        Assert.assertNotNull(TokenRepository.getInstance().getKey(kid));
        Assert.assertArrayEquals(key128,
        						 TokenRepository.getInstance().getKey(kid).get(KeyKeys.Octet_K).GetByteString());

       //Test that the token is there
        Assert.assertEquals(TokenRepository.OK,
        					TokenRepository.getInstance().canAccess(kid, kid, "temp", Constants.GET, null));
    }
    
    
    /**
     * Test a POST to /authz-info, followed by an attempt to update
     * access rights by posting a new Access Token over DTLS
     * 
     * @throws AceException 
     * @throws IntrospectionException 
     * @throws IOException 
     */
    @Test
    public void testPOSTtokenUpdateAccessRights() 
            throws AceException, IntrospectionException, IOException {
        Request req = new Request(Code.POST);
        req.setPayload(payload.EncodeToBytes());
        AddressEndpointContext destCtx = new AddressEndpointContext(
                new InetSocketAddress(InetAddress.getLocalHost(), CoAP.DEFAULT_COAP_PORT),
                new PreSharedKeyIdentity("psk"));
        req.setDestinationContext(destCtx);
        

        req.setType(Type.NON);
        req.setAcknowledged(false);
        AddressEndpointContext srcCtx = new AddressEndpointContext(
                new InetSocketAddress(InetAddress.getLocalHost(), CoAP.DEFAULT_COAP_PORT));
        req.setSourceContext(srcCtx);
        
        req.setToken(new byte[]{0x02});
        Exchange iex = new Exchange(req, null, Origin.REMOTE, new TestSynchroneExecutor());
        CoapEndpoint cep = new Builder().build();
        cep.start();
        iex.setEndpoint(cep);
        CoapExchange ex = new CoapExchange(iex);
        dai.handlePOST(ex);
      
        byte[] kidBytes = new byte[]{0x01, 0x02};
        String kid = Base64.getEncoder().encodeToString(kidBytes);
        
        
        //Test that the token is there and that responses are as expected
        Assert.assertNotNull(TokenRepository.getInstance().getKey(kid));
        Assert.assertArrayEquals(key128,
                TokenRepository.getInstance().getKey(kid).get(KeyKeys.Octet_K).GetByteString());

        Assert.assertEquals(TokenRepository.OK, 
                TokenRepository.getInstance().canAccess(kid, null, "temp", Constants.GET, null));
        
        Assert.assertEquals(TokenRepository.METHODNA,
                TokenRepository.getInstance().canAccess(kid, null, "temp", Constants.POST, null));
        
        Assert.assertEquals(TokenRepository.FORBID,
                TokenRepository.getInstance().canAccess(kid, null, "co2", Constants.POST, null));
        
        
        // Build a new Token for updating access rights, with a different 'scope'
        
        // Posting the Token through an unprotected request.
        // This fails since such a Token needs to include the
        // a 'cnf' claim transporting also the actual key 'k'
        LocalMessage req2 = new LocalMessage(0, null, null, payload4);
        req2 = new LocalMessage(0, null, null, payload4);
        LocalMessage resp2 = (LocalMessage)ai.processMessage(req2);
        assert(resp2.getMessageCode() == Message.FAIL_BAD_REQUEST);
          
  	    req2 = new LocalMessage(0, kid, null, payload4);
  	    resp2 = (LocalMessage)ai.processMessage(req2);
  	    assert(resp2.getMessageCode() == Message.CREATED);
  	  
        // Test that the new token is there, and both GET and POST
        // are consistently authorized on the "co2" resource
        //
        // The 'kid' has not changed, since the same PoP key
        // with the same 'kid' is bound also to the new token
  	    
  	    
        Assert.assertEquals(TokenRepository.OK, 
                TokenRepository.getInstance().canAccess(kid, kid, "co2", Constants.GET, null));
        
        Assert.assertEquals(TokenRepository.OK, 
                TokenRepository.getInstance().canAccess(kid, kid, "co2", Constants.POST, null));
		
        Assert.assertEquals(TokenRepository.METHODNA, 
                TokenRepository.getInstance().canAccess(kid, kid, "co2", Constants.DELETE, null));
        
        // ... and that access to the "temp" resource is not allowed anymore
        Assert.assertEquals(TokenRepository.FORBID, 
                TokenRepository.getInstance().canAccess(kid, kid, "temp", Constants.GET, null));
        
    }

    
    /**
     * Test a POST to /authz-info for accessing
     * an OSCORE group with a single role
     * @throws AceException 
     * @throws IntrospectionException 
     * @throws IOException 
     */
    @Test
    public void testPOSTtokenGroupOSCORESingleRole() 
            throws AceException, IntrospectionException, IOException {
        Request req = new Request(Code.POST);
        req.setPayload(payload2.EncodeToBytes());
        AddressEndpointContext destCtx = new AddressEndpointContext(new InetSocketAddress(
                InetAddress.getLocalHost(), CoAP.DEFAULT_COAP_PORT), new PreSharedKeyIdentity("psk"));
        req.setDestinationContext(destCtx);
        

        req.setType(Type.NON);
        req.setAcknowledged(false);
        AddressEndpointContext srcCtx = new AddressEndpointContext(
                new InetSocketAddress(InetAddress.getLocalHost(), CoAP.DEFAULT_COAP_PORT));
        req.setSourceContext(srcCtx);
        
        req.setToken(new byte[]{0x03});
        Exchange iex = new Exchange(req, null, Origin.REMOTE, new TestSynchroneExecutor());
        CoapEndpoint cep = new Builder().build();
        cep.start();
        iex.setEndpoint(cep);
        CoapExchange ex = new CoapExchange(iex);
        dai2.handlePOST(ex);
      
        byte[] kidBytes = new byte[]{0x03, 0x04};
        String kid = Base64.getEncoder().encodeToString(kidBytes);
        
        
        //Test that the PoP key was stored
        Assert.assertNotNull(TokenRepository.getInstance().getKey(kid));
        Assert.assertArrayEquals(key128,
                TokenRepository.getInstance().getKey(kid).get(KeyKeys.Octet_K).GetByteString());
               
        // Test that the token is there
        String groupName = "feedca570000";
        Assert.assertEquals(TokenRepository.OK, 
               TokenRepository.getInstance().canAccess(
                       kid, kid, rootGroupMembershipResource + "/" + groupName, Constants.POST, null));
    }
    
    /**
     * Test a POST to /authz-info for accessing
     * an OSCORE group with multiple roles
     * @throws AceException 
     * @throws IntrospectionException 
     * @throws IOException 
     */
    @Test
    public void testPOSTtokenGroupOSCOREMultipleRoles() 
            throws AceException, IntrospectionException, IOException {
        Request req = new Request(Code.POST);
        req.setPayload(payload3.EncodeToBytes());
        AddressEndpointContext destCtx = new AddressEndpointContext(
                new InetSocketAddress(InetAddress.getLocalHost(), CoAP.DEFAULT_COAP_PORT),
                new PreSharedKeyIdentity("psk"));
        req.setDestinationContext(destCtx);
        

        req.setType(Type.NON);
        req.setAcknowledged(false);
        AddressEndpointContext srcCtx = new AddressEndpointContext(
                new InetSocketAddress(InetAddress.getLocalHost(), CoAP.DEFAULT_COAP_PORT));
        req.setSourceContext(srcCtx);
        
        req.setToken(new byte[]{0x04});
        Exchange iex = new Exchange(req, null, Origin.REMOTE, new TestSynchroneExecutor());
        CoapEndpoint cep = new Builder().build();
        cep.start();
        iex.setEndpoint(cep);
        CoapExchange ex = new CoapExchange(iex);
        dai2.handlePOST(ex);
      
        byte[] kidBytes = new byte[]{0x05, 0x06};
        String kid = Base64.getEncoder().encodeToString(kidBytes);
        
        
        //Test that the PoP key was stored
        Assert.assertNotNull(TokenRepository.getInstance().getKey(kid));
        Assert.assertArrayEquals(key128,
                TokenRepository.getInstance().getKey(kid).get(KeyKeys.Octet_K).GetByteString());
               
        //Test that the token is there
        String groupName = "feedca570000";
        Assert.assertEquals(TokenRepository.OK, 
                TokenRepository.getInstance().canAccess(kid, kid, rootGroupMembershipResource + "/" +
                										groupName, Constants.POST, null));
    }
    
    /**
     * Deletes the test file after the tests
     * @throws AceException 
     */
    @AfterClass
    public static void tearDown() throws AceException {
        ai.close();
        ai2.close();
        new File(TestConfig.testFilePath + "tokens.json").delete();
    }
    
    /**
     * Synchronous Executor.
     * 
     * Executes command synchronous to simplify unit tests.
     * 
     * @since 3.0 (replaces SyncSerialExecutor)
     */
    private class TestSynchroneExecutor implements Executor {
        /**
         * Synchronous executor.
         * 
         * For unit tests.
         */
        private TestSynchroneExecutor() {
        }

        /**
         * Execute the job synchronous.
         */
        @Override
        public void execute(final Runnable command) {
            command.run();
        }
    }
    
    private static void setGroupManagerKeyPairs() {
    	
    	gmSigningPublicAuthCred.put(Constants.COSE_HEADER_PARAM_KCCS, new HashMap<CBORObject, String>());
    	gmKeyAgreementPublicAuthCred.put(Constants.COSE_HEADER_PARAM_KCCS, new HashMap<CBORObject, String>());
    	
    	// Set the key signing key pairs
    	
    	// Key pair for ECDSA with curve P-256
    	String keySigningKeyPairP256 = "a60102032620012158202236658ca675bb62d7b24623db0453a3b90533b7c3b221cc1c2c73c4e919d540225820770916bc4c97c3c46604f430b06170c7b3d6062633756628c31180fa3bb65a1b2358204a7b844a4c97ef91ed232aa564c9d5d373f2099647f9e9bd3fe6417a0d0f91ad";
    	gmSigningKeyPairs.put(org.eclipse.californium.cose.KeyKeys.EC2_P256, keySigningKeyPairP256);
    	
    	// Authentication credential for ECDSA with curve P-256, as a CCS
    	String keySigningAuthCredP256CCS = "a2026008a101a50102032620012158202236658ca675bb62d7b24623db0453a3b90533b7c3b221cc1c2c73c4e919d540225820770916bc4c97c3c46604f430b06170c7b3d6062633756628c31180fa3bb65a1b";    	
    	gmSigningPublicAuthCred.get(Constants.COSE_HEADER_PARAM_KCCS).put(org.eclipse.californium.cose.KeyKeys.EC2_P256, keySigningAuthCredP256CCS);

    	
    	// Key pair for EdDSA with curve Ed25519
    	String keySigningKeyPairEd25519 = "a5010103272006215820c6ec665e817bd064340e7c24bb93a11e8ec0735ce48790f9c458f7fa340b8ca3235820d0a2ce11b2ba614b048903b72638ef4a3b0af56e1a60c6fb6706b0c1ad8a14fb";
    	gmSigningKeyPairs.put(org.eclipse.californium.cose.KeyKeys.OKP_Ed25519, keySigningKeyPairEd25519);
    	
    	// Authentication credential for EdDSA with curve Ed25519, as a CCS
    	String keySigningAuthCredEd25519CCS = "a2026008a101a4010103272006215820c6ec665e817bd064340e7c24bb93a11e8ec0735ce48790f9c458f7fa340b8ca3";
    	gmSigningPublicAuthCred.get(Constants.COSE_HEADER_PARAM_KCCS).put(org.eclipse.californium.cose.KeyKeys.OKP_Ed25519, keySigningAuthCredEd25519CCS);
    	
    	
    	// Set the key agreement key pairs
    	
    	// Key pair for ECDSA with curve P-256
    	String keyAgreementKeyPairP256 = "a6010203262001215820b95e2727b98d6f6f98852e2b360c4e6872c3a8070192d4f810e051572657775522582060aca41e3b065853f836dac69617efd69bad45f29bb7f4335ef93961941f79c5235820b77698f83f3f5a6473eba56125fd0ed2501ac7028d1f906abfa0a6080ef7936a";
    	gmKeyAgreementKeyPairs.put(org.eclipse.californium.cose.KeyKeys.EC2_P256, keyAgreementKeyPairP256);
    	
    	// Authentication credential for ECDSA with curve P-256, as a CCS
    	String keyAgreementAuthCredP256CCS = "a2026008a101a5010203262001215820b95e2727b98d6f6f98852e2b360c4e6872c3a8070192d4f810e051572657775522582060aca41e3b065853f836dac69617efd69bad45f29bb7f4335ef93961941f79c5";
    	gmKeyAgreementPublicAuthCred.get(Constants.COSE_HEADER_PARAM_KCCS).put(org.eclipse.californium.cose.KeyKeys.EC2_P256, keyAgreementAuthCredP256CCS);
    	
    	// Key pair with curve X25519
    	// TODO - This is just a placeholder with a non valid private coordinate. Replace with a valid key pair using X25519
    	String keyAgreementKeyPairX25519 = "a5010103381A2004215820c6ec665e817bd064340e7c24bb93a11e8ec0735ce48790f9c458f7fa340b8ca3235820d0a2ce11b2ba614b048903b72638ef4a3b0af56e1a60c6fb6706b0c1ad8a14fb";
    	gmKeyAgreementKeyPairs.put(org.eclipse.californium.cose.KeyKeys.OKP_X25519, keyAgreementKeyPairX25519);
    	
    	// Authentication credential with curve X25519, as a CCS
    	// TODO - This is just a placeholder. Replace with an authentication credential corresponding to a valid key pair using X25519 (see above)
    	String keyAgreementAuthCredX25519 = "a2026008a101a4010103381a2004215820c6ec665e817bd064340e7c24bb93a11e8ec0735ce48790f9c458f7fa340b8ca3";
    	gmKeyAgreementPublicAuthCred.get(Constants.COSE_HEADER_PARAM_KCCS).put(org.eclipse.californium.cose.KeyKeys.OKP_X25519, keyAgreementAuthCredX25519);
    	
    }
    
}
