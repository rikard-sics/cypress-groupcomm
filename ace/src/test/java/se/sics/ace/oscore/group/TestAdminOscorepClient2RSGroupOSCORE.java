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

import java.net.InetSocketAddress;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import org.eclipse.californium.oscore.OSException;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.MessageTag;
import org.eclipse.californium.cose.OneKey;
import net.i2p.crypto.eddsa.Utils;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.GroupcommErrors;
import se.sics.ace.GroupcommParameters;
import se.sics.ace.GroupcommPolicies;
import se.sics.ace.Util;
import se.sics.ace.coap.client.OSCOREProfileRequests;
import se.sics.ace.coap.client.OSCOREProfileRequestsGroupOSCORE;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.oscore.GroupOSCOREInputMaterialObjectParameters;
import se.sics.ace.oscore.OSCOREInputMaterialObjectParameters;

/**
 * A test case for the OSCORE profile interactions between
 * a Group OSCORE Administrator acting as ACE Client and
 * an OSCORE Group Manager acting as ACE Resource Server.
 * 
 * @author Marco Tiloca
 *
 */
public class TestAdminOscorepClient2RSGroupOSCORE {
	
	private final String groupCollectionResourcePath = "manage";
	
	private final String rootGroupMembershipResource = "ace-group";

	// Sets the port of the RS
	private final static int PORT = 5685;
	
    private final static int MAX_UNFRAGMENTED_SIZE = 4096;
    
    private static byte[] groupKeyPair;
	private static byte[] publicKeyGM;
    
    /**
     * The cnf key used in these tests, when the ACE Client is the group Administrator 
     */
    private static byte[] keyCnfAdmin = {'a', 'b', 'c', 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    
    /**
     * The cnf key used in these tests, when the ACE Client is a group member
     */
    private static byte[] keyCnfGroupMember = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    /**
     * The AS <-> RS key used in these tests
     */
    private static byte[] keyASRS = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static RunTestServer srv = null;
    private static OSCoreCtx osctx;
    
    private static OSCoreCtxDB ctxDB;
    
    // Uncomment to set ECDSA with curve P-256 for countersignatures
    // private static int signKeyCurve = KeyKeys.EC2_P256.AsInt32();
    
    // Uncomment to set EDDSA with curve Ed25519 for countersignatures
    private static int signKeyCurve = KeyKeys.OKP_Ed25519.AsInt32();
    
    // Uncomment to set curve P-256 for pairwise key derivation
    // private static int ecdhKeyCurve = KeyKeys.EC2_P256.AsInt32();
    
    // Uncomment to set curve X25519 for pairwise key derivation
    private static int ecdhKeyCurve = KeyKeys.OKP_X25519.AsInt32();
    
	// Each set of the list refers to a different size of Recipient IDs.
	// The element with index 0 includes as elements Recipient IDs with size 1 byte.
	private static List<Set<Integer>> usedRecipientIds = new ArrayList<Set<Integer>>();
    
    private static class RunTestServer implements Runnable {
        
        public RunTestServer() {
           //Do nothing
        }

        /**
         * Stop the server
         * @throws Exception 
         */
        public void stop() throws Exception {
            TestAdminOscorepRSGroupOSCORE.stop();
        }
        
        @Override
        public void run() {
            try {
            	TestAdminOscorepRSGroupOSCORE.main(null);
            } catch (final Throwable t) {
                System.err.println(t.getMessage());
                try {
                	TestAdminOscorepRSGroupOSCORE.stop();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        
    }
    
    /**
     * This sets up everything for the tests including the server
     * @throws OSException 
     */
    @BeforeClass
    public static void setUp() throws OSException {    	
        srv = new RunTestServer();
        srv.run();
        
        //Initialize a fake context
        osctx = new OSCoreCtx(keyCnfAdmin, true, null, 
                "clientA".getBytes(Constants.charset),
                "rs1".getBytes(Constants.charset),
                null, null, null, null, MAX_UNFRAGMENTED_SIZE);
    	
		// ECDSA asymmetric keys, as serialization of COSE Keys
    	if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
    		
    	    // Private and public key to be used in the OSCORE group (ECDSA_256)
    	    groupKeyPair = Utils.hexToBytes("a6010203262001215820e8f9a8d5850a533cda24b9fa8a1ee293f6a0e1e81e1e560a64ff134d65f7ecec225820164a6d5d4b97f56d1f60a12811d55de7a055ebac6164c9ef9302cbcbff1f0abe2358203be0047599b42aa44b8f8a0fa88d4da11697b58d9fcc4e39443e9843bf230586");
    	    
    	    // Public key of the Group Manager (ECDSA_256)
    	    publicKeyGM = Utils.hexToBytes("a50102032620012158202236658ca675bb62d7b24623db0453a3b90533b7c3b221cc1c2c73c4e919d540225820770916bc4c97c3c46604f430b06170c7b3d6062633756628c31180fa3bb65a1b");
    	}

    	// EDDSA asymmetric keys, as serialization of COSE Keys
    	if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
    		
    	    // Private and public key to be used in the OSCORE group (EDDSA - Ed25519)
    	    groupKeyPair = Utils.hexToBytes("a5010103272006215820069e912b83963acc5941b63546867dec106e5b9051f2ee14f3bc5cc961acd43a23582064714d41a240b61d8d823502717ab088c9f4af6fc9844553e4ad4c42cc735239");
    	    
    	    // Public key of the Group Manager (EDDSA - Ed25519)
    	    publicKeyGM = Utils.hexToBytes("a4010103272006215820c6ec665e817bd064340e7c24bb93a11e8ec0735ce48790f9c458f7fa340b8ca3");
    	    
    	}
        
        ctxDB = new org.eclipse.californium.oscore.HashMapCtxDB();
        
    	for (int i = 0; i < 4; i++) {
        	// Empty sets of assigned Sender IDs; one set for each possible Sender ID size in bytes.
        	// The set with index 0 refers to Sender IDs with size 1 byte
    		usedRecipientIds.add(new HashSet<Integer>());
    		
    	}
    }
    
    /**
     * Deletes the test DB after the tests
     * @throws Exception 
     */
    @AfterClass
    public static void tearDown() throws Exception {
        srv.stop();
    }
    
    /**
     * Test successful submission of a token to the RS with subsequent
     * access based on the token
     * 
     * @throws Exception 
     */
    @Test
    public void testSuccess() throws Exception {

        //Generate a token
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx  = CwtCryptoCtx.encrypt0(keyASRS, coseP.getAlg().AsCBOR());
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("r_helloWorld"));
        params.put(Constants.AUD, CBORObject.FromObject("aud1"));
        params.put(Constants.CTI, CBORObject.FromObject("token2".getBytes(Constants.charset)));
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

        CBORObject osc = CBORObject.NewMap();
        osc.Add(Constants.OS_MS, keyCnfAdmin);
        osc.Add(Constants.OS_ID, Util.intToBytes(3));
        
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.OSCORE_Input_Material, osc);
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx).EncodeToBytes());
        payload.Add(Constants.CNF, cnf);
        Response asRes = new Response(CoAP.ResponseCode.CREATED);
        asRes.setPayload(payload.EncodeToBytes());
        Response rsRes = OSCOREProfileRequests.postToken(
                "coap://localhost:" + PORT + "/authz-info", asRes, ctxDB, usedRecipientIds);
        
        assert(rsRes.getCode().equals(CoAP.ResponseCode.CREATED));
        
        //Check that the OSCORE context has been created:
        Assert.assertNotNull(ctxDB.getContext("coap://localhost:" + PORT + "/helloWorld"));
       
       //Submit a request

       CoapClient c = OSCOREProfileRequestsGroupOSCORE.getClient(new InetSocketAddress(
               "coap://localhost:" + PORT + "/helloWorld", PORT), ctxDB);
       
       Request helloReq = new Request(CoAP.Code.GET);
       helloReq.getOptions().setOscore(new byte[0]);
       CoapResponse helloRes = c.advanced(helloReq);
       Assert.assertEquals("Hello World!", helloRes.getResponseText());
       
       //Submit a forbidden request
       
       CoapClient c2 = OSCOREProfileRequestsGroupOSCORE.getClient(new InetSocketAddress(
    		   "coap://localhost:" + PORT + "/temp", PORT), ctxDB);
       
       Request getTemp = new Request(CoAP.Code.GET);
       getTemp.getOptions().setOscore(new byte[0]);
       CoapResponse getTempRes = c2.advanced(getTemp);
       assert(getTempRes.getCode().equals(CoAP.ResponseCode.FORBIDDEN));
       
       //Submit a request with unallowed method
       Request deleteHello = new Request(CoAP.Code.DELETE);
       deleteHello.getOptions().setOscore(new byte[0]);
       CoapResponse deleteHelloRes = c.advanced(deleteHello);
       assert(deleteHelloRes.getCode().equals(CoAP.ResponseCode.METHOD_NOT_ALLOWED));
       
    }
    

    /**
     * Test admin operations at the OSCORE Group Manager
     * Uses the ACE OSCORE Profile.
     * 
     * @throws Exception 
     */
    @Test
	@Ignore
    public void testAdminOperations() throws Exception {
            	
        //Generate a token
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(keyASRS, coseP.getAlg().AsCBOR());
        Map<Short, CBORObject> params = new HashMap<>(); 
        
        //Create the scope
        String groupNamePattern = null;
        int myPermissions;
        CBORObject cborArrayEntry;
        CBORObject cborArrayScope = CBORObject.NewArray();
        
        cborArrayEntry = CBORObject.NewArray();
        groupNamePattern = new String("gp500");
    	myPermissions = 0;
    	myPermissions = Util.addGroupOSCOREAdminPermission(myPermissions, GroupcommParameters.GROUP_OSCORE_ADMIN_LIST);
    	myPermissions = Util.addGroupOSCOREAdminPermission(myPermissions, GroupcommParameters.GROUP_OSCORE_ADMIN_CREATE);
    	myPermissions = Util.addGroupOSCOREAdminPermission(myPermissions, GroupcommParameters.GROUP_OSCORE_ADMIN_READ);
    	myPermissions = Util.addGroupOSCOREAdminPermission(myPermissions, GroupcommParameters.GROUP_OSCORE_ADMIN_WRITE);
    	myPermissions = Util.addGroupOSCOREAdminPermission(myPermissions, GroupcommParameters.GROUP_OSCORE_ADMIN_DELETE);
        cborArrayEntry.Add(groupNamePattern);
    	cborArrayEntry.Add(myPermissions);
    	cborArrayScope.Add(cborArrayEntry);
    	
    	cborArrayEntry = CBORObject.NewArray();
        groupNamePattern = new String("gp1");
        cborArrayEntry.Add(groupNamePattern);
    	cborArrayEntry.Add(myPermissions);
    	cborArrayScope.Add(cborArrayEntry);
    	
    	cborArrayEntry = CBORObject.NewArray();
        groupNamePattern = new String("gp600");
        cborArrayEntry.Add(groupNamePattern);
    	cborArrayEntry.Add(myPermissions);
    	cborArrayScope.Add(cborArrayEntry);
    	    	
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject("aud2"));
        params.put(Constants.CTI, CBORObject.FromObject(
                "token4Admin".getBytes(Constants.charset))); //Need different CTI
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

        CBORObject osc = CBORObject.NewMap();
        osc.Add(Constants.OS_MS, keyCnfAdmin);
        osc.Add(Constants.OS_ID, Util.intToBytes(4));
        
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.OSCORE_Input_Material, osc);
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx).EncodeToBytes());
        payload.Add(Constants.CNF, cnf);
        Response asRes = new Response(CoAP.ResponseCode.CREATED);
        asRes.setPayload(payload.EncodeToBytes());
        Response rsRes = OSCOREProfileRequests.postToken(
        		"coap://localhost:" + PORT + "/authz-info", asRes, ctxDB, usedRecipientIds);
        assert(rsRes.getCode().equals(CoAP.ResponseCode.CREATED));
        
        //Check that the OSCORE context has been created:
        Assert.assertNotNull(ctxDB.getContext("coap://localhost:" + PORT + "/helloWorld"));

        
        CoapClient c = null;
        Request adminReq = null;
        CoapResponse adminRes = null;
        CBORObject requestPayloadCbor = null;
        CBORObject responsePayloadCbor = null;
        
        // ============================================
        
        // Send a GET request to /manage

        System.out.println();
        c = OSCOREProfileRequests.getClient(
        		new InetSocketAddress("coap://localhost:" + PORT + "/" + groupCollectionResourcePath, PORT), ctxDB);
        
        adminReq = new Request(CoAP.Code.GET);
        adminReq.getOptions().setOscore(new byte[0]);
        
        adminRes = c.advanced(adminReq);
        
        Assert.assertEquals(ResponseCode.CONTENT, adminRes.getCode());
        System.out.println("Response code: " + adminRes.advanced().getCode());
        if (adminRes.getOptions().hasContentFormat()) {
        	System.out.println("Response Content-Format: " + adminRes.getOptions().getContentFormat());
        }
        System.out.println("Response payload:\n" + new String(adminRes.getPayload()));
        
        // ============================================
        
        // Send a FETCH request to /manage
        
        System.out.println();
        c = OSCOREProfileRequests.getClient(
        		new InetSocketAddress("coap://localhost:" + PORT + "/" + groupCollectionResourcePath, PORT), ctxDB);
        
        adminReq = new Request(CoAP.Code.FETCH);
        adminReq.getOptions().setOscore(new byte[0]);
        adminReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        requestPayloadCbor = CBORObject.NewMap();
        requestPayloadCbor.Add(GroupcommParameters.GROUP_NAME, "gp500");
        adminReq.setPayload(requestPayloadCbor.EncodeToBytes());
        
        adminRes = c.advanced(adminReq);
        
        Assert.assertEquals(ResponseCode.CONTENT, adminRes.getCode());
        System.out.println("Response code: " + adminRes.advanced().getCode());
        if (adminRes.getOptions().hasContentFormat()) {
        	System.out.println("Response Content-Format: " + adminRes.getOptions().getContentFormat());
        }
        System.out.println("Response payload:\n" + new String(adminRes.getPayload()));
        
        // ============================================
        
        // Send a POST request to /manage

        System.out.println();
        c = OSCOREProfileRequests.getClient(
        		new InetSocketAddress("coap://localhost:" + PORT + "/" + groupCollectionResourcePath, PORT), ctxDB);
        
        adminReq = new Request(CoAP.Code.POST);
        adminReq.getOptions().setOscore(new byte[0]);
        adminReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        requestPayloadCbor = CBORObject.NewMap();
        requestPayloadCbor.Add(GroupcommParameters.GROUP_NAME, CBORObject.FromObject("gp1"));
        requestPayloadCbor.Add(GroupcommParameters.ACTIVE, CBORObject.True);
        adminReq.setPayload(requestPayloadCbor.EncodeToBytes());
        
        adminRes = c.advanced(adminReq);
        
        Assert.assertNotNull(adminRes);
        Assert.assertEquals(ResponseCode.CREATED, adminRes.getCode());
        Assert.assertNotNull(adminRes.getPayload());
        
        responsePayloadCbor = CBORObject.DecodeFromBytes(adminRes.getPayload());
        Assert.assertNotNull(responsePayloadCbor);
        
        Assert.assertEquals(CBORType.Map, responsePayloadCbor.getType());
        System.out.println("Response code: " + adminRes.advanced().getCode());
        if (adminRes.getOptions().hasContentFormat()) {
        	System.out.println("Response Content-Format: " + adminRes.getOptions().getContentFormat());
        }
        System.out.println("Response payload:");
        Util.prettyPrintCborMap(responsePayloadCbor);
        Assert.assertEquals(3, responsePayloadCbor.size());

        // ============================================
        
        // Send a GET request to /manage/gp1

        c = OSCOREProfileRequests.getClient(
        		new InetSocketAddress("coap://localhost:" + PORT + "/" + groupCollectionResourcePath + "/" + "gp1", PORT), ctxDB);
        
        adminReq = new Request(CoAP.Code.GET);
        adminReq.getOptions().setOscore(new byte[0]);
        
        adminRes = c.advanced(adminReq);
        
        Assert.assertNotNull(adminRes);
        Assert.assertEquals(ResponseCode.CONTENT, adminRes.getCode());
        Assert.assertNotNull(adminRes.getPayload());
        
        responsePayloadCbor = CBORObject.DecodeFromBytes(adminRes.getPayload());
        Assert.assertNotNull(responsePayloadCbor);
        
        Assert.assertEquals(CBORType.Map, responsePayloadCbor.getType());
        System.out.println("Response code: " + adminRes.advanced().getCode());
        if (adminRes.getOptions().hasContentFormat()) {
        	System.out.println("Response Content-Format: " + adminRes.getOptions().getContentFormat());
        }
        System.out.println("Response payload:");
        Util.prettyPrintCborMap(responsePayloadCbor);
        Assert.assertEquals(23, responsePayloadCbor.size());
        
        // ============================================
        
        // Send a FETCH request to /manage/gp1

        c = OSCOREProfileRequests.getClient(
        		new InetSocketAddress("coap://localhost:" + PORT + "/" + groupCollectionResourcePath + "/" + "gp1", PORT), ctxDB);
        
        adminReq = new Request(CoAP.Code.FETCH);
        adminReq.getOptions().setOscore(new byte[0]);
        adminReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        requestPayloadCbor = CBORObject.NewMap();
        CBORObject confFilter = CBORObject.NewArray();
        confFilter.Add(GroupcommParameters.GROUP_NAME);
        confFilter.Add(GroupcommParameters.HKDF);
        confFilter.Add(GroupcommParameters.PAIRWISE_MODE);
        confFilter.Add(GroupcommParameters.DET_HASH_ALG);
        requestPayloadCbor.Add(GroupcommParameters.CONF_FILTER, confFilter);
        adminReq.setPayload(requestPayloadCbor.EncodeToBytes());
        
        adminRes = c.advanced(adminReq);
        
        Assert.assertNotNull(adminRes);
        Assert.assertEquals(ResponseCode.CONTENT, adminRes.getCode());
        Assert.assertNotNull(adminRes.getPayload());
        
        responsePayloadCbor = CBORObject.DecodeFromBytes(adminRes.getPayload());
        Assert.assertNotNull(responsePayloadCbor);
        
        Assert.assertEquals(CBORType.Map, responsePayloadCbor.getType());
        System.out.println("Response code: " + adminRes.advanced().getCode());
        if (adminRes.getOptions().hasContentFormat()) {
        	System.out.println("Response Content-Format: " + adminRes.getOptions().getContentFormat());
        }
        System.out.println("Response payload:");
        Util.prettyPrintCborMap(responsePayloadCbor);
        Assert.assertEquals(3, responsePayloadCbor.size());
        
        // ============================================
        
        // Send a GET request to /manage
        
        c = OSCOREProfileRequests.getClient(
        		new InetSocketAddress("coap://localhost:" + PORT + "/" + groupCollectionResourcePath, PORT), ctxDB);
        
        adminReq = new Request(CoAP.Code.GET);
        adminReq.getOptions().setOscore(new byte[0]);
        
        adminRes = c.advanced(adminReq);
        
        Assert.assertEquals(ResponseCode.CONTENT, adminRes.getCode());
        System.out.println("Response code: " + adminRes.advanced().getCode());
        if (adminRes.getOptions().hasContentFormat()) {
        	System.out.println("Response Content-Format: " + adminRes.getOptions().getContentFormat());
        }
        System.out.println("Response payload:\n" + new String(adminRes.getPayload()));
        
        // ============================================
        
        // Let a Client join the group as a new member
        
    	boolean askForSignInfo = true;
    	boolean askForEcdhInfo = true;
        boolean askForAuthCreds = true;
        boolean provideAuthCred = true;
        
        String groupName = new String("gp1");
        
        System.out.println("");
        
        // Generate a token
        COSEparams coseParamsGroupMember = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctxGroupMember = CwtCryptoCtx.encrypt0(keyASRS, coseParamsGroupMember.getAlg().AsCBOR());
        Map<Short, CBORObject> paramsGroupMember = new HashMap<>();
        
        
        // Create the scope
        
        // Create the user scope entry for joining the group
        
        CBORObject cborArrayScopeGroupMember = CBORObject.NewArray();
        CBORObject cborArrayEntryGroupMember = CBORObject.NewArray();
        String groupNameGroupMember = new String(groupName);
        cborArrayEntryGroupMember.Add(groupNameGroupMember);
        int myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_RESPONDER);
    	cborArrayEntryGroupMember.Add(myRoles);
        cborArrayScopeGroupMember.Add(cborArrayEntryGroupMember);
        
        // Create also admin scope entries - This is required for allowing this Test Unit
        // to continue with further admin operations after the group joining.
        //
        // The reason is that the OSCORE Security Context CTX established when posting this
        // access token will replace the previous OSCORE Security Context established by the
        // Administrator client in the Context Database.
        //
        // In turn, this is because the Context Database uses as lookup keys only the authority component
        // of the URI of the target server, but not other information such as a URI Path segment.
        //
        // As a consequence, any further request sent by the original Administrator would be protected
        // with CTX (i.e., not with the OSCORE Security Context originally established by the Administrator).
        // In turn, CTX will point the Group Manager to the latest access token posted by the joining node,
        // which has to include an admin scope entry allowing to perform the requested admin operations.
        //
        // As a workaround, this access token in fact includes admin entries that thus allow this Test Unit
        // to continue with further admin operations after the group joining, protecting those messages with
        // the latest established OSCORE Security Context CTX.
        
        cborArrayEntryGroupMember = CBORObject.NewArray();
        groupNamePattern = new String("gp500");
        cborArrayEntryGroupMember.Add(groupNamePattern);
        cborArrayEntryGroupMember.Add(myPermissions); // Same permissions as for the previous Administrator
        cborArrayScopeGroupMember.Add(cborArrayEntryGroupMember);
        
        cborArrayEntryGroupMember = CBORObject.NewArray();
        groupNamePattern = new String("gp1");
        cborArrayEntryGroupMember.Add(groupNamePattern);
        cborArrayEntryGroupMember.Add(myPermissions); // Same permissions as for the previous Administrator
    	cborArrayScopeGroupMember.Add(cborArrayEntryGroupMember);
    	
        cborArrayEntryGroupMember = CBORObject.NewArray();
        groupNamePattern = new String("gp600");
        cborArrayEntryGroupMember.Add(groupNamePattern);
        cborArrayEntryGroupMember.Add(myPermissions); // Same permissions as for the previous Administrator
    	cborArrayScopeGroupMember.Add(cborArrayEntryGroupMember);
        
        
    	byte[] byteStringScopeGroupMember = cborArrayScopeGroupMember.EncodeToBytes();
    	
        paramsGroupMember.put(Constants.SCOPE, CBORObject.FromObject(byteStringScopeGroupMember));
        paramsGroupMember.put(Constants.AUD, CBORObject.FromObject("aud2"));
        paramsGroupMember.put(Constants.CTI, CBORObject.FromObject(
                    "token4JoinAfterCreationMultipleRole".getBytes(Constants.charset))); //Need different CTI
        paramsGroupMember.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        
        CBORObject oscGroupMember = CBORObject.NewMap();
        oscGroupMember.Add(Constants.OS_MS, keyCnfGroupMember);
        oscGroupMember.Add(Constants.OS_ID, Util.intToBytes(4));        
        CBORObject cnfGroupMember = CBORObject.NewMap();
        cnfGroupMember.Add(Constants.OSCORE_Input_Material, oscGroupMember);
        paramsGroupMember.put(Constants.CNF, cnfGroupMember);
        CWT tokenGroupMember = new CWT(paramsGroupMember);
        CBORObject payloadGroupMember = CBORObject.NewMap();
        payloadGroupMember.Add(Constants.ACCESS_TOKEN, tokenGroupMember.encode(ctxGroupMember).EncodeToBytes());
        payloadGroupMember.Add(Constants.CNF, cnfGroupMember);
        Response asResGroupMember = new Response(CoAP.ResponseCode.CREATED);
        asResGroupMember.setPayload(payloadGroupMember.EncodeToBytes());
        
        
        rsRes = OSCOREProfileRequestsGroupOSCORE.postToken(
                "coap://localhost:" + PORT + "/authz-info", asResGroupMember, askForSignInfo, askForEcdhInfo, ctxDB, usedRecipientIds);
        
        assert(rsRes.getCode().equals(CoAP.ResponseCode.CREATED));
        
        //Check that the OSCORE context has been created:
        Assert.assertNotNull(ctxDB.getContext(
                "coap://localhost:" + PORT + "/" + rootGroupMembershipResource + "/" + groupNameGroupMember));
        
        // Sanity checks already occurred in OSCOREProfileRequestsGroupOSCORE.postToken()
        CBORObject rsPayload = CBORObject.DecodeFromBytes(rsRes.getPayload());
        
        // Nonce from the GM, to use together with a local nonce to prove possession of the private key
        byte[] gm_nonce = rsPayload.get(CBORObject.FromObject(Constants.KDCCHALLENGE)).GetByteString();
        
        CBORObject signInfo = null;
        CBORObject ecdhInfo = null;
        
        // Group OSCORE specific values for the countersignature
        CBORObject signAlgExpected = null;
        CBORObject signParamsExpected = CBORObject.NewArray();
        CBORObject signKeyParamsExpected = CBORObject.NewArray();

        // ECDSA_256
        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            signAlgExpected = AlgorithmID.ECDSA_256.AsCBOR();
            
            // The algorithm capabilities
            signParamsExpected.Add(KeyKeys.KeyType_EC2);    // Key Type
            
            // The key type capabilities
            signKeyParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type
            signKeyParamsExpected.Add(KeyKeys.EC2_P256);    // Curve
        }

        // EDDSA (Ed25519)
        if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            signAlgExpected = AlgorithmID.EDDSA.AsCBOR();
            
            // The algorithm capabilities
            signParamsExpected.Add(KeyKeys.KeyType_OKP);    // Key Type
            
            // The key type capabilities
            signKeyParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type
            signKeyParamsExpected.Add(KeyKeys.OKP_Ed25519); // Curve
        }
        
        // Group OSCORE specific values for the pairwise key derivation
        CBORObject ecdhAlgExpected = AlgorithmID.ECDH_SS_HKDF_256.AsCBOR();
        CBORObject ecdhParamsExpected = CBORObject.NewArray();
        CBORObject ecdhKeyParamsExpected = CBORObject.NewArray();
        
        // P-256
        if (ecdhKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
            // The algorithm capabilities
            ecdhParamsExpected.Add(KeyKeys.KeyType_EC2);    // Key Type
            
            // The key type capabilities
            ecdhKeyParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type
            ecdhKeyParamsExpected.Add(KeyKeys.EC2_P256);    // Curve
        }

        // X25519
        if (ecdhKeyCurve == KeyKeys.OKP_X25519.AsInt32()) {
            // The algorithm capabilities
            ecdhParamsExpected.Add(KeyKeys.KeyType_OKP);    // Key Type
            
            // The key type capabilities
            ecdhKeyParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type
            ecdhKeyParamsExpected.Add(KeyKeys.OKP_X25519);  // Curve
        }
        
        CBORObject credFmtExpected = CBORObject.FromObject(Constants.COSE_HEADER_PARAM_KCCS);
        
        if (askForSignInfo) {
        	Assert.assertEquals(true, rsPayload.ContainsKey(CBORObject.FromObject(Constants.SIGN_INFO)));
            Assert.assertEquals(CBORType.Array, rsPayload.get(CBORObject.FromObject(Constants.SIGN_INFO)).getType());
            signInfo = CBORObject.NewArray();
        	signInfo = rsPayload.get(CBORObject.FromObject(Constants.SIGN_INFO));
        	
	    	CBORObject signInfoExpected = CBORObject.NewArray();
	    	CBORObject signInfoEntry = CBORObject.NewArray();
	    	
	    	signInfoEntry.Add(CBORObject.FromObject(groupName));
	    	
	    	if (signAlgExpected == null)
	    		signInfoEntry.Add(CBORObject.Null);
	    	else
	    		signInfoEntry.Add(signAlgExpected);
	    	
	    	if (signParamsExpected == null)
	    		signInfoEntry.Add(CBORObject.Null);
	    	else
	    		signInfoEntry.Add(signParamsExpected);
	    	
	    	if (signKeyParamsExpected == null)
	    		signInfoEntry.Add(CBORObject.Null);
	    	else
	    		signInfoEntry.Add(signKeyParamsExpected);
        	
        	if (credFmtExpected == null)
        		signInfoEntry.Add(CBORObject.Null);
        	else
        		signInfoEntry.Add(credFmtExpected);
	    	
	        signInfoExpected.Add(signInfoEntry);

        	Assert.assertEquals(signInfoExpected, signInfo);
        }
        
        if (askForEcdhInfo) {
        	Assert.assertEquals(true, rsPayload.ContainsKey(CBORObject.FromObject(Constants.ECDH_INFO)));
        	
        	if (rsPayload.ContainsKey(CBORObject.FromObject(Constants.ECDH_INFO))) {
        	
	            Assert.assertEquals(CBORType.Array, rsPayload.get(CBORObject.FromObject(Constants.ECDH_INFO)).getType());
	            ecdhInfo = CBORObject.NewArray();
	        	ecdhInfo = rsPayload.get(CBORObject.FromObject(Constants.ECDH_INFO));
	        	
		    	CBORObject ecdhInfoExpected = CBORObject.NewArray();
		    	CBORObject ecdhInfoEntry = CBORObject.NewArray();
		    	
		    	ecdhInfoEntry.Add(CBORObject.FromObject(groupName));
		    	
		    	if (ecdhAlgExpected == null)
		    		ecdhInfoEntry.Add(CBORObject.Null);
		    	else
		    		ecdhInfoEntry.Add(ecdhAlgExpected);
		    	
		    	if (ecdhParamsExpected == null)
		    		ecdhInfoEntry.Add(CBORObject.Null);
		    	else
		    		ecdhInfoEntry.Add(ecdhParamsExpected);
		    	
		    	if (ecdhKeyParamsExpected == null)
		    		ecdhInfoEntry.Add(CBORObject.Null);
		    	else
		    		ecdhInfoEntry.Add(ecdhKeyParamsExpected);
	        	
	        	if (credFmtExpected == null)
	        		ecdhInfoEntry.Add(CBORObject.Null);
	        	else
	        		ecdhInfoEntry.Add(credFmtExpected);
		    	
	        	ecdhInfoExpected.Add(ecdhInfoEntry);
	
	        	Assert.assertEquals(ecdhInfoExpected, ecdhInfo);
	        	
        	}
        }
        
        CoapClient joiningNodeClient = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost" + ":" + PORT + "/" + rootGroupMembershipResource + "/" +
        		groupName, PORT), ctxDB);
        
        CBORObject requestPayload = CBORObject.NewMap();
        
        
        // Prepare material for later tests
        
        final AlgorithmID hkdf = AlgorithmID.HMAC_SHA_256;
		
		final AlgorithmID gpEncAlg = AlgorithmID.AES_CCM_16_64_128;
		AlgorithmID signAlg = null;
		CBORObject signAlgCapabilities = CBORObject.NewArray();
		CBORObject signKeyCapabilities = CBORObject.NewArray();
		CBORObject signParams = CBORObject.NewArray();

		// ECDSA_256
		if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
		signAlg = AlgorithmID.ECDSA_256;
		signAlgCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
		signKeyCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
		signKeyCapabilities.Add(KeyKeys.EC2_P256);    // Curve
		}
		    
		// EDDSA (Ed25519)
		if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
		signAlg = AlgorithmID.EDDSA;
		signAlgCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
		signKeyCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
		signKeyCapabilities.Add(KeyKeys.OKP_Ed25519); // Curve
		}
		    
		signParams.Add(signAlgCapabilities);
		signParams.Add(signKeyCapabilities);
        
		
		final AlgorithmID ecdhAlg = AlgorithmID.ECDH_SS_HKDF_256;
		CBORObject ecdhAlgCapabilities = CBORObject.NewArray();
		CBORObject ecdhKeyCapabilities = CBORObject.NewArray();
		CBORObject ecdhParams = CBORObject.NewArray();

		// ECDSA_256
		if (ecdhKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
		ecdhAlgCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
		ecdhKeyCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
		ecdhKeyCapabilities.Add(KeyKeys.EC2_P256);    // Curve
		}
		    
		// X25519
		if (ecdhKeyCurve == KeyKeys.OKP_X25519.AsInt32()) {
		ecdhAlgCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
		ecdhKeyCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
		ecdhKeyCapabilities.Add(KeyKeys.OKP_X25519);  // Curve
		}
		    
		ecdhParams.Add(ecdhAlgCapabilities);
		ecdhParams.Add(ecdhKeyCapabilities);
		
		
        // Send a Join Request
        
        System.out.println("\nPerforming Join Request using OSCORE to GM at " +
        				   "coap://localhost:" + PORT + "/" + rootGroupMembershipResource + "/" + groupName);       
        requestPayload = CBORObject.NewMap();
		
        cborArrayScope = CBORObject.NewArray();
        cborArrayScope.Add(groupName);
        
    	myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_RESPONDER);
    	cborArrayScope.Add(myRoles);
    	
        byteStringScope = cborArrayScope.EncodeToBytes();
        requestPayload.Add(GroupcommParameters.SCOPE, CBORObject.FromObject(byteStringScope));
        
        // Add cnonce
        byte[] cnonce = new byte[8];
        new SecureRandom().nextBytes(cnonce);
        requestPayload.Add(GroupcommParameters.CNONCE, cnonce);
        byte[] serializedCNonceCBOR = CBORObject.FromObject(cnonce).EncodeToBytes();
		
        if (askForAuthCreds) {
            
            CBORObject getAuthCreds = CBORObject.NewArray();
            
            getAuthCreds.Add(CBORObject.True); // This must be true
            
            getAuthCreds.Add(CBORObject.NewArray());
            // The following is required to retrieve the public keys
            // of both the already present group members
            myRoles = 0;
            myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
            getAuthCreds.get(1).Add(myRoles);            
            myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
        	myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_RESPONDER);
        	getAuthCreds.get(1).Add(myRoles);
            
            getAuthCreds.Add(CBORObject.NewArray()); // This must be empty
            
            requestPayload.Add(GroupcommParameters.GET_CREDS, getAuthCreds);
           
        }
        
        
        if (provideAuthCred) {
     	   
 	       // This should never happen, if the Group Manager has provided
     	   // 'kdc_challenge' in the Token POST response, or the joining node
 	       // has computed N_S differently (e.g. through a TLS exporter)
     	   if (gm_nonce == null)
     		   Assert.fail("Error: the component N_S of the PoP evidence challence is null");
            
     	    
           byte[] cred = null;
                          
           switch (credFmtExpected.AsInt32()) {
 	       		case Constants.COSE_HEADER_PARAM_KCCS:
 	       			// A CCS including the public key
 	            	if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
 	            		cred = Utils.hexToBytes("A2026008A101A5010203262001215820E8F9A8D5850A533CDA24B9FA8A1EE293F6A0E1E81E1E560A64FF134D65F7ECEC225820164A6D5D4B97F56D1F60A12811D55DE7A055EBAC6164C9EF9302CBCBFF1F0ABE");
 	            	}
 	            	if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
 	            		cred = Utils.hexToBytes("A2026008A101A4010103272006215820069E912B83963ACC5941B63546867DEC106E5B9051F2EE14F3BC5CC961ACD43A");
 	            	}
 	                break;
 	            case Constants.COSE_HEADER_PARAM_KCWT:
 	                // A CWT including the public key
 	                // TODO
 	            	cred = null;
 	                break;
 	            case Constants.COSE_HEADER_PARAM_X5CHAIN:
 	                // A certificate including the public key
 	                // TODO
 	            	cred = null;
 	                break;
           }
             
           requestPayload.Add(GroupcommParameters.CLIENT_CRED, CBORObject.FromObject(cred));
             
           // Add the signature computed over (scope | rsnonce | cnonce), using the Client's private key
           int offset = 0;
           PrivateKey privKey = (new OneKey(CBORObject.DecodeFromBytes(groupKeyPair))).AsPrivateKey();
             
           byte[] serializedScopeCBOR = CBORObject.FromObject(byteStringScope).EncodeToBytes();
           byte[] serializedGMNonceCBOR = CBORObject.FromObject(gm_nonce).EncodeToBytes();
           byte[] dataToSign = new byte [serializedScopeCBOR.length +
        	                             serializedGMNonceCBOR.length +
        	                             serializedCNonceCBOR.length];
           System.arraycopy(serializedScopeCBOR, 0, dataToSign, offset, serializedScopeCBOR.length);
           offset += serializedScopeCBOR.length;
           System.arraycopy(serializedGMNonceCBOR, 0, dataToSign, offset, serializedGMNonceCBOR.length);
           offset += serializedGMNonceCBOR.length;
           System.arraycopy(serializedCNonceCBOR, 0, dataToSign, offset, serializedCNonceCBOR.length);
             
        	   
           byte[] popEvidence = Util.computeSignature(signKeyCurve, privKey, dataToSign);
             
           if (popEvidence != null)
        	   requestPayload.Add(GroupcommParameters.CLIENT_CRED_VERIFY, popEvidence);
           else
        	   Assert.fail("Computed signature is empty");
            
        }
        
        
        Request joinReq = new Request(Code.POST, Type.CON);
        joinReq.getOptions().setOscore(new byte[0]);
        joinReq.setPayload(requestPayload.EncodeToBytes());
        joinReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
       
        // Submit the request
        System.out.println("");
        System.out.println("Sent Join request to GM: " + requestPayload.toString() + "\n");
        CoapResponse r2 = joiningNodeClient.advanced(joinReq);
       
        Assert.assertEquals("CREATED", r2.getCode().name());
        
        byte[] responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
       
        Assert.assertEquals(CBORType.Map, joinResponse.getType());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.GKTY)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(GroupcommParameters.GKTY)).getType());
        Assert.assertEquals(GroupcommParameters.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, joinResponse.get(CBORObject.FromObject(GroupcommParameters.GKTY)).AsInt32());
       
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.KEY)));
        Assert.assertEquals(CBORType.Map, joinResponse.get(CBORObject.FromObject(GroupcommParameters.KEY)).getType());
       
        CBORObject myMap = joinResponse.get(CBORObject.FromObject(GroupcommParameters.KEY));
        
        // Sanity check
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.gp_enc_alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_alg)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_alg)));
        
        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32() || signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)));
        }
        if (ecdhKeyCurve == KeyKeys.EC2_P256.AsInt32() || ecdhKeyCurve == KeyKeys.OKP_X25519.AsInt32()) {
            Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)));
        }
 
        // Check the presence, type and value of the public key encoding
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cred_fmt)));
        Assert.assertEquals(CBORType.Integer, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cred_fmt)).getType());        
        Assert.assertEquals(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_KCCS), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cred_fmt)));
        
        int credFmt = myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cred_fmt)).AsInt32();
        
        // The 'exp' parameter, the OSCORE Master Secret, Master Salt, and Group ID cannot be tested,
        // as the Group Manager generates them in a non deterministic way
        
        final byte[] senderId = new byte[] { (byte) 0x25 };
        Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)).GetByteString());
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(gpEncAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.gp_enc_alg)));
        Assert.assertNotNull(signAlg);
        Assert.assertEquals(signAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_alg)));
        Assert.assertNotNull(ecdhAlg);
        Assert.assertEquals(ecdhAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_alg)));
        
        // Add default values for missing parameters
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.hkdf, AlgorithmID.HMAC_SHA_256);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.salt, CBORObject.FromObject(new byte[0]));
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.NUM)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(GroupcommParameters.NUM)).getType());
        // This assumes that the Group Manager did not rekey the group upon previous nodes' joining
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(GroupcommParameters.NUM)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.ACE_GROUPCOMM_PROFILE)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(GroupcommParameters.ACE_GROUPCOMM_PROFILE)).getType());
        Assert.assertEquals(GroupcommParameters.COAP_GROUP_OSCORE_APP, joinResponse.get(CBORObject.FromObject(GroupcommParameters.ACE_GROUPCOMM_PROFILE)).AsInt32());
       
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.EXP)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(GroupcommParameters.EXP)).getType());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.EXI)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(GroupcommParameters.EXI)).getType());
        
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(signParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)));
        }
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(ecdhParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)));
        }
		
        // No other peers are expected to already be in the group
        CBORObject authCredsArray = null;
        if (askForAuthCreds) {
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.CREDS)));
            Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(GroupcommParameters.CREDS)).getType());
           
            authCredsArray = joinResponse.get(CBORObject.FromObject(GroupcommParameters.CREDS));
            Assert.assertEquals(0, authCredsArray.size());
           
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)));
            Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)).getType());
            Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)).size());
           
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)));
            Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)).getType());
            Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)).size());           
        }
        else {
            Assert.assertEquals(false, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.CREDS)));
            Assert.assertEquals(false, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)));
        }
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.GROUP_POLICIES)));
        Assert.assertEquals(3600, joinResponse.get(CBORObject.FromObject(GroupcommParameters.GROUP_POLICIES)).get(CBORObject.FromObject(GroupcommPolicies.KEY_CHECK_INTERVAL)).AsInt32());
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(GroupcommParameters.GROUP_POLICIES)).get(CBORObject.FromObject(GroupcommPolicies.EXP_DELTA)).AsInt32());
        
        
	    // Check the proof-of-possession evidence over kdc_nonce, using the GM's public key
	    Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.KDC_NONCE)));
	    Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(GroupcommParameters.KDC_NONCE)).getType());
	    Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.KDC_CRED)));
	    Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(GroupcommParameters.KDC_CRED)).getType());
	    Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.KDC_CRED_VERIFY)));
	    Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(GroupcommParameters.KDC_CRED_VERIFY)).getType());
	    
	    OneKey gmPublicKeyRetrieved = null;
	    byte[] kdcCredBytes = joinResponse.get(CBORObject.FromObject(GroupcommParameters.KDC_CRED)).GetByteString();
	    switch (credFmt) {
	        case Constants.COSE_HEADER_PARAM_KCCS:
	            CBORObject ccs = CBORObject.DecodeFromBytes(kdcCredBytes);
	            if (ccs.getType() == CBORType.Map) {
	                // Retrieve the public key from the CCS
	                gmPublicKeyRetrieved = Util.ccsToOneKey(ccs);
	            }
	            else {
	                Assert.fail("Invalid format of Group Manager public key");
	            }
	            break;
	        case Constants.COSE_HEADER_PARAM_KCWT:
	            CBORObject cwt = CBORObject.DecodeFromBytes(kdcCredBytes);
	            if (cwt.getType() == CBORType.Array) {
	                // Retrieve the public key from the CWT
	                // TODO
	            }
	            else {
	                Assert.fail("Invalid format of Group Manager public key");
	            }
	            break;
	        case Constants.COSE_HEADER_PARAM_X5CHAIN:
	            // Retrieve the public key from the certificate
	            // TODO
	            break;
	        default:
	            Assert.fail("Invalid format of Group Manager public key");
	    }
        if (gmPublicKeyRetrieved == null)
        	Assert.fail("Invalid format of Group Manager public key");
        Assert.assertEquals(CBORObject.DecodeFromBytes(publicKeyGM), gmPublicKeyRetrieved.AsCBOR());
	
    	PublicKey gmPublicKey = gmPublicKeyRetrieved.AsPublicKey();
    	
        int offset = 0;
		byte[] serializedGMNonceCBOR = joinResponse.get(CBORObject.FromObject(GroupcommParameters.KDC_NONCE)).EncodeToBytes();
		byte[] popInput = new byte[serializedCNonceCBOR.length +serializedGMNonceCBOR.length];
		System.arraycopy(serializedCNonceCBOR, 0, popInput, offset, serializedCNonceCBOR.length);
		offset += serializedCNonceCBOR.length;
		System.arraycopy(serializedGMNonceCBOR, 0, popInput, offset, serializedGMNonceCBOR.length);
		
    	CBORObject gmPopEvidence = joinResponse.get(CBORObject.FromObject(GroupcommParameters.KDC_CRED_VERIFY));
    	byte[] rawGmPopEvidence = gmPopEvidence.GetByteString();
            	
    	Assert.assertEquals(true, Util.verifySignature(signKeyCurve, gmPublicKey, popInput, rawGmPopEvidence));

        System.out.println("Response code: " + r2.advanced().getCode());
        if (r2.getOptions().getLocationPath().size() != 0) {
	        System.out.print("Response Location-Path: ");
	        System.out.println(r2.getOptions().getLocationPathString());
        }
        if (r2.getOptions().hasContentFormat()) {
        	System.out.println("Response Content-Format: " + r2.getOptions().getContentFormat());
        }
        System.out.println("Response payload:\n" + joinResponse.toString());
        
        // ============================================
        
        // Send a POST request to /manage/gp1

        System.out.println();
        c = OSCOREProfileRequests.getClient(
        		new InetSocketAddress("coap://localhost:" + PORT + "/" + groupCollectionResourcePath + "/" + "gp1", PORT), ctxDB);
        
        adminReq = new Request(CoAP.Code.POST);
        adminReq.getOptions().setOscore(new byte[0]);
        adminReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        requestPayloadCbor = CBORObject.NewMap();
        requestPayloadCbor.Add(GroupcommParameters.GROUP_DESCRIPTION, CBORObject.FromObject("My first group"));
        adminReq.setPayload(requestPayloadCbor.EncodeToBytes());
        
        adminRes = c.advanced(adminReq);
        
        Assert.assertNotNull(adminRes);
        Assert.assertEquals(ResponseCode.CHANGED, adminRes.getCode());
        Assert.assertNotNull(adminRes.getPayload());
        
        responsePayloadCbor = CBORObject.DecodeFromBytes(adminRes.getPayload());
        Assert.assertNotNull(responsePayloadCbor);
        
        Assert.assertEquals(CBORType.Map, responsePayloadCbor.getType());
        System.out.println("Response code: " + adminRes.advanced().getCode());
        if (adminRes.getOptions().hasContentFormat()) {
        	System.out.println("Response Content-Format: " + adminRes.getOptions().getContentFormat());
        }
        System.out.println("Response payload:");
        Util.prettyPrintCborMap(responsePayloadCbor);
        Assert.assertEquals(3, responsePayloadCbor.size());
        
        // ============================================
        
        // Send a GET request to /manage/gp1

        c = OSCOREProfileRequests.getClient(
        		new InetSocketAddress("coap://localhost:" + PORT + "/" + groupCollectionResourcePath + "/" + "gp1", PORT), ctxDB);
        
        adminReq = new Request(CoAP.Code.GET);
        adminReq.getOptions().setOscore(new byte[0]);
        
        adminRes = c.advanced(adminReq);
        
        Assert.assertNotNull(adminRes);
        Assert.assertEquals(ResponseCode.CONTENT, adminRes.getCode());
        Assert.assertNotNull(adminRes.getPayload());
        
        responsePayloadCbor = CBORObject.DecodeFromBytes(adminRes.getPayload());
        Assert.assertNotNull(responsePayloadCbor);
        
        Assert.assertEquals(CBORType.Map, responsePayloadCbor.getType());
        System.out.println("Response code: " + adminRes.advanced().getCode());
        if (adminRes.getOptions().hasContentFormat()) {
        	System.out.println("Response Content-Format: " + adminRes.getOptions().getContentFormat());
        }
        System.out.println("Response payload:");
        Util.prettyPrintCborMap(responsePayloadCbor);
        Assert.assertEquals(23, responsePayloadCbor.size());
        Assert.assertEquals("My first group", responsePayloadCbor.get(GroupcommParameters.GROUP_DESCRIPTION).AsString());
        
        // ============================================
        
        // Send a POST request to /manage
        
        // This requests attempts to create a group with name "gp1", although that name is already in use.
        //
        // The Group Manager will create the new group using the alternative name "gp600", since:
        // i) the name "gp600" is not in use; and
        // ii) there are admin scope entries for this Administrator such that the Administrator's permissions
        //     for a group with name "gp600" are identical to those for a group with name "gp1"

        c = OSCOREProfileRequests.getClient(
        		new InetSocketAddress("coap://localhost:" + PORT + "/" + groupCollectionResourcePath, PORT), ctxDB);
        
        adminReq = new Request(CoAP.Code.POST);
        adminReq.getOptions().setOscore(new byte[0]);
        adminReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        requestPayloadCbor = CBORObject.NewMap();
        requestPayloadCbor.Add(GroupcommParameters.GROUP_NAME, CBORObject.FromObject("gp1"));
        requestPayloadCbor.Add(GroupcommParameters.ACTIVE, CBORObject.True);
        adminReq.setPayload(requestPayloadCbor.EncodeToBytes());
        
        adminRes = c.advanced(adminReq);
        
        Assert.assertNotNull(adminRes);
        Assert.assertEquals(ResponseCode.CREATED, adminRes.getCode());
        Assert.assertNotNull(adminRes.getPayload());
        
        responsePayloadCbor = CBORObject.DecodeFromBytes(adminRes.getPayload());
        Assert.assertNotNull(responsePayloadCbor);
        
        Assert.assertEquals(CBORType.Map, responsePayloadCbor.getType());
        System.out.println("Response code: " + adminRes.advanced().getCode());
        if (adminRes.getOptions().hasContentFormat()) {
        	System.out.println("Response Content-Format: " + adminRes.getOptions().getContentFormat());
        }
        System.out.println("Response payload:");
        Util.prettyPrintCborMap(responsePayloadCbor);
        Assert.assertEquals(3, responsePayloadCbor.size());
        Assert.assertEquals("gp600", responsePayloadCbor.get(GroupcommParameters.GROUP_NAME).AsString());
        
        // ============================================
        
        // Send a GET request to /manage/gp600

        c = OSCOREProfileRequests.getClient(
        		new InetSocketAddress("coap://localhost:" + PORT + "/" + groupCollectionResourcePath + "/" + "gp600", PORT), ctxDB);
        
        adminReq = new Request(CoAP.Code.GET);
        adminReq.getOptions().setOscore(new byte[0]);
        
        adminRes = c.advanced(adminReq);
        
        Assert.assertNotNull(adminRes);
        Assert.assertEquals(ResponseCode.CONTENT, adminRes.getCode());
        Assert.assertNotNull(adminRes.getPayload());
        
        responsePayloadCbor = CBORObject.DecodeFromBytes(adminRes.getPayload());
        Assert.assertNotNull(responsePayloadCbor);
        
        Assert.assertEquals(CBORType.Map, responsePayloadCbor.getType());
        System.out.println("Response code: " + adminRes.advanced().getCode());
        if (adminRes.getOptions().hasContentFormat()) {
        	System.out.println("Response Content-Format: " + adminRes.getOptions().getContentFormat());
        }
        System.out.println("Response payload:");
        Util.prettyPrintCborMap(responsePayloadCbor);
        Assert.assertEquals(23, responsePayloadCbor.size());
        
        // ============================================
        
        // Send a GET request to /manage
        
        c = OSCOREProfileRequests.getClient(
        		new InetSocketAddress("coap://localhost:" + PORT + "/" + groupCollectionResourcePath, PORT), ctxDB);
        
        adminReq = new Request(CoAP.Code.GET);
        adminReq.getOptions().setOscore(new byte[0]);
        
        adminRes = c.advanced(adminReq);
        
        Assert.assertEquals(ResponseCode.CONTENT, adminRes.getCode());
        System.out.println("Response code: " + adminRes.advanced().getCode());
        if (adminRes.getOptions().hasContentFormat()) {
        	System.out.println("Response Content-Format: " + adminRes.getOptions().getContentFormat());
        }
        System.out.println("Response payload:\n" + new String(adminRes.getPayload()));
        
        // ============================================
        
        // Send a DELETE request to /manage/gp1

        System.out.println();
        c = OSCOREProfileRequests.getClient(
        		new InetSocketAddress("coap://localhost:" + PORT + "/" + groupCollectionResourcePath + "/" + "gp1", PORT), ctxDB);
        
        adminReq = new Request(CoAP.Code.DELETE);
        adminReq.getOptions().setOscore(new byte[0]);
        
        adminRes = c.advanced(adminReq);
        
        Assert.assertNotNull(adminRes);
        Assert.assertEquals(ResponseCode.DELETED, adminRes.getCode());
        Assert.assertNotNull(adminRes.getPayload());
        Assert.assertArrayEquals(Bytes.EMPTY, adminRes.getPayload());
        
        // ============================================
        
        // Send a GET request to /manage
        
        System.out.println();
        c = OSCOREProfileRequests.getClient(
        		new InetSocketAddress("coap://localhost:" + PORT + "/" + groupCollectionResourcePath, PORT), ctxDB);
        
        adminReq = new Request(CoAP.Code.GET);
        adminReq.getOptions().setOscore(new byte[0]);
        
        adminRes = c.advanced(adminReq);
        
        Assert.assertEquals(ResponseCode.CONTENT, adminRes.getCode());
        System.out.println("Response code: " + adminRes.advanced().getCode());
        if (adminRes.getOptions().hasContentFormat()) {
        	System.out.println("Response Content-Format: " + adminRes.getOptions().getContentFormat());
        }
        System.out.println("Response payload:\n" + new String(adminRes.getPayload()));
        
        // ============================================
        
        // Send a GET request to /manage/gp1

        System.out.println();
        c = OSCOREProfileRequests.getClient(
        		new InetSocketAddress("coap://localhost:" + PORT + "/" + groupCollectionResourcePath + "/" + "gp1", PORT), ctxDB);
        
        adminReq = new Request(CoAP.Code.GET);
        adminReq.getOptions().setOscore(new byte[0]);
        
        adminRes = c.advanced(adminReq);
        Assert.assertNotNull(adminRes);
        Assert.assertEquals(ResponseCode.NOT_FOUND, adminRes.getCode());
        Assert.assertArrayEquals(Bytes.EMPTY, adminRes.getPayload());
        
        // ============================================
        
        // Send a POST request to /manage/gp1

        System.out.println();
        c = OSCOREProfileRequests.getClient(
        		new InetSocketAddress("coap://localhost:" + PORT + "/" + groupCollectionResourcePath + "/" + "gp1", PORT), ctxDB);
        
        adminReq = new Request(CoAP.Code.POST);
        adminReq.getOptions().setOscore(new byte[0]);
        adminReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        requestPayloadCbor = CBORObject.NewMap();
        requestPayloadCbor.Add(GroupcommParameters.GROUP_DESCRIPTION, CBORObject.FromObject("My first group"));
        adminReq.setPayload(requestPayloadCbor.EncodeToBytes());
        
        adminRes = c.advanced(adminReq);
        
        Assert.assertNotNull(adminRes);
        Assert.assertEquals(ResponseCode.NOT_FOUND, adminRes.getCode());

    }
    
    /**
     * Test unauthorized access to the RS
     * 
     * @throws Exception 
     */
    @Test
    public void testNoAccess() throws Exception {
        
        ctxDB.addContext("coap://localhost:" + PORT + "/helloWorld", osctx);
        CoapClient c = OSCOREProfileRequests.getClient(
                new InetSocketAddress("coap://localhost:" + PORT + "/helloWorld", PORT), ctxDB);
        
        CoapResponse res = c.get();
        assert(res.getCode().equals(CoAP.ResponseCode.UNAUTHORIZED));
    }
   
}
