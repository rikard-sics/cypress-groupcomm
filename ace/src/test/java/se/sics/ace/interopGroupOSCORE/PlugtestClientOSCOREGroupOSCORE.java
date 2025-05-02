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

import java.net.InetSocketAddress;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import org.junit.Assert;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.MessageTag;
import org.eclipse.californium.cose.OneKey;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.Util;
import se.sics.ace.coap.client.OSCOREProfileRequests;
import se.sics.ace.coap.client.OSCOREProfileRequestsGroupOSCORE;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.oscore.GroupOSCOREInputMaterialObjectParameters;

/**
 * Test the coap classes.
 * 
 * NOTE: This will automatically start a server in another thread
 * 
 * @author Marco Tiloca
 *
 */
public class PlugtestClientOSCOREGroupOSCORE {
    
	/* START LIST OF KEYS */
    
	// For old tests - PSK to encrypt the token
    private static byte[] key128_token_rs1 = {(byte)0xa1, (byte)0xa2, (byte)0xa3, 0x04, 0x05, 0x06, 0x07,
    									      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    
	// Sender ID 0x52 for an already present group member
	private static final byte[] idClient2 = new byte[] { (byte) 0x52 };
	
	// Sender ID 0x77 for an already present group member
	private static final byte[] idClient3 = new byte[] { (byte) 0x77 };
    
    /* ECDSA_256 keys */
    /* */
    // Asymmetric key pair of the Client joining the OSCORE group (ECDSA_256)
    private static String c1X_ECDSA = "E8F9A8D5850A533CDA24B9FA8A1EE293F6A0E1E81E1E560A64FF134D65F7ECEC";
    private static String c1Y_ECDSA = "164A6D5D4B97F56D1F60A12811D55DE7A055EBAC6164C9EF9302CBCBFF1F0ABE";
    private static String c1D_ECDSA = "3BE0047599B42AA44B8F8A0FA88D4DA11697B58D9FCC4E39443E9843BF230586";
    
    // Public key of the a client already in the OSCORE group, with Sender ID 'idClient2' (ECDSA_256)
    private static String c2X_ECDSA = "35F3656092E1269AAAEE6262CD1C0D9D38ED78820803305BC8EA41702A50B3AF";
    private static String c2Y_ECDSA = "5D31247C2959E7B7D3F62F79622A7082FF01325FC9549E61BB878C2264DF4C4F";
    
    // Public key of the a client already in the OSCORE group, with Sender ID 'idClient3' (ECDSA_256)
    private static String c3X_ECDSA = "9DFA6D63FD1515761460B7B02D54F8D7345819D2E5576C160D3148CC7886D5F1";
    private static String c3Y_ECDSA = "76C81A0C1A872F1730C10317AB4F3616238FB23A08719E8B982B2D9321A2EF7D";
    
    // Public key of the Group Manager (ECDSA_256)
    private static String gmX_ECDSA = "2236658CA675BB62D7B24623DB0453A3B90533B7C3B221CC1C2C73C4E919D540";
    private static String gmY_ECDSA = "770916BC4C97C3C46604F430B06170C7B3D6062633756628C31180FA3BB65A1B";
    /* */
    
    
    /* Ed25519 keys */
    /* */
    // Asymmetric key pair of the Client joining the OSCORE group (Ed25519)
    private static String c1X_EDDSA = "069E912B83963ACC5941B63546867DEC106E5B9051F2EE14F3BC5CC961ACD43A";
    private static String c1D_EDDSA = "64714D41A240B61D8D823502717AB088C9F4AF6FC9844553E4AD4C42CC735239";
    
    // Public key of the a client already in the OSCORE group, with Sender ID 'idClient2' (Ed25519)
    private static String c2X_EDDSA = "77EC358C1D344E41EE0E87B8383D23A2099ACD39BDF989CE45B52E887463389B";
    
    // Public key of the a client already in the OSCORE group, with Sender ID 'idClient3' (Ed25519)
    private static String c3X_EDDSA = "105B8C6A8C88019BF0C354592934130BAA8007399CC2AC3BE845884613D5BA2E";
    
    // Public key of the Group Manager (Ed25519)
    private static String gmX_EDDSA = "C6EC665E817BD064340E7C24BB93A11E8EC0735CE48790F9C458F7FA340B8CA3";
    /* */
    
    private static OneKey C1keyPair = null;
    private static OneKey C2pubKey = null;
    private static OneKey C3pubKey = null;
    private static OneKey gmPubKey = null;
    
    /* END LIST OF KEYS */
    
    // The cnf key (OSCORE Master Secret) used in these tests
    private static byte[] keyCnf = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    
    private static OSCoreCtxDB ctxDB;
    
	// Each set of the list refers to a different size of Recipient IDs.
	// The element with index 0 includes as elements Recipient IDs with size 1 byte.
	private static List<Set<Integer>> usedRecipientIds = new ArrayList<Set<Integer>>();
    
    //Needed to show token content
    private static CwtCryptoCtx ctx1 = null;    
    
    private static String uri = "";
    private static int portNumberRSnosec = 5690;
    
    private static String rsAddr = "";
    private static final String rootGroupMembershipResource = "ace-group";
    private static final String groupName = new String("feedca570000");
    
    // Uncomment to set ECDSA with curve P-256 for countersignatures
    // private static int signKeyCurve = KeyKeys.EC2_P256.AsInt32();
    
    // Uncomment to set EDDSA with curve Ed25519 for countersignatures
    private static int signKeyCurve = KeyKeys.OKP_Ed25519.AsInt32();
    
    // Uncomment to set curve P-256 for pairwise key derivation
    // private static int ecdhKeyCurve = KeyKeys.EC2_P256.AsInt32();
    
    // Uncomment to set curve X25519 for pairwise key derivation
    private static int ecdhKeyCurve = KeyKeys.OKP_X25519.AsInt32();
    
    /**
     * @param args
     * @throws Exception 
     */
    public static void main(String[] args)
            throws Exception {
        
        if (args.length < 2) { 
            System.out.println("First argument should be the number of the"
            				 + " test case, second the address of the other endpoint"
            				 + "(AS/RS) without the path");
            // args[0] is the test case, 
            // args[1] is the address of the other endpoint
            return;
        }
        
    	final Provider PROVIDER = new BouncyCastleProvider();
    	final Provider EdDSA = new EdDSASecurityProvider();
    	Security.insertProviderAt(PROVIDER, 2);
    	Security.insertProviderAt(EdDSA, 1);
        
        // Setup the asymmetric key pair of the joining node
    	CBORObject rpkData = null;
    	
		// ECDSA_256
    	if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
    		rpkData = CBORObject.NewMap();
    		rpkData = Util.buildRpkData(signKeyCurve, c1X_ECDSA, c1Y_ECDSA, c1D_ECDSA);
            C1keyPair = new OneKey(rpkData);
       	}
    	// EDDSA (Ed25519)
    	if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
    		rpkData = CBORObject.NewMap();
    		rpkData = Util.buildRpkData(signKeyCurve, c1X_EDDSA, null, c1D_EDDSA);
    	}
        C1keyPair = new OneKey(rpkData);
        
        // Setup the public key of the group members and of the Group Manager
    	if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
    		rpkData = CBORObject.NewMap();
    		rpkData = Util.buildRpkData(signKeyCurve, c2X_ECDSA, c2Y_ECDSA, null);
            C2pubKey = new OneKey(rpkData);

            rpkData = CBORObject.NewMap();
            rpkData = Util.buildRpkData(signKeyCurve, c3X_ECDSA, c3Y_ECDSA, null);
            C3pubKey = new OneKey(rpkData);     
            
            rpkData = CBORObject.NewMap();
            rpkData = Util.buildRpkData(signKeyCurve, gmX_ECDSA, gmY_ECDSA, null);
            gmPubKey = new OneKey(rpkData); 
       	}
    	// EDDSA (Ed25519) and of the Group Manager
    	if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
    		rpkData = CBORObject.NewMap();
    		rpkData = Util.buildRpkData(signKeyCurve, c2X_EDDSA, null, null);
            C2pubKey = new OneKey(rpkData);
            
            rpkData = CBORObject.NewMap();
            rpkData = Util.buildRpkData(signKeyCurve, c3X_EDDSA, null, null);
            C3pubKey = new OneKey(rpkData);
            
            rpkData = CBORObject.NewMap();
            rpkData = Util.buildRpkData(signKeyCurve, gmX_EDDSA, null, null);
            gmPubKey = new OneKey(rpkData);
    	}
        
        int testcase = Integer.parseInt(args[0]);
        
        rsAddr = new String(args[1]);
        uri = new String(args[1]); 
        // add schema if not present
        if (!uri.contains("://")) {
            uri = "coap://" + uri;
        }
        if (uri.endsWith("/")) {
            uri = uri.substring(-1);
        }
        uri = uri + ":";

        //Set up COSE parameters
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_64_128, AlgorithmID.Direct);
        ctx1 = CwtCryptoCtx.encrypt0(key128_token_rs1, coseP.getAlg().AsCBOR());
        
        ctxDB = new org.eclipse.californium.oscore.HashMapCtxDB();
        
    	for (int i = 0; i < 4; i++) {
        	// Empty sets of assigned Sender IDs; one set for each possible Sender ID size in bytes.
        	// The set with index 0 refers to Sender IDs with size 1 byte
    		usedRecipientIds.add(new HashSet<Integer>());
    		
    	}
        
        switch (testcase) {
        
        /* Client and AS */
        case 1: // Test post to Authz-Info, then join using a single role.
        	testSuccessGroupOSCORESingleRole();
        	break;
        	
        case 2: // Test post to Authz-Info, then join using multiple roles.
        	testSuccessGroupOSCOREMultipleRoles();
        	break;
        	
        default:
        	// TBD
    	    break;
        }
        
    }

    private static void printMapPayload(CBORObject obj) throws Exception {
        if (obj != null) {
        	System.out.println("*** Map Payload *** ");
        	System.out.println(obj);
        } else {
        	System.out.println("*** The payload argument is null!");
        }
    }
    
    private static void printResponseFromRS(Response res) throws Exception {
        if (res != null) {
        	System.out.println("*** Response from the RS *** ");
            System.out.print(res.getCode().codeClass + ".0" + res.getCode().codeDetail);
            System.out.println(" " + res.getCode().name());

            if (res.getPayload() != null) {
            	
            	if (res.getOptions().getContentFormat() == Constants.APPLICATION_ACE_CBOR ||
            		res.getOptions().getContentFormat() == Constants.APPLICATION_ACE_GROUPCOMM_CBOR) {
		        	CBORObject resCBOR = CBORObject.DecodeFromBytes(res.getPayload());
		            System.out.println(resCBOR.toString());
            	}
            	else {
		            System.out.println(new String(res.getPayload()));
            	}
            }
        } else {
        	System.out.println("*** The response from the RS is null!");
            System.out.print("No response received");
        }
    }
    
    
    // Start tests with the Group Manager
    
    // === Case 1 ===
    /**
     * Test post to Authz-Info, then join using a single role.
     * Uses the ACE OSCORE Profile.
     * 
     * @throws Exception 
     */
    public static void testSuccessGroupOSCORESingleRole() throws Exception {

    	boolean askForSignInfo = true;
    	boolean askForEcdhInfo = true;
        boolean askForAuthCreds = true;
        boolean provideAuthCred = true;
        
        //Generate a token
        Map<Short, CBORObject> params = new HashMap<>(); 
        
        //Create the scope        
        CBORObject cborArrayScope = CBORObject.NewArray();
        CBORObject cborArrayEntry = CBORObject.NewArray();
        
        cborArrayEntry.Add(groupName);
        
    	int myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayEntry.Add(myRoles);
    	
        cborArrayScope.Add(cborArrayEntry);
    	byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject("aud2"));
        params.put(Constants.CTI, CBORObject.FromObject(
                   "token4JoinSingleRole".getBytes(Constants.charset))); //Need different CTI
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

        CBORObject osc = CBORObject.NewMap();
        osc.Add(Constants.OS_MS, keyCnf);
        osc.Add(Constants.OS_ID, Util.intToBytes(0));

        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.OSCORE_Input_Material, osc);
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx1).EncodeToBytes());
        payload.Add(Constants.CNF, cnf);
        Response asRes = new Response(CoAP.ResponseCode.CREATED);
        asRes.setPayload(payload.EncodeToBytes());
        Response rsRes = OSCOREProfileRequestsGroupOSCORE.postToken(
                		 	"coap://" + rsAddr + ":" + portNumberRSnosec + "/authz-info",
                		 	asRes, askForSignInfo, askForEcdhInfo, ctxDB, usedRecipientIds);
        assert(rsRes.getCode().equals(CoAP.ResponseCode.CREATED));
        
        printResponseFromRS(rsRes);
        
        //Check that the OSCORE context has been created:
        Assert.assertNotNull(ctxDB.getContext(
                "coap://" + rsAddr + ":" + portNumberRSnosec + "/" + rootGroupMembershipResource + "/" + groupName));
        
        CBORObject rsPayload = CBORObject.DecodeFromBytes(rsRes.getPayload());
        // Sanity checks already occurred in OSCOREProfileRequestsGroupOSCORE.postToken()
        
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
            signParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type
            
            // The key type capabilities
            signKeyParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type
            signKeyParamsExpected.Add(KeyKeys.EC2_P256); // Curve
        }

        // EDDSA (Ed25519)
        if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            signAlgExpected = AlgorithmID.EDDSA.AsCBOR();
            
                // The algorithm capabilities
            signParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type
            
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
        ecdhParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type

        // The key type capabilities
        ecdhKeyParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type
        ecdhKeyParamsExpected.Add(KeyKeys.EC2_P256); // Curve
        }

        // X25519
        if (ecdhKeyCurve == KeyKeys.OKP_X25519.AsInt32()) {
        // The algorithm capabilities
        ecdhParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type

        // The key type capabilities
        ecdhKeyParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type
        ecdhKeyParamsExpected.Add(KeyKeys.OKP_X25519); // Curve
        }
        
        CBORObject credFmtExpected = CBORObject.FromObject(Constants.COSE_HEADER_PARAM_CCS);

        
        // DEBUG: START SET OF ASSERTIONS
        /*
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

                Assert.assertEquals(ecdhInfo, ecdhInfoExpected);
                
            }
        }
        */
        // DEBUG: END SET OF ASSERTIONS
        
        
        // Now proceed with the Join request
        
        CoapClient c = OSCOREProfileRequestsGroupOSCORE.getClient(new InetSocketAddress(
        		"coap://" + rsAddr + ":" + portNumberRSnosec + "/" +
        		rootGroupMembershipResource + "/" + groupName, portNumberRSnosec),
        		ctxDB);
        
        System.out.println("Performing Join request using OSCORE to GM at " +
        				   "coap://" + rsAddr + ":" + portNumberRSnosec + "/" +
        				   rootGroupMembershipResource + "/" + groupName);
       
        CBORObject requestPayload = CBORObject.NewMap();
       
        cborArrayScope = CBORObject.NewArray();
        cborArrayScope.Add(groupName);

        myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	cborArrayScope.Add(myRoles);
                
    	byteStringScope = cborArrayScope.EncodeToBytes();
        requestPayload.Add(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
       
        if (askForAuthCreds) {
           
            CBORObject getCreds = CBORObject.NewArray();
            
            getCreds.Add(CBORObject.True); // This must be true
            
            getCreds.Add(CBORObject.NewArray());
            // The following is required to retrieve the authentication credentials of both the already present group members 
            myRoles = 0;
            myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
            getCreds.get(1).Add(myRoles);            
            myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
        	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
        	getCreds.get(1).Add(myRoles);
            
        	getCreds.Add(CBORObject.NewArray()); // This must be empty
            
            requestPayload.Add(Constants.GET_CREDS, getCreds);
           
        }
       
        if (provideAuthCred) {
           
        	// This should never happen, if the Group Manager has provided 'kdc_challenge' in the Token POST response,
        	// or the joining node has computed N_S differently (e.g. through a TLS exporter)
        	if (gm_nonce == null)
        		Assert.fail("Error: the component N_S of the signature challence is null");
        	
            byte[] encodedPublicKey = null;


            /*
            // Build the authentication credential according to the format used in the group
            // Note: most likely, the result will NOT follow the required deterministic
			//       encoding in byte lexicographic order, and it has to be adjusted offline
            OneKey publicKey = C1keyPair.PublicKey();
	        switch (credFmtExpected.AsInt32()) {
	            case Constants.COSE_HEADER_PARAM_CCS:
	                // Build a CCS including the public key
	                encodedPublicKey = Util.oneKeyToCCS(publicKey, "");
	                break;
	            case Constants.COSE_HEADER_PARAM_CWT:
	                // Build a CWT including the public key
	                // TODO
	                break;
	            case Constants.COSE_HEADER_PARAM_X5CHAIN:
	                // Build/retrieve the certificate including the public key
	                // TODO
	                break;
	        }
	        */
	
	        switch (credFmtExpected.AsInt32()) {
		        case Constants.COSE_HEADER_PARAM_CCS:
		            // A CCS including the public key
		            if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
		                encodedPublicKey = net.i2p.crypto.eddsa.Utils.hexToBytes("A2026008A101A5010203262001215820E8F9A8D5850A533CDA24B9FA8A1EE293F6A0E1E81E1E560A64FF134D65F7ECEC225820164A6D5D4B97F56D1F60A12811D55DE7A055EBAC6164C9EF9302CBCBFF1F0ABE");
		            }
		            if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
		                encodedPublicKey = net.i2p.crypto.eddsa.Utils.hexToBytes("A2026008A101A4010103272006215820069E912B83963ACC5941B63546867DEC106E5B9051F2EE14F3BC5CC961ACD43A");
		            }
		            break;
		        case Constants.COSE_HEADER_PARAM_CWT:
		            // A CWT including the public key
		            // TODO
		            encodedPublicKey = null;
		            break;
		        case Constants.COSE_HEADER_PARAM_X5CHAIN:
		            // A certificate including the public key
		            // TODO
		            encodedPublicKey = null;
		            break;
	        }
	
	        requestPayload.Add(Constants.CLIENT_CRED, CBORObject.FromObject(encodedPublicKey));
        	
            
        	// Add the nonce for PoP of the Client's private key
            byte[] cnonce = new byte[8];
            new SecureRandom().nextBytes(cnonce);
            requestPayload.Add(Constants.CNONCE, cnonce);
            
            // Add the signature computed over (scope | rsnonce | cnonce), using the Client's private key
            int offset = 0;
            PrivateKey privKey = C1keyPair.AsPrivateKey();
            
            byte[] serializedScopeCBOR = CBORObject.FromObject(byteStringScope).EncodeToBytes();
            byte[] serializedGMSignNonceCBOR = CBORObject.FromObject(gm_nonce).EncodeToBytes();
            byte[] serializedCNonceCBOR = CBORObject.FromObject(cnonce).EncodeToBytes();
       	    byte[] dataToSign = new byte [serializedScopeCBOR.length +
       	                                   serializedGMSignNonceCBOR.length +
       	                                   serializedCNonceCBOR.length];
       	    System.arraycopy(serializedScopeCBOR, 0, dataToSign, offset, serializedScopeCBOR.length);
       	    offset += serializedScopeCBOR.length;
       	    System.arraycopy(serializedGMSignNonceCBOR, 0, dataToSign, offset, serializedGMSignNonceCBOR.length);
       	    offset += serializedGMSignNonceCBOR.length;
       	    System.arraycopy(serializedCNonceCBOR, 0, dataToSign, offset, serializedCNonceCBOR.length);
                   	   
       	    byte[] clientSignature = Util.computeSignature(signKeyCurve, privKey, dataToSign);
            
            if (clientSignature != null)
            	requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
        	else
        		Assert.fail("Computed signature is empty");
           
        }
       
        Request joinReq = new Request(Code.POST, Type.CON);
        joinReq.getOptions().setOscore(new byte[0]);
        joinReq.setPayload(requestPayload.EncodeToBytes());
        joinReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
       
        // Submit the request
        System.out.println("");
        System.out.println("Sent Join request to GM: " + requestPayload.toString());
        printMapPayload(requestPayload);
        
        CoapResponse r2 = c.advanced(joinReq);

        if (r2.getOptions().getLocationPath().size() != 0) {
	        System.out.print("Location-Path: ");
	        System.out.println(r2.getOptions().getLocationPathString());
        }
        
        printResponseFromRS(r2.advanced());
       
        
        Assert.assertEquals("CREATED", r2.getCode().name());
       
        byte[] responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
       
        Assert.assertEquals(CBORType.Map, joinResponse.getType());
        int credFmt;
        
        
        // DEBUG: START SET OF ASSERTIONS
        /*
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GKTY)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).getType());
        // Assume that "Group_OSCORE_Input_Material object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).AsInt32());
       
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
        Assert.assertEquals(CBORType.Map, joinResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
       
        CBORObject myMap = joinResponse.get(CBORObject.FromObject(Constants.KEY));
       
        // Sanity check
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_enc_alg)));
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
       
        // Check the presence, type and value of the authentication credential
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cred_fmt)));
        Assert.assertEquals(CBORType.Integer, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cred_fmt)).getType());
        Assert.assertEquals(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_CCS), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cred_fmt)));
        
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cred_fmt)));
        Assert.assertEquals(CBORType.Integer, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cred_fmt)).getType());
        credFmt = myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cred_fmt)).AsInt32();
       
        final byte[] masterSecret = { (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
                                      (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08,
                                      (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C,
                                      (byte) 0x0D, (byte) 0x0E, (byte) 0x0F, (byte) 0x10 };
        final byte[] masterSalt =   { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22,
                                      (byte) 0x23, (byte) 0x78, (byte) 0x63, (byte) 0x40 };
        final byte[] senderId = new byte[] { (byte) 0x25 };
        final byte[] groupId = new byte[] { (byte) 0xfe, (byte) 0xed, (byte) 0xca, (byte) 0x57, (byte) 0xf0, (byte) 0x5c };
        
        final AlgorithmID hkdf = AlgorithmID.HMAC_SHA_256;
       
        
        final AlgorithmID signEncAlg = AlgorithmID.AES_CCM_16_64_128;
        AlgorithmID signAlg = null;
        CBORObject signAlgCapabilities = CBORObject.NewArray();
        CBORObject signKeyCapabilities = CBORObject.NewArray();
        CBORObject signParams = CBORObject.NewArray();

        // ECDSA_256
        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        signAlg = AlgorithmID.ECDSA_256;
        signAlgCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
        signKeyCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
        signKeyCapabilities.Add(KeyKeys.EC2_P256); // Curve
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
        ecdhKeyCapabilities.Add(KeyKeys.EC2_P256); // Curve
        }
            
        // X25519
        if (ecdhKeyCurve == KeyKeys.OKP_X25519.AsInt32()) {
        ecdhAlgCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
        ecdhKeyCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
        ecdhKeyCapabilities.Add(KeyKeys.OKP_X25519); // Curve
        }
            
        ecdhParams.Add(ecdhAlgCapabilities);
        ecdhParams.Add(ecdhKeyCapabilities);
        
                
        Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)).GetByteString());
        Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)).GetByteString());
       
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(signEncAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_enc_alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)).GetByteString());
        Assert.assertNotNull(signAlg);
        Assert.assertEquals(signAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_alg)));
        Assert.assertNotNull(ecdhAlg);
        Assert.assertEquals(ecdhAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_alg)));
        
        // Add default values for missing parameters
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.hkdf, AlgorithmID.HMAC_SHA_256);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.salt, CBORObject.FromObject(new byte[0]));
              
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.NUM)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.NUM)).getType());
        // This assumes that the Group Manager did not rekeyed the group upon previous nodes' joining
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.NUM)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(Constants.COAP_GROUP_OSCORE_APP, joinResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).AsInt32());
       
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.EXP)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.EXP)).getType());
        Assert.assertEquals(1000000, joinResponse.get(CBORObject.FromObject(Constants.EXP)).AsInt32());
       
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(signParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)));
        }
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(ecdhParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)));
        }
       
        CBORObject authCredsArray = null;
        if (askForAuthCreds) {
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.CREDS)));
            Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(Constants.CREDS)).getType());
           
            authCredsArray = joinResponse.get(CBORObject.FromObject(Constants.CREDS));
            Assert.assertEquals(2, authCredsArray.size());
           
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)));
            Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).getType());
            Assert.assertEquals(2, joinResponse.get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).size());
            
            byte[] peerSenderId;
            OneKey peerPublicKey;
            byte[] peerSenderIdFromResponse;
           
            OneKey peerPublicKeyRetrieved = null;
            CBORObject peerAuthCredRetrieved;
            
            peerSenderId = new byte[] { (byte) 0x77 };
            peerSenderIdFromResponse = joinResponse.
                    get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).get(0).GetByteString();
            peerPublicKey = C3pubKey;
            Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
           
            peerAuthCredRetrieved = authCredsArray.get(0);
	        if (peerAuthCredRetrieved.getType() != CBORType.ByteString) {
	        	Assert.fail("Elements of the parameter 'creds' must be CBOR byte strings");
	        }
	        byte[] peerPublicKeyRetrievedBytes = peerAuthCredRetrieved.GetByteString();
	        switch (credFmt) {
	            case Constants.COSE_HEADER_PARAM_CCS:
	            	CBORObject ccs = CBORObject.DecodeFromBytes(peerPublicKeyRetrievedBytes);
	                if (ccs.getType() == CBORType.Map) {
	                	// Retrieve the public key from the CCS
	                    peerPublicKeyRetrieved = Util.ccsToOneKey(ccs);
	                }
	                else {
	                    Assert.fail("Invalid format of authentication credential");
	                }
	                break;
	            case Constants.COSE_HEADER_PARAM_CWT:
	            	CBORObject cwt = CBORObject.DecodeFromBytes(peerPublicKeyRetrievedBytes);
	                if (cwt.getType() == CBORType.Array) {
	                    // Retrieve the public key from the CWT
	                    // TODO
	                }
	                else {
	                    Assert.fail("Invalid format of authentication credential");
	                }
	                break;
	            case Constants.COSE_HEADER_PARAM_X5CHAIN:
	                // Retrieve the public key from the certificate
	                // TODO
	                break;
	            default:
	                Assert.fail("Invalid format of authentication credential");
	        }
	        if (peerPublicKeyRetrieved == null)
	            Assert.fail("Invalid format of authentication credential");
            
            // ECDSA_256
            if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_EC2, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.EC2_P256, peerPublicKeyRetrieved.get(KeyKeys.EC2_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_X.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_Y.AsCBOR()));
            }
           
            // EDDSA (Ed25519)
            if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_OKP, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.OKP_Ed25519, peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_X.AsCBOR()));
            }
            
            peerSenderId = new byte[] { (byte) 0x52 };
            peerSenderIdFromResponse = joinResponse.
                    get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).get(1).GetByteString();
            peerPublicKey = C2pubKey;
            Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
           
            peerAuthCredRetrieved = authCredsArray.get(1);
            if (peerAuthCredRetrieved.getType() != CBORType.ByteString) {
	        	Assert.fail("Elements of the parameter 'creds' must be CBOR byte strings");
	        }
	        peerPublicKeyRetrievedBytes = peerAuthCredRetrieved.GetByteString();
	        switch (credFmt) {
	            case Constants.COSE_HEADER_PARAM_CCS:
	            	CBORObject ccs = CBORObject.DecodeFromBytes(peerPublicKeyRetrievedBytes);
	                if (ccs.getType() == CBORType.Map) {
	                	// Retrieve the public key from the CCS
	                    peerPublicKeyRetrieved = Util.ccsToOneKey(ccs);
	                }
	                else {
	                    Assert.fail("Invalid format of authentication credential");
	                }
	                break;
	            case Constants.COSE_HEADER_PARAM_CWT:
	            	CBORObject cwt = CBORObject.DecodeFromBytes(peerPublicKeyRetrievedBytes);
	                if (cwt.getType() == CBORType.Array) {
	                    // Retrieve the public key from the CWT
	                    // TODO
	                }
	                else {
	                    Assert.fail("Invalid format of authentication credential");
	                }
	                break;
	            case Constants.COSE_HEADER_PARAM_X5CHAIN:
	                // Retrieve the public key from the certificate
	                // TODO
	                break;
	            default:
	                Assert.fail("Invalid format of authentication credential");
	        }
	        if (peerPublicKeyRetrieved == null)
	            Assert.fail("Invalid format of authentication credential");
            
            // ECDSA_256
            if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_EC2, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.EC2_P256, peerPublicKeyRetrieved.get(KeyKeys.EC2_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_X.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_Y.AsCBOR()));
            }
           
            // EDDSA (Ed25519)
            if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_OKP, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.OKP_Ed25519, peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_X.AsCBOR()));
            }

            
			Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
            Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).getType());
            Assert.assertEquals(2, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).size());
            
            int expectedRoles = 0;
            expectedRoles = Util.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
            expectedRoles = Util.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_RESPONDER);
            Assert.assertEquals(expectedRoles, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(0).AsInt32());
            expectedRoles = 0;
            expectedRoles = Util.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
            Assert.assertEquals(expectedRoles, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(1).AsInt32());
           
        }
        else {
            Assert.assertEquals(false, joinResponse.ContainsKey(CBORObject.FromObject(Constants.CREDS)));
            Assert.assertEquals(false, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
        }
        
		Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GROUP_POLICIES)));
        Assert.assertEquals(3600, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_KEY_CHECK_INTERVAL)).AsInt32());
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_EXP_DELTA)).AsInt32());
	    */
        // DEBUG: END SET OF ASSERTIONS
        
        
	    // Check the proof-of-possession evidence over kdc_nonce, using the GM's public key
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_NONCE)));
        Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.KDC_NONCE)).getType());
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_CRED)));
        Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED)).getType());
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_CRED_VERIFY)));
		Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED_VERIFY)).getType());
	    
	    Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
        Assert.assertEquals(CBORType.Map, joinResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
	    Assert.assertEquals(true, joinResponse.get(CBORObject.FromObject(Constants.KEY)).
	    		            ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cred_fmt)));
        Assert.assertEquals(CBORType.Map, joinResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.KEY)).
        					get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cred_fmt)).getType());
        credFmt = joinResponse.get(CBORObject.FromObject(Constants.KEY)).
							get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cred_fmt)).AsInt32();
	    
        OneKey gmPublicKeyRetrieved = null;
        byte[] kdcCredBytes = joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED)).GetByteString();
        switch (credFmt) {
            case Constants.COSE_HEADER_PARAM_CCS:
                CBORObject ccs = CBORObject.DecodeFromBytes(kdcCredBytes);
                if (ccs.getType() == CBORType.Map) {
                    // Retrieve the public key from the CCS
                    gmPublicKeyRetrieved = Util.ccsToOneKey(ccs);
                }
                else {
                    Assert.fail("Invalid format of Group Manager authentication credential");
                }
                break;
            case Constants.COSE_HEADER_PARAM_CWT:
                CBORObject cwt = CBORObject.DecodeFromBytes(kdcCredBytes);
                if (cwt.getType() == CBORType.Array) {
                    // Retrieve the public key from the CWT
                    // TODO
                }
                else {
                    Assert.fail("Invalid format of Group Manager authentication credential");
                }
                break;
            case Constants.COSE_HEADER_PARAM_X5CHAIN:
                // Retrieve the public key from the certificate
                // TODO
                break;
            default:
                Assert.fail("Invalid format of Group Manager authentication credential");
        }
        if (gmPublicKeyRetrieved == null)
        	Assert.fail("Invalid format of Group Manager authentication credential");
        
        PublicKey gmPublicKey = gmPublicKeyRetrieved.AsPublicKey();
	
	    byte[] gmNonce = joinResponse.get(CBORObject.FromObject(Constants.KDC_NONCE)).GetByteString();
		
	    CBORObject gmPopEvidence = joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED_VERIFY));
	    byte[] rawGmPopEvidence = gmPopEvidence.GetByteString();
        
        // Invalid Client's PoP signature
        if (!Util.verifySignature(signKeyCurve, gmPublicKey, gmNonce, rawGmPopEvidence)) {
        	Assert.fail("Invalid GM's PoP evidence");
        }
        
    }
    
    // === Case 2 ===
    /**
     * Test post to Authz-Info, then join using multiple roles.
     * Uses the ACE OSCORE Profile.
     * 
     * @throws Exception 
     */
    public static void testSuccessGroupOSCOREMultipleRoles() throws Exception {

    	boolean askForSignInfo = true;
    	boolean askForEcdhInfo = true;
        boolean askForAuthCreds = true;
        boolean providePublicKey = true;
        
        Map<Short, CBORObject> params = new HashMap<>(); 
        
        // Create the scope
        CBORObject cborArrayScope = CBORObject.NewArray();
        CBORObject cborArrayEntry = CBORObject.NewArray();
        
        cborArrayEntry.Add(groupName);
        
    	int myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayEntry.Add(myRoles);
    	
        cborArrayScope.Add(cborArrayEntry);
        byte[] byteStringScope = cborArrayScope.EncodeToBytes();
        
        params.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
        params.put(Constants.AUD, CBORObject.FromObject("aud2"));
        params.put(Constants.CTI, CBORObject.FromObject(
                   "token4JoinMultipleRoles".getBytes(Constants.charset))); //Need different CTI
        params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

        CBORObject osc = CBORObject.NewMap();        
        osc.Add(Constants.OS_MS, keyCnf);
        osc.Add(Constants.OS_ID, Util.intToBytes(0));
        
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.OSCORE_Input_Material, osc);
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx1).EncodeToBytes());
        payload.Add(Constants.CNF, cnf);
        Response asRes = new Response(CoAP.ResponseCode.CREATED);
        asRes.setPayload(payload.EncodeToBytes());
        
        Response rsRes = OSCOREProfileRequestsGroupOSCORE.postToken(
                		 "coap://" + rsAddr + ":" + portNumberRSnosec + "/authz-info",
                		 asRes, askForSignInfo, askForEcdhInfo, ctxDB, usedRecipientIds);
        
        printResponseFromRS(rsRes);
        
        //Check that the OSCORE context has been created:
        Assert.assertNotNull(ctxDB.getContext(
                "coap://" + rsAddr + ":" + portNumberRSnosec + "/" + rootGroupMembershipResource + "/" + groupName));
        
        CBORObject rsPayload = CBORObject.DecodeFromBytes(rsRes.getPayload());
        // Sanity checks already occurred in OSCOREProfileRequestsGroupOSCORE.postToken()
        
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
            signParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type
            
            // The key type capabilities
            signKeyParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type
            signKeyParamsExpected.Add(KeyKeys.EC2_P256); // Curve
        }

        // EDDSA (Ed25519)
        if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
            signAlgExpected = AlgorithmID.EDDSA.AsCBOR();
            
            // The algorithm capabilities
            signParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type
            
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
        ecdhParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type

        // The key type capabilities
        ecdhKeyParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type
        ecdhKeyParamsExpected.Add(KeyKeys.EC2_P256); // Curve
        }

        // X25519
        if (ecdhKeyCurve == KeyKeys.OKP_X25519.AsInt32()) {
        // The algorithm capabilities
        ecdhParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type

        // The key type capabilities
        ecdhKeyParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type
        ecdhKeyParamsExpected.Add(KeyKeys.OKP_X25519); // Curve
        }
        
        CBORObject credFmtExpected = CBORObject.FromObject(Constants.COSE_HEADER_PARAM_CCS);
                
        
        // DEBUG: START SET OF ASSERTIONS
        /*
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
		
		        Assert.assertEquals(ecdhInfo, ecdhInfoExpected);
		        
		    }
		}
        */
        // DEBUG: END SET OF ASSERTIONS
        
        
        // Now proceed with the Join request
        
        CoapClient c = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://" + rsAddr + ":" + portNumberRSnosec + "/" +
        		rootGroupMembershipResource + "/" + groupName, portNumberRSnosec),
        		ctxDB);
        
        System.out.println("Performing Join request using OSCORE to GM at " + "coap://localhost/feedca570000");
       
        CBORObject requestPayload = CBORObject.NewMap();
       
        cborArrayScope = CBORObject.NewArray();
        cborArrayScope.Add(groupName);
        
    	myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
    	cborArrayScope.Add(myRoles);
        
        byteStringScope = cborArrayScope.EncodeToBytes();
        requestPayload.Add(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
       
        if (askForAuthCreds) {
           
            CBORObject getCreds = CBORObject.NewArray();
            
            getCreds.Add(CBORObject.True); // This must be true
            
            getCreds.Add(CBORObject.NewArray());
            // The following is required to retrieve the authentication credentials of both the already present group members
            myRoles = 0;
            myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
            getCreds.get(1).Add(myRoles);            
            myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_REQUESTER);
        	myRoles = Util.addGroupOSCORERole(myRoles, Constants.GROUP_OSCORE_RESPONDER);
        	getCreds.get(1).Add(myRoles);
            
        	getCreds.Add(CBORObject.NewArray()); // This must be empty
            
            requestPayload.Add(Constants.GET_CREDS, getCreds);
           
        }
       
       if (providePublicKey) {
           
	    	// This should never happen, if the Group Manager has provided 'kdc_challenge' in the Token POST response,
	       	// or the joining node has computed N_S differently (e.g. through a TLS exporter)
	       	if (gm_nonce == null)
	       		Assert.fail("Error: the component N_S of the PoP evidence challence is null");
            
            
            byte[] authCred = null;

            /*
            // Build the authentication credential according to the format used in the group
            // Note: most likely, the result will NOT follow the required deterministic
            //       encoding in byte lexicographic order, and it has to be adjusted offline
            OneKey publicKey = C1keyPair.PublicKey();
	        switch (credFmtExpected.AsInt32()) {
	            case Constants.COSE_HEADER_PARAM_CCS:
	                // Build a CCS including the public key
	                authCred = Util.oneKeyToCCS(publicKey, "");
	                break;
	            case Constants.COSE_HEADER_PARAM_CWT:
	                // Build a CWT including the public key
	                // TODO
	                break;
	            case Constants.COSE_HEADER_PARAM_X5CHAIN:
	                // Build/retrieve the certificate including the public key
	                // TODO
	                break;
	        }
	        */
	
	        switch (credFmtExpected.AsInt32()) {
		        case Constants.COSE_HEADER_PARAM_CCS:
		            // A CCS including the public key
		            if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
		            	authCred = net.i2p.crypto.eddsa.Utils.hexToBytes("A2026008A101A5010203262001215820E8F9A8D5850A533CDA24B9FA8A1EE293F6A0E1E81E1E560A64FF134D65F7ECEC225820164A6D5D4B97F56D1F60A12811D55DE7A055EBAC6164C9EF9302CBCBFF1F0ABE");
		            }
		            if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
		            	authCred = net.i2p.crypto.eddsa.Utils.hexToBytes("A2026008A101A4010103272006215820069E912B83963ACC5941B63546867DEC106E5B9051F2EE14F3BC5CC961ACD43A");
		            }
		            break;
		        case Constants.COSE_HEADER_PARAM_CWT:
		            // A CWT including the public key
		            // TODO
		        	authCred = null;
		            break;
		        case Constants.COSE_HEADER_PARAM_X5CHAIN:
		            // A certificate including the public key
		            // TODO
		        	authCred = null;
		            break;
	        }
	
	        requestPayload.Add(Constants.CLIENT_CRED, CBORObject.FromObject(authCred));
        	
            
        	// Add the nonce for PoP of the Client's private key
            byte[] cnonce = new byte[8];
            new SecureRandom().nextBytes(cnonce);
            requestPayload.Add(Constants.CNONCE, cnonce);
            
            // Add the signature computed over (scope | rsnonce | cnonce), using the Client's private key
            int offset = 0;
            PrivateKey privKey = C1keyPair.AsPrivateKey();
            
            byte[] serializedScopeCBOR = CBORObject.FromObject(byteStringScope).EncodeToBytes();
            byte[] serializedGMNonceCBOR = CBORObject.FromObject(gm_nonce).EncodeToBytes();
            byte[] serializedCNonceCBOR = CBORObject.FromObject(cnonce).EncodeToBytes();
       	    byte [] dataToSign = new byte [serializedScopeCBOR.length + serializedGMNonceCBOR.length + serializedCNonceCBOR.length];
       	    System.arraycopy(serializedScopeCBOR, 0, dataToSign, offset, serializedScopeCBOR.length);
       	    offset += serializedScopeCBOR.length;
       	    System.arraycopy(serializedGMNonceCBOR, 0, dataToSign, offset, serializedGMNonceCBOR.length);
       	    offset += serializedGMNonceCBOR.length;
       	    System.arraycopy(serializedCNonceCBOR, 0, dataToSign, offset, serializedCNonceCBOR.length);
                   	   
       	    byte[] clientSignature = Util.computeSignature(signKeyCurve, privKey, dataToSign);
            
            if (clientSignature != null)
            	requestPayload.Add(Constants.CLIENT_CRED_VERIFY, clientSignature);
        	else
        		Assert.fail("Computed signature is empty");
           
        }
       
        Request joinReq = new Request(Code.POST, Type.CON);
        joinReq.getOptions().setOscore(new byte[0]);
        joinReq.setPayload(requestPayload.EncodeToBytes());
        joinReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
       
        //Submit the request
        System.out.println("");
        System.out.println("Sent Join request to GM: " + requestPayload.toString());
        printMapPayload(requestPayload);
        
        CoapResponse r2 = c.advanced(joinReq);
       
        if (r2.getOptions().getLocationPath().size() != 0) {
	        System.out.print("Location-Path: ");
	        System.out.println(r2.getOptions().getLocationPathString());
        }
        
        printResponseFromRS(r2.advanced());
        

        Assert.assertEquals("CREATED", r2.getCode().name());
       
        byte[] responsePayload = r2.getPayload();
        CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);
       
        Assert.assertEquals(CBORType.Map, joinResponse.getType());
        int credFmt;
       
        
        // DEBUG: START SET OF ASSERTIONS
        /*
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GKTY)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).getType());
        // Assume that "Group_OSCORE_Input_Material object" is registered with value 0 in the "ACE Groupcomm Key" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(Constants.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, joinResponse.get(CBORObject.FromObject(Constants.GKTY)).AsInt32());
       
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
        Assert.assertEquals(CBORType.Map, joinResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
       
        CBORObject myMap = joinResponse.get(CBORObject.FromObject(Constants.KEY));
       
        // Sanity check
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_enc_alg)));
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

       
        // Check the presence, type and value of the authentication credential encoding
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cred_fmt)));
        Assert.assertEquals(CBORType.Integer, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cred_fmt)).getType());        
        Assert.assertEquals(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_CCS), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cred_fmt)));
       
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cred_fmt)));
        Assert.assertEquals(CBORType.Integer, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cred_fmt)).getType());
        credFmt = myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cred_fmt)).AsInt32();
        
        final byte[] masterSecret = { (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
                                      (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08,
                                      (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C,
                                      (byte) 0x0D, (byte) 0x0E, (byte) 0x0F, (byte) 0x10 };
        final byte[] masterSalt =   { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22,
                                      (byte) 0x23, (byte) 0x78, (byte) 0x63, (byte) 0x40 };
        final byte[] senderId = new byte[] { (byte) 0x25 };
        final byte[] groupId = new byte[] { (byte) 0xfe, (byte) 0xed, (byte) 0xca, (byte) 0x57, (byte) 0xf0, (byte) 0x5c };

        final AlgorithmID hkdf = AlgorithmID.HMAC_SHA_256;
       
        
        final AlgorithmID signEncAlg = AlgorithmID.AES_CCM_16_64_128;
        AlgorithmID signAlg = null;
        CBORObject signAlgCapabilities = CBORObject.NewArray();
        CBORObject signKeyCapabilities = CBORObject.NewArray();
        CBORObject signParams = CBORObject.NewArray();

        // ECDSA_256
        if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
        signAlg = AlgorithmID.ECDSA_256;
        signAlgCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
        signKeyCapabilities.Add(KeyKeys.KeyType_EC2); // Key Type
        signKeyCapabilities.Add(KeyKeys.EC2_P256); // Curve
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
        ecdhKeyCapabilities.Add(KeyKeys.EC2_P256); // Curve
        }
            
        // X25519
        if (ecdhKeyCurve == KeyKeys.OKP_X25519.AsInt32()) {
        ecdhAlgCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
        ecdhKeyCapabilities.Add(KeyKeys.KeyType_OKP); // Key Type
        ecdhKeyCapabilities.Add(KeyKeys.OKP_X25519); // Curve
        }
            
        ecdhParams.Add(ecdhAlgCapabilities);
        ecdhParams.Add(ecdhKeyCapabilities);
        

        Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)).GetByteString());
        Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)).GetByteString());
       
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(signEncAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_enc_alg)));
        Assert.assertArrayEquals(masterSalt, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)).GetByteString());
        Assert.assertArrayEquals(groupId, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.contextId)).GetByteString());
        Assert.assertNotNull(signAlg);
        Assert.assertEquals(signAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_alg)));
        Assert.assertNotNull(ecdhAlg);
        Assert.assertEquals(ecdhAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_alg)));
        
        // Add default values for missing parameters
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.hkdf, AlgorithmID.HMAC_SHA_256);
        if (myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.salt)) == false)
            myMap.Add(OSCOREInputMaterialObjectParameters.salt, CBORObject.FromObject(new byte[0]));
       
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.NUM)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.NUM)).getType());
        // This assumes that the Group Manager did not rekeyed the group upon previous nodes' joining
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.NUM)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).getType());
        // Assume that "coap_group_oscore" is registered with value 0 in the "ACE Groupcomm Profile" Registry of draft-ietf-ace-key-groupcomm
        Assert.assertEquals(Constants.COAP_GROUP_OSCORE_APP, joinResponse.get(CBORObject.FromObject(Constants.ACE_GROUPCOMM_PROFILE)).AsInt32());
       
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.EXP)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.EXP)).getType());
        Assert.assertEquals(1000000, joinResponse.get(CBORObject.FromObject(Constants.EXP)).AsInt32());
       
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(signParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)));
        }
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(ecdhParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)));
        }
        
        CBORObject authCredsArray = null;
        if (askForAuthCreds) {
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.CREDS)));
            Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(Constants.CREDS)).getType());
           
            authCredsArray = joinResponse.get(CBORObject.FromObject(Constants.CREDS));
            Assert.assertEquals(2, authCredsArray.size());
           
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)));
            Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).getType());
            Assert.assertEquals(2, joinResponse.get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).size());
            
            byte[] peerSenderId;
            OneKey peerPublicKey;
            byte[] peerSenderIdFromResponse;
           
            OneKey peerPublicKeyRetrieved = null;
            CBORObject peerAuthCredRetrieved;
            
            peerSenderId = new byte[] { (byte) 0x77 };
            peerSenderIdFromResponse = joinResponse.
                    get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).get(0).GetByteString();
            peerPublicKey = C3pubKey;
            Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
           
            peerAuthCredRetrieved = authCredsArray.get(0);
	            if (peerAuthCredRetrieved.getType() != CBORType.ByteString) {
	        	Assert.fail("Elements of the parameter 'creds' must be CBOR byte strings");
	        }
	        byte[] peerAuthCredRetrievedBytes = peerAuthCredRetrieved.GetByteString();
	        switch (credFmt) {
	            case Constants.COSE_HEADER_PARAM_CCS:
	            	CBORObject ccs = CBORObject.DecodeFromBytes(peerAuthCredRetrievedBytes);
	                if (ccs.getType() == CBORType.Map) {
	                	// Retrieve the public key from the CCS
	                    peerPublicKeyRetrieved = Util.ccsToOneKey(ccs);
	                }
	                else {
	                    Assert.fail("Invalid format of authentication credential");
	                }
	                break;
	            case Constants.COSE_HEADER_PARAM_CWT:
	            	CBORObject cwt = CBORObject.DecodeFromBytes(peerAuthCredRetrievedBytes);
	                if (cwt.getType() == CBORType.Array) {
	                    // Retrieve the public key from the CWT
	                    // TODO
	                }
	                else {
	                    Assert.fail("Invalid format of authentication credential");
	                }
	                break;
	            case Constants.COSE_HEADER_PARAM_X5CHAIN:
	                // Retrieve the public key from the certificate
	                // TODO
	                break;
	            default:
	                Assert.fail("Invalid format of authentication credential");
	        }
	        if (peerPublicKeyRetrieved == null)
	            Assert.fail("Invalid format of authentication credential");
            
            // ECDSA_256
            if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_EC2, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.EC2_P256, peerPublicKeyRetrieved.get(KeyKeys.EC2_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_X.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_Y.AsCBOR()));
            }
           
            // EDDSA (Ed25519)
            if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_OKP, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.OKP_Ed25519, peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_X.AsCBOR()));
            }
            
            peerSenderId = new byte[] { (byte) 0x52 };
            peerSenderIdFromResponse = joinResponse.
                    get(CBORObject.FromObject(Constants.PEER_IDENTIFIERS)).get(1).GetByteString();
            peerPublicKey = C2pubKey;
            Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
           
            peerAuthCredRetrieved = authCredsArray.get(1);
	            if (peerAuthCredRetrieved.getType() != CBORType.ByteString) {
	        	Assert.fail("Elements of the parameter 'creds' must be CBOR byte strings");
	        }
	        peerAuthCredRetrievedBytes = peerAuthCredRetrieved.GetByteString();
	        switch (credFmt) {
	            case Constants.COSE_HEADER_PARAM_CCS:
	            	CBORObject ccs = CBORObject.DecodeFromBytes(peerAuthCredRetrievedBytes);
	                if (ccs.getType() == CBORType.Map) {
	                	// Retrieve the public key from the CCS
	                    peerPublicKeyRetrieved = Util.ccsToOneKey(ccs);
	                }
	                else {
	                    Assert.fail("Invalid format of authentication credential");
	                }
	                break;
	            case Constants.COSE_HEADER_PARAM_CWT:
	            	CBORObject cwt = CBORObject.DecodeFromBytes(peerAuthCredRetrievedBytes);
	                if (cwt.getType() == CBORType.Array) {
	                    // Retrieve the public key from the CWT
	                    // TODO
	                }
	                else {
	                    Assert.fail("Invalid format of authentication credential");
	                }
	                break;
	            case Constants.COSE_HEADER_PARAM_X5CHAIN:
	                // Retrieve the public key from the certificate
	                // TODO
	                break;
	            default:
	                Assert.fail("Invalid format of authentication credential");
	        }
	        if (peerPublicKeyRetrieved == null)
	            Assert.fail("Invalid format of authentication credential");
            
            // ECDSA_256
            if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_EC2, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.EC2_P256, peerPublicKeyRetrieved.get(KeyKeys.EC2_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_X.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.EC2_Y.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.EC2_Y.AsCBOR()));
            }
           
            // EDDSA (Ed25519)
            if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
                Assert.assertEquals(KeyKeys.KeyType_OKP, peerPublicKeyRetrieved.get(KeyKeys.KeyType.AsCBOR()));
                Assert.assertEquals(KeyKeys.OKP_Ed25519, peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_Curve.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_Curve.AsCBOR()));
                Assert.assertEquals(peerPublicKey.get(KeyKeys.OKP_X.AsCBOR()), peerPublicKeyRetrieved.get(KeyKeys.OKP_X.AsCBOR()));
            }

            
			Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
            Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).getType());
            Assert.assertEquals(2, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).size());
            
            int expectedRoles = 0;
            expectedRoles = Util.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
            expectedRoles = Util.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_RESPONDER);
            Assert.assertEquals(expectedRoles, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(0).AsInt32());
            expectedRoles = 0;
            expectedRoles = Util.addGroupOSCORERole(expectedRoles, Constants.GROUP_OSCORE_REQUESTER);
            Assert.assertEquals(expectedRoles, joinResponse.get(CBORObject.FromObject(Constants.PEER_ROLES)).get(1).AsInt32());
           
        }
        else {
            Assert.assertEquals(false, joinResponse.ContainsKey(CBORObject.FromObject(Constants.CREDS)));
            Assert.assertEquals(false, joinResponse.ContainsKey(CBORObject.FromObject(Constants.PEER_ROLES)));
        }
        
		Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.GROUP_POLICIES)));
        Assert.assertEquals(3600, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_KEY_CHECK_INTERVAL)).AsInt32());
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(Constants.GROUP_POLICIES)).get(CBORObject.FromObject(Constants.POLICY_EXP_DELTA)).AsInt32());
        */
        // DEBUG: END SET OF ASSERTIONS
        
        
        
	    // Check the proof-of-possession evidence over kdc_nonce, using the GM's public key
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_NONCE)));
        Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.KDC_NONCE)).getType());
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_CRED)));
        Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED)).getType());
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KDC_CRED_VERIFY)));
		Assert.assertEquals(CBORType.ByteString, joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED_VERIFY)).getType());
        
	    Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(Constants.KEY)));
        Assert.assertEquals(CBORType.Map, joinResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
	    Assert.assertEquals(true, joinResponse.get(CBORObject.FromObject(Constants.KEY)).
	    		            ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cred_fmt)));
        Assert.assertEquals(CBORType.Map, joinResponse.get(CBORObject.FromObject(Constants.KEY)).getType());
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(Constants.KEY)).
        					get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cred_fmt)).getType());
        credFmt = joinResponse.get(CBORObject.FromObject(Constants.KEY)).
							get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cred_fmt)).AsInt32();
	    
        OneKey gmPublicKeyRetrieved = null;
        byte[] kdcCredBytes = joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED)).GetByteString();
        switch (credFmt) {
            case Constants.COSE_HEADER_PARAM_CCS:
                CBORObject ccs = CBORObject.DecodeFromBytes(kdcCredBytes);
                if (ccs.getType() == CBORType.Map) {
                    // Retrieve the public key from the CCS
                    gmPublicKeyRetrieved = Util.ccsToOneKey(ccs);
                }
                else {
                    Assert.fail("Invalid format of Group Manager authentication credential");
                }
                break;
            case Constants.COSE_HEADER_PARAM_CWT:
                CBORObject cwt = CBORObject.DecodeFromBytes(kdcCredBytes);
                if (cwt.getType() == CBORType.Array) {
                    // Retrieve the public key from the CWT
                    // TODO
                }
                else {
                    Assert.fail("Invalid format of Group Manager authentication credential");
                }
                break;
            case Constants.COSE_HEADER_PARAM_X5CHAIN:
                // Retrieve the public key from the certificate
                // TODO
                break;
            default:
                Assert.fail("Invalid format of Group Manager authentication credential");
        }
        if (gmPublicKeyRetrieved == null)
        	Assert.fail("Invalid format of Group Manager authentication credential");
        
        PublicKey gmPublicKey = gmPublicKeyRetrieved.AsPublicKey();
	
	    byte[] gmNonce = joinResponse.get(CBORObject.FromObject(Constants.KDC_NONCE)).GetByteString();
		
	    CBORObject gmPopEvidence = joinResponse.get(CBORObject.FromObject(Constants.KDC_CRED_VERIFY));
	    byte[] rawGmPopEvidence = gmPopEvidence.GetByteString();
        
        // Invalid Client's PoP signature
        if (!Util.verifySignature(signKeyCurve, gmPublicKey, gmNonce, rawGmPopEvidence)) {
        	Assert.fail("Invalid GM's PoP evidence");
        }

    }
    
    // End tests with the Group Manager
    
}
