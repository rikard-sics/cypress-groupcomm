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
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.Type;
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

import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.Utils;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
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
 * a candidate OSCORE group member acting as ACE Client and
 * an OSCORE Group Manager acting as ACE Resource Server.
 * 
 * @author Marco Tiloca and Rikard Höglund
 *
 */
public class TestOscorepClient2RSGroupOSCORE {

	private final String rootGroupMembershipResource = "ace-group";
	
    private static byte[] groupKeyPair;
    private static byte[] groupKeyPairUpdate;
    private static byte[] publicKeyPeer1;
    private static byte[] publicKeyPeer2;
	private static byte[] publicKeyGM;
	
    // Uncomment to set ECDSA with curve P-256 for countersignatures
    // private static int signKeyCurve = KeyKeys.EC2_P256.AsInt32();
    
    // Uncomment to set EDDSA with curve Ed25519 for countersignatures
    private static int signKeyCurve = KeyKeys.OKP_Ed25519.AsInt32();
    
    // Uncomment to set curve P-256 for pairwise key derivation
    // private static int ecdhKeyCurve = KeyKeys.EC2_P256.AsInt32();
    
    // Uncomment to set curve X25519 for pairwise key derivation
    private static int ecdhKeyCurve = KeyKeys.OKP_X25519.AsInt32();

    private final static int MAX_UNFRAGMENTED_SIZE = 4096;
    
    /**
     * The cnf key used in these tests
     */
    private static byte[] keyCnf = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    
    /**
     * The AS <-> RS key used in these tests
     */
    private static byte[] keyASRS = {'c', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    private static RunTestServer srv = null;
    private static OSCoreCtx osctx;
    
    private static OSCoreCtxDB ctxDB;
    
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
            TestOscorepRSGroupOSCORE.stop();
        }
        
        @Override
        public void run() {
            try {
            	TestOscorepRSGroupOSCORE.main(null);
            } catch (final Throwable t) {
                System.err.println(t.getMessage());
                try {
                	TestOscorepRSGroupOSCORE.stop();
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
        final Provider PROVIDER = new BouncyCastleProvider();
        final Provider EdDSA = new EdDSASecurityProvider();
        Security.insertProviderAt(PROVIDER, 2);
        Security.insertProviderAt(EdDSA, 1);

        srv = new RunTestServer();
        srv.run();
        //Initialize a fake context
        osctx = new OSCoreCtx(keyCnf, true, null, 
                "clientA".getBytes(Constants.charset),
                "rs1".getBytes(Constants.charset),
                null, null, null, null, MAX_UNFRAGMENTED_SIZE);
        
		// ECDSA asymmetric keys, as serialization of COSE Keys
    	if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
    		
    	    // Private and public key to be used in the OSCORE group (ECDSA_256)
    	    groupKeyPair = Utils.hexToBytes("a6010203262001215820e8f9a8d5850a533cda24b9fa8a1ee293f6a0e1e81e1e560a64ff134d65f7ecec225820164a6d5d4b97f56d1f60a12811d55de7a055ebac6164c9ef9302cbcbff1f0abe2358203be0047599b42aa44b8f8a0fa88d4da11697b58d9fcc4e39443e9843bf230586");
    	    
    	    // Alternative private and public key, for later uploading of a new public key (ECDSA_256)
    	    groupKeyPairUpdate = Utils.hexToBytes("a6010203262001215820d8692e6cc344a51bb8d62ab768c52f3d281317b789f4f123614806d0b051443d225820a9f0024604bb007c4a92210fef5ca81c779bc5303f8c1e65f2686b81d22440882358208b17ca790a93761b2e6febb6b7fe56d211b6623ca9dafd9f34fee0bfaaef9644");
    	    
    	    // Public key to be received for the group member with Sender ID 0x52 (ECDSA_256)
    	    publicKeyPeer1 = Utils.hexToBytes("a501020326200121582035f3656092e1269aaaee6262cd1c0d9d38ed78820803305bc8ea41702a50b3af2258205d31247c2959e7b7d3f62f79622a7082ff01325fc9549e61bb878c2264df4c4f");
    	    
    	    // Public key to be received for the group member with Sender ID 0x77 (ECDSA_256)
    	    publicKeyPeer2 = Utils.hexToBytes("a50102032620012158209dfa6d63fd1515761460b7b02d54f8d7345819d2e5576c160d3148cc7886d5f122582076c81a0c1a872f1730c10317ab4f3616238fb23a08719e8b982b2d9321a2ef7d");
    		
    	    // Public key of the Group Manager (ECDSA_256)
    	    publicKeyGM = Utils.hexToBytes("a50102032620012158202236658ca675bb62d7b24623db0453a3b90533b7c3b221cc1c2c73c4e919d540225820770916bc4c97c3c46604f430b06170c7b3d6062633756628c31180fa3bb65a1b");
    	}

    	// EDDSA asymmetric keys, as serialization of COSE Keys
    	if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
    		
    	    // Private and public key to be used in the OSCORE group (EDDSA - Ed25519)
    	    groupKeyPair = Utils.hexToBytes("a5010103272006215820069e912b83963acc5941b63546867dec106e5b9051f2ee14f3bc5cc961acd43a23582064714d41a240b61d8d823502717ab088c9f4af6fc9844553e4ad4c42cc735239");
    	    
    	    // Alternative private and public key, for later uploading of a new public key (EDDSA - Ed25519)
    	    groupKeyPairUpdate = Utils.hexToBytes("a501010327200621582021c96449bdf354f6c8306b96cfd9e62859b5190e27c0f926fbeea144606db40423582066c22513317788e57c3c50b60462a8462d0adb61e609e62f0bcc6ad6e8b60b97");
    	    
    	    // Public key to be received for the group member with Sender ID 0x52 (EDDSA - Ed25519)
    	    publicKeyPeer1 = Utils.hexToBytes("a401010327200621582077ec358c1d344e41ee0e87b8383d23a2099acd39bdf989ce45b52e887463389b");
    	    
    	    // Public key to be received for the group member with Sender ID 0x77 (EDDSA - Ed25519)
    	    publicKeyPeer2 = Utils.hexToBytes("a4010103272006215820105b8c6a8c88019bf0c354592934130baa8007399cc2ac3be845884613d5ba2e");
    		
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
        osc.Add(Constants.OS_MS, keyCnf);
        osc.Add(Constants.OS_ID, Util.intToBytes(0));
        
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
                "coap://localhost/authz-info", asRes, ctxDB, usedRecipientIds);
        
        assert(rsRes.getCode().equals(CoAP.ResponseCode.CREATED));
        
        //Check that the OSCORE context has been created:
        Assert.assertNotNull(ctxDB.getContext("coap://localhost/helloWorld"));
       
       //Submit a request

       CoapClient c = OSCOREProfileRequestsGroupOSCORE.getClient(new InetSocketAddress(
               "coap://localhost/helloWorld", CoAP.DEFAULT_COAP_PORT), ctxDB);
       
       Request helloReq = new Request(CoAP.Code.GET);
       helloReq.getOptions().setOscore(new byte[0]);
       CoapResponse helloRes = c.advanced(helloReq);
       Assert.assertEquals("Hello World!", helloRes.getResponseText());
       
       //Submit a forbidden request
       
       CoapClient c2 = OSCOREProfileRequestsGroupOSCORE.getClient(new InetSocketAddress(
               "coap://localhost/temp", CoAP.DEFAULT_COAP_PORT), ctxDB);
       
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
     * Test post to Authz-Info, then join using a single role.
     * Uses the ACE OSCORE Profile.
     * 
     * @throws Exception 
     */
    @Test
	@Ignore
    public void testSuccessGroupOSCORESingleRole() throws Exception {

    	boolean askForSignInfo = true;
    	boolean askForEcdhInfo = true;
        boolean askForAuthCreds = true;
        boolean provideAuthCred = true;
        
        //Generate a token
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx 
            = CwtCryptoCtx.encrypt0(keyASRS, coseP.getAlg().AsCBOR());
        Map<Short, CBORObject> params = new HashMap<>(); 
        
        //Create the scope        
        CBORObject cborArrayScope = CBORObject.NewArray();
        CBORObject cborArrayEntry = CBORObject.NewArray();
        
        String groupName = new String("feedca570000");
        String nodeResourceLocationPath = "";
        cborArrayEntry.Add(groupName);
        
    	int myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
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
        osc.Add(Constants.OS_ID, Util.intToBytes(1));
        
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.OSCORE_Input_Material, osc);
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx).EncodeToBytes());
        payload.Add(Constants.CNF, cnf);
        Response asRes = new Response(CoAP.ResponseCode.CREATED);
        asRes.setPayload(payload.EncodeToBytes());
        Response rsRes = OSCOREProfileRequestsGroupOSCORE.postToken(
                "coap://localhost/authz-info", asRes, askForSignInfo, askForEcdhInfo, ctxDB, usedRecipientIds);
        assert(rsRes.getCode().equals(CoAP.ResponseCode.CREATED));
        
        //Check that the OSCORE context has been created:
        Assert.assertNotNull(ctxDB.getContext(
                "coap://localhost/" + rootGroupMembershipResource + "/" + groupName));
        
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
        
        CoapClient c = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" +
        		groupName, CoAP.DEFAULT_COAP_PORT), ctxDB);
        
        CBORObject requestPayload = CBORObject.NewMap();
        
        // Prepare material for later tests
        final byte[] masterSecret = { (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
                (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08,
                (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C,
                (byte) 0x0D, (byte) 0x0E, (byte) 0x0F, (byte) 0x10 };
        final byte[] masterSalt =   { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22,
                (byte) 0x23, (byte) 0x78, (byte) 0x63, (byte) 0x40 };
		final byte[] groupId = new byte[] { (byte) 0xfe, (byte) 0xed, (byte) 0xca, (byte) 0x57, (byte) 0xf0, (byte) 0x5c };

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

		        
        /////////////////
        //
        // Part 1
        //
        /////////////////
        
        // Send a Join Request
        
        System.out.println("\nPerforming Join Request using OSCORE to GM at " +
        				   "coap://localhost/" + rootGroupMembershipResource + "/" + groupName);

        requestPayload = CBORObject.NewMap();
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayScope.Add(groupName);

        myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
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
            
            /*
        	// Build the authentication credential according to the format used in the group
        	// Note: most likely, the result will NOT follow the required deterministic
        	//       encoding in byte lexicographic order, and it has to be adjusted offline
            OneKey publicKey = new OneKey(CBORObject.DecodeFromBytes(groupKeyPair)).PublicKey();
            switch (credFmtExpected.AsInt32()) {
            	case Constants.COSE_HEADER_PARAM_KCCS:
            		// Build a CCS including the public key
            		cred = Util.oneKeyToCCS(publicKey, "");
            		break;
            	case Constants.COSE_HEADER_PARAM_KCWT:
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
       	    byte[] popInput = new byte[serializedScopeCBOR.length +
       	                               serializedGMNonceCBOR.length +
       	                               serializedCNonceCBOR.length];
       	    System.arraycopy(serializedScopeCBOR, 0, popInput, offset, serializedScopeCBOR.length);
       	    offset += serializedScopeCBOR.length;
       	    System.arraycopy(serializedGMNonceCBOR, 0, popInput, offset, serializedGMNonceCBOR.length);
       	    offset += serializedGMNonceCBOR.length;
       	    System.arraycopy(serializedCNonceCBOR, 0, popInput, offset, serializedCNonceCBOR.length);
            
       	    
       	    byte[] popEvidence = Util.computeSignature(signKeyCurve, privKey, popInput);
            
            if (popEvidence != null)
            	requestPayload.Add(GroupcommParameters.CLIENT_CRED_VERIFY,popEvidence);
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
        CoapResponse r2 = c.advanced(joinReq);
       
        System.out.println("Received Join Reponse from the GM: " +
        				   CBORObject.DecodeFromBytes(r2.getPayload()).toString()); 
        
        Assert.assertEquals("CREATED", r2.getCode().name());
       
        if (r2.getOptions().getLocationPath().size() != 0) {
	        System.out.print("Location-Path: ");
	        System.out.println(r2.getOptions().getLocationPathString());
	        nodeResourceLocationPath = r2.getOptions().getLocationPathString();
        }
        
    	final byte[] senderId = new byte[] { (byte) 0x25 };
    	
        String nodeName =  Utils.bytesToHex(groupId) + "-" + Utils.bytesToHex(senderId);
        
        String uriNodeResource = new String (rootGroupMembershipResource + "/" +
        									 groupName + "/nodes/" + nodeName);
        Assert.assertEquals(uriNodeResource, r2.getOptions().getLocationPathString());
        
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
        
        Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)).GetByteString());
        Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)).GetByteString());
       
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(gpEncAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.gp_enc_alg)));
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
              
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.NUM)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(GroupcommParameters.NUM)).getType());
        // This assumes that the Group Manager did not rekey the group upon previous nodes' joining
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(GroupcommParameters.NUM)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.ACE_GROUPCOMM_PROFILE)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(GroupcommParameters.ACE_GROUPCOMM_PROFILE)).getType());
        Assert.assertEquals(GroupcommParameters.COAP_GROUP_OSCORE_APP, joinResponse.get(CBORObject.FromObject(GroupcommParameters.ACE_GROUPCOMM_PROFILE)).AsInt32());
       
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.EXP)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(GroupcommParameters.EXP)).getType());
        Assert.assertEquals(2682374400L, joinResponse.get(CBORObject.FromObject(GroupcommParameters.EXP)).AsInt64Value());
        
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
        
        CBORObject authCredsArray = null;
        
        if (askForAuthCreds) {
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.CREDS)));
            Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(GroupcommParameters.CREDS)).getType());
           
            authCredsArray = joinResponse.get(CBORObject.FromObject(GroupcommParameters.CREDS));
            Assert.assertEquals(2, authCredsArray.size());
           
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)));
            Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)).getType());
            Assert.assertEquals(2, joinResponse.get(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)).size());
            
            byte[] peerSenderId;
            OneKey peerPublicKey;
            OneKey peerPublicKeyRetrieved = null;
            CBORObject peerAuthCredRetrieved;
            byte[] peerSenderIdFromResponse;
            
            
            peerSenderId = new byte[] { (byte) 0x77 };
            peerSenderIdFromResponse = joinResponse.
 				   get(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)).get(0).GetByteString();
            peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(publicKeyPeer2));
            Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
            
            peerAuthCredRetrieved = authCredsArray.get(0);
            if (peerAuthCredRetrieved.getType() != CBORType.ByteString) {
            	Assert.fail("Elements of the parameter 'creds' must be CBOR byte strings");
            }
            byte[] peerPublicKeyRetrievedBytes = peerAuthCredRetrieved.GetByteString();
            switch (credFmt) {
                case Constants.COSE_HEADER_PARAM_KCCS:
                	CBORObject ccs = CBORObject.DecodeFromBytes(peerPublicKeyRetrievedBytes);
                    if (ccs.getType() == CBORType.Map) {
                    	// Retrieve the public key from the CCS
                        peerPublicKeyRetrieved = Util.ccsToOneKey(ccs);
                    }
                    else {
                        Assert.fail("Invalid format of authentication credential");
                    }
                    break;
                case Constants.COSE_HEADER_PARAM_KCWT:
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
 				   get(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)).get(1).GetByteString();
            peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(publicKeyPeer1));
            Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
           
            peerAuthCredRetrieved = authCredsArray.get(1);
            if (peerAuthCredRetrieved.getType() != CBORType.ByteString) {
            	Assert.fail("Elements of the parameter 'creds' must be CBOR byte strings");
            }
            peerPublicKeyRetrievedBytes = peerAuthCredRetrieved.GetByteString();
            switch (credFmt) {
                case Constants.COSE_HEADER_PARAM_KCCS:
                	CBORObject ccs = CBORObject.DecodeFromBytes(peerPublicKeyRetrievedBytes);
                    if (ccs.getType() == CBORType.Map) {
                    	// Retrieve the public key from the CCS
                        peerPublicKeyRetrieved = Util.ccsToOneKey(ccs);
                    }
                    else {
                        Assert.fail("Invalid format of authentication credential");
                    }
                    break;
                case Constants.COSE_HEADER_PARAM_KCWT:
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
            
            
			Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)));
            Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)).getType());
            Assert.assertEquals(2, joinResponse.get(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)).size());
            
            int expectedRoles = 0;
            expectedRoles = Util.addGroupOSCORERole(expectedRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
            expectedRoles = Util.addGroupOSCORERole(expectedRoles, GroupcommParameters.GROUP_OSCORE_RESPONDER);
            Assert.assertEquals(expectedRoles, joinResponse.get(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)).get(0).AsInt32());
            expectedRoles = 0;
            expectedRoles = Util.addGroupOSCORERole(expectedRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
            Assert.assertEquals(expectedRoles, joinResponse.get(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)).get(1).AsInt32());
            
           
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
        
        int offset = 0;
		byte[] serializedGMNonceCBOR = joinResponse.get(CBORObject.FromObject(GroupcommParameters.KDC_NONCE)).EncodeToBytes();
		byte[] popInput = new byte[serializedCNonceCBOR.length + serializedGMNonceCBOR.length];
		System.arraycopy(serializedCNonceCBOR, 0, popInput, offset, serializedCNonceCBOR.length);
		offset += serializedCNonceCBOR.length;
		System.arraycopy(serializedGMNonceCBOR, 0, popInput, offset, serializedGMNonceCBOR.length);
		
    	CBORObject gmPopEvidence = joinResponse.get(CBORObject.FromObject(GroupcommParameters.KDC_CRED_VERIFY));
    	byte[] rawGmPopEvidence = gmPopEvidence.GetByteString();
    	
    	PublicKey gmPublicKey = gmPublicKeyRetrieved.AsPublicKey();
            	
    	Assert.assertEquals(true, Util.verifySignature(signKeyCurve, gmPublicKey, popInput, rawGmPopEvidence));
    	
        
        /////////////////
        //
        // Part 2
        //
        /////////////////
        
        // Send a second Key Distribution Request, now as a group member
        
        System.out.println("\nPerforming a Key Distribution Rquest using OSCORE to GM at " +
        				   "coap://localhost/" + rootGroupMembershipResource + "/" + groupName);
        
        Request keyDistrReq = new Request(Code.GET, Type.CON);
        keyDistrReq.getOptions().setOscore(new byte[0]);        
        
        System.out.println("");
        System.out.println("Sent Key Distribution request to GM as non member");
        CoapResponse r3 = c.advanced(keyDistrReq);
       
        Assert.assertEquals("CONTENT", r3.getCode().name());
        
        responsePayload = r3.getPayload();
        CBORObject keyDistributionResponse = CBORObject.DecodeFromBytes(responsePayload);
       
        Assert.assertEquals(CBORType.Map, keyDistributionResponse.getType());
       
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.GKTY)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.GKTY)).getType());
        Assert.assertEquals(GroupcommParameters.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, keyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.GKTY)).AsInt32());
       
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.KEY)));
        Assert.assertEquals(CBORType.Map, keyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.KEY)).getType());
       
        myMap = keyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.KEY));
       
        // Sanity check
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)));
        Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)));
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
        
        Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)).GetByteString());
       
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(gpEncAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.gp_enc_alg)));
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
              
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.NUM)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.NUM)).getType());
        // This assumes that the Group Manager did not rekey the group upon previous nodes' joining
        Assert.assertEquals(0, keyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.NUM)).AsInt32());
        
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.ACE_GROUPCOMM_PROFILE)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.ACE_GROUPCOMM_PROFILE)).getType());
        Assert.assertEquals(GroupcommParameters.COAP_GROUP_OSCORE_APP, keyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.ACE_GROUPCOMM_PROFILE)).AsInt32());
       
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.EXP)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.EXP)).getType());
        Assert.assertEquals(2682374400L, keyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.EXP)).AsInt64Value());
        
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.EXI)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.EXI)).getType());
       
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(signParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)));
        }
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(ecdhParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)));
        }
        
        
        /////////////////
        //
        // Part 3
        //
        /////////////////
		
        // Send a Version Request
        
        System.out.println("Performing a Version Request using OSCORE to GM at " +
        				   "coap://localhost/" + rootGroupMembershipResource + "/" + groupName + "/num");
        
        CoapClient c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" +
        		groupName + "/num", CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        Request VersionReq = new Request(Code.GET, Type.CON);
        VersionReq.getOptions().setOscore(new byte[0]);
        CoapResponse r4 = c1.advanced(VersionReq);
        
        System.out.println("");
        System.out.println("Sent Version request to GM");

        Assert.assertEquals("CONTENT", r4.getCode().name());
        
        CBORObject myObject = CBORObject.DecodeFromBytes(r4.getPayload());
        Assert.assertEquals(CBORType.Integer, myObject.getType());
        Assert.assertEquals(0, myObject.AsInt32());
        
        
        /////////////////
        //
        // Part 4
        //
        /////////////////
		
        // Send a Group Status Request
        
        System.out.println("Performing a Group Status Request using OSCORE to GM at " +
        				   "coap://localhost/" + rootGroupMembershipResource + "/" + groupName + "/active");
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" +
        		groupName + "/active", CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        Request GroupStatusReq = new Request(Code.GET, Type.CON);
        GroupStatusReq.getOptions().setOscore(new byte[0]);
        CoapResponse r5 = c1.advanced(GroupStatusReq);
        
        System.out.println("");
        System.out.println("Sent Group Status request to GM");

        Assert.assertEquals("CONTENT", r5.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r5.getPayload());
        Assert.assertEquals(CBORType.Boolean, myObject.getType());
        Assert.assertEquals(true, myObject.AsBoolean());
        
        
        /////////////////
        //
        // Part 5
        //
        /////////////////
		
        // Send a Policies Request
        
        System.out.println("Performing a Policies Request using OSCORE to GM at " +
        				   "coap://localhost/" + rootGroupMembershipResource + "/" + groupName + "/policies");
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" +
        		groupName + "/policies", CoAP.DEFAULT_COAP_PORT),
        		ctxDB);
                
        Request GroupPoliciesReq = new Request(Code.GET, Type.CON);
        GroupPoliciesReq.getOptions().setOscore(new byte[0]);
        CoapResponse r6 = c1.advanced(GroupPoliciesReq);
        
        System.out.println("");
        System.out.println("Sent Group Policies request to GM");

        Assert.assertEquals("CONTENT", r6.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r6.getPayload());
        Assert.assertEquals(CBORType.Map, myObject.getType());
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(GroupcommParameters.GROUP_POLICIES)));
        Assert.assertEquals(3600, myObject.get(CBORObject.FromObject(GroupcommParameters.GROUP_POLICIES)).get(CBORObject.FromObject(GroupcommPolicies.KEY_CHECK_INTERVAL)).AsInt32());
        Assert.assertEquals(0, myObject.get(CBORObject.FromObject(GroupcommParameters.GROUP_POLICIES)).get(CBORObject.FromObject(GroupcommPolicies.EXP_DELTA)).AsInt32());
        
        
        /////////////////
        //
        // Part 6
        //
        /////////////////
		
        // Send an Authentication Credential Request, using the GET method
        
        System.out.println("Performing an Authentication Credential GET Request using OSCORE to GM at " +
        				   "coap://localhost/" + rootGroupMembershipResource + "/" + groupName + "/creds");
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" +
        		groupName + "/creds", CoAP.DEFAULT_COAP_PORT),
        		ctxDB);
                
        Request AuthCredReq = new Request(Code.GET, Type.CON);
        AuthCredReq.getOptions().setOscore(new byte[0]);
        CoapResponse r7 = c1.advanced(AuthCredReq);
        
        System.out.println("");
        System.out.println("Sent Authentication Credential GET request to GM");

        Assert.assertEquals("CONTENT", r7.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r7.getPayload());
        Assert.assertEquals(CBORType.Map, myObject.getType());
        
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(GroupcommParameters.NUM)));
        Assert.assertEquals(CBORType.Integer, myObject.get(CBORObject.FromObject(GroupcommParameters.NUM)).getType());
        // This assumes that the Group Manager did not rekey the group upon previous nodes' joining
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(GroupcommParameters.NUM)).AsInt32());
        
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(GroupcommParameters.CREDS)));
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)));
        
        Assert.assertEquals(CBORType.Array, myObject.get(CBORObject.FromObject(GroupcommParameters.CREDS)).getType());
        authCredsArray = myObject.get(CBORObject.FromObject(GroupcommParameters.CREDS));
        Assert.assertEquals(3, authCredsArray.size());
        
        byte[] peerSenderId;
        OneKey peerPublicKey;
        OneKey peerPublicKeyRetrieved = null;
        CBORObject peerAuthCredRetrieved;
        byte[] peerSenderIdFromResponse;
        int expectedRoles = 0;
               
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)));
        Assert.assertEquals(CBORType.Array, myObject.get(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)).getType());
        Assert.assertEquals(3, myObject.get(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)).size());
        
        // Retrieve and check the public key of another node in the group
        peerSenderId = new byte[] { (byte) 0x77 };
        peerSenderIdFromResponse = myObject.
                get(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)).get(0).GetByteString();
        peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(publicKeyPeer2));
        
        peerAuthCredRetrieved = authCredsArray.get(0);
        if (peerAuthCredRetrieved.getType() != CBORType.ByteString) {
        	Assert.fail("Elements of the parameter 'creds' must be CBOR byte strings");
        }
        byte[] peerPublicKeyRetrievedBytes = peerAuthCredRetrieved.GetByteString();
        switch (credFmt) {
            case Constants.COSE_HEADER_PARAM_KCCS:
            	CBORObject ccs = CBORObject.DecodeFromBytes(peerPublicKeyRetrievedBytes);
                if (ccs.getType() == CBORType.Map) {
                	// Retrieve the public key from the CCS
                    peerPublicKeyRetrieved = Util.ccsToOneKey(ccs);
                }
                else {
                    Assert.fail("Invalid format of authentication credential");
                }
                break;
            case Constants.COSE_HEADER_PARAM_KCWT:
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
        
        Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
       
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
        
        // Retrieve and check the public key of another node in the group
        peerSenderId = new byte[] { (byte) 0x52 };
        peerSenderIdFromResponse = myObject.
                get(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)).get(1).GetByteString();
        peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(publicKeyPeer1));
        Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
       
        peerAuthCredRetrieved = authCredsArray.get(1);
        if (peerAuthCredRetrieved.getType() != CBORType.ByteString) {
        	Assert.fail("Elements of the parameter 'creds' must be CBOR byte strings");
        }
        peerPublicKeyRetrievedBytes = peerAuthCredRetrieved.GetByteString();
        switch (credFmt) {
            case Constants.COSE_HEADER_PARAM_KCCS:
            	CBORObject ccs = CBORObject.DecodeFromBytes(peerPublicKeyRetrievedBytes);
                if (ccs.getType() == CBORType.Map) {
                	// Retrieve the public key from the CCS
                    peerPublicKeyRetrieved = Util.ccsToOneKey(ccs);
                }
                else {
                    Assert.fail("Invalid format of authentication credential");
                }
                break;
            case Constants.COSE_HEADER_PARAM_KCWT:
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
        
        // Retrieve and check the public key of this exact requester node
        peerSenderId = new byte[] { (byte) 0x25 };
        peerSenderIdFromResponse = myObject.
                get(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)).get(2).GetByteString();
        peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(groupKeyPair)).PublicKey();
        Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
        
        peerAuthCredRetrieved = authCredsArray.get(2);
        if (peerAuthCredRetrieved.getType() != CBORType.ByteString) {
        	Assert.fail("Elements of the parameter 'creds' must be CBOR byte strings");
        }
        peerPublicKeyRetrievedBytes = peerAuthCredRetrieved.GetByteString();
        switch (credFmt) {
            case Constants.COSE_HEADER_PARAM_KCCS:
            	CBORObject ccs = CBORObject.DecodeFromBytes(peerPublicKeyRetrievedBytes);
                if (ccs.getType() == CBORType.Map) {
                	// Retrieve the public key from the CCS
                    peerPublicKeyRetrieved = Util.ccsToOneKey(ccs);
                }
                else {
                    Assert.fail("Invalid format of authentication credential");
                }
                break;
            case Constants.COSE_HEADER_PARAM_KCWT:
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
        
        Assert.assertEquals(3, myObject.get(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)).size());
        
        expectedRoles = Util.addGroupOSCORERole(expectedRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
        expectedRoles = Util.addGroupOSCORERole(expectedRoles, GroupcommParameters.GROUP_OSCORE_RESPONDER);
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)).get(0).AsInt32());
        
        expectedRoles = 0;
        expectedRoles = Util.addGroupOSCORERole(expectedRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)).get(1).AsInt32());
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)).get(2).AsInt32());

        
        
        /////////////////
        //
        // Part 7
        //
        /////////////////
		
        // Send an Authentication Credential Request, using the FETCH method
        
        System.out.println("Performing an Authentication Credential FETCH Request using OSCORE to GM at " +
        				   "coap://localhost/" + rootGroupMembershipResource + "/" + groupName + "/creds");
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" +
        		groupName + "/creds", CoAP.DEFAULT_COAP_PORT),
        		ctxDB);

        requestPayload = CBORObject.NewMap();

        CBORObject getAuthCreds = CBORObject.NewArray();
        
        // Ask for the public keys of group members that are (also) both requester and responder
        // This will have a neutral effect, by matching only the node with Sender ID = 0x77
        
        getAuthCreds.Add(CBORObject.True);
        
        getAuthCreds.Add(CBORObject.NewArray());
        myRoles = 0;
        myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
        myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_RESPONDER);
        getAuthCreds.get(1).Add(myRoles);
        

        // Ask for the public keys of the other group members
        getAuthCreds.Add(CBORObject.NewArray());
        peerSenderId = new byte[] { (byte) 0x52 };
        getAuthCreds.get(2).Add(peerSenderId);
        peerSenderId = new byte[] { (byte) 0x77 };
        getAuthCreds.get(2).Add(peerSenderId);
        
        requestPayload.Add(GroupcommParameters.GET_CREDS, getAuthCreds);
        
        AuthCredReq = new Request(Code.FETCH, Type.CON);
        AuthCredReq.getOptions().setOscore(new byte[0]);
        AuthCredReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        AuthCredReq.setPayload(requestPayload.EncodeToBytes());
        CoapResponse r8 = c1.advanced(AuthCredReq);
        
        System.out.println("");
        System.out.println("Sent Authentication Credential FETCH request to GM");

        Assert.assertEquals("CONTENT", r8.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r8.getPayload());
        Assert.assertEquals(CBORType.Map, myObject.getType());
        
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(GroupcommParameters.NUM)));
        Assert.assertEquals(CBORType.Integer, myObject.get(CBORObject.FromObject(GroupcommParameters.NUM)).getType());
        // This assumes that the Group Manager did not rekey the group upon previous nodes' joining
        Assert.assertEquals(0, myObject.get(CBORObject.FromObject(GroupcommParameters.NUM)).AsInt32());
        
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(GroupcommParameters.CREDS)));
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)));
        
        Assert.assertEquals(CBORType.Array, myObject.get(CBORObject.FromObject(GroupcommParameters.CREDS)).getType());
        authCredsArray = myObject.get(CBORObject.FromObject(GroupcommParameters.CREDS));
        Assert.assertEquals(2, authCredsArray.size());
        
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)));
        Assert.assertEquals(CBORType.Array, myObject.get(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)).getType());
        Assert.assertEquals(2, myObject.get(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)).size());
        
        // Retrieve and check the public key of another node in the group
        peerSenderId = new byte[] { (byte) 0x77 };
        peerSenderIdFromResponse = myObject.
        	    get(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)).get(0).GetByteString();
        peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(publicKeyPeer2));
        Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
       
        peerAuthCredRetrieved = authCredsArray.get(0);
        if (peerAuthCredRetrieved.getType() != CBORType.ByteString) {
        	Assert.fail("Elements of the parameter 'creds' must be CBOR byte strings");
        }
        peerPublicKeyRetrievedBytes = peerAuthCredRetrieved.GetByteString();
        switch (credFmt) {
            case Constants.COSE_HEADER_PARAM_KCCS:
            	CBORObject ccs = CBORObject.DecodeFromBytes(peerPublicKeyRetrievedBytes);
                if (ccs.getType() == CBORType.Map) {
                	// Retrieve the public key from the CCS
                    peerPublicKeyRetrieved = Util.ccsToOneKey(ccs);
                }
                else {
                    Assert.fail("Invalid format of authentication credential");
                }
                break;
            case Constants.COSE_HEADER_PARAM_KCWT:
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
        
        // Retrieve and check the public key of another node in the group
        peerSenderId = new byte[] { (byte) 0x52 };
        peerSenderIdFromResponse = myObject.
        	    get(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)).get(1).GetByteString();
        peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(publicKeyPeer1));
        Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
       
        peerAuthCredRetrieved = authCredsArray.get(1);
        if (peerAuthCredRetrieved.getType() != CBORType.ByteString) {
        	Assert.fail("Elements of the parameter 'creds' must be CBOR byte strings");
        }
        peerPublicKeyRetrievedBytes = peerAuthCredRetrieved.GetByteString();
        switch (credFmt) {
            case Constants.COSE_HEADER_PARAM_KCCS:
            	CBORObject ccs = CBORObject.DecodeFromBytes(peerPublicKeyRetrievedBytes);
                if (ccs.getType() == CBORType.Map) {
                	// Retrieve the public key from the CCS
                    peerPublicKeyRetrieved = Util.ccsToOneKey(ccs);
                }
                else {
                    Assert.fail("Invalid format of authentication credential");
                }
                break;
            case Constants.COSE_HEADER_PARAM_KCWT:
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
        
                
        Assert.assertEquals(2, myObject.get(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)).size());

        expectedRoles = 0;
        expectedRoles = Util.addGroupOSCORERole(expectedRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
        expectedRoles = Util.addGroupOSCORERole(expectedRoles, GroupcommParameters.GROUP_OSCORE_RESPONDER);
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)).get(0).AsInt32());
        
        expectedRoles = 0;
        expectedRoles = Util.addGroupOSCORERole(expectedRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)).get(1).AsInt32());
        
        
        /////////////////
        //
        // Part 8
        //
        /////////////////
		
        // Send a Key Distribution Request to the node sub-resource, using the GET method
        
        System.out.println("Performing a Key Distribution Request GET Request " +
        				   "using OSCORE to GM at coap://localhost/" + nodeResourceLocationPath);
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + nodeResourceLocationPath, CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        Request KeyDistributionReq = new Request(Code.GET, Type.CON);
        KeyDistributionReq.getOptions().setOscore(new byte[0]);
                
        CoapResponse r9 = c1.advanced(KeyDistributionReq);

        System.out.println("");
        System.out.println("Sent Key Distribution GET request to the node sub-resource at the GM");
        
        Assert.assertEquals("CONTENT", r9.getCode().name());
        
        responsePayload = r9.getPayload();
        CBORObject KeyDistributionResponse = CBORObject.DecodeFromBytes(responsePayload);
       
        Assert.assertEquals(CBORType.Map, KeyDistributionResponse.getType());
       
        Assert.assertEquals(true, KeyDistributionResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.GKTY)));
        Assert.assertEquals(CBORType.Integer, KeyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.GKTY)).getType());
        Assert.assertEquals(GroupcommParameters.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, KeyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.GKTY)).AsInt32());
       
        Assert.assertEquals(true, KeyDistributionResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.KEY)));
        Assert.assertEquals(CBORType.Map, KeyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.KEY)).getType());
       
        myMap = KeyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.KEY));
       
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
       
        Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)).GetByteString());
        Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)).GetByteString());
       
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(gpEncAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.gp_enc_alg)));
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
              
        Assert.assertEquals(true, KeyDistributionResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.NUM)));
        Assert.assertEquals(CBORType.Integer, KeyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.NUM)).getType());
        // This assumes that the Group Manager did not rekey the group upon previous nodes' joining
        Assert.assertEquals(0, KeyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.NUM)).AsInt32());
        
        Assert.assertEquals(true, KeyDistributionResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.ACE_GROUPCOMM_PROFILE)));
        Assert.assertEquals(CBORType.Integer, KeyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.ACE_GROUPCOMM_PROFILE)).getType());
        Assert.assertEquals(GroupcommParameters.COAP_GROUP_OSCORE_APP, KeyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.ACE_GROUPCOMM_PROFILE)).AsInt32());
       
        Assert.assertEquals(true, KeyDistributionResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.EXP)));
        Assert.assertEquals(CBORType.Integer, KeyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.EXP)).getType());
        Assert.assertEquals(2682374400L, keyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.EXP)).AsInt64Value());
        
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.EXI)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.EXI)).getType());
       
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(signParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)));
        }
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(ecdhParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)));
        }

        
        /////////////////
        //
        // Part 9
        //
        /////////////////
		
        // Send a Key Renewal Request to the node sub-resource, using the PUT method
        
        System.out.println("Performing a Key Renewal Request " +
        				   "using OSCORE to GM at coap://localhost/" + nodeResourceLocationPath);
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + nodeResourceLocationPath, CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        Request KeyRenewalReq = new Request(Code.POST, Type.CON);
        KeyRenewalReq.getOptions().setOscore(new byte[0]);
                
        CoapResponse r10 = c1.advanced(KeyRenewalReq);

        System.out.println("");
        System.out.println("Sent Key Renewal Request to the node sub-resource at the GM");
        
        Assert.assertEquals("CHANGED", r10.getCode().name());
        
        responsePayload = r10.getPayload();
        CBORObject KeyRenewalResponse = CBORObject.DecodeFromBytes(responsePayload);
       
        Assert.assertEquals(CBORType.Map, KeyRenewalResponse.getType());
        Assert.assertEquals(true, KeyRenewalResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.GROUP_SENDER_ID)));
        Assert.assertEquals(CBORType.ByteString, KeyRenewalResponse.get(CBORObject.FromObject(GroupcommParameters.GROUP_SENDER_ID)).getType());
     
        
        /////////////////
        //
        // Part 10
        //
        /////////////////
		
        // Send an Authentication Credential Update Request to the node sub-resource /cred, using the POST method
        
        System.out.println("Performing an Authentication Credential Update Request " +
        				   "using OSCORE to GM at coap://localhost/" + nodeResourceLocationPath + "/cred");
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + nodeResourceLocationPath +  "/cred", CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        requestPayload = CBORObject.NewMap();
        
        byte[] cred = null;
        
        /*
	    // Build the authentication credential according to the format used in the group
	    // Note: most likely, the result will NOT follow the required deterministic
	    //       encoding in byte lexicographic order, and it has to be adjusted offline
        OneKey publicKey = new OneKey(CBORObject.DecodeFromBytes(groupKeyPairUpdate)).PublicKey();
        switch (credFmtExpected.AsInt32()) {
            case Constants.COSE_HEADER_PARAM_KCCS:
            	// Build a CCS including the public key
                cred = Util.oneKeyToCCS(publicKey, "");
                break;
            case Constants.COSE_HEADER_PARAM_KCWT:
                // Build/retrieve a CWT including the public key
                // TODO
                break;
            case Constants.COSE_HEADER_PARAM_X5CHAIN:
                // Build/retrieve the certificate including the public key
                // TODO
                break;
        }
        */
        
        switch (credFmtExpected.AsInt32()) {
	        case Constants.COSE_HEADER_PARAM_KCCS:
	            // A CCS including the public key
	            if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
	                cred = Utils.hexToBytes("A2026008A101A5010203262001215820D8692E6CC344A51BB8D62AB768C52F3D281317B789F4F123614806D0B051443D225820A9F0024604BB007C4A92210FEF5CA81C779BC5303F8C1E65F2686B81D2244088");
	            }
	            if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
	                cred = Utils.hexToBytes("A2026008A101A401010327200621582021C96449BDF354F6C8306B96CFD9E62859B5190E27C0F926FBEEA144606DB404");
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

        
        // Add the nonce for PoP of the Client's private key
        byte[] cnonceCred = new byte[8];
        new SecureRandom().nextBytes(cnonceCred);
        requestPayload.Add(GroupcommParameters.CNONCE, cnonceCred);

        // Add the signature computed over
        // (scope | rsnonce | cnonce), using the Client's private key
        offset = 0;
        PrivateKey privKey = (new OneKey(CBORObject.DecodeFromBytes(groupKeyPairUpdate))).AsPrivateKey();

        byte[] serializedScopeCBOR = CBORObject.FromObject(byteStringScope).EncodeToBytes();
        serializedGMNonceCBOR = CBORObject.FromObject(gm_nonce).EncodeToBytes();
        byte[] serializedCNonceCredCBOR = CBORObject.FromObject(cnonceCred).EncodeToBytes();
        popInput = new byte[serializedScopeCBOR.length +
                            serializedGMNonceCBOR.length +
                            serializedCNonceCredCBOR.length];
        System.arraycopy(serializedScopeCBOR, 0, popInput, offset, serializedScopeCBOR.length);
        offset += serializedScopeCBOR.length;
        System.arraycopy(serializedGMNonceCBOR, 0, popInput, offset, serializedGMNonceCBOR.length);
        offset += serializedGMNonceCBOR.length;
        System.arraycopy(serializedCNonceCredCBOR, 0, popInput, offset, serializedCNonceCredCBOR.length);

        byte[] popEvidence = Util.computeSignature(signKeyCurve, privKey, popInput);

        if (popEvidence != null)
            requestPayload.Add(GroupcommParameters.CLIENT_CRED_VERIFY, popEvidence);
        else
            Assert.fail("Computed signature is empty");
        
        Request AuthCredUpdateReq = new Request(Code.POST, Type.CON);
        AuthCredUpdateReq.getOptions().setOscore(new byte[0]);
        AuthCredUpdateReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        AuthCredUpdateReq.setPayload(requestPayload.EncodeToBytes());
        
        CoapResponse r11 = c1.advanced(AuthCredUpdateReq);

        System.out.println("");
        System.out.println("Sent Authentication Credential Update Request to the node sub-resource at the GM");
        
        Assert.assertEquals("CHANGED", r11.getCode().name());
        
        responsePayload = r11.getPayload();
        
        
        /////////////////
        //
        // Part 11
        //
        /////////////////
		
        // Send a Group Name and URI Retrieval Request, using the FETCH method
        
        System.out.println("Performing a Group Name and URI Retrieval Request using OSCORE to GM at " +
        				   "coap://localhost/" + rootGroupMembershipResource);
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource, CoAP.DEFAULT_COAP_PORT), ctxDB);

        requestPayload = CBORObject.NewMap();

        CBORObject reqGroupIds = CBORObject.NewArray();
        reqGroupIds.Add(CBORObject.FromObject(groupId));
        
        requestPayload.Add(GroupcommParameters.GID, reqGroupIds);
        
        Request GroupNamesReq = new Request(Code.FETCH, Type.CON);
        GroupNamesReq.getOptions().setOscore(new byte[0]);
        GroupNamesReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        GroupNamesReq.setPayload(requestPayload.EncodeToBytes());
        CoapResponse r12 = c1.advanced(GroupNamesReq);
        
        System.out.println("");
        System.out.println("Sent Group Name and URI Retrieval Request FETCH request to GM");

        Assert.assertEquals("CONTENT", r12.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r12.getPayload());
        
        Assert.assertEquals(CBORType.Map, myObject.getType());
        Assert.assertEquals(3, myObject.size());
        
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(GroupcommParameters.GID)));
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(GroupcommParameters.GNAME)));
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(GroupcommParameters.GURI)));
        
        Assert.assertEquals(CBORType.Array, myObject.get(CBORObject.FromObject(GroupcommParameters.GID)).getType());
        Assert.assertEquals(CBORType.Array, myObject.get(CBORObject.FromObject(GroupcommParameters.GNAME)).getType());
        Assert.assertEquals(CBORType.Array, myObject.get(CBORObject.FromObject(GroupcommParameters.GURI)).getType());
        
        Assert.assertEquals(1, myObject.get(CBORObject.FromObject(GroupcommParameters.GID)).size());
        Assert.assertArrayEquals(groupId, myObject.get(CBORObject.FromObject(GroupcommParameters.GID)).get(0).GetByteString());
        
        Assert.assertEquals(1, myObject.get(CBORObject.FromObject(GroupcommParameters.GNAME)).size());
        Assert.assertEquals(groupName, myObject.get(CBORObject.FromObject(GroupcommParameters.GNAME)).get(0).AsString());
        
        Assert.assertEquals(1, myObject.get(CBORObject.FromObject(GroupcommParameters.GURI)).size());
        String expectedUri = new String("/" + rootGroupMembershipResource + "/" + groupName);
        Assert.assertEquals(expectedUri, myObject.get(CBORObject.FromObject(GroupcommParameters.GURI)).get(0).AsString());
        
        // Send a second request, indicating the Group ID of a non existing OSCORE group
        
        requestPayload = CBORObject.NewMap();

        reqGroupIds = CBORObject.NewArray();
        byte[] groupId2 = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22 };
        reqGroupIds.Add(CBORObject.FromObject(groupId2));
        
        requestPayload.Add(GroupcommParameters.GID, reqGroupIds);
        
        GroupNamesReq = new Request(Code.FETCH, Type.CON);
        GroupNamesReq.getOptions().setOscore(new byte[0]);
        GroupNamesReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        GroupNamesReq.setPayload(requestPayload.EncodeToBytes());
        r12 = c1.advanced(GroupNamesReq);
        
        Assert.assertEquals("CONTENT", r12.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r12.getPayload());
        
        Assert.assertEquals(CBORType.ByteString, myObject.getType());
        Assert.assertEquals(0, myObject.size());
        

        /////////////////
        //
        // Part 12
        //
        /////////////////
        
        // Send a KDC Authentication Credential Request, using the GET method

        System.out.println("Performing a KDC Authentication Credential GET Request using OSCORE to GM at " +
        				   "coap://localhost/" + rootGroupMembershipResource + "/" + groupName + "/kdc-cred");

        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
                "coap://localhost/" + rootGroupMembershipResource + "/" +
                groupName + "/kdc-cred", CoAP.DEFAULT_COAP_PORT),
        		ctxDB);
                
        Request GmAuthCredReq = new Request(Code.GET, Type.CON);
        GmAuthCredReq.getOptions().setOscore(new byte[0]);
        CoapResponse r13 = c1.advanced(GmAuthCredReq);

        System.out.println("");
        System.out.println("Sent Group Manager Public Key GET request to GM");

        Assert.assertEquals("CONTENT", r13.getCode().name());

        myObject = CBORObject.DecodeFromBytes(r13.getPayload());
        Assert.assertEquals(CBORType.Map, myObject.getType());
        
        // Check the proof-of-possession evidence over kdc_nonce, using the GM's public key
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(GroupcommParameters.KDC_NONCE)));
        Assert.assertEquals(CBORType.ByteString, myObject.get(CBORObject.FromObject(GroupcommParameters.KDC_NONCE)).getType());
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(GroupcommParameters.KDC_CRED)));
        Assert.assertEquals(CBORType.ByteString, myObject.get(CBORObject.FromObject(GroupcommParameters.KDC_CRED)).getType());
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(GroupcommParameters.KDC_CRED_VERIFY)));
        Assert.assertEquals(CBORType.ByteString, myObject.get(CBORObject.FromObject(GroupcommParameters.KDC_CRED_VERIFY)).getType());
        
        gmPublicKeyRetrieved = null;
        kdcCredBytes = myObject.get(CBORObject.FromObject(GroupcommParameters.KDC_CRED)).GetByteString();
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
        Assert.assertEquals(CBORObject.DecodeFromBytes(publicKeyGM),gmPublicKeyRetrieved.AsCBOR());
        
        gmPublicKey = gmPublicKeyRetrieved.AsPublicKey();
        
        offset = 0;
		serializedGMNonceCBOR = myObject.get(CBORObject.FromObject(GroupcommParameters.KDC_NONCE)).EncodeToBytes();
		popInput = new byte[serializedCNonceCBOR.length + serializedGMNonceCBOR.length];
		System.arraycopy(serializedCNonceCBOR, 0, popInput, offset, serializedCNonceCBOR.length);
		offset += serializedCNonceCBOR.length;
		System.arraycopy(serializedGMNonceCBOR, 0, popInput, offset, serializedGMNonceCBOR.length);
		
    	gmPopEvidence = myObject.get(CBORObject.FromObject(GroupcommParameters.KDC_CRED_VERIFY));
    	rawGmPopEvidence = gmPopEvidence.GetByteString();
    	
    	Assert.assertEquals(true, Util.verifySignature(signKeyCurve, gmPublicKey, popInput, rawGmPopEvidence));
        
        
        /////////////////
        //
        // Part 13
        //
        /////////////////
		
        // Send a Leaving Group Request to the node sub-resource, using the DELETE method
        
        System.out.println("\nPerforming a Leaving Group Request " +
        				   "using OSCORE to GM at coap://localhost/" + nodeResourceLocationPath);
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + nodeResourceLocationPath, CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        Request LeavingGroupReq = new Request(Code.DELETE, Type.CON);
        LeavingGroupReq.getOptions().setOscore(new byte[0]);
        
        CoapResponse r14 = c1.advanced(LeavingGroupReq);

        System.out.println("");
        System.out.println("Sent Group Leaving Request to the node sub-resource at the GM");
        
        Assert.assertEquals("DELETED", r14.getCode().name());
        
        responsePayload = r14.getPayload();
        
        // Send a Version Request, not as a member any more
        
        System.out.println("\nPerforming a Version Request using OSCORE to GM at " +
        				   "coap://localhost/" + rootGroupMembershipResource + "/" + groupName + "/num");
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" + groupName + "/num", CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        VersionReq = new Request(Code.GET, Type.CON);
        VersionReq.getOptions().setOscore(new byte[0]);
        CoapResponse r15 = c1.advanced(VersionReq);
        
        System.out.println("");
        System.out.println("Sent Version request to GM");

        Assert.assertEquals("FORBIDDEN", r15.getCode().name());
        
        
        /////////////////
        //
        // Part 14
        //
        /////////////////
		
        // Send a new Access Token to update access rights and
        // join the same OSCORE group again with multiple roles
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayEntry = CBORObject.NewArray();
        cborArrayEntry.Add(groupName);
        
        myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_RESPONDER); // Allow this role too
    	cborArrayEntry.Add(myRoles);
    	
    	cborArrayScope.Add(cborArrayEntry);
    	byteStringScope = cborArrayScope.EncodeToBytes();
    	
    	Map<Short, CBORObject> params2 = new HashMap<>();
    	params2.put(Constants.SCOPE, CBORObject.FromObject(byteStringScope));
    	params2.put(Constants.AUD, CBORObject.FromObject("aud2"));
                params2.put(Constants.CTI, CBORObject.FromObject(
                "token4JoinSingleRoleUpdateAccessRights".getBytes(Constants.charset))); //Need different CTI
        params2.put(Constants.ISS, CBORObject.FromObject("TestAS"));
        
        // Now the 'cnf' claim includes only a 'kid' with value the 'id'
        // used in the first Token and identifying the OSCORE_Input_Material
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.COSE_KID_CBOR, Util.intToBytes(1));
        params2.put(Constants.CNF, cbor);
        CWT token2 = new CWT(params2);
        
        // Include only the Token now. If Id1 and Nonce1 were
        // included here too, the RS would silently ignore them
        payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token2.encode(ctx).EncodeToBytes());
        
        asRes = new Response(CoAP.ResponseCode.CREATED);
        asRes.setPayload(payload.EncodeToBytes());
        
 	    // Posting the Token through an OSCORE-protected request
        // 
        // Normally, a client understands that the Token is indeed for updating access rights,
        // since the response from the AS does not include the 'cnf' parameter.
        CoapResponse rsRes2 = OSCOREProfileRequestsGroupOSCORE.
        		postTokenUpdate("coap://localhost/authz-info", asRes, askForSignInfo, askForEcdhInfo, ctxDB);
        
        assert(rsRes2.getCode() == CoAP.ResponseCode.CREATED);
        
        Assert.assertNotNull(ctxDB.getContext(
                "coap://localhost/" + rootGroupMembershipResource + "/" + groupName));
        
        rsPayload = CBORObject.DecodeFromBytes(rsRes2.getPayload());
        // Sanity checks already occurred in OSCOREProfileRequestsGroupOSCORE.postToken()
        
        // Nonce from the GM, to use together with a local nonce to prove possession of the private key
        gm_nonce = rsPayload.get(CBORObject.FromObject(Constants.KDCCHALLENGE)).GetByteString();
        
        
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
		
		
        /////////////////
        //
        // Part 15
        //
        /////////////////
		
        // Send a new Join Request under the new Access Token
        
        System.out.println("\nPerforming Join Request using OSCORE to GM at " +
        			       "coap://localhost/" + rootGroupMembershipResource + "/" + groupName);

        requestPayload = CBORObject.NewMap();
        
        cborArrayScope = CBORObject.NewArray();
        cborArrayScope.Add(groupName);

        myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_RESPONDER); // Now this role is also allowed
    	cborArrayScope.Add(myRoles);
		
    	byteStringScope = cborArrayScope.EncodeToBytes();
        requestPayload.Add(GroupcommParameters.SCOPE, CBORObject.FromObject(byteStringScope));
       
    	// Add the nonce for PoP of the Client's private key
        cnonce = new byte[8];
        new SecureRandom().nextBytes(cnonce);
        requestPayload.Add(GroupcommParameters.CNONCE, cnonce);
        
        if (askForAuthCreds) {
           
            getAuthCreds = CBORObject.NewArray();
            
            getAuthCreds.Add(CBORObject.True); // This must be true
            
            getAuthCreds.Add(CBORObject.NewArray());
            // The following is required to retrieve the public keys
            // of both the already present group members
            myRoles = 0;
            myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
            getAuthCreds.get(1).Add(myRoles);
            myRoles = 0;
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
        	

            cred = null;
        	
            /*
        	// Build the authentication credential according to the format used in the group
        	// Note: most likely, the result will NOT follow the required deterministic
        	//       encoding in byte lexicographic order, and it has to be adjusted offline
            OneKey publicKey = new OneKey(CBORObject.DecodeFromBytes(groupKeyPair)).PublicKey();
            switch (credFmtExpected.AsInt32()) {
                case Constants.COSE_HEADER_PARAM_KCCS:
                    // Build a CCS including the public key
                    cred = Util.oneKeyToCCS(publicKey, "");
                    break;
                case Constants.COSE_HEADER_PARAM_KCWT:
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
            
            // Add the signature computed over
            // (scope | rsnonce | cnonce), using the Client's private key
            offset = 0;
            privKey = (new OneKey(CBORObject.DecodeFromBytes(groupKeyPair))).AsPrivateKey();
            
            serializedScopeCBOR = CBORObject.FromObject(byteStringScope).EncodeToBytes();
            serializedGMNonceCBOR = CBORObject.FromObject(gm_nonce).EncodeToBytes();
            serializedCNonceCBOR = CBORObject.FromObject(cnonce).EncodeToBytes();
            popInput = new byte[serializedScopeCBOR.length +
       	                        serializedGMNonceCBOR.length +
       	                        serializedCNonceCBOR.length];
       	    System.arraycopy(serializedScopeCBOR, 0, popInput, offset, serializedScopeCBOR.length);
       	    offset += serializedScopeCBOR.length;
       	    System.arraycopy(serializedGMNonceCBOR, 0, popInput, offset, serializedGMNonceCBOR.length);
       	    offset += serializedGMNonceCBOR.length;
       	    System.arraycopy(serializedCNonceCBOR, 0, popInput, offset, serializedCNonceCBOR.length);
            
       	    
       	 popEvidence = Util.computeSignature(signKeyCurve, privKey, popInput);
            
            if (popEvidence != null)
            	requestPayload.Add(GroupcommParameters.CLIENT_CRED_VERIFY, popEvidence);
        	else
        		Assert.fail("Computed signature is empty");
            
            joinReq = new Request(Code.POST, Type.CON);
            joinReq.getOptions().setOscore(new byte[0]);
            joinReq.setPayload(requestPayload.EncodeToBytes());
            joinReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
            
            c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
            		"coap://localhost/" + rootGroupMembershipResource + "/" +
            		groupName, CoAP.DEFAULT_COAP_PORT), ctxDB);
            
            // Submit the request
            System.out.println("");
            System.out.println("Sent Join request to GM: " + requestPayload.toString());
            r2 = c1.advanced(joinReq);
            
            System.out.println("Received Join Reponse from the GM: " +
            				   CBORObject.DecodeFromBytes(r2.getPayload()).toString()); 
            
            Assert.assertEquals("CREATED", r2.getCode().name());
            
            if (r2.getOptions().getLocationPath().size() != 0) {
    	        System.out.print("Location-Path: ");
    	        System.out.println(r2.getOptions().getLocationPathString());
    	        nodeResourceLocationPath = r2.getOptions().getLocationPathString();
            }
           
            // The same dedicated URI has to have been returned
            Assert.assertEquals(uriNodeResource, r2.getOptions().getLocationPathString());
            
            responsePayload = r2.getPayload();
            joinResponse = CBORObject.DecodeFromBytes(responsePayload);
            
            Assert.assertEquals(CBORType.Map, joinResponse.getType());
            
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.GKTY)));
            Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(GroupcommParameters.GKTY)).getType());
            Assert.assertEquals(GroupcommParameters.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, joinResponse.get(CBORObject.FromObject(GroupcommParameters.GKTY)).AsInt32());
           
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.KEY)));
            Assert.assertEquals(CBORType.Map, joinResponse.get(CBORObject.FromObject(GroupcommParameters.KEY)).getType());
           
            myMap = joinResponse.get(CBORObject.FromObject(GroupcommParameters.KEY));
           
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
            
            credFmt = myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.cred_fmt)).AsInt32();
            
            Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)).GetByteString());
            Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)).GetByteString());
           
            Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
            Assert.assertEquals(gpEncAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.gp_enc_alg)));
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
                  
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.NUM)));
            Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(GroupcommParameters.NUM)).getType());
            // This assumes that the Group Manager did not rekey the group upon previous nodes' joining
            Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(GroupcommParameters.NUM)).AsInt32());
            
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.ACE_GROUPCOMM_PROFILE)));
            Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(GroupcommParameters.ACE_GROUPCOMM_PROFILE)).getType());
            Assert.assertEquals(GroupcommParameters.COAP_GROUP_OSCORE_APP, joinResponse.get(CBORObject.FromObject(GroupcommParameters.ACE_GROUPCOMM_PROFILE)).AsInt32());
           
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.EXP)));
            Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(GroupcommParameters.EXP)).getType());
            Assert.assertEquals(2682374400L, joinResponse.get(CBORObject.FromObject(GroupcommParameters.EXP)).AsInt64Value());
           
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

            authCredsArray = null;
            
            if (askForAuthCreds) {
                Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.CREDS)));
                Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(GroupcommParameters.CREDS)).getType());
               
                authCredsArray = joinResponse.get(CBORObject.FromObject(GroupcommParameters.CREDS));
                Assert.assertEquals(2, authCredsArray.size());
               
                peerSenderId = new byte[] { (byte) 0x77 };
                peerSenderIdFromResponse = joinResponse.
                						   get(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)).get(0).GetByteString();
                Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);

                peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(publicKeyPeer2));
                
                peerPublicKeyRetrieved = null;
                peerAuthCredRetrieved = authCredsArray.get(0);
                if (peerAuthCredRetrieved.getType() != CBORType.ByteString) {
                	Assert.fail("Elements of the parameter 'creds' must be CBOR byte strings");
                }
                peerPublicKeyRetrievedBytes = peerAuthCredRetrieved.GetByteString();
                switch (credFmt) {
                    case Constants.COSE_HEADER_PARAM_KCCS:
                    	CBORObject ccs = CBORObject.DecodeFromBytes(peerPublicKeyRetrievedBytes);
                        if (ccs.getType() == CBORType.Map) {
                        	// Retrieve the public key from the CCS
                            peerPublicKeyRetrieved = Util.ccsToOneKey(ccs);
                        }
                        else {
                            Assert.fail("Invalid format of authentication credential");
                        }
                        break;
                    case Constants.COSE_HEADER_PARAM_KCWT:
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
						   get(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)).get(1).GetByteString();
                
                peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(publicKeyPeer1));
                Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
               
                peerPublicKeyRetrieved = null;
                peerAuthCredRetrieved = authCredsArray.get(1);
                if (peerAuthCredRetrieved.getType() != CBORType.ByteString) {
                	Assert.fail("Elements of the parameter 'creds' must be CBOR byte strings");
                }
                peerPublicKeyRetrievedBytes = peerAuthCredRetrieved.GetByteString();
                switch (credFmt) {
                    case Constants.COSE_HEADER_PARAM_KCCS:
                    	CBORObject ccs = CBORObject.DecodeFromBytes(peerPublicKeyRetrievedBytes);
                        if (ccs.getType() == CBORType.Map) {
                        	// Retrieve the public key from the CCS
                            peerPublicKeyRetrieved = Util.ccsToOneKey(ccs);
                        }
                        else {
                            Assert.fail("Invalid format of authentication credential");
                        }
                        break;
                    case Constants.COSE_HEADER_PARAM_KCWT:
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
                
                Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)));
                Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)).getType());
                Assert.assertEquals(2, joinResponse.get(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)).size());
                
                expectedRoles = 0;
                expectedRoles = Util.addGroupOSCORERole(expectedRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
                expectedRoles = Util.addGroupOSCORERole(expectedRoles, GroupcommParameters.GROUP_OSCORE_RESPONDER);
                Assert.assertEquals(expectedRoles, joinResponse.get(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)).get(0).AsInt32());
                
                expectedRoles = 0;
                expectedRoles = Util.addGroupOSCORERole(expectedRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
                Assert.assertEquals(expectedRoles, joinResponse.get(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)).get(1).AsInt32());
                
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
            
            gmPublicKeyRetrieved = null;
            kdcCredBytes = joinResponse.get(CBORObject.FromObject(GroupcommParameters.KDC_CRED)).GetByteString();
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
        	
        	gmPublicKey = gmPublicKeyRetrieved.AsPublicKey();
        	
            offset = 0;
    		serializedGMNonceCBOR = joinResponse.get(CBORObject.FromObject(GroupcommParameters.KDC_NONCE)).EncodeToBytes();
    		popInput = new byte[serializedCNonceCBOR.length + serializedGMNonceCBOR.length];
    		System.arraycopy(serializedCNonceCBOR, 0, popInput, offset, serializedCNonceCBOR.length);
    		offset += serializedCNonceCBOR.length;
    		System.arraycopy(serializedGMNonceCBOR, 0, popInput, offset, serializedGMNonceCBOR.length);
    		
        	gmPopEvidence = joinResponse.get(CBORObject.FromObject(GroupcommParameters.KDC_CRED_VERIFY));
        	rawGmPopEvidence = gmPopEvidence.GetByteString();
                	
        	Assert.assertEquals(true, Util.verifySignature(signKeyCurve, gmPublicKey, popInput, rawGmPopEvidence));
        	
        }
    	
        
        /////////////////
        //
        // Part 16
        //
        /////////////////
		
        // Send a Stale Sender IDs Request
        
        System.out.println("\nPerforming a Stale Sender IDs FETCH Request using OSCORE to GM at " +
                		   "coap://localhost/" + rootGroupMembershipResource + "/" + groupName + "/stale-sids");
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
                "coap://localhost/" + rootGroupMembershipResource + "/" +
                groupName + "/stale-sids", CoAP.DEFAULT_COAP_PORT), ctxDB);
        
        requestPayload = CBORObject.FromObject(0);
        
        Request StaleSenderIdsReq = new Request(Code.FETCH, Type.CON);
        StaleSenderIdsReq.getOptions().setOscore(new byte[0]);
        StaleSenderIdsReq.setPayload(requestPayload.EncodeToBytes());
        CoapResponse r16 = c1.advanced(StaleSenderIdsReq);

        System.out.println("");
        System.out.println("Sent Stale Sender IDs FETCH request to GM");
        
        System.out.println("Received Stale Sender IDs FETCH request from the GM: " +
        				   new String(r16.getPayload()));
        
        Assert.assertEquals("BAD_REQUEST", r16.getCode().name());
        Assert.assertEquals("Invalid payload format", new String(r16.getPayload()));

    }
    
    /**
     * Test post to Authz-Info, then join using multiple roles.
     * Uses the ACE OSCORE Profile.
     * 
     * @throws Exception 
     */
    @Test
	@Ignore
    public void testSuccessGroupOSCOREMultipleRoles() throws Exception {

    	boolean askForSignInfo = true;
    	boolean askForEcdhInfo = true;
        boolean askForAuthCreds = true;
        boolean provideAuthCred = true;
        
        //Generate a token
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(keyASRS, coseP.getAlg().AsCBOR());
        Map<Short, CBORObject> params = new HashMap<>(); 
        
        // Create the scope
        CBORObject cborArrayScope = CBORObject.NewArray();
        CBORObject cborArrayEntry = CBORObject.NewArray();
        
        String groupName = new String("feedca570000");
        String nodeResourceLocationPath = "";
        cborArrayEntry.Add(groupName);
        
    	int myRoles = 0;
    	myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
    	myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_RESPONDER);
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
        osc.Add(Constants.OS_ID, Util.intToBytes(2));
        
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.OSCORE_Input_Material, osc);
        params.put(Constants.CNF, cnf);
        CWT token = new CWT(params);
        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token.encode(ctx).EncodeToBytes());
        payload.Add(Constants.CNF, cnf);
        Response asRes = new Response(CoAP.ResponseCode.CREATED);
        asRes.setPayload(payload.EncodeToBytes());
        Response rsRes = OSCOREProfileRequestsGroupOSCORE.postToken(
                "coap://localhost/authz-info", asRes, askForSignInfo, askForEcdhInfo, ctxDB, usedRecipientIds);
        assert(rsRes.getCode().equals(CoAP.ResponseCode.CREATED));
        
        //Check that the OSCORE context has been created:
        Assert.assertNotNull(ctxDB.getContext("coap://localhost/feedca570000"));
        
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
        
        
        CoapClient c = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" +
        		groupName, CoAP.DEFAULT_COAP_PORT), ctxDB);
        
        CBORObject requestPayload = CBORObject.NewMap();
        
        // Prepare material for later tests
        final byte[] masterSecret = { (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
					                  (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08,
					                  (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C,
					                  (byte) 0x0D, (byte) 0x0E, (byte) 0x0F, (byte) 0x10 };
		final byte[] masterSalt =   { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22,
		                			  (byte) 0x23, (byte) 0x78, (byte) 0x63, (byte) 0x40 };
		final byte[] groupId = new byte[] { (byte) 0xfe, (byte) 0xed, (byte) 0xca, (byte) 0x57, (byte) 0xf0, (byte) 0x5c };

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
        
		
        /////////////////
        //
        // Part 1
        //
        /////////////////
        
        // Send a Join Request
        
        System.out.println("\nPerforming Join Request using OSCORE to GM at " +
        				   "coap://localhost/" + rootGroupMembershipResource + "/" + groupName);       
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
            
            /*
        	// Build the authentication credential according to the format used in the group
        	// Note: most likely, the result will NOT follow the required deterministic
        	//       encoding in byte lexicographic order, and it has to be adjusted offline
            OneKey publicKey = new OneKey(CBORObject.DecodeFromBytes(groupKeyPair)).PublicKey();
            switch (credFmtExpected.AsInt32()) {
            	case Constants.COSE_HEADER_PARAM_KCCS:
            		// Build a CCS including the public key
            		cred = Util.oneKeyToCCS(publicKey, "");
            		break;
            	case Constants.COSE_HEADER_PARAM_KCWT:
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
       	    byte[] popInput = new byte[serializedScopeCBOR.length +
       	                               serializedGMNonceCBOR.length +
       	                               serializedCNonceCBOR.length];
       	    System.arraycopy(serializedScopeCBOR, 0, popInput, offset, serializedScopeCBOR.length);
       	    offset += serializedScopeCBOR.length;
       	    System.arraycopy(serializedGMNonceCBOR, 0, popInput, offset, serializedGMNonceCBOR.length);
       	    offset += serializedGMNonceCBOR.length;
       	    System.arraycopy(serializedCNonceCBOR, 0, popInput, offset, serializedCNonceCBOR.length);
            
       	   
       	    byte[] popEvidence = Util.computeSignature(signKeyCurve, privKey, popInput);
            
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
        System.out.println("Sent Join request to GM: " + requestPayload.toString());
        CoapResponse r2 = c.advanced(joinReq);
       
        Assert.assertEquals("CREATED", r2.getCode().name());
       
        if (r2.getOptions().getLocationPath().size() != 0) {
	        System.out.print("Location-Path: ");
	        System.out.println(r2.getOptions().getLocationPathString());
	        nodeResourceLocationPath = r2.getOptions().getLocationPathString();
        }
        
    	final byte[] senderId = new byte[] { (byte) 0x25 };
    	String nodeName =  Utils.bytesToHex(groupId) + "-" + Utils.bytesToHex(senderId);
        String uriNodeResource = new String(rootGroupMembershipResource + "/" + groupName + "/nodes/" + nodeName);
        Assert.assertEquals(uriNodeResource, r2.getOptions().getLocationPathString());
        
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
        
        Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)).GetByteString());
        Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)).GetByteString());
       
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(gpEncAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.gp_enc_alg)));
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
       
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.NUM)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(GroupcommParameters.NUM)).getType());
        // This assumes that the Group Manager did not rekey the group upon previous nodes' joining
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(GroupcommParameters.NUM)).AsInt32());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.ACE_GROUPCOMM_PROFILE)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(GroupcommParameters.ACE_GROUPCOMM_PROFILE)).getType());
        Assert.assertEquals(GroupcommParameters.COAP_GROUP_OSCORE_APP, joinResponse.get(CBORObject.FromObject(GroupcommParameters.ACE_GROUPCOMM_PROFILE)).AsInt32());
       
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.EXP)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(GroupcommParameters.EXP)).getType());
        Assert.assertEquals(2682374400L, joinResponse.get(CBORObject.FromObject(GroupcommParameters.EXP)).AsInt64Value());
        
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
       
        CBORObject authCredsArray = null;
        if (askForAuthCreds) {
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.CREDS)));
            Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(GroupcommParameters.CREDS)).getType());
           
            authCredsArray = joinResponse.get(CBORObject.FromObject(GroupcommParameters.CREDS));
            Assert.assertEquals(2, authCredsArray.size());
           
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)));
            Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)).getType());
            Assert.assertEquals(2, joinResponse.get(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)).size());
            
            byte[] peerSenderId;
            OneKey peerPublicKey;
            byte[] peerSenderIdFromResponse;
            
            OneKey peerPublicKeyRetrieved = null;
            CBORObject peerAuthCredRetrieved;
            
            peerAuthCredRetrieved = authCredsArray.get(0);
            if (peerAuthCredRetrieved.getType() != CBORType.ByteString) {
            	Assert.fail("Elements of the parameter 'creds' must be CBOR byte strings");
            }
            byte[] peerPublicKeyRetrievedBytes = peerAuthCredRetrieved.GetByteString();
            switch (credFmt) {
                case Constants.COSE_HEADER_PARAM_KCCS:
                	CBORObject ccs = CBORObject.DecodeFromBytes(peerPublicKeyRetrievedBytes);
                    if (ccs.getType() == CBORType.Map) {
                    	// Retrieve the public key from the CCS
                        peerPublicKeyRetrieved = Util.ccsToOneKey(ccs);
                    }
                    else {
                        Assert.fail("Invalid format of authentication credential");
                    }
                    break;
                case Constants.COSE_HEADER_PARAM_KCWT:
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
            
            peerSenderId = new byte[] { (byte) 0x77 };
            peerSenderIdFromResponse = joinResponse.
            	    get(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)).get(0).GetByteString(); 
            peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(publicKeyPeer2));
            Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
           
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
            	    get(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)).get(1).GetByteString();
            peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(publicKeyPeer1));
            Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
            
            peerAuthCredRetrieved = authCredsArray.get(1);
            if (peerAuthCredRetrieved.getType() != CBORType.ByteString) {
            	Assert.fail("Elements of the parameter 'creds' must be CBOR byte strings");
            }
            peerPublicKeyRetrievedBytes = peerAuthCredRetrieved.GetByteString();
            switch (credFmt) {
                case Constants.COSE_HEADER_PARAM_KCCS:
                	CBORObject ccs = CBORObject.DecodeFromBytes(peerPublicKeyRetrievedBytes);
                    if (ccs.getType() == CBORType.Map) {
                    	// Retrieve the public key from the CCS
                        peerPublicKeyRetrieved = Util.ccsToOneKey(ccs);
                    }
                    else {
                        Assert.fail("Invalid format of authentication credential");
                    }
                    break;
                case Constants.COSE_HEADER_PARAM_KCWT:
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
           
            Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)));
            Assert.assertEquals(CBORType.Array, joinResponse.get(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)).getType());
            Assert.assertEquals(2, joinResponse.get(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)).size());
            
            int expectedRoles = 0;
            expectedRoles = Util.addGroupOSCORERole(expectedRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
            expectedRoles = Util.addGroupOSCORERole(expectedRoles, GroupcommParameters.GROUP_OSCORE_RESPONDER);
            Assert.assertEquals(expectedRoles, joinResponse.get(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)).get(0).AsInt32());
            
            expectedRoles = 0;
            expectedRoles = Util.addGroupOSCORERole(expectedRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
            Assert.assertEquals(expectedRoles, joinResponse.get(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)).get(1).AsInt32());
           
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
	    
        int offset = 0;
		byte[] serializedGMNonceCBOR = joinResponse.get(CBORObject.FromObject(GroupcommParameters.KDC_NONCE)).EncodeToBytes();
		byte[] popInput = new byte[serializedCNonceCBOR.length + serializedGMNonceCBOR.length];
		System.arraycopy(serializedCNonceCBOR, 0, popInput, offset, serializedCNonceCBOR.length);
		offset += serializedCNonceCBOR.length;
		System.arraycopy(serializedGMNonceCBOR, 0, popInput, offset, serializedGMNonceCBOR.length);
		
    	CBORObject gmPopEvidence = joinResponse.get(CBORObject.FromObject(GroupcommParameters.KDC_CRED_VERIFY));
    	byte[] rawGmPopEvidence = gmPopEvidence.GetByteString();
    	
    	PublicKey gmPublicKey = gmPublicKeyRetrieved.AsPublicKey();
            	
    	Assert.assertEquals(true, Util.verifySignature(signKeyCurve, gmPublicKey, popInput, rawGmPopEvidence));
        
        
        /////////////////
        //
        // Part 2
        //
        /////////////////
        
        // Send a second Key Distribution Request, now as a group member
        
        System.out.println("\nPerforming a Key Distribution Rquest using OSCORE to GM at " +
        				   "coap://localhost/" + rootGroupMembershipResource + "/" + groupName);
        
        Request keyDistrReq = new Request(Code.GET, Type.CON);
        keyDistrReq.getOptions().setOscore(new byte[0]);
        
        
        System.out.println("");
        System.out.println("Sent Key Distribution request to GM as non member");
        CoapResponse r3 = c.advanced(keyDistrReq);
       
        Assert.assertEquals("CONTENT", r3.getCode().name());
        
        responsePayload = r3.getPayload();
        CBORObject keyDistributionResponse = CBORObject.DecodeFromBytes(responsePayload);
       
        Assert.assertEquals(CBORType.Map, keyDistributionResponse.getType());
       
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.GKTY)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.GKTY)).getType());
        Assert.assertEquals(GroupcommParameters.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, keyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.GKTY)).AsInt32());
       
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.KEY)));
        Assert.assertEquals(CBORType.Map, keyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.KEY)).getType());
       
        myMap = keyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.KEY));
       
        // Sanity check
        Assert.assertEquals(true, myMap.ContainsKey(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)));
        Assert.assertEquals(false, myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)));
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
        
        Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)).GetByteString());
       
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(gpEncAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.gp_enc_alg)));
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
              
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.NUM)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.NUM)).getType());
        // This assumes that the Group Manager did not rekey the group upon previous nodes' joining
        Assert.assertEquals(0, keyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.NUM)).AsInt32());
        
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.ACE_GROUPCOMM_PROFILE)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.ACE_GROUPCOMM_PROFILE)).getType());
        Assert.assertEquals(GroupcommParameters.COAP_GROUP_OSCORE_APP, keyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.ACE_GROUPCOMM_PROFILE)).AsInt32());
       
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.EXP)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.EXP)).getType());
        Assert.assertEquals(2682374400L, keyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.EXP)).AsInt64Value());
        
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.EXI)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.EXI)).getType());
       
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(signParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)));
        }
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(ecdhParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)));
        }
        
        
        /////////////////
        //
        // Part 3
        //
        /////////////////
		
        // Send a Version Request
        
        System.out.println("Performing a Version Request using OSCORE to GM at " +
        				   "coap://localhost/" + rootGroupMembershipResource + "/" + groupName + "/num");
        
        CoapClient c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" +
        		groupName + "/num", CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        Request VersionReq = new Request(Code.GET, Type.CON);
        VersionReq.getOptions().setOscore(new byte[0]);
        CoapResponse r4 = c1.advanced(VersionReq);
        
        System.out.println("");
        System.out.println("Sent Version request to GM");

        Assert.assertEquals("CONTENT", r4.getCode().name());
        
        CBORObject myObject = CBORObject.DecodeFromBytes(r4.getPayload());
        Assert.assertEquals(CBORType.Integer, myObject.getType());
        Assert.assertEquals(0, myObject.AsInt32());
        
        
        /////////////////
        //
        // Part 4
        //
        /////////////////
		
        // Send a Group Status Request
        
        System.out.println("Performing a Group Status Request using OSCORE to GM at " +
        				   "coap://localhost/" + rootGroupMembershipResource + "/" + groupName + "/active");
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" +
        		groupName + "/active", CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        Request GroupStatusReq = new Request(Code.GET, Type.CON);
        GroupStatusReq.getOptions().setOscore(new byte[0]);
        CoapResponse r5 = c1.advanced(GroupStatusReq);
        
        System.out.println("");
        System.out.println("Sent Group Status request to GM");

        Assert.assertEquals("CONTENT", r5.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r5.getPayload());
        Assert.assertEquals(CBORType.Boolean, myObject.getType());
        Assert.assertEquals(true, myObject.AsBoolean());
        
        
        /////////////////
        //
        // Part 5
        //
        /////////////////
		
        // Send a Policies Request
        
        System.out.println("Performing a Policies Request using OSCORE to GM at " +
        				   "coap://localhost/" + rootGroupMembershipResource + "/" + groupName+ "/policies");
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" +
        		groupName + "/policies", CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        Request GroupPoliciesReq = new Request(Code.GET, Type.CON);
        GroupPoliciesReq.getOptions().setOscore(new byte[0]);
        CoapResponse r6 = c1.advanced(GroupPoliciesReq);
        
        System.out.println("");
        System.out.println("Sent Group Policies request to GM");

        Assert.assertEquals("CONTENT", r6.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r6.getPayload());
        Assert.assertEquals(CBORType.Map, myObject.getType());
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(GroupcommParameters.GROUP_POLICIES)));
        Assert.assertEquals(3600, myObject.get(CBORObject.FromObject(GroupcommParameters.GROUP_POLICIES)).get(CBORObject.FromObject(GroupcommPolicies.KEY_CHECK_INTERVAL)).AsInt32());
        Assert.assertEquals(0, myObject.get(CBORObject.FromObject(GroupcommParameters.GROUP_POLICIES)).get(CBORObject.FromObject(GroupcommPolicies.EXP_DELTA)).AsInt32());

        
        /////////////////
        //
        // Part 6
        //
        /////////////////
		
        // Send an Authentication Credential Request, using the GET method
        
        System.out.println("Performing an Authentication Credential GET Request using OSCORE to GM at " +
        				   "coap://localhost/" + rootGroupMembershipResource + "/" +
        	        		groupName + "/creds");
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" +
        		groupName + "/creds", CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        Request AuthCredReq = new Request(Code.GET, Type.CON);
        AuthCredReq.getOptions().setOscore(new byte[0]);
        CoapResponse r7 = c1.advanced(AuthCredReq);
        
        System.out.println("");
        System.out.println("Sent Authentication Credential GET request to GM");

        Assert.assertEquals("CONTENT", r7.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r7.getPayload());
        Assert.assertEquals(CBORType.Map, myObject.getType());
        
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(GroupcommParameters.NUM)));
        Assert.assertEquals(CBORType.Integer, myObject.get(CBORObject.FromObject(GroupcommParameters.NUM)).getType());
        // This assumes that the Group Manager did not rekey the group upon previous nodes' joining
        Assert.assertEquals(0, myObject.get(CBORObject.FromObject(GroupcommParameters.NUM)).AsInt32());
        
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(GroupcommParameters.CREDS)));
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)));
        Assert.assertEquals(CBORType.Array, myObject.get(CBORObject.FromObject(GroupcommParameters.CREDS)).getType());
        
        authCredsArray = myObject.get(CBORObject.FromObject(GroupcommParameters.CREDS));        
        
        byte[] peerSenderId;
        OneKey peerPublicKey;
        OneKey peerPublicKeyRetrieved = null;
        CBORObject peerAuthCredRetrieved;
        byte[] peerSenderIdFromResponse;
        
        Assert.assertEquals(3, authCredsArray.size());
        
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)));
        Assert.assertEquals(CBORType.Array, myObject.get(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)).getType());
        Assert.assertEquals(3, myObject.get(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)).size());
        
        // Retrieve and check the public key of another node in the group
        peerSenderId = new byte[] { (byte) 0x77 };
        peerSenderIdFromResponse = myObject.
        	    get(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)).get(0).GetByteString();
        peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(publicKeyPeer2));
        Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
       
        peerAuthCredRetrieved = authCredsArray.get(0);
        if (peerAuthCredRetrieved.getType() != CBORType.ByteString) {
        	Assert.fail("Elements of the parameter 'creds' must be CBOR byte strings");
        }
        byte[] peerPublicKeyRetrievedBytes = peerAuthCredRetrieved.GetByteString();
        switch (credFmt) {
            case Constants.COSE_HEADER_PARAM_KCCS:
            	CBORObject ccs = CBORObject.DecodeFromBytes(peerPublicKeyRetrievedBytes);
                if (ccs.getType() == CBORType.Map) {
                	// Retrieve the public key from the CCS
                    peerPublicKeyRetrieved = Util.ccsToOneKey(ccs);
                }
                else {
                    Assert.fail("Invalid format of authentication credential");
                }
                break;
            case Constants.COSE_HEADER_PARAM_KCWT:
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
        
        peerAuthCredRetrieved = authCredsArray.get(1);
        if (peerAuthCredRetrieved.getType() != CBORType.ByteString) {
        	Assert.fail("Elements of the parameter 'creds' must be CBOR byte strings");
        }
        peerPublicKeyRetrievedBytes = peerAuthCredRetrieved.GetByteString();
        switch (credFmt) {
            case Constants.COSE_HEADER_PARAM_KCCS:
            	CBORObject ccs = CBORObject.DecodeFromBytes(peerPublicKeyRetrievedBytes);
                if (ccs.getType() == CBORType.Map) {
                	// Retrieve the public key from the CCS
                    peerPublicKeyRetrieved = Util.ccsToOneKey(ccs);
                }
                else {
                    Assert.fail("Invalid format of authentication credential");
                }
                break;
            case Constants.COSE_HEADER_PARAM_KCWT:
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
        
        // Retrieve and check the public key of another node in the group
        peerSenderId = new byte[] { (byte) 0x52 };
        peerSenderIdFromResponse = myObject.
        	    get(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)).get(1).GetByteString();    
        peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(publicKeyPeer1));
        Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
       
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
        
        peerAuthCredRetrieved = authCredsArray.get(2);
        if (peerAuthCredRetrieved.getType() != CBORType.ByteString) {
        	Assert.fail("Elements of the parameter 'creds' must be CBOR byte strings");
        }
        peerPublicKeyRetrievedBytes = peerAuthCredRetrieved.GetByteString();
        switch (credFmt) {
            case Constants.COSE_HEADER_PARAM_KCCS:
            	CBORObject ccs = CBORObject.DecodeFromBytes(peerPublicKeyRetrievedBytes);
                if (ccs.getType() == CBORType.Map) {
                	// Retrieve the public key from the CCS
                    peerPublicKeyRetrieved = Util.ccsToOneKey(ccs);
                }
                else {
                    Assert.fail("Invalid format of authentication credential");
                }
                break;
            case Constants.COSE_HEADER_PARAM_KCWT:
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
        
        // Retrieve and check the public key of this exact requester node
        peerSenderId = new byte[] { (byte) 0x25 };
        peerSenderIdFromResponse = myObject.
        	    get(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)).get(2).GetByteString();   
        peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(groupKeyPair)).PublicKey();
        Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
        
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
        
        Assert.assertEquals(3, myObject.get(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)).size());
        
        int expectedRoles = 0;
        expectedRoles = Util.addGroupOSCORERole(expectedRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
        expectedRoles = Util.addGroupOSCORERole(expectedRoles, GroupcommParameters.GROUP_OSCORE_RESPONDER);
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)).get(0).AsInt32());
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)).get(2).AsInt32());
        expectedRoles = 0;
        expectedRoles = Util.addGroupOSCORERole(expectedRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)).get(1).AsInt32());
        
        
        /////////////////
        //
        // Part 7
        //
        /////////////////
		
        // Send an Authentication Credential Request, using the FETCH method
        
        System.out.println("Performing an Authentication Credential FETCH Request using OSCORE to GM at " +
        				   "coap://localhost/" + rootGroupMembershipResource + "/" + groupName + "/creds");
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" +
        		groupName + "/creds", CoAP.DEFAULT_COAP_PORT), ctxDB);

        requestPayload = CBORObject.NewMap();

        CBORObject getAuthCreds = CBORObject.NewArray();
        
        // Ask for the public keys of group members that are (also) responder.
        //
        // This will match with both this node's public key,
        // as well as the public key of the node with Sender ID 0x77 
        
        getAuthCreds.Add(CBORObject.True);
        
        getAuthCreds.Add(CBORObject.NewArray());
        myRoles = 0;
        myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_RESPONDER);
        getAuthCreds.get(1).Add(myRoles);

        // Ask for the public keys of the other group members
        getAuthCreds.Add(CBORObject.NewArray());
        peerSenderId = new byte[] { (byte) 0x52 };
        getAuthCreds.get(2).Add(peerSenderId);
        peerSenderId = new byte[] { (byte) 0x77 };
        getAuthCreds.get(2).Add(peerSenderId);
        
        requestPayload.Add(GroupcommParameters.GET_CREDS, getAuthCreds);
        
        AuthCredReq = new Request(Code.FETCH, Type.CON);
        AuthCredReq.getOptions().setOscore(new byte[0]);
        AuthCredReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        AuthCredReq.setPayload(requestPayload.EncodeToBytes());
        CoapResponse r8 = c1.advanced(AuthCredReq);
        
        System.out.println("");
        System.out.println("Sent Authentication Credential FETCH request to GM");

        Assert.assertEquals("CONTENT", r8.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r8.getPayload());
        Assert.assertEquals(CBORType.Map, myObject.getType());
        
        Assert.assertEquals(true, joinResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.NUM)));
        Assert.assertEquals(CBORType.Integer, joinResponse.get(CBORObject.FromObject(GroupcommParameters.NUM)).getType());
        // This assumes that the Group Manager did not rekey the group upon previous nodes' joining
        Assert.assertEquals(0, joinResponse.get(CBORObject.FromObject(GroupcommParameters.NUM)).AsInt32());
        
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(GroupcommParameters.CREDS)));
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)));
        
        Assert.assertEquals(CBORType.Array, myObject.get(CBORObject.FromObject(GroupcommParameters.CREDS)).getType());
        authCredsArray = myObject.get(CBORObject.FromObject(GroupcommParameters.CREDS));
        Assert.assertEquals(3, authCredsArray.size());
        
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)));
        Assert.assertEquals(CBORType.Array, myObject.get(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)).getType());
        Assert.assertEquals(3, myObject.get(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)).size());
        
        
        // Retrieve and check the public key of another node in the group
        peerSenderId = new byte[] { (byte) 0x77 };
        peerSenderIdFromResponse = myObject.
        	    get(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)).get(0).GetByteString();      
        peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(publicKeyPeer2));
        Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
       
        peerAuthCredRetrieved = authCredsArray.get(0);
        if (peerAuthCredRetrieved.getType() != CBORType.ByteString) {
        	Assert.fail("Elements of the parameter 'creds' must be CBOR byte strings");
        }
        peerPublicKeyRetrievedBytes = peerAuthCredRetrieved.GetByteString();
        switch (credFmt) {
            case Constants.COSE_HEADER_PARAM_KCCS:
            	CBORObject ccs = CBORObject.DecodeFromBytes(peerPublicKeyRetrievedBytes);
                if (ccs.getType() == CBORType.Map) {
                	// Retrieve the public key from the CCS
                    peerPublicKeyRetrieved = Util.ccsToOneKey(ccs);
                }
                else {
                    Assert.fail("Invalid format of authentication credential");
                }
                break;
            case Constants.COSE_HEADER_PARAM_KCWT:
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
        
        // Retrieve and check the public key of another node in the group
        peerSenderId = new byte[] { (byte) 0x52 };
        peerSenderIdFromResponse = myObject.
        	    get(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)).get(1).GetByteString();      
        peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(publicKeyPeer1));
        Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
       
        peerAuthCredRetrieved = authCredsArray.get(1);
        if (peerAuthCredRetrieved.getType() != CBORType.ByteString) {
        	Assert.fail("Elements of the parameter 'creds' must be CBOR byte strings");
        }
        peerPublicKeyRetrievedBytes = peerAuthCredRetrieved.GetByteString();
        switch (credFmt) {
            case Constants.COSE_HEADER_PARAM_KCCS:
            	CBORObject ccs = CBORObject.DecodeFromBytes(peerPublicKeyRetrievedBytes);
                if (ccs.getType() == CBORType.Map) {
                	// Retrieve the public key from the CCS
                    peerPublicKeyRetrieved = Util.ccsToOneKey(ccs);
                }
                else {
                    Assert.fail("Invalid format of authentication credential");
                }
                break;
            case Constants.COSE_HEADER_PARAM_KCWT:
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

        
        // Retrieve and check the public key this same node in the group
        peerSenderId = senderId;
        peerSenderIdFromResponse = myObject.
        	    get(CBORObject.FromObject(GroupcommParameters.PEER_IDENTIFIERS)).get(2).GetByteString();   
        peerPublicKey = new OneKey(CBORObject.DecodeFromBytes(groupKeyPair)).PublicKey();
        Assert.assertArrayEquals(peerSenderId, peerSenderIdFromResponse);
       
        peerAuthCredRetrieved = authCredsArray.get(2);
        if (peerAuthCredRetrieved.getType() != CBORType.ByteString) {
        	Assert.fail("Elements of the parameter 'creds' must be CBOR byte strings");
        }
        peerPublicKeyRetrievedBytes = peerAuthCredRetrieved.GetByteString();
        switch (credFmt) {
            case Constants.COSE_HEADER_PARAM_KCCS:
            	CBORObject ccs = CBORObject.DecodeFromBytes(peerPublicKeyRetrievedBytes);
                if (ccs.getType() == CBORType.Map) {
                	// Retrieve the public key from the CCS
                    peerPublicKeyRetrieved = Util.ccsToOneKey(ccs);
                }
                else {
                    Assert.fail("Invalid format of authentication credential");
                }
                break;
            case Constants.COSE_HEADER_PARAM_KCWT:
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
        
        
        Assert.assertEquals(3, myObject.get(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)).size());
        
        expectedRoles = 0;
        expectedRoles = Util.addGroupOSCORERole(expectedRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
        expectedRoles = Util.addGroupOSCORERole(expectedRoles, GroupcommParameters.GROUP_OSCORE_RESPONDER);
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)).get(0).AsInt32());
        expectedRoles = 0;
        expectedRoles = Util.addGroupOSCORERole(expectedRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
        Assert.assertEquals(expectedRoles, myObject.get(CBORObject.FromObject(GroupcommParameters.PEER_ROLES)).get(1).AsInt32());
        
        
        /////////////////
        //
        // Part 8
        //
        /////////////////
		
        // Send a Key Distribution Request to the node sub-resource, using the GET method
        
        System.out.println("Performing a Key Distribution Request GET Request " +
        				   "using OSCORE to GM at coap://localhost/" + nodeResourceLocationPath);
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + nodeResourceLocationPath, CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        Request KeyDistributionReq = new Request(Code.GET, Type.CON);
        KeyDistributionReq.getOptions().setOscore(new byte[0]);
        CoapResponse r9 = c1.advanced(KeyDistributionReq);
        
        System.out.println("");
        System.out.println("Sent Key Distribution GET request to the node sub-resource at the GM");
        
        Assert.assertEquals("CONTENT", r9.getCode().name());
        
        responsePayload = r9.getPayload();
        CBORObject KeyDistributionResponse = CBORObject.DecodeFromBytes(responsePayload);
       
        Assert.assertEquals(CBORType.Map, KeyDistributionResponse.getType());
       
        Assert.assertEquals(true, KeyDistributionResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.GKTY)));
        Assert.assertEquals(CBORType.Integer, KeyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.GKTY)).getType());
        Assert.assertEquals(GroupcommParameters.GROUP_OSCORE_INPUT_MATERIAL_OBJECT, KeyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.GKTY)).AsInt32());
       
        Assert.assertEquals(true, KeyDistributionResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.KEY)));
        Assert.assertEquals(CBORType.Map, KeyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.KEY)).getType());
       
        myMap = KeyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.KEY));
       
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
       
        Assert.assertArrayEquals(masterSecret, myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.ms)).GetByteString());
        Assert.assertArrayEquals(senderId, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.group_SenderID)).GetByteString());
       
        Assert.assertEquals(hkdf.AsCBOR(), myMap.get(CBORObject.FromObject(OSCOREInputMaterialObjectParameters.hkdf)));
        Assert.assertEquals(gpEncAlg.AsCBOR(), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.gp_enc_alg)));
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
              
        Assert.assertEquals(true, KeyDistributionResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.NUM)));
        Assert.assertEquals(CBORType.Integer, KeyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.NUM)).getType());
        // This assumes that the Group Manager did not rekey the group upon previous nodes' joining
        Assert.assertEquals(0, KeyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.NUM)).AsInt32());
        
        Assert.assertEquals(true, KeyDistributionResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.ACE_GROUPCOMM_PROFILE)));
        Assert.assertEquals(CBORType.Integer, KeyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.ACE_GROUPCOMM_PROFILE)).getType());
        Assert.assertEquals(GroupcommParameters.COAP_GROUP_OSCORE_APP, KeyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.ACE_GROUPCOMM_PROFILE)).AsInt32());
       
        Assert.assertEquals(true, KeyDistributionResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.EXP)));
        Assert.assertEquals(CBORType.Integer, KeyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.EXP)).getType());
        Assert.assertEquals(2682374400L, keyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.EXP)).AsInt64Value());
       
        Assert.assertEquals(true, keyDistributionResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.EXI)));
        Assert.assertEquals(CBORType.Integer, keyDistributionResponse.get(CBORObject.FromObject(GroupcommParameters.EXI)).getType());
        
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(signParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.sign_params)));
        }
        if (myMap.ContainsKey(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params))) {
            Assert.assertEquals(CBORType.Array, myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)).getType());
            Assert.assertEquals(CBORObject.FromObject(ecdhParams), myMap.get(CBORObject.FromObject(GroupOSCOREInputMaterialObjectParameters.ecdh_params)));
        }

        
        /////////////////
        //
        // Part 9
        //
        /////////////////
		
        // Send a Key Renewal Request to the node sub-resource, using the PUT method
        
        System.out.println("Performing a Key Renewal Request " +
        				   "using OSCORE to GM at coap://localhost/" + nodeResourceLocationPath);
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + nodeResourceLocationPath, CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        Request KeyRenewalReq = new Request(Code.POST, Type.CON);
        KeyRenewalReq.getOptions().setOscore(new byte[0]);
                
        CoapResponse r10 = c1.advanced(KeyRenewalReq);

        System.out.println("");
        System.out.println("Sent Key Renewal Request to the node sub-resource at the GM");
        
        Assert.assertEquals("CHANGED", r10.getCode().name());
        
        responsePayload = r10.getPayload();
        CBORObject KeyRenewalResponse = CBORObject.DecodeFromBytes(responsePayload);
       
        Assert.assertEquals(CBORType.Map, KeyRenewalResponse.getType());
        Assert.assertEquals(true, KeyRenewalResponse.ContainsKey(CBORObject.FromObject(GroupcommParameters.GROUP_SENDER_ID)));
        Assert.assertEquals(CBORType.ByteString, KeyRenewalResponse.get(CBORObject.FromObject(GroupcommParameters.GROUP_SENDER_ID)).getType());
        
        
        
        /////////////////
        //
        // Part 10
        //
        /////////////////
		
        // Send an Authentication Credential Update Request to the node sub-resource /cred, using the POST method
        
        System.out.println("Performing an Authentication Credential Update Request " +
        		"using OSCORE to GM at coap://localhost/" + nodeResourceLocationPath + "/cred");
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + nodeResourceLocationPath +  "/cred", CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        requestPayload = CBORObject.NewMap();
        
        
        byte[] cred = null;
        
        /*
	    // Build the authentication credential according to the format used in the group
	    // Note: most likely, the result will NOT follow the required deterministic
	    //       encoding in byte lexicographic order, and it has to be adjusted offline
        OneKey publicKey = new OneKey(CBORObject.DecodeFromBytes(groupKeyPairUpdate)).PublicKey();
        switch (credFmtExpected.AsInt32()) {
            case Constants.COSE_HEADER_PARAM_KCCS:
            	// Build a CCS including the public key
                cred = Util.oneKeyToCCS(publicKey, "");
                break;
            case Constants.COSE_HEADER_PARAM_KCWT:
                // Build/retrieve a CWT including the public key
                // TODO
                break;
            case Constants.COSE_HEADER_PARAM_X5CHAIN:
                // Build/retrieve the certificate including the public key
                // TODO
                break;
        }
        */
        
        switch (credFmtExpected.AsInt32()) {
	        case Constants.COSE_HEADER_PARAM_KCCS:
	            // A CCS including the public key
	            if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
	                cred = Utils.hexToBytes("A2026008A101A5010203262001215820D8692E6CC344A51BB8D62AB768C52F3D281317B789F4F123614806D0B051443D225820A9F0024604BB007C4A92210FEF5CA81C779BC5303F8C1E65F2686B81D2244088");
	            }
	            if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
	                cred = Utils.hexToBytes("A2026008A101A401010327200621582021C96449BDF354F6C8306B96CFD9E62859B5190E27C0F926FBEEA144606DB404");
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

        
        // Add the nonce for the PoP of the Client's private key
        byte[] cnonceCred = new byte[8];
        new SecureRandom().nextBytes(cnonceCred);
        requestPayload.Add(GroupcommParameters.CNONCE, cnonceCred);

        // Add the signature computed over
        // (scope | rsnonce | cnonce), using the Client's private key
        offset = 0;
        PrivateKey privKey = (new OneKey(CBORObject. DecodeFromBytes(groupKeyPairUpdate))).AsPrivateKey();

        byte[] serializedScopeCBOR = CBORObject.FromObject(byteStringScope).EncodeToBytes();
        serializedGMNonceCBOR = CBORObject.FromObject(gm_nonce).EncodeToBytes();
        byte[] serializedCNonceCredCBOR = CBORObject.FromObject(cnonceCred).EncodeToBytes();
        popInput = new byte[serializedScopeCBOR.length + serializedGMNonceCBOR.length + serializedCNonceCredCBOR.length];
        System.arraycopy(serializedScopeCBOR, 0, popInput, offset, serializedScopeCBOR.length);
        offset += serializedScopeCBOR.length;
        System.arraycopy(serializedGMNonceCBOR, 0, popInput, offset, serializedGMNonceCBOR.length);
        offset += serializedGMNonceCBOR.length;
        System.arraycopy(serializedCNonceCredCBOR, 0, popInput, offset, serializedCNonceCredCBOR.length);

        byte[] popEvidence = Util.computeSignature(signKeyCurve, privKey, popInput);

        if (popEvidence != null)
            requestPayload.Add(GroupcommParameters.CLIENT_CRED_VERIFY, popEvidence);
        else
            Assert.fail("Computed signature is empty");
        
        Request AuthCredUpdateReq = new Request(Code.POST, Type.CON);
        AuthCredUpdateReq.getOptions().setOscore(new byte[0]);
        AuthCredUpdateReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        AuthCredUpdateReq.setPayload(requestPayload.EncodeToBytes());
        
        CoapResponse r11 = c1.advanced(AuthCredUpdateReq);

        System.out.println("");
        System.out.println("Sent Authentication Credential Update Request to the node sub-resource at the GM");
        
        Assert.assertEquals("CHANGED", r11.getCode().name());
        
        responsePayload = r11.getPayload();
        
        
        /////////////////
        //
        // Part 11
        //
        /////////////////
		
        // Send a Group Name and URI Retrieval Request, using the FETCH method
        
        System.out.println("Performing a Group Name and URI Retrieval Request using OSCORE to GM at " +
        				   "coap://localhost/" + rootGroupMembershipResource);
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource, CoAP.DEFAULT_COAP_PORT), ctxDB);

        requestPayload = CBORObject.NewMap();

        CBORObject reqGroupIds = CBORObject.NewArray();
        reqGroupIds.Add(CBORObject.FromObject(groupId));
        
        requestPayload.Add(GroupcommParameters.GID, reqGroupIds);
        
        Request GroupNamesReq = new Request(Code.FETCH, Type.CON);
        GroupNamesReq.getOptions().setOscore(new byte[0]);
        GroupNamesReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        GroupNamesReq.setPayload(requestPayload.EncodeToBytes());
        CoapResponse r12 = c1.advanced(GroupNamesReq);
        
        System.out.println("");
        System.out.println("Sent Group Name and URI Retrieval Request FETCH request to GM");

        Assert.assertEquals("CONTENT", r12.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r12.getPayload());
        
        Assert.assertEquals(CBORType.Map, myObject.getType());
        Assert.assertEquals(3, myObject.size());
        
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(GroupcommParameters.GID)));
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(GroupcommParameters.GNAME)));
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(GroupcommParameters.GURI)));
        
        Assert.assertEquals(CBORType.Array, myObject.get(CBORObject.FromObject(GroupcommParameters.GID)).getType());
        Assert.assertEquals(CBORType.Array, myObject.get(CBORObject.FromObject(GroupcommParameters.GNAME)).getType());
        Assert.assertEquals(CBORType.Array, myObject.get(CBORObject.FromObject(GroupcommParameters.GURI)).getType());
        
        Assert.assertEquals(1, myObject.get(CBORObject.FromObject(GroupcommParameters.GID)).size());
        Assert.assertArrayEquals(groupId, myObject.get(CBORObject.FromObject(GroupcommParameters.GID)).get(0).GetByteString());
        
        Assert.assertEquals(1, myObject.get(CBORObject.FromObject(GroupcommParameters.GNAME)).size());
        Assert.assertEquals(groupName, myObject.get(CBORObject.FromObject(GroupcommParameters.GNAME)).get(0).AsString());
        
        Assert.assertEquals(1, myObject.get(CBORObject.FromObject(GroupcommParameters.GURI)).size());
        String expectedUri = new String("/" + rootGroupMembershipResource + "/" + groupName);
        Assert.assertEquals(expectedUri, myObject.get(CBORObject.FromObject(GroupcommParameters.GURI)).get(0).AsString());
        
        // Send a second request, indicating the Group ID of a non existing OSCORE group
        
        requestPayload = CBORObject.NewMap();

        reqGroupIds = CBORObject.NewArray();
        byte[] groupId2 = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22 };
        reqGroupIds.Add(CBORObject.FromObject(groupId2));
        
        requestPayload.Add(GroupcommParameters.GID, reqGroupIds);
        
        GroupNamesReq = new Request(Code.FETCH, Type.CON);
        GroupNamesReq.getOptions().setOscore(new byte[0]);
        GroupNamesReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        GroupNamesReq.setPayload(requestPayload.EncodeToBytes());
        r12 = c1.advanced(GroupNamesReq);
        
        Assert.assertEquals("CONTENT", r12.getCode().name());
        
        myObject = CBORObject.DecodeFromBytes(r12.getPayload());
        
        Assert.assertEquals(CBORType.ByteString, myObject.getType());
        Assert.assertEquals(0, myObject.size());
        
        
        /////////////////
        //
        // Part 12
        //
        /////////////////
        
        // Send a KDC Authentication Credential Request, using the GET method

        System.out.println("Performing a KDC Authentication Credential GET Request using OSCORE to GM at " +
        				   "coap://localhost/" + rootGroupMembershipResource + "/" + groupName + "/kdc-cred");

        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
                "coap://localhost/" + rootGroupMembershipResource + "/" +
                groupName + "/kdc-cred", CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        Request GmAuthCredReq = new Request(Code.GET, Type.CON);
        GmAuthCredReq.getOptions().setOscore(new byte[0]);
        CoapResponse r13 = c1.advanced(GmAuthCredReq);

        System.out.println("");
        System.out.println("Sent KDC Authentication Credential GET request to GM");

        Assert.assertEquals("CONTENT", r13.getCode().name());

        myObject = CBORObject.DecodeFromBytes(r13.getPayload());
        Assert.assertEquals(CBORType.Map, myObject.getType());
        
        // Check the proof-of-possession evidence over kdc_nonce, using the GM's public key
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(GroupcommParameters.KDC_NONCE)));
        Assert.assertEquals(CBORType.ByteString, myObject.get(CBORObject.FromObject(GroupcommParameters.KDC_NONCE)).getType());
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(GroupcommParameters.KDC_CRED)));
        Assert.assertEquals(CBORType.ByteString, myObject.get(CBORObject.FromObject(GroupcommParameters.KDC_CRED)).getType());
        Assert.assertEquals(true, myObject.ContainsKey(CBORObject.FromObject(GroupcommParameters.KDC_CRED_VERIFY)));
        Assert.assertEquals(CBORType.ByteString, myObject.get(CBORObject.FromObject(GroupcommParameters.KDC_CRED_VERIFY)).getType());
        
        gmPublicKeyRetrieved = null;
        kdcCredBytes = myObject.get(CBORObject.FromObject(GroupcommParameters.KDC_CRED)).GetByteString();
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
        
        gmPublicKey = gmPublicKeyRetrieved.AsPublicKey();
        
        offset = 0;
		serializedGMNonceCBOR = myObject.get(CBORObject.FromObject(GroupcommParameters.KDC_NONCE)).EncodeToBytes();
		popInput = new byte[serializedCNonceCBOR.length + serializedGMNonceCBOR.length];
		System.arraycopy(serializedCNonceCBOR, 0, popInput, offset, serializedCNonceCBOR.length);
		offset += serializedCNonceCBOR.length;
		System.arraycopy(serializedGMNonceCBOR, 0, popInput, offset, serializedGMNonceCBOR.length);
		
    	gmPopEvidence = myObject.get(CBORObject.FromObject(GroupcommParameters.KDC_CRED_VERIFY));
    	rawGmPopEvidence = gmPopEvidence.GetByteString();
    	
    	Assert.assertEquals(true, Util.verifySignature(signKeyCurve, gmPublicKey, popInput, rawGmPopEvidence));
        

        /////////////////
        //
        // Part 13
        //
        /////////////////
		
        // Send a Stale Sender IDs Request
        
        System.out.println("\nPerforming a Stale Sender IDs FETCH Request using OSCORE to GM at " +
                		   "coap://localhost/" + rootGroupMembershipResource + "/" + groupName + "/stale-sids");
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
                "coap://localhost/" + rootGroupMembershipResource + "/" +
                groupName + "/stale-sids", CoAP.DEFAULT_COAP_PORT), ctxDB);
        
        requestPayload = CBORObject.FromObject(0);
        
        Request StaleSenderIdsReq = new Request(Code.FETCH, Type.CON);
        StaleSenderIdsReq.getOptions().setOscore(new byte[0]);
        StaleSenderIdsReq.setPayload(requestPayload.EncodeToBytes());
        CoapResponse r14 = c1.advanced(StaleSenderIdsReq);

        System.out.println("");
        System.out.println("Sent Stale Sender IDs FETCH request to GM");
        
        System.out.println("Received Stale Sender IDs FETCH request from the GM: " +
        				   new String(r14.getPayload()));
        
        Assert.assertEquals("BAD_REQUEST", r14.getCode().name());
        Assert.assertEquals("Invalid payload format", new String(r14.getPayload()));
    	
    	
        /////////////////
        //
        // Part 14
        //
        /////////////////
		
        // Send a Leaving Group Request to the node sub-resource, using the DELETE method
        
        System.out.println("\nPerforming a Leaving Group Request using OSCORE to GM at coap://localhost/" +
        				   nodeResourceLocationPath);
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + nodeResourceLocationPath, CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        Request LeavingGroupReq = new Request(Code.DELETE, Type.CON);
        LeavingGroupReq.getOptions().setOscore(new byte[0]);
        
        CoapResponse r15 = c1.advanced(LeavingGroupReq);

        System.out.println("");
        System.out.println("Sent Group Leaving Request to the node sub-resource at the GM");
        
        Assert.assertEquals("DELETED", r15.getCode().name());
        
        responsePayload = r14.getPayload();
        
        // Send a Version Request, not as a member any more
        
        System.out.println("\nPerforming a Version Request using OSCORE to GM at " +
        				   "coap://localhost/" + rootGroupMembershipResource + "/" + groupName + "/num");
        
        c1 = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		"coap://localhost/" + rootGroupMembershipResource + "/" +
        		groupName + "/num", CoAP.DEFAULT_COAP_PORT), ctxDB);
                
        VersionReq = new Request(Code.GET, Type.CON);
        VersionReq.getOptions().setOscore(new byte[0]);
        CoapResponse r16 = c1.advanced(VersionReq);
        
        System.out.println("");
        System.out.println("Sent Version request to GM");

        Assert.assertEquals("FORBIDDEN", r16.getCode().name());
        
    }
    
    /**
     * Test unauthorized access to the RS
     * 
     * @throws Exception 
     */
    @Test
    public void testNoAccess() throws Exception {
        
        ctxDB.addContext("coap://localhost/helloWorld", osctx);
        CoapClient c = OSCOREProfileRequests.getClient(
                new InetSocketAddress("coap://localhost/helloWorld", CoAP.DEFAULT_COAP_PORT), ctxDB);
        
        CoapResponse res = c.get();
        assert(res.getCode().equals(CoAP.ResponseCode.UNAUTHORIZED));
    }
   
}
