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
package se.sics.prototype.apps;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import org.eclipse.californium.oscore.group.MultiKey;
import org.junit.Assert;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import com.upokecenter.cbor.CBORException;

import se.sics.ace.Constants;
import se.sics.ace.GroupcommParameters;
import se.sics.ace.Util;
import se.sics.ace.client.GetToken;
import se.sics.ace.coap.client.OSCOREProfileRequests;
import se.sics.ace.coap.client.OSCOREProfileRequestsGroupOSCORE;
import se.sics.prototype.support.KeyStorage;
import se.sics.prototype.support.Tools;

/**
 * A stand-alone application for Admin->AS followed by Admin->GM communication
 * using the OSCORE profile.
 * 
 * First the Admin will request an Access Token from the AS, it will then post
 * it to the GM and then proceed with creating two groups for further use.
 * 
 * @author Rikard Höglund
 *
 */
public class OscoreAdminClient {

	private final static String groupCollectionResourcePath = "manage";

	// Sets the default GM port to use
	private static int GM_PORT = CoAP.DEFAULT_COAP_PORT + 100;
	// Sets the default GM hostname/IP to use
	private static String GM_HOST = "localhost";

	// Sets the default AS port to use
	private static int AS_PORT = CoAP.DEFAULT_COAP_PORT - 100;
	// Sets the default AS hostname/IP to use
	private static String AS_HOST = "localhost";

	// Multicast IP for Group A
	static final InetAddress groupA_multicastIP = new InetSocketAddress("224.0.1.191", 0).getAddress();

	// Multicast IP for Group B
	static final InetAddress groupB_multicastIP = new InetSocketAddress("224.0.1.192", 0).getAddress();

	static HashMapCtxDB db = new HashMapCtxDB();

	// OSCORE Context shared between Client and AS
	static OSCoreCtx ctx = null;

	private final static int MAX_UNFRAGMENTED_SIZE = 4096;

	// Each set of the list refers to a different size of Recipient IDs.
	// The element with index 0 includes as elements Recipient IDs with size 1
	// byte.
	private static List<Set<Integer>> usedRecipientIds = new ArrayList<Set<Integer>>();

	static {
		CoapConfig.register();
	}

	/**
	 * Main method for Token request followed by Group joining
	 * 
	 * @param args input command line arguments
	 * 
	 * @throws URISyntaxException on failure to parse command line arguments
	 */
	public static void main(String[] args) throws URISyntaxException {

		System.out.println("Starting OscoreAdminClient:");
		System.out.println("Group admin that configures group(s) at a GM");

		// install needed cryptography providers
		try {
			org.eclipse.californium.oscore.InstallCryptoProviders.installProvider();
		} catch (Exception e) {
			System.err.println("Failed to install cryptography providers.");
			e.printStackTrace();
		}

		// Set member name, AS and GM to use from command line arguments
		String memberName = "admin1";
		int delay = 0;
		for (int i = 0; i < args.length; i++) {
			if (args[i].equals("-name")) {
				memberName = args[i + 1];
				i++;
			} else if (args[i].equals("-gm")) {
				GM_HOST = new URI(args[i + 1]).getHost();
				GM_PORT = new URI(args[i + 1]).getPort();
				i++;
			} else if (args[i].equals("-as")) {
				AS_HOST = new URI(args[i + 1]).getHost();
				AS_PORT = new URI(args[i + 1]).getPort();
				i++;
			} else if (args[i].toLowerCase().endsWith("-delay")) {
				delay = Integer.parseInt(args[i + 1]);
				i++;
			} else if (args[i].toLowerCase().endsWith("-help")) {
				printHelp();
				System.exit(0);
			}
		}

		// Delay before starting
		try {
			Thread.sleep(delay * 1000);
		} catch (InterruptedException e) {
			System.err.println("Failed to sleep before starting");
			e.printStackTrace();
		}

		// Explicitly enable the OSCORE Stack
		if (CoapEndpoint.isDefaultCoapStackFactorySet() == false) {
			OSCoreCoapStackFactory.useAsDefault(db);
		}

		// Wait for Authorization Server to become available
		Tools.waitForAs(AS_HOST, AS_PORT);

		// Build empty sets of assigned Sender IDs; one set for each possible
		for (int i = 0; i < 4; i++) {
			// Sender ID size in bytes.
			// The set with index 0 refers to Sender IDs with size 1 byte
			usedRecipientIds.add(new HashSet<Integer>());
		}

		// Set public/private key to use in the group
		String publicPrivateKey;
		publicPrivateKey = CBORObject.DecodeFromBytes(KeyStorage.memberCcs.get(memberName)).toString();

		// Set key (OSCORE master secret) to use towards AS
		byte[] keyToAS;
		keyToAS = KeyStorage.memberAsKeys.get(memberName);

		System.out.println("Configured with parameters:");
		System.out.println("\tAS: " + AS_HOST + ":" + AS_PORT);
		System.out.println("\tGM: " + GM_HOST + ":" + GM_PORT);
		System.out.println("\tMember name: " + memberName);
		System.out.println("\tGroup Key: " + publicPrivateKey);
		System.out.println("\tKey to AS: " + StringUtil.byteArray2Hex(keyToAS));

		printPause(memberName, "Will now request Token from AS");

		// Request Token from AS
		Response responseFromAS = null;
		try {
			responseFromAS = requestToken(memberName, keyToAS);
		} catch (Exception e) {
			System.err.print("Token request procedure failed: ");
			e.printStackTrace();
		}

		// Retry if Token was not provided
		while (responseFromAS == null || responseFromAS.getPayload() == null || responseFromAS.getPayloadSize() == 0) {
			System.err.println("No Token received from AS, retrying...");
			try {
				Thread.sleep(30 * 1000);
				responseFromAS = requestToken(memberName, keyToAS);
			} catch (Exception e) {
				System.err.println("Token request retry failed");
			}
		}

		printPause(memberName, "Will now post Token to Group Manager and perform group configuration");

		// Wait for Group Manager to become available
		Tools.waitForGm(GM_HOST, GM_PORT);

		// Get OneKey representation of this member's public/private key
		OneKey cKeyPair = new MultiKey(KeyStorage.memberCcs.get(memberName),
				KeyStorage.memberPrivateKeys.get(memberName)).getCoseKey();
		// Get byte array of this member's CCS
		byte[] memberCcs = KeyStorage.memberCcs.get(memberName);

		// Post Token to GM and perform Group joining
		boolean adminSuccess = false;
		try {
			adminSuccess = testAdminRequestToGM(memberName, GM_HOST, GM_PORT, db, cKeyPair,
					responseFromAS, memberCcs);
		} catch (Exception e1) {
			System.err.println("Failed Token post and Joining");
			e1.printStackTrace();
		}

		System.out.println("Admin config successful: " + adminSuccess);
		System.out.println("Admin config has finished");
	}

	/**
	 * Request a Token from the AS.
	 * 
	 * @param memberName name of client/server peer
	 * @param keyToAS key shared with the AS
	 * @return the CoAP response from the AS
	 * @throws Exception on failure
	 */
	public static Response requestToken(String memberName, byte[] keyToAS) throws Exception {

		/* Configure parameters */

		String clientID = memberName;
		byte[] key128 = keyToAS;

		String tokenURI = "coap://" + AS_HOST + ":" + AS_PORT + "/token";

		/* Set byte string scope */

		// Create the scope
		String groupNamePattern = null;
		int myPermissions;
		CBORObject cborArrayEntry;
		CBORObject cborArrayScope = CBORObject.NewArray();

		cborArrayEntry = CBORObject.NewArray();
		groupNamePattern = new String(KeyStorage.newGroupName1);
		myPermissions = 0;
		myPermissions = Util.addGroupOSCOREAdminPermission(myPermissions, GroupcommParameters.GROUP_OSCORE_ADMIN_LIST);
		myPermissions = Util.addGroupOSCOREAdminPermission(myPermissions,
				GroupcommParameters.GROUP_OSCORE_ADMIN_CREATE);
		myPermissions = Util.addGroupOSCOREAdminPermission(myPermissions, GroupcommParameters.GROUP_OSCORE_ADMIN_READ);
		myPermissions = Util.addGroupOSCOREAdminPermission(myPermissions, GroupcommParameters.GROUP_OSCORE_ADMIN_WRITE);
		myPermissions = Util.addGroupOSCOREAdminPermission(myPermissions,
				GroupcommParameters.GROUP_OSCORE_ADMIN_DELETE);
		cborArrayEntry.Add(groupNamePattern);
		cborArrayEntry.Add(myPermissions);
		cborArrayScope.Add(cborArrayEntry);

		cborArrayEntry = CBORObject.NewArray();
		groupNamePattern = new String(KeyStorage.newGroupName2);
		cborArrayEntry.Add(groupNamePattern);
		cborArrayEntry.Add(myPermissions);
		cborArrayScope.Add(cborArrayEntry);

		cborArrayEntry = CBORObject.NewArray();
		groupNamePattern = new String("G3000");
		cborArrayEntry.Add(groupNamePattern);
		cborArrayEntry.Add(myPermissions);
		cborArrayScope.Add(cborArrayEntry);

		byte[] byteStringScope = cborArrayScope.EncodeToBytes();

		/* Perform Token request */

		System.out.println("Performing Token request to AS.");
		System.out.println("AS Token resource is at: " + tokenURI);

		CBORObject params = GetToken.getClientCredentialsRequest(CBORObject.FromObject("rs2"),
				CBORObject.FromObject(byteStringScope), null);

		byte[] senderId = KeyStorage.aceSenderIds.get(clientID);
		byte[] recipientId = KeyStorage.aceSenderIds.get("AS");
		if (ctx == null) {
			ctx = new OSCoreCtx(key128, true, null, senderId, recipientId, null, null, null, null,
					MAX_UNFRAGMENTED_SIZE, true);
		}

		Response response = OSCOREProfileRequestsGroupOSCORE.getToken(tokenURI, params, ctx, db);

		/* Parse and print response */

		try {
			CBORObject res = CBORObject.DecodeFromBytes(response.getPayload());
			System.out.println("Received response from AS to Token request: " + res.toString());
		} catch (CBORException e) {
			System.err.println("Failed to parse response from AS as CBOR");
			System.out.println("Response from AS: " + response.getPayloadString());
		}

		db.purge();
		return response;
	}

	/**
	 * Post to the GM from the admin to create two groups.
	 * 
	 */
	public static boolean testAdminRequestToGM(String memberName, String rsAddr,
			int portNumberRSnosec, OSCoreCtxDB ctxDB, OneKey cKeyPair, Response responseFromAS, byte[] clientCcsBytes)
			throws Exception {

		// Upload token

		Response rsRes = OSCOREProfileRequests.postToken("coap://" + rsAddr + ":" + portNumberRSnosec + "/authz-info",
				responseFromAS, ctxDB, usedRecipientIds);

		printResponseFromRS(rsRes);

		// Check that the OSCORE context has been created:
		Assert.assertNotNull(ctxDB.getContext(
				"coap://" + rsAddr + ":" + portNumberRSnosec + "/" + groupCollectionResourcePath));

		// === Retrieve list of existing groups

		System.out.println();
		printPause(memberName, "Will now request the list of current groups (expected to be empty)");

		CoapClient c = OSCOREProfileRequests.getClient(new InetSocketAddress(
				"coap://" + rsAddr + ":" + portNumberRSnosec + "/" + groupCollectionResourcePath, GM_PORT), ctxDB);

		Request adminReq = new Request(CoAP.Code.GET);
		adminReq.getOptions().setOscore(new byte[0]);
		CoapResponse adminRes = c.advanced(adminReq);
		System.out.println(Utils.prettyPrint(adminRes));

		// === Send a POST request to /manage to create the first group ====

		System.out.println();
		printPause(memberName, "Send a POST request to /manage to create the first group (g1)");

		c = OSCOREProfileRequests.getClient(new InetSocketAddress(
				"coap://" + rsAddr + ":" + portNumberRSnosec + "/" + groupCollectionResourcePath, GM_PORT), ctxDB);

		adminReq = new Request(CoAP.Code.POST);
		adminReq.getOptions().setOscore(new byte[0]);
		adminReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
		CBORObject requestPayloadCbor = CBORObject.NewMap();

		//
		requestPayloadCbor.Add(GroupcommParameters.GROUP_NAME, CBORObject.FromObject(KeyStorage.newGroupName1));
		requestPayloadCbor.Add(GroupcommParameters.ACTIVE, CBORObject.True);

		requestPayloadCbor.Add(GroupcommParameters.GROUP_MODE, CBORObject.FromObject(true));
		requestPayloadCbor.Add(GroupcommParameters.PAIRWISE_MODE, CBORObject.FromObject(true));

		requestPayloadCbor.Add(GroupcommParameters.HKDF, AlgorithmID.HMAC_SHA_256.AsCBOR());
		requestPayloadCbor.Add(GroupcommParameters.SIGN_ALG, AlgorithmID.ECDSA_256.AsCBOR());
		requestPayloadCbor.Add(GroupcommParameters.GP_ENC_ALG, AlgorithmID.AES_CCM_16_64_128.AsCBOR());
		requestPayloadCbor.Add(GroupcommParameters.ECDH_ALG, AlgorithmID.ECDH_SS_HKDF_256.AsCBOR());

		requestPayloadCbor.Add(GroupcommParameters.GROUP_DESCRIPTION, CBORObject.FromObject("The first group."));
		requestPayloadCbor.Add(GroupcommParameters.MAX_STALE_SETS, CBORObject.FromObject(5));
		requestPayloadCbor.Add(GroupcommParameters.GID_REUSE, CBORObject.FromObject(false));

		requestPayloadCbor.Add(GroupcommParameters.AS_URI,
				CBORObject.FromObject("coap://" + AS_HOST + ":" + AS_PORT + "/token"));

		//

		// System.out.println("Request payload to GM: " +
		// Utils.toHexString(requestPayloadCbor.EncodeToBytes()));
		adminReq.setPayload(requestPayloadCbor.EncodeToBytes());

		adminRes = c.advanced(adminReq);
		printResponseFromRS(adminRes.advanced());
		System.out.println("group-configuration resource at: " + adminRes.getOptions().getLocationPath());

		Assert.assertNotNull(adminRes);
		Assert.assertEquals(ResponseCode.CREATED, adminRes.getCode());
		Assert.assertNotNull(adminRes.getPayload());

		CBORObject responsePayloadCbor = CBORObject.DecodeFromBytes(adminRes.getPayload());
		Assert.assertNotNull(responsePayloadCbor);

		Assert.assertEquals(CBORType.Map, responsePayloadCbor.getType());
		System.out.println("Response code: " + adminRes.advanced().getCode());
		if (adminRes.getOptions().hasContentFormat()) {
			System.out.println("Response Content-Format: " + adminRes.getOptions().getContentFormat());
		}
		System.out.println("Response payload:");
		Util.prettyPrintCborMap(responsePayloadCbor);
		Assert.assertEquals(3, responsePayloadCbor.size());

		// String createdGroupName =
		// responsePayloadCbor.get(GroupcommParameters.GROUP_NAME).AsString();

		System.out.println();

		// === Send a POST request to /manage to create the second group ====

		System.out.println();
		printPause(memberName, "Send a POST request to /manage to create the second group (g2)");

		c = OSCOREProfileRequests.getClient(new InetSocketAddress(
				"coap://" + rsAddr + ":" + portNumberRSnosec + "/" + groupCollectionResourcePath, GM_PORT), ctxDB);

		adminReq = new Request(CoAP.Code.POST);
		adminReq.getOptions().setOscore(new byte[0]);
		adminReq.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
		requestPayloadCbor = CBORObject.NewMap();

		//
		requestPayloadCbor.Add(GroupcommParameters.GROUP_NAME, CBORObject.FromObject(KeyStorage.newGroupName2));
		requestPayloadCbor.Add(GroupcommParameters.ACTIVE, CBORObject.True);

		requestPayloadCbor.Add(GroupcommParameters.GROUP_MODE, CBORObject.FromObject(true));
		requestPayloadCbor.Add(GroupcommParameters.PAIRWISE_MODE, CBORObject.FromObject(true));

		requestPayloadCbor.Add(GroupcommParameters.ALG, AlgorithmID.CHACHA20_POLY1305.AsCBOR());

		requestPayloadCbor.Add(GroupcommParameters.HKDF, AlgorithmID.HMAC_SHA_256.AsCBOR());
		requestPayloadCbor.Add(GroupcommParameters.SIGN_ALG, AlgorithmID.EDDSA.AsCBOR());
		requestPayloadCbor.Add(GroupcommParameters.GP_ENC_ALG, AlgorithmID.AES_CCM_16_64_128.AsCBOR());
		requestPayloadCbor.Add(GroupcommParameters.ECDH_ALG, AlgorithmID.ECDH_SS_HKDF_256.AsCBOR());

		requestPayloadCbor.Add(GroupcommParameters.GROUP_DESCRIPTION, CBORObject.FromObject("The second group."));
		requestPayloadCbor.Add(GroupcommParameters.MAX_STALE_SETS, CBORObject.FromObject(5));
		requestPayloadCbor.Add(GroupcommParameters.GID_REUSE, CBORObject.FromObject(false));
		requestPayloadCbor.Add(GroupcommParameters.DET_REQ, CBORObject.FromObject(false));

		requestPayloadCbor.Add(GroupcommParameters.AS_URI,
				CBORObject.FromObject("coap://" + AS_HOST + ":" + AS_PORT + "/token"));

		//

		adminReq.setPayload(requestPayloadCbor.EncodeToBytes());

		adminRes = c.advanced(adminReq);
		printResponseFromRS(adminRes.advanced());
		System.out.println("group-configuration resource at: " + adminRes.getOptions().getLocationPath());

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

		// === Again retrieve list of existing groups

		System.out.println();
		printPause(memberName, "Will now request the list of current groups (expected to contain g1 and g2)");

		c = OSCOREProfileRequests.getClient(new InetSocketAddress(
				"coap://" + rsAddr + ":" + portNumberRSnosec + "/" + groupCollectionResourcePath, GM_PORT), ctxDB);

		adminReq = new Request(CoAP.Code.GET);
		adminReq.getOptions().setOscore(new byte[0]);

		adminRes = c.advanced(adminReq);

		System.out.println("Response payload:");
		printResponseFromRS(adminRes.advanced());

		// === Retrieve the group configuration of group g1

		System.out.println();
		printPause(memberName, "Will now request the group configuration of group g1");

		c = OSCOREProfileRequests.getClient(new InetSocketAddress(
				"coap://" + rsAddr + ":" + portNumberRSnosec + "/" + groupCollectionResourcePath + "/"
						+ KeyStorage.newGroupName1,
				GM_PORT), ctxDB);

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

		// === Retrieve the group configuration of group g2

		System.out.println();
		printPause(memberName, "Will now request the group configuration of group g2");

		c = OSCOREProfileRequests.getClient(new InetSocketAddress("coap://" + rsAddr + ":" + portNumberRSnosec + "/"
				+ groupCollectionResourcePath + "/" + KeyStorage.newGroupName2, GM_PORT), ctxDB);

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

		return true;
	}

	/**
	 * Simple method for "press enter to continue" functionality
	 */
	static void printPause(String memberName, String message) {

		// Only print for admin1
		if (!memberName.toLowerCase().equals("admin1")) {
			return;
		}

		System.out.println("===");
		System.out.println(message);
		System.out.println("Press ENTER to continue");
		System.out.println("===");
		try {
			@SuppressWarnings("unused")
			int read = System.in.read(new byte[2]);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static void printResponseFromRS(Response res) {
		if (res != null) {
			System.out.println("*** Response from the RS *** ");
			System.out.print(res.getCode().codeClass + ".0" + res.getCode().codeDetail);
			System.out.println(" " + res.getCode().name());

			if (res.getPayload() != null) {

				if (res.getOptions().getContentFormat() == Constants.APPLICATION_ACE_CBOR
						|| res.getOptions().getContentFormat() == Constants.APPLICATION_ACE_GROUPCOMM_CBOR) {
					CBORObject resCBOR = CBORObject.DecodeFromBytes(res.getPayload());
					System.out.println(resCBOR.toString());
				} else {
					System.out.println(new String(res.getPayload()));
				}
			}
		} else {
			System.out.println("*** The response from the RS is null! ");
			System.out.print("No response received");
		}
	}

	/**
	 * Print help message with valid command line arguments
	 */
	private static void printHelp() {
		System.out.println("Usage: [ -name Name ] [ -gm URI ] [ -as URI ] [-delay Seconds ] [ -help ]");

		System.out.println("Options:");

		System.out.print("-name");
		System.out.println("\t Name/Role of this peer");

		System.out.print("-gm");
		System.out.println("\t Group Manager base URI");

		System.out.print("-as");
		System.out.println("\t Authorization Server base URI");

		System.out.print("-delay");
		System.out.println("\t Delay in seconds before starting");

		System.out.print("-help");
		System.out.println("\t Print help");
	}
}
