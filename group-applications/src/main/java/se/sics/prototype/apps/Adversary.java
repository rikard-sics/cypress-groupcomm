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

import java.io.File;
import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Scanner;
import java.util.Set;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.serialization.UdpDataParser;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import org.eclipse.californium.oscore.group.GroupCtx;
import org.eclipse.californium.oscore.group.MultiKey;
import org.junit.Assert;

import com.upokecenter.cbor.CBORObject;
import se.sics.ace.Constants;
import se.sics.ace.GroupcommParameters;
import se.sics.ace.Util;
import se.sics.ace.client.GetToken;
import se.sics.ace.coap.client.OSCOREProfileRequests;
import se.sics.ace.coap.client.OSCOREProfileRequestsGroupOSCORE;
import se.sics.prototype.support.KeyStorage;
import se.sics.prototype.support.Tools;

/**
 * Simulates a Group Adversary (for Group B) attempting the following 3 actions:
 *
 * 1. Invalid request for Access Token from AS
 * 
 * 2. Invalid request to join group at GM
 * 
 * 3. Injecting Group messages (which will be rejected)
 *
 * 
 * 
 * @author Rikard Höglund
 *
 */
public class Adversary {

	// File name for network configuration.
	private static final File CONFIG_FILE = new File("CaliforniumMulticast.properties");

	// Header for network configuration.
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Multicast Client";

	// Special network configuration defaults handler.
	private static DefinitionsProvider DEFAULTS = new DefinitionsProvider() {

		@Override
		public void applyDefinitions(Configuration config) {
			config.set(CoapConfig.MULTICAST_BASE_MID, 65000);
		}

	};

	// Time to wait for replies to the multicast request
	private static final int HANDLER_TIMEOUT = 2000;

	// Port to send multicast requests to (injected requests)
	private static final int destinationPort = CoAP.DEFAULT_COAP_PORT - 1000;

	// Sets the default GM port to use
	private static int GM_PORT = CoAP.DEFAULT_COAP_PORT + 100;
	// Sets the default GM hostname/IP to use
	private static String GM_HOST = "localhost";

	// Sets the default AS port to use
	private static int AS_PORT = CoAP.DEFAULT_COAP_PORT - 100;
	// Sets the default AS hostname/IP to use
	private static String AS_HOST = "localhost";

	// Multicast IP for Group B
	static final InetAddress groupB_multicastIP = new InetSocketAddress("224.0.1.192", 0).getAddress();

	static HashMapCtxDB db = new HashMapCtxDB();

	private final static int MAX_UNFRAGMENTED_SIZE = 4096;

	// Each set of the list refers to a different size of Recipient IDs.
	// The element with index 0 includes as elements Recipient IDs with size 1
	// byte.
	private static List<Set<Integer>> usedRecipientIds = new ArrayList<Set<Integer>>();

	private static final String rootGroupMembershipResource = "ace-group";

	// Uncomment to set EDDSA with curve Ed25519 for countersignatures
	private static int signKeyCurve = KeyKeys.OKP_Ed25519.AsInt32();
	// Uncomment to set curve X25519 for pairwise key derivation
	private static int ecdhKeyCurve = KeyKeys.OKP_X25519.AsInt32();

	static byte[] injectedRequest_groupB = StringUtil.hex2ByteArray(
			"5802fed93a3ef749ba83319a9a390006bbbbbb57f03a22ff0245768cf835da1d58c887e5717d49979ceef353a547607568810f0092a88a7e903aff35bb4948a46d3507e549fb45708d2924df1eef8a18b08b43b3a1a7345ff95d252a08219dab64a3a01cab6d2e2f5c9e5f62");

	/**
	 * Main method for Token request followed by Group joining
	 * 
	 * @param args input command line arguments
	 * @throws Exception on ACE failure
	 */
	public static void main(String[] args) throws Exception {

		System.out.println("Starting Group adversary...");

		// install needed cryptography providers
		try {
			org.eclipse.californium.oscore.InstallCryptoProviders.installProvider();
		} catch (Exception e) {
			System.err.println("Failed to install cryptography providers.");
			e.printStackTrace();
		}

		// Set member name, AS and GM to use from command line arguments
		String memberName = "Adversary";
		int delay = 0;
		for (int i = 0; i < args.length; i++) {
			if (args[i].equals("-name")) {
				System.err.println("Error: Unsupported argument");
				System.exit(1);
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
			} else if (args[i].toLowerCase().equals("-delay")) {
				delay = Integer.parseInt(args[i + 1]);
				i++;
			} else if (args[i].toLowerCase().equals("-help")) {
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

		// Build empty sets of assigned Sender IDs; one set for each possible
		for (int i = 0; i < 4; i++) {
			// Sender ID size in bytes.
			// The set with index 0 refers to Sender IDs with size 1 byte
			usedRecipientIds.add(new HashSet<Integer>());
		}

		// Set group to target
		String group = "bbbbbb570000";
		InetAddress multicastIP = groupB_multicastIP;

		// Set key (OSCORE master secret) to use towards AS
		byte[] keyToAS = KeyStorage.memberAsKeys.get(memberName);

		System.out.println("Adversary configured with parameters:");
		System.out.println("\tAS: " + AS_HOST + ":" + AS_PORT);
		System.out.println("\tGM: " + GM_HOST + ":" + GM_PORT);
		System.out.println("\tGroup: " + group);
		System.out.println("\tMulticast dst: " + multicastIP.getHostAddress() + ":" + destinationPort);

		// Adversary command line interface
		String attackType = null;
		try (Scanner scanner = new Scanner(System.in)) {

			System.out.println("");
			System.out.println("Enter attack type: ");
			System.out.println("1. Request Access Token from AS without correct credentials");
			System.out.println("2. Attempt to Join group without correct rights");
			System.out.println("3. Injecting a request message to the Group");
			attackType = scanner.next();
		}

		// Enable (Group) OSCORE stack for ACE-based attacks
		if (attackType.equals("1") || attackType.equals("2")) {
			// Explicitly enable the OSCORE Stack
			if (CoapEndpoint.isDefaultCoapStackFactorySet() == false) {
				OSCoreCoapStackFactory.useAsDefault(db);
			}
		}

		if (attackType.equals("1")) {
			// Invalid Token request to AS
			invalidTokenRequest(memberName, group, keyToAS);
			System.exit(0);

		} else if (attackType.equals("2")) {
			// Invalid Join Request to GM
			invalidJoinRequest(memberName, group, keyToAS);
			System.exit(0);

		} else if (attackType.equals("3")) {
			// Inject a Group Request
			injectGroupRequest(multicastIP);
			System.exit(0);
		} else {
			System.err.println("Invalid attack type specified");
			System.exit(1);
		}

	}

	/**
	 * Inject a message to the group (group B)
	 * 
	 * @param multicastIP targeted multicast IP for this group
	 */
	private static void injectGroupRequest(InetAddress multicastIP) {
		// Prepare parser for the request bytes and creating Request objects
		UdpDataParser parser = new UdpDataParser();
		Request replayRequest = null;

		replayRequest = (Request) parser.parseMessage(injectedRequest_groupB);

		Request multicastRequest = replayRequest;

		if (multicastRequest == null || multicastIP == null) {
			System.err.println("Error in setting up Adversary");
			return;
		}

		// URI to perform request against. Need to check for IPv6 to surround it
		// with []
		String requestURI;
		if (multicastIP instanceof Inet6Address) {
			requestURI = "coap://" + "[" + multicastIP.getHostAddress() + "]" + ":" + destinationPort;
		} else {
			requestURI = "coap://" + multicastIP.getHostAddress() + ":" + destinationPort;
		}

		// Now prepare to send request
		Configuration config = Configuration.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);

		CoapEndpoint endpoint = new CoapEndpoint.Builder().setConfiguration(config).build();
		CoapClient client = new CoapClient();

		client.setEndpoint(endpoint);
		client.setURI(requestURI);

		// sends a multicast request
		client.advanced(handler, multicastRequest);
		while (handler.waitOn(HANDLER_TIMEOUT)) {
			// Wait and listen for responses
		}

		System.out.println("Responses received: ");
		ArrayList<CoapResponse> responseList = handler.getResponses();
		for (int i = 0; i < responseList.size(); i++) {
			CoapResponse resp = responseList.get(i);
			System.out.println("Received from: " + resp.advanced().getSourceContext().getPeerAddress());
			System.out.println(Utils.prettyPrint(resp));
		}
		handler.clearResponses();
	}

	/**
	 * Perform an invalid Join request towards the GM
	 * 
	 * @param memberName the member name
	 * @param group the group name
	 * @param keyToAS this peer's shared key with the AS
	 * @throws Exception on failure
	 */
	private static void invalidJoinRequest(String memberName, String group, byte[] keyToAS) throws Exception {
		Tools.waitForAs(AS_HOST, AS_PORT);
		System.out.println("Will now request Token from Authorization Server");
		Response responseFromAS = requestToken(memberName, group, keyToAS, false);

		Tools.waitForGm(GM_HOST, GM_PORT);
		System.out.println("GM is available. Proceeding to post Token to GM.");

		// Perform invalid join request
		OneKey cKeyPair = new MultiKey(KeyStorage.memberCcs.get(memberName),
				KeyStorage.memberPrivateKeys.get(memberName)).getCoseKey();
		byte[] memberCcs = KeyStorage.memberCcs.get(memberName);
		testGroupOSCOREMultipleRoles(memberName, group, GM_HOST, GM_PORT, db, cKeyPair, responseFromAS, memberCcs,
				true);
	}

	/**
	 * Perform an invalid request for a Token from the AS
	 * 
	 * @param memberName the member name
	 * @param group the group name
	 * @param keyToAS this peer's shared key with the AS
	 * @throws Exception on failure
	 */
	private static void invalidTokenRequest(String memberName, String group, byte[] keyToAS) throws Exception {
		// Wait for Authorization Server to become available
		Tools.waitForAs(AS_HOST, AS_PORT);
		System.out.println("AS is available.");

		// Now request Token
		System.out.println("Will now request Token from Authorization Server");
		requestToken(memberName, group, keyToAS, true);
	}

	/**
	 * Request a Token from the AS.
	 * 
	 * @param memberName name of client/server peer
	 * @param group to request token for
	 * @param keyToAS key shared with the AS
	 * @param invalid is request invalid
	 * @return the CoAP response from the AS
	 * 
	 * @throws Exception on failure
	 */
	public static Response requestToken(String memberName, String group, byte[] keyToAS, boolean invalid)
			throws Exception {

		/* Configure parameters */

		printPause(memberName, "Will now request Token from AS");

		String clientID = memberName;
		String groupName = group;
		byte[] key128 = keyToAS; // KeyStorage.memberAsKeys.get(memberName);//
									// {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11,
									// 12, 13, 14, 15, 16};
		String tokenURI = "coap://" + AS_HOST + ":" + AS_PORT + "/token";

		/* Set byte string scope */

		// Map<Short, CBORObject> params = new HashMap<>();
		// params.put(Constants.GRANT_TYPE, Token.clientCredentials);

		CBORObject cborArrayScope = CBORObject.NewArray();
		CBORObject cborArrayEntry = CBORObject.NewArray();
		cborArrayEntry.Add(groupName);

		int myRoles = 0;
		myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
		myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_RESPONDER);
		cborArrayEntry.Add(myRoles);

		cborArrayScope.Add(cborArrayEntry);
		byte[] byteStringScope = cborArrayScope.EncodeToBytes();

		/* Perform Token request */

		System.out.println("Performing Token request to AS.");
		System.out.println("AS Token resource is at: " + tokenURI);

		CBORObject params = GetToken.getClientCredentialsRequest(CBORObject.FromObject("rs2"),
				CBORObject.FromObject(byteStringScope), null);

		byte[] senderId = KeyStorage.aceSenderIds.get(clientID);

		// Unauthorized client
		if (invalid) {
			senderId = new byte[] { (byte) 0xFF, (byte) 0xFF };
		}
		byte[] recipientId = KeyStorage.aceSenderIds.get("AS");
		OSCoreCtx ctx = new OSCoreCtx(key128, true, null, senderId, recipientId, null, null, null, null,
				MAX_UNFRAGMENTED_SIZE, true);
		
		Response response = OSCOREProfileRequestsGroupOSCORE.getToken(tokenURI, params, ctx, db);

		System.out.println("DB content: " + db.getContext(new byte[] { 0x00 }, null));

		/* Parse and print response */

		// System.out.println("Response from AS: " +
		// response.getPayloadString());
		CBORObject res = CBORObject.DecodeFromBytes(response.getPayload());
		// Map<Short, CBORObject> map = Constants.getParams(res);
		// System.out.println(map);

		System.out.println("\nReceived response from AS to Token request: " + res.toString());

		Collection<CBORObject> keys = res.getKeys();
		if (keys.contains(CBORObject.FromObject(Constants.ERROR))) {
			System.out.print("Error: ");
		}
		if (res.get(Constants.ERROR) != null && res.get(Constants.ERROR).AsInt32() == Constants.UNAUTHORIZED_CLIENT) {
			System.out.println("Unauthorized Client");
		}

		db.purge();
		return response;
	}

	/**
	 * Post to Authz-Info, then perform join request using multiple roles. Uses
	 * the ACE OSCORE Profile.
	 * 
	 * @param memberName name of client/server peer
	 * @param groupName name of group to join
	 * @param rsAddr address of the Resource Server
	 * @param portNumberRSnosec port number for RS no sec. communication
	 * @param ctxDB OSCORE context database
	 * @param cKeyPair key pair for joining peer
	 * @param responseFromAS response message previously received from AS
	 * @param clientCcsBytes joining peer's CCS as bytes
	 * @param invalid sets this request to be invalid
	 * 
	 * @return the generated Group OSCORE context after joining
	 * @throws Exception on failure
	 */
	public static GroupCtx testGroupOSCOREMultipleRoles(String memberName, String groupName, String rsAddr,
			int portNumberRSnosec, OSCoreCtxDB ctxDB, OneKey cKeyPair, Response responseFromAS, byte[] clientCcsBytes,
			boolean invalid) throws Exception {

		System.out.println(memberName + " is attempting to join the Group");

		boolean askForSignInfo = true;
		boolean askForEcdhInfo = true;
		boolean askForAuthCreds = true;
		boolean provideAuthCreds = true;

		// Create the scope
		CBORObject cborArrayScope = CBORObject.NewArray();
		CBORObject cborArrayEntry = CBORObject.NewArray();

		cborArrayEntry.Add(groupName);

		int myRoles = 0;
		myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
		cborArrayEntry.Add(myRoles);

		if (invalid) {
			myRoles = 0;
			myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
			myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_RESPONDER);
			cborArrayEntry.Add(myRoles);
		}

		cborArrayScope.Add(cborArrayEntry);
		byte[] byteStringScope = cborArrayScope.EncodeToBytes();

		Response rsRes = OSCOREProfileRequestsGroupOSCORE.postToken(
				"coap://" + rsAddr + ":" + portNumberRSnosec + "/authz-info", responseFromAS, askForSignInfo,
				askForEcdhInfo, ctxDB, usedRecipientIds);

		printResponseFromRS(rsRes);

		// Check that the OSCORE context has been created:
		Assert.assertNotNull(ctxDB.getContext(
				"coap://" + rsAddr + ":" + portNumberRSnosec + "/" + rootGroupMembershipResource + "/" + groupName));

		CBORObject rsPayload = CBORObject.DecodeFromBytes(rsRes.getPayload());
		// Sanity checks already occurred in
		// OSCOREProfileRequestsGroupOSCORE.postToken()

		// Nonce from the GM, to use together with a local nonce to prove
		// possession of the private key
		byte[] gm_nonce = rsPayload.get(CBORObject.FromObject(Constants.KDCCHALLENGE)).GetByteString();

		// Group OSCORE specific values for the countersignature
		CBORObject signParamsExpected = CBORObject.NewArray();
		CBORObject signKeyParamsExpected = CBORObject.NewArray();

		// ECDSA_256
		if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {

			// The algorithm capabilities
			signParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type

			// The key type capabilities
			signKeyParamsExpected.Add(KeyKeys.KeyType_EC2); // Key Type
			signKeyParamsExpected.Add(KeyKeys.EC2_P256); // Curve
		}

		// EDDSA (Ed25519)
		if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {

			// The algorithm capabilities
			signParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type

			// The key type capabilities
			signKeyParamsExpected.Add(KeyKeys.KeyType_OKP); // Key Type
			signKeyParamsExpected.Add(KeyKeys.OKP_Ed25519); // Curve
		}

		// Group OSCORE specific values for the pairwise key derivation
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

		CBORObject credFmtExpected = CBORObject.FromObject(Constants.COSE_HEADER_PARAM_KCCS);

		// Now proceed with the Join request

		CoapClient c = OSCOREProfileRequests.getClient(new InetSocketAddress(
				"coap://" + rsAddr + ":" + portNumberRSnosec + "/" + rootGroupMembershipResource + "/" + groupName,
				portNumberRSnosec), ctxDB);

		System.out.println("Performing Join request using OSCORE to GM.");

		CBORObject requestPayload = CBORObject.NewMap();

		cborArrayScope = CBORObject.NewArray();
		cborArrayScope.Add(groupName);

		myRoles = 0;
		myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
		myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_RESPONDER);
		cborArrayScope.Add(myRoles);

		byteStringScope = cborArrayScope.EncodeToBytes();
		requestPayload.Add(Constants.SCOPE, CBORObject.FromObject(byteStringScope));

		if (askForAuthCreds) {

			CBORObject getCreds = CBORObject.NewArray();

			getCreds.Add(CBORObject.True); // This must be true

			getCreds.Add(CBORObject.NewArray());
			// The following is required to retrieve the authentication
			// credentials of both the already present group members
			myRoles = 0;
			myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
			getCreds.get(1).Add(myRoles);
			myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_REQUESTER);
			myRoles = Util.addGroupOSCORERole(myRoles, GroupcommParameters.GROUP_OSCORE_RESPONDER);
			getCreds.get(1).Add(myRoles);

			getCreds.Add(CBORObject.NewArray()); // This must be empty

			requestPayload.Add(GroupcommParameters.GET_CREDS, getCreds);

		}

		byte[] authCred = null;
		if (provideAuthCreds) {

			// This should never happen, if the Group Manager has provided
			// 'kdc_challenge' in the Token POST response,
			// or the joining node has computed N_S differently (e.g. through a
			// TLS exporter)
			if (gm_nonce == null) {
				Assert.fail("Error: the component N_S of the PoP evidence challence is null");
			}

			switch (credFmtExpected.AsInt32()) {
			case Constants.COSE_HEADER_PARAM_KCCS:
				// A CCS including the public key
				if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
					System.out.println("Needs further configuration");
					authCred = StringUtil.hex2ByteArray(
							"A2026008A101A5010203262001215820E8F9A8D5850A533CDA24B9FA8A1EE293F6A0E1E81E1E560A64FF134D65F7ECEC225820164A6D5D4B97F56D1F60A12811D55DE7A055EBAC6164C9EF9302CBCBFF1F0ABE");
				}
				if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
					authCred = clientCcsBytes;
				}
				break;
			case Constants.COSE_HEADER_PARAM_KCWT:
				// A CWT including the public key
				break;
			case Constants.COSE_HEADER_PARAM_X5CHAIN:
				// A certificate including the public key
				break;
			default:
				System.err.println("Error: credFmtExpected set incorrectly.");
				break;
			}

			requestPayload.Add(GroupcommParameters.CLIENT_CRED, CBORObject.FromObject(authCred));

			// Add the nonce for PoP of the Client's private key
			byte[] cnonce = new byte[8];
			new SecureRandom().nextBytes(cnonce);
			requestPayload.Add(Constants.CNONCE, cnonce);

			// Add the signature computed over (scope | rsnonce | cnonce), using
			// the Client's private key
			int offset = 0;
			PrivateKey privKey = cKeyPair.AsPrivateKey();

			byte[] serializedScopeCBOR = CBORObject.FromObject(byteStringScope).EncodeToBytes();
			byte[] serializedGMNonceCBOR = CBORObject.FromObject(gm_nonce).EncodeToBytes();
			byte[] serializedCNonceCBOR = CBORObject.FromObject(cnonce).EncodeToBytes();
			byte[] dataToSign = new byte[serializedScopeCBOR.length + serializedGMNonceCBOR.length
					+ serializedCNonceCBOR.length];
			System.arraycopy(serializedScopeCBOR, 0, dataToSign, offset, serializedScopeCBOR.length);
			offset += serializedScopeCBOR.length;
			System.arraycopy(serializedGMNonceCBOR, 0, dataToSign, offset, serializedGMNonceCBOR.length);
			offset += serializedGMNonceCBOR.length;
			System.arraycopy(serializedCNonceCBOR, 0, dataToSign, offset, serializedCNonceCBOR.length);

			byte[] clientSignature = Util.computeSignature(signKeyCurve, privKey, dataToSign);

			if (clientSignature != null)
				requestPayload.Add(GroupcommParameters.CLIENT_CRED_VERIFY, clientSignature);
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

		byte[] responsePayload = r2.getPayload();
		CBORObject joinResponse = CBORObject.DecodeFromBytes(responsePayload);

		// Final join response parsing and Group Context generation

		MultiKey clientKey = new MultiKey(authCred, cKeyPair.get(KeyKeys.OKP_D).GetByteString());
		GroupCtx groupOscoreCtx = null;
		if (joinResponse.get(CBORObject.FromObject(GroupcommParameters.KDC_CRED)) != null) {
			groupOscoreCtx = Tools.generateGroupOSCOREContext(joinResponse, clientKey, "");
		}
		return groupOscoreCtx;
	}

	/**
	 * Simple method for "press enter to continue" functionality
	 */
	static void printPause(String memberName, String message) {

		// Only print for Server7
		if (!memberName.toLowerCase().equals("server7")) {
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

	// Printing methods

	private static void printMapPayload(CBORObject obj) {
		if (obj != null) {
			System.out.println("*** Map Payload *** ");
			System.out.println(obj);
		} else {
			System.out.println("*** The payload argument is null!");
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
			System.out.println("*** The response from the RS is null!");
			System.out.print("No response received");
		}
	}

	/**
	 * Print help message with valid command line arguments
	 */
	private static void printHelp() {
		System.out.println("Usage: [ -gm URI ] [ -as URI ] [-delay Seconds ] [ -help ]");

		System.out.println("Options:");

		System.out.print("-gm");
		System.out.println("\t Group Manager base URI");

		System.out.print("-as");
		System.out.println("\t Authorization Server base URI");

		System.out.print("-delay");
		System.out.println("\t Delay in seconds before starting");

		System.out.print("-help");
		System.out.println("\t Print help");
	}

	private static final MultiCoapHandler handler = new MultiCoapHandler();

	private static class MultiCoapHandler implements CoapHandler {

		private boolean on;
		private ArrayList<CoapResponse> responseMessages = new ArrayList<CoapResponse>();

		public synchronized boolean waitOn(long timeout) {
			on = false;
			try {
				wait(timeout);
			} catch (InterruptedException e) {
				//
			}
			return on;
		}

		private synchronized void on() {
			on = true;
			notifyAll();
		}

		private synchronized ArrayList<CoapResponse> getResponses() {
			return responseMessages;
		}

		private synchronized void clearResponses() {
			responseMessages.clear();
		}

		/**
		 * Handle and parse incoming responses.
		 */
		@Override
		public void onLoad(CoapResponse response) {
			on();

			// System.out.println("Receiving to: ");
			// System.out.println("Receiving from: " +
			// response.advanced().getSourceContext().getPeerAddress());

			// System.out.println(Utils.prettyPrint(response));

			responseMessages.add(response);
		}

		@Override
		public void onError() {
			System.err.println("error");
		}
	}
}
