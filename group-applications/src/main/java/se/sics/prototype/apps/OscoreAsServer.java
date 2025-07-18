/*******************************************************************************
 * Copyright (c) 2023, RISE AB
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

import java.util.Base64;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.upokecenter.cbor.CBORObject;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.MessageTag;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.oscore.OSCoreCtx;

import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.GroupcommParameters;
import se.sics.ace.as.AccessTokenFactory;
import se.sics.ace.coap.as.CoapDBConnector;
import se.sics.ace.coap.as.OscoreAS;
import se.sics.ace.coap.rs.oscoreProfile.OscoreCtxDbSingleton;
import se.sics.ace.examples.KissTime;
import se.sics.ace.oscore.as.GroupOSCOREJoinPDP;
import se.sics.prototype.support.DBHelper;
import se.sics.prototype.support.KeyStorage;
import se.sics.prototype.support.Tools;

/**
 * ACE Authorization Server using OSCORE for communication.
 *
 */
public class OscoreAsServer {

	// Default URI for DHT WebSocket connection. Can be changed using command
	// line arguments.
	private static String dhtWebsocketUri = "ws://localhost:3000/ws";

	// Key information for ACE
	static byte[] key128 = { (byte) 0xa1, (byte) 0xa2, (byte) 0xa3, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
			0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
	static byte[] key128a = { (byte) 0xa1, (byte) 0xa2, (byte) 0xa3, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
			0x0c, 0x0d, 0x0e, 0x0f, 0x10 };

	private static CoapDBConnector db = null;
	private static OscoreAS as = null;
	private static GroupOSCOREJoinPDP pdp = null;

	// The map has as key the name of a Client or Resource Server,
	// and as value the OSCORE identity of that peer with the AS.
	//
	// The identities are strings with format ["A" + ":" +] "B", where A and B
	// are the base64 encoding of the ContextID (if present) and of the
	// SenderID.
	private static Map<String, String> peerNamesToIdentities = new HashMap<>();

	// The map has as key the OSCORE identity of the Client or Resource Server,
	// and as value the name of that peer with the AS.
	//
	// The identities are strings with format ["A" + ":" +] "B", where A and B
	// are the base64 encoding of the ContextID (if present) and of the
	// SenderID.
	private static Map<String, String> peerIdentitiesToNames = new HashMap<>();

	// The inner map has as key the name of a Client or Resource Server, and
	// as value the OSCORE identity that this specific AS has with that peer.
	//
	// The identities are strings with format ["A" + ":" +] "B", where A and B
	// are the base64 encoding of the ContextID (if present) and of the
	// SenderID.
	private static Map<String, String> myIdentities = new HashMap<>();

	static int port = CoAP.DEFAULT_COAP_PORT - 100;


	/**
	 * An OSCORE AS.
	 * 
	 * @param args command line arguments
	 * @throws Exception on failure
	 */
	public static void main(String[] args) throws Exception {

		System.out.println("Starting Authorization Server: OscoreAsServer...");

		// Parse command line arguments
		boolean useDht = false;
		String dbConnStr = null;
		for (int i = 0; i < args.length; i++) {
			if (args[i].toLowerCase().endsWith("-dht") || args[i].toLowerCase().endsWith("-usedht")) {
				useDht = true;

				// Check if a WebSocket URI for the DHT is also indicated
				URI parsed = null;
				try {
					parsed = new URI(args[i + 1]);
				} catch (URISyntaxException | ArrayIndexOutOfBoundsException e) {
					// No URI indicated
				}
				if (parsed != null) {
					dhtWebsocketUri = parsed.toString();
					i++;
				}

			} else if (args[i].toLowerCase().endsWith("-db")) {
				dbConnStr = args[i + 1];
				i++;
			} else if (args[i].toLowerCase().endsWith("-help")) {
				printHelp();
				System.exit(0);
			}
		}

		byte[] idContext = null;
		String myIdentity = buildOscoreIdentity(KeyStorage.aceSenderIds.get("AS"), idContext);
		String asName = "AS";

		// If custom DB string is used, wait for MySQL server to be available
		if (dbConnStr != null) {
			Tools.waitForDb(dbConnStr);
		}

		DBHelper.setUpDB(dbConnStr);
		db = DBHelper.getCoapDBConnector();

		CBORObject keyData = CBORObject.NewMap();
		keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
		keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128a));
		OneKey tokenPsk = new OneKey(keyData);

		keyData = CBORObject.NewMap();
		keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
		keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128));
		OneKey authPsk = new OneKey(keyData);

		// Setup RS entries
		Set<String> profiles = new HashSet<>();
		profiles.add("coap_oscore");
		Set<String> scopes = new HashSet<>();
		scopes.add("rw_valve");
		scopes.add("r_pressure");
		scopes.add("foobar");

		// Group OSCORE scopes
		String groupName1 = "aaaaaa570000";
		String groupName2 = "bbbbbb570000";

		scopes.add(GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX + ":" + groupName1.length() + ":"
				+ groupName1 + "_requester");
		scopes.add(GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX + ":" + groupName1.length() + ":"
				+ groupName1 + "_responder");
		scopes.add(GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX + ":" + groupName1.length() + ":"
				+ groupName1 + "_monitor");
		scopes.add(GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX + ":" + groupName1.length() + ":"
				+ groupName1 + "_requester_responder");
		scopes.add(GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX + ":" + groupName1.length() + ":"
				+ groupName1 + "_requester_monitor");

		scopes.add(GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX + ":" + groupName2.length() + ":"
				+ groupName2 + "_requester");
		scopes.add(GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX + ":" + groupName2.length() + ":"
				+ groupName2 + "_responder");
		scopes.add(GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX + ":" + groupName2.length() + ":"
				+ groupName2 + "_monitor");
		scopes.add(GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX + ":" + groupName2.length() + ":"
				+ groupName2 + "_requester_responder");
		scopes.add(GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX + ":" + groupName2.length() + ":"
				+ groupName2 + "_requester_monitor");

		// Add identifiers of scope for admin scope entries

		String complexPattern = "^[A-Z][0-9][-a-z0-9]*$";
		String[] prefixes = { GroupcommParameters.GROUP_OSCORE_AS_SCOPE_WILDCARD_PREFIX + ":",
				GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX + ":" + groupName1.length() + ":" + groupName1
						+ "_",
				GroupcommParameters.GROUP_OSCORE_AS_SCOPE_COMPLEX_PREFIX + ":" + "21065" + ":" + complexPattern.length()
						+ ":" + complexPattern + "_" };
		String[] permissions = GroupcommParameters.GROUP_OSCORE_ADMIN_PERMISSIONS;

		// One permission
		for (int i = 0; i < prefixes.length; i++) {
			scopes.add(prefixes[i] + permissions[0]);
		}
		// Two permissions
		for (int i = 0; i < prefixes.length; i++) {
			scopes.add(prefixes[i] + permissions[0] + "_" + permissions[1]);
			scopes.add(prefixes[i] + permissions[0] + "_" + permissions[2]);
			scopes.add(prefixes[i] + permissions[0] + "_" + permissions[3]);
			scopes.add(prefixes[i] + permissions[0] + "_" + permissions[4]);
		}
		// Three permissions
		for (int i = 0; i < prefixes.length; i++) {
			scopes.add(prefixes[i] + permissions[0] + "_" + permissions[1] + "_" + permissions[2]);
			scopes.add(prefixes[i] + permissions[0] + "_" + permissions[1] + "_" + permissions[3]);
			scopes.add(prefixes[i] + permissions[0] + "_" + permissions[1] + "_" + permissions[4]);
			scopes.add(prefixes[i] + permissions[0] + "_" + permissions[2] + "_" + permissions[3]);
			scopes.add(prefixes[i] + permissions[0] + "_" + permissions[2] + "_" + permissions[4]);
			scopes.add(prefixes[i] + permissions[0] + "_" + permissions[3] + "_" + permissions[4]);
		}
		// Four permissions
		for (int i = 0; i < prefixes.length; i++) {
			scopes.add(
					prefixes[i] + permissions[0] + "_" + permissions[1] + "_" + permissions[2] + "_" + permissions[3]);
			scopes.add(
					prefixes[i] + permissions[0] + "_" + permissions[1] + "_" + permissions[2] + "_" + permissions[4]);
			scopes.add(
					prefixes[i] + permissions[0] + "_" + permissions[2] + "_" + permissions[3] + "_" + permissions[4]);
		}
		// Five permissions
		for (int i = 0; i < prefixes.length; i++) {
			scopes.add(prefixes[i] + permissions[0] + "_" + permissions[1] + "_" + permissions[2] + "_" + permissions[3]
					+ "_" + permissions[4]);
		}

		//

		String[] prefixes2 = { GroupcommParameters.GROUP_OSCORE_AS_SCOPE_WILDCARD_PREFIX + ":",
				GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX + ":" + groupName2.length() + ":" + groupName2
						+ "_",
				GroupcommParameters.GROUP_OSCORE_AS_SCOPE_COMPLEX_PREFIX + ":" + "21065" + ":" + complexPattern.length()
						+ ":" + complexPattern + "_" };

		// One permission
		for (int i = 0; i < prefixes2.length; i++) {
			scopes.add(prefixes2[i] + permissions[0]);
		}
		// Two permissions
		for (int i = 0; i < prefixes2.length; i++) {
			scopes.add(prefixes2[i] + permissions[0] + "_" + permissions[1]);
			scopes.add(prefixes2[i] + permissions[0] + "_" + permissions[2]);
			scopes.add(prefixes2[i] + permissions[0] + "_" + permissions[3]);
			scopes.add(prefixes2[i] + permissions[0] + "_" + permissions[4]);
		}
		// Three permissions
		for (int i = 0; i < prefixes2.length; i++) {
			scopes.add(prefixes2[i] + permissions[0] + "_" + permissions[1] + "_" + permissions[2]);
			scopes.add(prefixes2[i] + permissions[0] + "_" + permissions[1] + "_" + permissions[3]);
			scopes.add(prefixes2[i] + permissions[0] + "_" + permissions[1] + "_" + permissions[4]);
			scopes.add(prefixes2[i] + permissions[0] + "_" + permissions[2] + "_" + permissions[3]);
			scopes.add(prefixes2[i] + permissions[0] + "_" + permissions[2] + "_" + permissions[4]);
			scopes.add(prefixes2[i] + permissions[0] + "_" + permissions[3] + "_" + permissions[4]);
		}
		// Four permissions
		for (int i = 0; i < prefixes2.length; i++) {
			scopes.add(
					prefixes2[i] + permissions[0] + "_" + permissions[1] + "_" + permissions[2] + "_" + permissions[3]);
			scopes.add(
					prefixes2[i] + permissions[0] + "_" + permissions[1] + "_" + permissions[2] + "_" + permissions[4]);
			scopes.add(
					prefixes2[i] + permissions[0] + "_" + permissions[2] + "_" + permissions[3] + "_" + permissions[4]);
		}
		// Five permissions
		for (int i = 0; i < prefixes2.length; i++) {
			scopes.add(prefixes2[i] + permissions[0] + "_" + permissions[1] + "_" + permissions[2] + "_"
					+ permissions[3] + "_" + permissions[4]);
		}

		// End Group OSCORE scopes

		Set<String> auds = new HashSet<>();
		auds.add("rs2");
		Set<String> keyTypes = new HashSet<>();
		keyTypes.add("PSK");
		Set<Short> tokenTypes = new HashSet<>();
		tokenTypes.add(AccessTokenFactory.CWT_TYPE);
		Set<COSEparams> cose = new HashSet<>();
		COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
		// COSEparams coseP = new COSEparams(MessageTag.MAC0,
		// AlgorithmID.HMAC_SHA_256, AlgorithmID.Direct);
		cose.add(coseP);
		long expiration = 800000000L;
		db.addRS("rs2", profiles, scopes, auds, keyTypes, tokenTypes, cose, expiration, authPsk, tokenPsk, null);
		String peerIdentity = buildOscoreIdentity(new byte[] { 0x01 }, idContext);
		peerNamesToIdentities.put("rs2", peerIdentity);
		peerIdentitiesToNames.put(peerIdentity, "rs2");
		myIdentities.put("rs2", myIdentity);

		// Add rs2 as OSCORE Group Manager
		db.addOSCOREGroupManagers("rs2", auds);

		profiles.clear();
		profiles.add("coap_oscore");
		keyTypes.clear();
		keyTypes.add("PSK");
		db.addClient("ClientA", profiles, null, null, keyTypes, authPsk, null);
		peerIdentity = buildOscoreIdentity(new byte[] { 0x02 }, idContext);
		peerNamesToIdentities.put("ClientA", peerIdentity);
		peerIdentitiesToNames.put(peerIdentity, "ClientA");
		myIdentities.put("ClientA", myIdentity);

		/* --- Configure clients and servers --- */

		CBORObject myKey = CBORObject.NewMap();
		myKey.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
		myKey.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(KeyStorage.memberAsKeys.get("Client1")));
		OneKey myPsk = new OneKey(myKey);

		profiles.clear();
		profiles.add("coap_oscore");
		keyTypes.clear();
		keyTypes.add("PSK");
		db.addClient("Client1", profiles, null, null, keyTypes, myPsk, null);
		peerIdentity = buildOscoreIdentity(KeyStorage.aceSenderIds.get("Client1"), idContext);
		peerNamesToIdentities.put("Client1", peerIdentity);
		peerIdentitiesToNames.put(peerIdentity, "Client1");
		myIdentities.put("Client1", myIdentity);

		myKey = CBORObject.NewMap();
		myKey.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
		myKey.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(KeyStorage.memberAsKeys.get("Client2")));
		myPsk = new OneKey(myKey);

		profiles.clear();
		profiles.add("coap_oscore");
		keyTypes.clear();
		keyTypes.add("PSK");
		db.addClient("Client2", profiles, null, null, keyTypes, myPsk, null);
		peerIdentity = buildOscoreIdentity(KeyStorage.aceSenderIds.get("Client2"), idContext);
		peerNamesToIdentities.put("Client2", peerIdentity);
		peerIdentitiesToNames.put(peerIdentity, "Client2");
		myIdentities.put("Client2", myIdentity);

		myKey = CBORObject.NewMap();
		myKey.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
		myKey.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(KeyStorage.memberAsKeys.get("Server1")));
		myPsk = new OneKey(myKey);

		profiles.clear();
		profiles.add("coap_oscore");
		keyTypes.clear();
		keyTypes.add("PSK");
		db.addClient("Server1", profiles, null, null, keyTypes, myPsk, null);
		peerIdentity = buildOscoreIdentity(KeyStorage.aceSenderIds.get("Server1"), idContext);
		peerNamesToIdentities.put("Server1", peerIdentity);
		peerIdentitiesToNames.put(peerIdentity, "Server1");
		myIdentities.put("Server1", myIdentity);

		myKey = CBORObject.NewMap();
		myKey.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
		myKey.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(KeyStorage.memberAsKeys.get("Server2")));
		myPsk = new OneKey(myKey);

		profiles.clear();
		profiles.add("coap_oscore");
		keyTypes.clear();
		keyTypes.add("PSK");
		db.addClient("Server2", profiles, null, null, keyTypes, myPsk, null);
		peerIdentity = buildOscoreIdentity(KeyStorage.aceSenderIds.get("Server2"), idContext);
		peerNamesToIdentities.put("Server2", peerIdentity);
		peerIdentitiesToNames.put(peerIdentity, "Server2");
		myIdentities.put("Server2", myIdentity);

		myKey = CBORObject.NewMap();
		myKey.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
		myKey.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(KeyStorage.memberAsKeys.get("Server3")));
		myPsk = new OneKey(myKey);

		profiles.clear();
		profiles.add("coap_oscore");
		keyTypes.clear();
		keyTypes.add("PSK");
		db.addClient("Server3", profiles, null, null, keyTypes, myPsk, null);
		peerIdentity = buildOscoreIdentity(KeyStorage.aceSenderIds.get("Server3"), idContext);
		peerNamesToIdentities.put("Server3", peerIdentity);
		peerIdentitiesToNames.put(peerIdentity, "Server3");
		myIdentities.put("Server3", myIdentity);

		myKey = CBORObject.NewMap();
		myKey.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
		myKey.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(KeyStorage.memberAsKeys.get("Server4")));
		myPsk = new OneKey(myKey);

		profiles.clear();
		profiles.add("coap_oscore");
		keyTypes.clear();
		keyTypes.add("PSK");
		db.addClient("Server4", profiles, null, null, keyTypes, myPsk, null);
		peerIdentity = buildOscoreIdentity(KeyStorage.aceSenderIds.get("Server4"), idContext);
		peerNamesToIdentities.put("Server4", peerIdentity);
		peerIdentitiesToNames.put(peerIdentity, "Server4");
		myIdentities.put("Server4", myIdentity);

		myKey = CBORObject.NewMap();
		myKey.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
		myKey.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(KeyStorage.memberAsKeys.get("Server5")));
		myPsk = new OneKey(myKey);

		profiles.clear();
		profiles.add("coap_oscore");
		keyTypes.clear();
		keyTypes.add("PSK");
		db.addClient("Server5", profiles, null, null, keyTypes, myPsk, null);
		peerIdentity = buildOscoreIdentity(KeyStorage.aceSenderIds.get("Server5"), idContext);
		peerNamesToIdentities.put("Server5", peerIdentity);
		peerIdentitiesToNames.put(peerIdentity, "Server5");
		myIdentities.put("Server5", myIdentity);

		myKey = CBORObject.NewMap();
		myKey.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
		myKey.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(KeyStorage.memberAsKeys.get("Server6")));
		myPsk = new OneKey(myKey);

		profiles.clear();
		profiles.add("coap_oscore");
		keyTypes.clear();
		keyTypes.add("PSK");
		db.addClient("Server6", profiles, null, null, keyTypes, myPsk, null);
		peerIdentity = buildOscoreIdentity(KeyStorage.aceSenderIds.get("Server6"), idContext);
		peerNamesToIdentities.put("Server6", peerIdentity);
		peerIdentitiesToNames.put(peerIdentity, "Server6");
		myIdentities.put("Server6", myIdentity);

		myKey = CBORObject.NewMap();
		myKey.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
		myKey.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(KeyStorage.memberAsKeys.get("Adversary")));
		myPsk = new OneKey(myKey);

		profiles.clear();
		profiles.add("coap_oscore");
		keyTypes.clear();
		keyTypes.add("PSK");
		db.addClient("Adversary", profiles, null, null, keyTypes, myPsk, null);
		peerIdentity = buildOscoreIdentity(KeyStorage.aceSenderIds.get("Adversary"), idContext);
		peerNamesToIdentities.put("Adversary", peerIdentity);
		peerIdentitiesToNames.put(peerIdentity, "Adversary");
		myIdentities.put("Adversary", myIdentity);

		// Add an further client "admin1" as an Administrator of OSCORE groups
		myKey = CBORObject.NewMap();
		myKey.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
		myKey.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(KeyStorage.memberAsKeys.get("admin1")));
		myPsk = new OneKey(myKey);

		profiles.clear();
		profiles.add("coap_oscore");
		keyTypes.clear();
		keyTypes.add("PSK");
		db.addClient("admin1", profiles, null, null, keyTypes, myPsk, null);
		peerIdentity = buildOscoreIdentity(KeyStorage.aceSenderIds.get("admin1"), idContext);
		peerNamesToIdentities.put("admin1", peerIdentity);
		peerIdentitiesToNames.put(peerIdentity, "admin1");
		myIdentities.put("admin1", myIdentity);

		/* --- End configure clients and servers --- */

		KissTime time = new KissTime();
		String cti = Base64.getEncoder().encodeToString(new byte[] { 0x00 });
		Map<Short, CBORObject> claims = new HashMap<>();
		claims.put(Constants.SCOPE, CBORObject.FromObject("co2"));
		claims.put(Constants.AUD, CBORObject.FromObject("sensors"));
		claims.put(Constants.EXP, CBORObject.FromObject(time.getCurrentTime() + 1000000L));
		claims.put(Constants.AUD, CBORObject.FromObject("actuators"));
		claims.put(Constants.CTI, CBORObject.FromObject(new byte[] { 0x00 }));
		db.addToken(cti, claims);
		db.addCti2Client(cti, "clientA");

		OneKey asymmKey = OneKey.generateKey(AlgorithmID.ECDSA_256);
		pdp = new GroupOSCOREJoinPDP(db);

		// Initialize data in PDP
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

		pdp.addAccess("clientA", "rs1", "r_temp");
		pdp.addAccess("clientA", "rs1", "rw_config");
		pdp.addAccess("clientA", "rs2", "r_light");
		pdp.addAccess("clientA", "rs2", "r_temp");
		pdp.addAccess("clientA", "rs2", "rw_config");
		pdp.addAccess("clientA", "rs5", "failTokenNotImplemented");

		pdp.addAccess("clientB", "rs1", "r_temp");
		pdp.addAccess("clientB", "rs1", "co2");
		pdp.addAccess("clientB", "rs2", "r_temp");
		pdp.addAccess("clientB", "rs2", "co2");
		pdp.addAccess("clientB", "rs2", "r_light");
		pdp.addAccess("clientB", "rs2", "r_config");
		pdp.addAccess("clientB", "rs2", "failTokenType");
		pdp.addAccess("clientB", "rs3", "rw_valve");
		pdp.addAccess("clientB", "rs3", "r_pressure");
		pdp.addAccess("clientB", "rs3", "failTokenType");
		pdp.addAccess("clientB", "rs3", "failProfile");
		pdp.addAccess("clientB", "rs4", "failProfile");
		pdp.addAccess("clientB", "rs6", "co2");
		pdp.addAccess("clientB", "rs7", "co2");

		pdp.addAccess("clientC", "rs3", "r_valve");
		pdp.addAccess("clientC", "rs3", "r_pressure");
		pdp.addAccess("clientC", "rs6", "r_valve");

		pdp.addAccess("clientD", "rs1", "r_temp");
		pdp.addAccess("clientD", "rs1", "rw_config");
		pdp.addAccess("clientD", "rs2", "r_light");
		pdp.addAccess("clientD", "rs5", "failTokenNotImplemented");
		pdp.addAccess("clientD", "rs1", "r_temp");

		pdp.addAccess("clientE", "rs3", "rw_valve");
		pdp.addAccess("clientE", "rs3", "r_pressure");
		pdp.addAccess("clientE", "rs3", "failTokenType");
		pdp.addAccess("clientE", "rs3", "failProfile");

		/* --- Configure clients and servers --- */

		// Add rs2 as OSCORE Group Manager
		Set<String> rs2 = Collections.singleton("rs2");
		pdp.addOSCOREGroupManagers("rs2", rs2);

		pdp.addTokenAccess("Client1");
		pdp.addTokenAccess("Client2");
		pdp.addTokenAccess("Server1");
		pdp.addTokenAccess("Server2");
		pdp.addTokenAccess("Server3");
		pdp.addTokenAccess("Server4");
		pdp.addTokenAccess("Server5");
		pdp.addTokenAccess("Server6");
		pdp.addTokenAccess("Adversary");

		// Add also client "admin1" as an Administrator of OSCORE groups.
		pdp.addTokenAccess("admin1");

		// Group A

		pdp.addAccess("Client1", "rs2", GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX + ":"
				+ groupName1.length() + ":" + groupName1 + "_requester_monitor_responder");

		pdp.addAccess("Client2", "rs2", GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX + ":"
				+ groupName1.length() + ":" + groupName1 + "_requester_monitor_responder");

		pdp.addAccess("Server1", "rs2", GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX + ":"
				+ groupName1.length() + ":" + groupName1 + "_requester_monitor_responder");

		pdp.addAccess("Server2", "rs2", GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX + ":"
				+ groupName1.length() + ":" + groupName1 + "_requester_monitor_responder");

		pdp.addAccess("Server3", "rs2", GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX + ":"
				+ groupName1.length() + ":" + groupName1 + "_requester_monitor_responder");

		pdp.addAccess("Server4", "rs2", GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX + ":"
				+ groupName1.length() + ":" + groupName1 + "_requester_monitor_responder");

		pdp.addAccess("Server5", "rs2", GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX + ":"
				+ groupName1.length() + ":" + groupName1 + "_requester_monitor_responder");

		pdp.addAccess("Server6", "rs2", GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX + ":"
				+ groupName1.length() + ":" + groupName1 + "_requester_monitor_responder");

		// Group B

		pdp.addAccess("Client1", "rs2", GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX + ":"
				+ groupName2.length() + ":" + groupName2 + "_requester_monitor_responder");

		pdp.addAccess("Client2", "rs2", GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX + ":"
				+ groupName2.length() + ":" + groupName2 + "_requester_monitor_responder");

		pdp.addAccess("Server1", "rs2", GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX + ":"
				+ groupName2.length() + ":" + groupName2 + "_requester_monitor_responder");

		pdp.addAccess("Server2", "rs2", GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX + ":"
				+ groupName2.length() + ":" + groupName2 + "_requester_monitor_responder");

		pdp.addAccess("Server3", "rs2", GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX + ":"
				+ groupName2.length() + ":" + groupName2 + "_requester_monitor_responder");

		pdp.addAccess("Server4", "rs2", GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX + ":"
				+ groupName2.length() + ":" + groupName2 + "_requester_monitor_responder");

		pdp.addAccess("Server5", "rs2", GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX + ":"
				+ groupName2.length() + ":" + groupName2 + "_requester_monitor_responder");

		pdp.addAccess("Server6", "rs2", GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX + ":"
				+ groupName2.length() + ":" + groupName2 + "_requester_monitor_responder");

		pdp.addAccess("Adversary", "rs2", GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX + ":"
				+ groupName2.length() + ":" + groupName2 + "_requester");

		// Admin

		// Specify admin permissions for client "admin1" as an Administrator of
		// the OSCORE groups. This Administrator is allowed to perform all the
		// possible operations on these particular groups.
		pdp.addAccess("admin1", "rs2", GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX + ":"
				+ groupName1.length() + ":" + groupName1 + "_list_create_read_write_delete");
		pdp.addAccess("admin1", "rs2", GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX + ":"
				+ groupName2.length() + ":" + groupName2 + "_list_create_read_write_delete");
		pdp.addAccess("admin1", "rs2", GroupcommParameters.GROUP_OSCORE_AS_SCOPE_COMPLEX_PREFIX + ":" + "21065" + ":"
				+ complexPattern.length() + ":" + complexPattern + "_list_create_read_write_delete");

		/* --- End configure clients and servers --- */

		as = new OscoreAS(asName, db, pdp, time, asymmKey, "token", "introspect", port, null, false, (short) 1, true,
				peerNamesToIdentities, peerIdentitiesToNames, myIdentities);

		AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
		AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;
		OSCoreCtx ctx = new OSCoreCtx(KeyStorage.memberAsKeys.get("Adversary"), true, alg,
				KeyStorage.aceSenderIds.get("AS"), new byte[] { (byte) 0xFF, (byte) 0xFF }, kdf, 32, null, idContext,
				4096);
		OscoreCtxDbSingleton.getInstance().addContext(ctx);

		as.start();
		System.out.println("OSCORE ACE AS Server started on port: " + port);
	}

	/**
	 * Stops the server
	 * 
	 * @throws Exception on failure to stop AS process
	 */
	public static void stop() throws Exception {
		DBHelper.tearDownDB();
		as.stop();
		pdp.close();

	}

	private static String buildOscoreIdentity(byte[] senderId, byte[] contextId) {

		if (senderId == null)
			return null;

		String identity = "";

		if (contextId != null) {
			identity += Base64.getEncoder().encodeToString(contextId);
			identity += ":";
		}

		identity += Base64.getEncoder().encodeToString(senderId);

		return identity;

	}

	/**
	 * Print help message with valid command line arguments
	 */
	private static void printHelp() {
		System.out.println("Usage: [ -dht {URI} ] [ -db {URI} ] [ -help ]");

		System.out.println("Options:");

		System.out.print("-dht");
		System.out.println("\t Use DHT: Optionally specify its WebSocket URI for logging");

		System.out.print("-db");
		System.out.println(
				"\t URI indicating configuration settings for connection to SQL database. Example: \"mysql://root:password@localhost:3306\"");

		System.out.print("-help");
		System.out.println("\t Print help");
	}

}
