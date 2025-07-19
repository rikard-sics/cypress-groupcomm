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
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;

import com.upokecenter.cbor.CBORObject;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.MessageTag;
import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.Util;
import se.sics.ace.coap.rs.CoapAuthzInfo;
import se.sics.ace.coap.rs.CoapDeliverer;
import se.sics.ace.coap.rs.oscoreProfile.OscoreCtxDbSingleton;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissTime;
import se.sics.ace.oscore.GroupInfo;
import se.sics.ace.oscore.rs.GroupOSCOREValidator;
import se.sics.ace.oscore.rs.OscoreAuthzInfoGroupOSCORE;
import se.sics.ace.oscore.rs.oscoreGroupManager.GroupOSCOREGroupCollectionResource;
import se.sics.ace.oscore.rs.oscoreGroupManager.GroupOSCOREGroupMembershipResource;
import se.sics.ace.oscore.rs.oscoreGroupManager.GroupOSCORERootGroupMembershipResource;
import se.sics.ace.oscore.rs.oscoreGroupManager.GroupOSCORESubResourceActive;
import se.sics.ace.oscore.rs.oscoreGroupManager.GroupOSCORESubResourceCreds;
import se.sics.ace.oscore.rs.oscoreGroupManager.GroupOSCORESubResourceKdcCred;
import se.sics.ace.oscore.rs.oscoreGroupManager.GroupOSCORESubResourceNodes;
import se.sics.ace.oscore.rs.oscoreGroupManager.GroupOSCORESubResourceNum;
import se.sics.ace.oscore.rs.oscoreGroupManager.GroupOSCORESubResourcePolicies;
import se.sics.ace.oscore.rs.oscoreGroupManager.GroupOSCORESubResourceStaleSids;
import se.sics.ace.oscore.rs.oscoreGroupManager.GroupOSCORESubResourceVerifData;
import se.sics.ace.rs.AsRequestCreationHints;

/**
 * A RS for testing the OSCORE profile of ACE (RFC 9203)
 * 
 * The RS acts as an OSCORE Group Manager.
 * 
 * @author Marco Tiloca and Rikard Höglund
 *
 */
public class OscoreRsServer {

	// Sets the port to use
	private final static int PORT = CoAP.DEFAULT_COAP_PORT + 100;

	private final static String rootGroupMembershipResourcePath = "ace-group";

	private final static String groupCollectionResourcePath = "manage";

	// Up to 4 bytes, same for all the OSCORE Group of the Group Manager
	private final static int groupIdPrefixSize = 4;

	// Initial part of the node name for monitors, since they do not have a
	// Sender ID
	private final static String prefixMonitorNames = "M";

	// For non-monitor members, separator between the two components of the node
	// name
	private final static String nodeNameSeparator = "-";

	// Uncomment to set ECDSA with curve P-256 for countersignatures
	// private static int signKeyCurve = KeyKeys.EC2_P256.AsInt32();

	private static Map<String, GroupInfo> existingGroupInfo = new HashMap<>();

	private static Set<CBORObject> usedGroupIdPrefixes = new HashSet<>();

	private static Map<String, Map<String, Set<Short>>> myScopes = new HashMap<>();

	private static GroupOSCOREValidator valid = null;

	// The map key is the cryptographic curve; the map value is the hex string
	// of the key pair
	private static Map<CBORObject, String> gmSigningKeyPairs = new HashMap<CBORObject, String>();

	// For the outer map, the map key is the type of authentication credential
	// For the inner map, the map key is the cryptographic curve, while the map
	// value is the hex string of the authentication credential
	private static Map<Integer, Map<CBORObject, String>> gmSigningPublicAuthCred = new HashMap<Integer, Map<CBORObject, String>>();

	// The map key is the cryptographic curve; the map value is the hex string
	// of the key pair
	private static Map<CBORObject, String> gmKeyAgreementKeyPairs = new HashMap<CBORObject, String>();

	// For the outer map, the map key is the type of authentication credential
	// For the inner map, the map key is the cryptographic curve, while the map
	// value is the hex string of the authentication credential
	private static Map<Integer, Map<CBORObject, String>> gmKeyAgreementPublicAuthCred = new HashMap<Integer, Map<CBORObject, String>>();

	// For old tests - PSK to encrypt the token (used for both audiences rs1 and
	// rs2)
	private static byte[] key128_token = { (byte) 0xa1, (byte) 0xa2, (byte) 0xa3, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
			0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };

	static String testpath = "temp-";

	static {
		CoapConfig.register();
	}

	/**
	 * Definition of the Hello-World Resource
	 */
	public static class HelloWorldResource extends CoapResource {

		/**
		 * Constructor
		 */
		public HelloWorldResource() {

			// set resource identifier
			super("helloWorld");

			// set display name
			getAttributes().setTitle("Hello-World Resource");
		}

		@Override
		public void handleGET(CoapExchange exchange) {

			// respond to the request
			exchange.respond("Hello World!");
		}
	}

	/**
	 * Definition of the Manage Resource
	 */
	public static class ManageResource extends CoapResource {

		/**
		 * Constructor
		 */
		public ManageResource() {

			// set resource identifier
			super("manage");

			// set display name
			getAttributes().setTitle("Manage Resource");
		}

		@Override
		public void handleGET(CoapExchange exchange) {

			// respond to the request
			exchange.respond("This is the /manage resource.");
		}

		@Override
		public void handlePOST(CoapExchange exchange) {

			// respond to the request
			exchange.respond("This is the /manage resource.");
		}
	}

	/**
	 * Definition of the Temp Resource
	 */
	public static class TempResource extends CoapResource {

		/**
		 * Constructor
		 */
		public TempResource() {

			// set resource identifier
			super("temp");

			// set display name
			getAttributes().setTitle("Temp Resource");
		}

		@Override
		public void handleGET(CoapExchange exchange) {

			// respond to the request
			exchange.respond("19.0 C");
		}
	}

	private static OscoreAuthzInfoGroupOSCORE ai = null;

	private static CoapServer rs = null;

	private static CoapDeliverer dpd = null;

	/**
	 * The CoAP OSCORE server for testing, run this before running the Junit
	 * tests.
	 * 
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {

		System.out.println("Starting Resource Server (Group Manager): OscoreRsServer...");

		// Parse command line arguments
		for (int i = 0; i < args.length; i++) {
			if (args[i].toLowerCase().endsWith("-help")) {
				printHelp();
				System.exit(0);
			}
		}

		// Set java.util.logging
		Logger rootLogger = LogManager.getLogManager().getLogger("");
		rootLogger.setLevel(Level.INFO);
		for (Handler h : rootLogger.getHandlers()) {
			h.setLevel(Level.INFO);
		}

		// install needed cryptography providers
		try {
			org.eclipse.californium.oscore.InstallCryptoProviders.installProvider();
		} catch (Exception e) {
			System.err.println("Failed to install cryptography providers.");
			e.printStackTrace();
		}

		setGroupManagerKeyPairs();

		final String groupName = "feedca570000";

		// Set up token repository
		Set<Short> actions = new HashSet<>();
		actions.add(Constants.GET);
		Map<String, Set<Short>> myResource = new HashMap<>();
		myResource.put("helloWorld", actions);
		myScopes.put("r_helloWorld", myResource);

		Set<Short> actions2 = new HashSet<>();
		actions2.add(Constants.GET);
		Map<String, Set<Short>> myResource2 = new HashMap<>();
		myResource2.put("temp", actions2);
		myScopes.put("r_temp", myResource2);

		// Adding the group-membership resource, with group name "feedca570000".
		Map<String, Set<Short>> myResource3 = new HashMap<>();
		Set<Short> actions3 = new HashSet<>();
		actions3.add(Constants.FETCH);
		myResource3.put(rootGroupMembershipResourcePath, actions3);
		actions3 = new HashSet<>();
		actions3.add(Constants.GET);
		actions3.add(Constants.POST);
		myResource3.put(rootGroupMembershipResourcePath + "/" + groupName, actions3);
		actions3 = new HashSet<>();
		actions3.add(Constants.GET);
		actions3.add(Constants.FETCH);
		myResource3.put(rootGroupMembershipResourcePath + "/" + groupName + "/creds", actions3);
		actions3 = new HashSet<>();
		actions3.add(Constants.GET);
		myResource3.put(rootGroupMembershipResourcePath + "/" + groupName + "/kdc-cred", actions3);
		myResource3.put(rootGroupMembershipResourcePath + "/" + groupName + "/verif-data", actions3);
		myResource3.put(rootGroupMembershipResourcePath + "/" + groupName + "/num", actions3);
		myResource3.put(rootGroupMembershipResourcePath + "/" + groupName + "/active", actions3);
		myResource3.put(rootGroupMembershipResourcePath + "/" + groupName + "/policies", actions3);
		actions3 = new HashSet<>();
		actions3.add(Constants.FETCH);
		myResource3.put(rootGroupMembershipResourcePath + "/" + groupName + "/stale-sids", actions3);
		myScopes.put(rootGroupMembershipResourcePath + "/" + groupName, myResource3);

		// Adding another group-membership resource, with group name
		// "fBBBca570000".
		// There will NOT be a token enabling the access to this resource.
		Map<String, Set<Short>> myResource4 = new HashMap<>();
		Set<Short> actions4 = new HashSet<>();
		actions4.add(Constants.GET);
		actions4.add(Constants.POST);
		myResource4.put(rootGroupMembershipResourcePath + "/" + "fBBBca570000", actions4);
		myScopes.put(rootGroupMembershipResourcePath + "/" + "fBBBca570000", myResource4);

		// Adding the group-collection resource
		Map<String, Set<Short>> myResource5 = new HashMap<>();
		Set<Short> actions5 = new HashSet<>();
		actions5.add(Constants.GET);
		actions5.add(Constants.FETCH);
		actions5.add(Constants.POST);
		myResource5.put(groupCollectionResourcePath, actions5);
		myScopes.put(groupCollectionResourcePath, myResource5);

		Set<String> auds = new HashSet<>();
		auds.add("aud1"); // Simple test audience
		auds.add("aud2"); // OSCORE Group Manager (This audience expects scopes
							// as Byte Strings)
		auds.add("rs2");
		valid = new GroupOSCOREValidator(auds, myScopes, rootGroupMembershipResourcePath, groupCollectionResourcePath);

		// Include this audience in the list of audiences recognized as OSCORE
		// Group Managers
		valid.setGMAudiences(Collections.singleton("rs2"));

		// Include the root group-membership resource for Group OSCORE.
		valid.setGroupMembershipResources(Collections.singleton(rootGroupMembershipResourcePath));

		// For each OSCORE group, include the associated group-membership
		// resource and its sub-resources
		valid.setGroupMembershipResources(Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName));
		valid.setGroupMembershipResources(
				Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName + "/creds"));
		valid.setGroupMembershipResources(
				Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName + "/kdc-cred"));
		valid.setGroupMembershipResources(
				Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName + "/verif-data"));
		valid.setGroupMembershipResources(
				Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName + "/num"));
		valid.setGroupMembershipResources(
				Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName + "/active"));
		valid.setGroupMembershipResources(
				Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName + "/policies"));
		valid.setGroupMembershipResources(
				Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName + "/stale-sids"));

		// Include the group-collection resource for Group OSCORE.
		valid.setGroupAdminResources(Collections.singleton(groupCollectionResourcePath));

		String rsId = "rs2";

		String tokenFile = testpath + "tokens.json";
		// Delete lingering old token files
		new File(tokenFile).delete();

		// Set up COSE parameters (enable for encrypting Tokens)
		COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_128_128, AlgorithmID.Direct);
		CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128_token, coseP.getAlg().AsCBOR());

		// Set up the inner Authz-Info library
		// Changed this OscoreAuthzInfo->OscoreAuthzInfoGroupOSCORE
		ai = new OscoreAuthzInfoGroupOSCORE(Collections.singletonList("AS"), new KissTime(), null, rsId, valid, ctx,
				tokenFile, valid, false);

		// Provide the authz-info endpoint with the set of existing OSCORE
		// groups
		ai.setExistingGroups(existingGroupInfo);

		// Add a test token to authz-info

		Map<Short, CBORObject> params = new HashMap<>();
		params.put(Constants.SCOPE, CBORObject.FromObject("r_temp"));
		params.put(Constants.AUD, CBORObject.FromObject("aud1"));
		params.put(Constants.CTI, CBORObject.FromObject("token1".getBytes(Constants.charset)));
		params.put(Constants.ISS, CBORObject.FromObject("TestAS"));

		// Build oscore CNF claim
		CBORObject osccnf = CBORObject.NewMap();
		CBORObject osc = CBORObject.NewMap();

		byte[] masterSecret = new byte[16];
		new SecureRandom().nextBytes(masterSecret);

		osc.Add(Constants.OS_MS, masterSecret);
		osc.Add(Constants.OS_ID, Util.intToBytes(0));
		osccnf.Add(Constants.OSCORE_Input_Material, osc);
		params.put(Constants.CNF, osccnf);

		AsRequestCreationHints archm = new AsRequestCreationHints("coap://blah/authz-info/", null, false, false);
		Resource hello = new HelloWorldResource();
		Resource temp = new TempResource();
		Resource authzInfo = new CoapAuthzInfo(ai);

		// The root group-membership resource
		Resource groupOSCORERootGroupMembership = new GroupOSCORERootGroupMembershipResource(
				rootGroupMembershipResourcePath, existingGroupInfo);

		/*
		 * For each OSCORE group, create the associated group-membership
		 * resource and its sub-resources
		 */
		// Group-membership resource - The name of the OSCORE group is used as
		// resource name
		Resource groupMembershipResource = new GroupOSCOREGroupMembershipResource(groupName, existingGroupInfo,
				rootGroupMembershipResourcePath, myScopes, valid);
		// Add the /creds sub-resource
		Resource credsSubResource = new GroupOSCORESubResourceCreds("creds", existingGroupInfo);
		groupMembershipResource.add(credsSubResource);

		// Add the /kdc-cred sub-resource
		Resource kdcCredSubResource = new GroupOSCORESubResourceKdcCred("kdc-cred", existingGroupInfo);
		groupMembershipResource.add(kdcCredSubResource);

		// Add the /verif-data sub-resource
		Resource verifDataSubResource = new GroupOSCORESubResourceVerifData("verif-data", existingGroupInfo);
		groupMembershipResource.add(verifDataSubResource);

		// Add the /num sub-resource
		Resource numSubResource = new GroupOSCORESubResourceNum("num", existingGroupInfo);
		groupMembershipResource.add(numSubResource);

		// Add the /active sub-resource
		Resource activeSubResource = new GroupOSCORESubResourceActive("active", existingGroupInfo);
		groupMembershipResource.add(activeSubResource);

		// Add the /policies sub-resource
		Resource policiesSubResource = new GroupOSCORESubResourcePolicies("policies", existingGroupInfo);
		groupMembershipResource.add(policiesSubResource);

		// Add the /stale-sids sub-resource
		Resource staleSidsSubResource = new GroupOSCORESubResourceStaleSids("stale-sids", existingGroupInfo);
		groupMembershipResource.add(staleSidsSubResource);

		// Add the /nodes sub-resource, as root to actually accessible per-node
		// sub-resources
		Resource nodesSubResource = new GroupOSCORESubResourceNodes("nodes");
		groupMembershipResource.add(nodesSubResource);

		// The group-collection resource
		Resource groupOSCOREGroupCollection = new GroupOSCOREGroupCollectionResource(groupCollectionResourcePath,
				groupOSCORERootGroupMembership, groupIdPrefixSize, usedGroupIdPrefixes, prefixMonitorNames,
				nodeNameSeparator, existingGroupInfo, gmSigningKeyPairs, gmSigningPublicAuthCred,
				gmKeyAgreementKeyPairs, gmKeyAgreementPublicAuthCred, myScopes, valid, "coap://as.example.com/token");

		// Create the OSCORE Group(s)
		// if (!OSCOREGroupCreation(groupName, signKeyCurve, ecdhKeyCurve))
		// return;

		rs = new CoapServer();
		rs.add(hello);
		rs.add(temp);
		rs.add(authzInfo);
		rs.add(groupOSCORERootGroupMembership);
		rs.add(groupOSCOREGroupCollection);
		groupOSCORERootGroupMembership.add(groupMembershipResource);

		CoapEndpoint cep = new CoapEndpoint.Builder().setCoapStackFactory(new OSCoreCoapStackFactory()).setPort(PORT)
				.setCustomCoapStackArgument(OscoreCtxDbSingleton.getInstance()).build();
		rs.addEndpoint(cep);

		dpd = new CoapDeliverer(rs.getRoot(), null, archm, cep);
		// Add special allowance for Token and message from this OSCORE Sender
		// ID
		rs.setMessageDeliverer(dpd);

		rs.start();
		System.out.println("OSCORE RS (GM) Server starting on port " + PORT);

	}

	/**
	 * Stops the server
	 * 
	 * @throws IOException
	 * @throws AceException
	 */
	public static void stop() throws AceException {
		rs.stop();
		ai.close();
		new File(testpath + "tokens.json").delete();
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
		gmSigningPublicAuthCred.get(Constants.COSE_HEADER_PARAM_KCCS).put(org.eclipse.californium.cose.KeyKeys.EC2_P256,
				keySigningAuthCredP256CCS);

		// Key pair for EdDSA with curve Ed25519
		String keySigningKeyPairEd25519 = "a5010103272006215820c6ec665e817bd064340e7c24bb93a11e8ec0735ce48790f9c458f7fa340b8ca3235820d0a2ce11b2ba614b048903b72638ef4a3b0af56e1a60c6fb6706b0c1ad8a14fb";
		gmSigningKeyPairs.put(org.eclipse.californium.cose.KeyKeys.OKP_Ed25519, keySigningKeyPairEd25519);

		// Authentication credential for EdDSA with curve Ed25519, as a CCS
		String keySigningAuthCredEd25519CCS = "a2026008a101a4010103272006215820c6ec665e817bd064340e7c24bb93a11e8ec0735ce48790f9c458f7fa340b8ca3";
		gmSigningPublicAuthCred.get(Constants.COSE_HEADER_PARAM_KCCS)
				.put(org.eclipse.californium.cose.KeyKeys.OKP_Ed25519, keySigningAuthCredEd25519CCS);

		// Set the key agreement key pairs

		// Key pair for ECDSA with curve P-256
		String keyAgreementKeyPairP256 = "a6010203262001215820b95e2727b98d6f6f98852e2b360c4e6872c3a8070192d4f810e051572657775522582060aca41e3b065853f836dac69617efd69bad45f29bb7f4335ef93961941f79c5235820b77698f83f3f5a6473eba56125fd0ed2501ac7028d1f906abfa0a6080ef7936a";
		gmKeyAgreementKeyPairs.put(org.eclipse.californium.cose.KeyKeys.EC2_P256, keyAgreementKeyPairP256);

		// Authentication credential for ECDSA with curve P-256, as a CCS
		String keyAgreementAuthCredP256CCS = "a2026008a101a5010203262001215820b95e2727b98d6f6f98852e2b360c4e6872c3a8070192d4f810e051572657775522582060aca41e3b065853f836dac69617efd69bad45f29bb7f4335ef93961941f79c5";
		gmKeyAgreementPublicAuthCred.get(Constants.COSE_HEADER_PARAM_KCCS)
				.put(org.eclipse.californium.cose.KeyKeys.EC2_P256, keyAgreementAuthCredP256CCS);

		// Key pair with curve X25519
		// TODO - This is just a placeholder with a non valid private
		// coordinate. Replace with a valid key pair using X25519
		String keyAgreementKeyPairX25519 = "a5010103381A2004215820c6ec665e817bd064340e7c24bb93a11e8ec0735ce48790f9c458f7fa340b8ca3235820d0a2ce11b2ba614b048903b72638ef4a3b0af56e1a60c6fb6706b0c1ad8a14fb";
		gmKeyAgreementKeyPairs.put(org.eclipse.californium.cose.KeyKeys.OKP_X25519, keyAgreementKeyPairX25519);

		// Authentication credential with curve X25519, as a CCS
		// TODO - This is just a placeholder. Replace with an authentication
		// credential corresponding to a valid key pair using X25519 (see above)
		String keyAgreementAuthCredX25519 = "a2026008a101a4010103381a2004215820c6ec665e817bd064340e7c24bb93a11e8ec0735ce48790f9c458f7fa340b8ca3";
		gmKeyAgreementPublicAuthCred.get(Constants.COSE_HEADER_PARAM_KCCS)
				.put(org.eclipse.californium.cose.KeyKeys.OKP_X25519, keyAgreementAuthCredX25519);

	}

	/**
	 * Print help message with valid command line arguments
	 */
	private static void printHelp() {
		System.out.println("Usage: [ -help ]");

		System.out.println("Options:");

		System.out.print("-help");
		System.out.println("\t Print help");
	}
}
