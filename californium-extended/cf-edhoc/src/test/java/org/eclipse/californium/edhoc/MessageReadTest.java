package org.eclipse.californium.edhoc;

import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.junit.Assert;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import net.i2p.crypto.eddsa.EdDSASecurityProvider;

/**
 * Test reading of EDHOC messages
 *
 */
public class MessageReadTest {

	/**
	 * Test reading of message 1
	 */
	@Test
	public void testReadMessage1() {

		// Insert EdDSA security provider
		final Provider EdDSA = new EdDSASecurityProvider();
		Security.insertProviderAt(EdDSA, 1);

		boolean initiator = true;
		int method = 0;

		// Connection Identifier of the Initiator
		byte[] connectionIdentifierInitiator = new byte[] { (byte) 0x2d };

		List<Integer> cipherSuites = new ArrayList<Integer>();
		cipherSuites.add(0);

		Set<Integer> supportedEADs = new HashSet<>();

		List<Integer> peerSupportedCipherSuites = new ArrayList<Integer>();

		// The identity key of the Initiator
		byte[] privateIdentityKeyBytes = StringUtil
				.hex2ByteArray("4c5b25878f507c6b9dae68fbd4fd3ff997533db0af00b25d324ea28e6c213bc8");
		byte[] publicIdentityKeyBytes = StringUtil
				.hex2ByteArray("ed06a8ae61a829ba5fa54525c9d07f48dd44a302f43e0f23d8cc20b73085141e");
		OneKey identityKey = SharedSecretCalculation.buildEd25519OneKey(privateIdentityKeyBytes,
				publicIdentityKeyBytes);

		// Just for method compatibility; it is not used for EDHOC Message 1
		// The x509 certificate of the Initiator
		byte[] serializedCert = StringUtil.hex2ByteArray(
				"3081EE3081A1A003020102020462319EA0300506032B6570301D311B301906035504030C124544484F4320526F6F742045643235353139301E170D3232303331363038323430305A170D3239313233313233303030305A30223120301E06035504030C174544484F4320496E69746961746F722045643235353139302A300506032B6570032100ED06A8AE61A829BA5FA54525C9D07F48DD44A302F43E0F23D8CC20B73085141E300506032B6570034100521241D8B3A770996BCFC9B9EAD4E7E0A1C0DB353A3BDF2910B39275AE48B756015981850D27DB6734E37F67212267DD05EEFF27B9E7A813FA574B72A00B430B");

		// CRED_I, as serialization of a CBOR byte string wrapping the
		// serialized certificate
		byte[] cred = CBORObject.FromObject(serializedCert).EncodeToBytes();

		CBORObject idCred = Util.buildIdCredX5t(cred);

		// Set the application profile
		// - Supported authentication methods
		// - Use of message_4 as expected to be sent by the Responder
		// - Use of EDHOC for keying OSCORE
		// - Supporting for the EDHOC+OSCORE request
		// - Method for converting from OSCORE Recipient/Sender ID to EDHOC
		// Connection Identifier
		//
		Set<Integer> authMethods = new HashSet<Integer>();
		for (int i = 0; i <= Constants.EDHOC_AUTH_METHOD_3; i++)
			authMethods.add(i);
		boolean useMessage4 = false;
		boolean usedForOSCORE = true;
		boolean supportCombinedRequest = false;
		AppProfile appProfile = new AppProfile(authMethods, useMessage4, usedForOSCORE, supportCombinedRequest);
		int trustModel = Constants.TRUST_MODEL_STRICT;

		// Specify the database of OSCORE Security Contexts
		HashMapCtxDB db = new HashMapCtxDB();

		HashMap<Integer, HashMap<Integer, OneKey>> keyPairs = new HashMap<Integer, HashMap<Integer, OneKey>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> creds = new HashMap<Integer, HashMap<Integer, CBORObject>>();
		HashMap<Integer, HashMap<Integer, CBORObject>> idCreds = new HashMap<Integer, HashMap<Integer, CBORObject>>();

		keyPairs.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, OneKey>());
		creds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());
		idCreds.put(Integer.valueOf(Constants.SIGNATURE_KEY), new HashMap<Integer, CBORObject>());

		keyPairs.get(Integer.valueOf(Constants.SIGNATURE_KEY)).put(Integer.valueOf(Constants.CURVE_Ed25519),
				identityKey);
		creds.get(Integer.valueOf(Constants.SIGNATURE_KEY)).put(Integer.valueOf(Constants.CURVE_Ed25519),
				CBORObject.FromObject(cred));
		idCreds.get(Integer.valueOf(Constants.SIGNATURE_KEY)).put(Integer.valueOf(Constants.CURVE_Ed25519), idCred);

		EdhocSession session = new EdhocSession(initiator, true, method, connectionIdentifierInitiator, keyPairs,
				idCreds, creds, cipherSuites, peerSupportedCipherSuites, supportedEADs, appProfile, trustModel, db);

		SideProcessor sideProcessor = new SideProcessor(trustModel, null, null);
		sideProcessor.setEdhocSession(session);

		// Force a specific ephemeral key
		byte[] privateEkeyBytes = StringUtil
				.hex2ByteArray("892ec28e5cb6669108470539500b705e60d008d347c5817ee9f3327c8a87bb03");
		byte[] publicEkeyBytes = StringUtil
				.hex2ByteArray("31f82c7b5b9cbbf0f194d913cc12ef1532d328ef32632a4881a1c0701e237f04");
		OneKey ek = SharedSecretCalculation.buildCurve25519OneKey(privateEkeyBytes, publicEkeyBytes);
		session.setEphemeralKey(ek);

		// List of supported cipher suites, in decreasing order of preference.
		List<Integer> supportedCipherSuites = new ArrayList<Integer>();
		supportedCipherSuites.add(Constants.EDHOC_CIPHER_SUITE_0);
		supportedCipherSuites.add(Constants.EDHOC_CIPHER_SUITE_1);
		supportedCipherSuites.add(Constants.EDHOC_CIPHER_SUITE_2);
		supportedCipherSuites.add(Constants.EDHOC_CIPHER_SUITE_3);

		byte[] message = StringUtil
				.hex2ByteArray("f5000058203a1477d582d3973c771776e722992bc8ac52c49fd76e985d924a6484e376266340");

		// Now read EDHOC message 1
		List<CBORObject> processingResult = new ArrayList<CBORObject>();
		processingResult = MessageProcessor.readMessage1(message, true, supportedCipherSuites, supportedEADs,
				appProfile, sideProcessor);

		if (processingResult.get(0) == null || processingResult.get(0).getType() != CBORType.ByteString) {
			String responseString = new String("Internal error when processing EDHOC Message 1");
			System.err.println(responseString);

			byte[] nextMessage = responseString.getBytes(Constants.charset);
			Response genericErrorResponse = new Response(ResponseCode.INTERNAL_SERVER_ERROR);
			genericErrorResponse.setPayload(nextMessage);
			Assert.fail();
		}

		Assert.assertEquals(1, processingResult.size());
		Assert.assertEquals(CBORType.ByteString, processingResult.get(0).getType());
		Assert.assertEquals(0, processingResult.get(0).size());

	}
}
