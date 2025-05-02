/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch Software Innovations - initial creation
 *    Rikard Höglund (RISE)
 ******************************************************************************/
package se.sics.prototype.apps;

import java.io.File;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Scanner;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.InstallCryptoProviders;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.Utility;
import org.eclipse.californium.oscore.group.GroupCtx;
import org.glassfish.tyrus.client.ClientManager;

import com.google.gson.Gson;

import jakarta.websocket.ClientEndpoint;
import jakarta.websocket.CloseReason;
import jakarta.websocket.DeploymentException;
import jakarta.websocket.OnClose;
import jakarta.websocket.OnMessage;
import jakarta.websocket.OnOpen;
import jakarta.websocket.Session;
import se.sics.prototype.json.incoming.JsonIn;
import se.sics.prototype.json.outgoing.JsonOut;
import se.sics.prototype.json.outgoing.OutValue;
import se.sics.prototype.json.outgoing.RequestPubMessage;
import se.sics.prototype.support.Tools;

/**
 * Group OSCORE client application.
 */
@ClientEndpoint
public class GroupOscoreClient {

	/**
	 * File name for network configuration.
	 */
	private static final File CONFIG_FILE = new File("CaliforniumMulticast.properties");
	/**
	 * Header for network configuration.
	 */
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Multicast Client";
	/**
	 * Special network configuration defaults handler.
	 */
	private static DefinitionsProvider DEFAULTS = new DefinitionsProvider() {

		@Override
		public void applyDefinitions(Configuration config) {
			config.set(CoapConfig.MULTICAST_BASE_MID, 65000);
		}

	};

	/**
	 * Time to wait for replies to the multicast request
	 */
	private static final int HANDLER_TIMEOUT = 2000;

	/**
	 * Whether to use OSCORE or not.
	 */
	static final boolean useOSCORE = true;
	//
	// /**
	// * Multicast address to send to (use the first line to set a custom one).
	// */
	// //static final InetAddress multicastIP = new
	// InetSocketAddress("FF01:0:0:0:0:0:0:FD", 0).getAddress();
	// static final InetAddress multicastIP = CoAP.MULTICAST_IPV4;

	/**
	 * Port to send to.
	 */
	private static final int destinationPort = CoAP.DEFAULT_COAP_PORT - 1000;

	/**
	 * Resource to perform request against.
	 */
	static final String requestResource = "/toggle";

	/**
	 * Payload in request sent (POST)
	 */
	// static final String requestPayload = "on";

	/**
	 * ED25519 curve value.
	 * https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
	 */
	static final int ED25519 = KeyKeys.OKP_Ed25519.AsInt32(); // Integer value 6

	/**
	 * Indicate if the basic UI for the client should be enabled
	 */
	// static final boolean ui = true;

	/**
	 * OSCORE Security Context database (sender)
	 */
	private final static HashMapCtxDB db = new HashMapCtxDB();

	private static CountDownLatch latch;
	private static CoapClient client;
	private static String clientName;

	/**
	 * Initialize and start Group OSCORE client.
	 * 
	 * @param derivedCtx the Group OSCORE context
	 * @param multicastIP multicast IP to send to
	 * @param useDht use input/output from/to DHT
	 * @param setClientName name of this client (Client1 / Client2)
	 * @param dhtWebsocketUri URI to use for the WebSocket connection to the DHT
	 * 
	 * @throws Exception on failure
	 */
	public static void start(GroupCtx derivedCtx, InetAddress multicastIP, String setClientName, boolean useDht,
			String dhtWebsocketUri) throws Exception {
		/**
		 * URI to perform request against. Need to check for IPv6 to surround it
		 * with []
		 */
		String requestURI;
		if (multicastIP instanceof Inet6Address) {
			requestURI = "coap://" + "[" + multicastIP.getHostAddress() + "]" + ":" + destinationPort + requestResource;
		} else {
			requestURI = "coap://" + multicastIP.getHostAddress() + ":" + destinationPort + requestResource;
		}
		clientName = setClientName;

		// Install cryptographic providers
		InstallCryptoProviders.installProvider();
		// InstallCryptoProviders.generateCounterSignKey(); //For generating
		// keys

		// If OSCORE is being used set the context information
		GroupCtx ctx = null;
		if (useOSCORE) {
			ctx = derivedCtx;
			// ctx.REPLAY_CHECK = true; //Enable replay checks
			db.addContext(requestURI, ctx);

			OSCoreCoapStackFactory.useAsDefault(db);
		}

		Configuration config = Configuration.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);

		CoapEndpoint endpoint = new CoapEndpoint.Builder().setConfiguration(config).build();
		client = new CoapClient();

		client.setEndpoint(endpoint);
		client.setURI(requestURI);

		// Information about the sender
		System.out.println("==================");
		System.out.println("*Multicast sender");
		System.out.println("Uses OSCORE: " + useOSCORE);
		System.out.println("Request destination: " + requestURI);
		System.out.println("Request destination port: " + destinationPort);
		System.out.println("Outgoing port: " + endpoint.getAddress().getPort());
		System.out.println("=");

		System.out.print("*");
		Utility.printContextInfo(ctx);
		System.out.println("==================");

		System.out.println("");
		System.out.println("Ready to send requests to the OSCORE group.");

		// Connect to DHT and continously retry if connection is lost
		while (useDht) {
			System.out.println("Using DHT");

			latch = new CountDownLatch(1);
			ClientManager dhtClient = ClientManager.createClient();
			try {
				// wss://socketsbay.com/wss/v2/2/demo/
				URI uri = new URI(dhtWebsocketUri);
				dhtClient.connectToServer(GroupOscoreClient.class, uri);
				latch.await();
			} catch (DeploymentException | URISyntaxException | InterruptedException e) {
				System.err.println("Error: Failed to connect to DHT");
				e.printStackTrace();
			}

			System.err.println("Connection to DHT lost. Retrying...");
			try {
				Thread.sleep(5000);
			} catch (InterruptedException e) {
				System.err.println("Error: Failed to sleep when reconnecting to DHT");
				e.printStackTrace();
			}

			Tools.waitForDht(dhtWebsocketUri);
		}

		Scanner scanner = new Scanner(System.in);
		String command = "";

		while (!command.equals("q")) {

			System.out.println("Enter command: ");
			command = scanner.next();

			if (command.equals("q")) {
				break;
			}
			sendRequest(command);
		}

		scanner.close();

	}

	/**
	 * 
	 * /** Method for building and sending Group OSCORE requests.
	 * 
	 * @param client to use for sending
	 * @param payload of the Group OSCORE request
	 * @return list with responses from servers
	 */
	private static ArrayList<CoapResponse> sendRequest(String payload) {
		Request multicastRequest = Request.newPost();
		multicastRequest.setPayload(payload);
		multicastRequest.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
		multicastRequest.setType(Type.NON);
		if (useOSCORE) {
			multicastRequest.getOptions().setOscore(Bytes.EMPTY);
		}

		System.out.println("In sendrequest");

		handler.clearResponses();
		try {
			String host = new URI(client.getURI()).getHost();
			int port = new URI(client.getURI()).getPort();
			System.out.println("Sending to: " + host + ":" + port);
		} catch (URISyntaxException e) {
			System.err.println("Failed to parse destination URI");
			e.printStackTrace();
		}
		System.out.println("Sending from: " + client.getEndpoint().getAddress());
		System.out.println(Utils.prettyPrint(multicastRequest));

		// sends a multicast request
		client.advanced(handler, multicastRequest);
		while (handler.waitOn(HANDLER_TIMEOUT)) {
			// Wait for responses
		}

		try {
			Thread.sleep(1000);
		} catch (InterruptedException e) {
			System.err.println("Error: Failed to sleep after sending request");
			e.printStackTrace();
		}

		return handler.getResponses();

		// count--;
		// if(payload.equals("on")) {
		// payload = "off";
		// } else {
		// payload = "on";
		// }
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
			System.out.println("Receiving from: " + response.advanced().getSourceContext().getPeerAddress());

			System.out.println(Utils.prettyPrint(response));

			responseMessages.add(response);
		}

		@Override
		public void onError() {
			System.err.println("error");
		}
	}

	// DHT related methods

	@OnOpen
	public void onOpen(Session session) {
		System.out.println("--- Connected " + session.getId());
		// try {
		// session.getBasicRemote().sendText("start");
		// } catch (IOException e) {
		// throw new RuntimeException(e);
		// }
	}

	@OnMessage
	public String onMessage(String message, Session session) {
		// Topics to listen for messages on
		String topicDev1 = "command_dev1";
		String topicDev2 = "command_dev2";

		// Do nothing if message does not contain one of the topics
		if (message.contains(topicDev1) == false && message.contains(topicDev2) == false) {
			return null;
		}

		System.out.println("--- Received " + message);

		// Parse incoming JSON string from DHT
		Gson gson = new Gson();
		JsonIn parsed = gson.fromJson(message, JsonIn.class);

		String topicField = parsed.getVolatile().getValue().getTopic();
		String messageField = parsed.getVolatile().getValue().getMessage();

		// Device 1 filter
		if (clientName.equals("Client1") && topicField.equals(topicDev1)) {
			System.out.println("Filter matched message (device 1)!");

			// Send group request and compile responses
			ArrayList<CoapResponse> responsesList = sendRequest(messageField);
			String responsesString = "";
			String toDhtString = "";
			for (int i = 0; i < responsesList.size(); i++) {
				responsesString += Utils.prettyPrint(responsesList.get(i)) + "\n|\n";
				toDhtString += "Response #" + (i + 1) + ": [" + responseToText(responsesList.get(i)) + "] ";
			}
			responsesString = responsesString.replace(".", "").replace(":", " ").replace("=", "-").replace("[", "")
					.replace("]", "").replace("/", "-").replace("\"", "").replace(".", "").replace("{", "")
					.replace("}", "");
			System.out.println("Compiled responses: " + responsesString);

			// Build outgoing JSON to DHT
			JsonOut outgoing = new JsonOut();
			RequestPubMessage pubMsg = new RequestPubMessage();
			OutValue outVal = new OutValue();
			outVal.setTopic("output_dev1");
			outVal.setMessage(toDhtString); // Responses
			pubMsg.setValue(outVal);
			outgoing.setRequestPubMessage(pubMsg);
			Gson gsonOut = new Gson();
			String jsonOut = gsonOut.toJson(outgoing);

			System.out.println("Outgoing JSON: " + jsonOut);
			return (jsonOut);
		}

		// Device 2 filter
		else if (clientName.equals("Client2") && topicField.equals(topicDev2)) {
			System.out.println("Filter matched message (device 2)!");

			// Send group request and compile responses
			ArrayList<CoapResponse> responsesList = sendRequest(messageField);
			String responsesString = "";
			String toDhtString = "";
			for (int i = 0; i < responsesList.size(); i++) {
				responsesString += Utils.prettyPrint(responsesList.get(i)) + "\n|\n";
				toDhtString += "Response #" + (i + 1) + ": [" + responseToText(responsesList.get(i)) + "]";
			}
			responsesString = responsesString.replace(".", "").replace(":", " ").replace("=", "-").replace("[", "")
					.replace("]", "").replace("/", "-").replace("\"", "").replace(".", "").replace("{", "")
					.replace("}", "");
			System.out.println("Compiled responses: " + responsesString);

			// Build outgoing JSON to DHT
			JsonOut outgoing = new JsonOut();
			RequestPubMessage pubMsg = new RequestPubMessage();
			OutValue outVal = new OutValue();
			outVal.setTopic("output_dev2");
			outVal.setMessage(toDhtString); // Responses
			pubMsg.setValue(outVal);
			outgoing.setRequestPubMessage(pubMsg);
			Gson gsonOut = new Gson();
			String jsonOut = gsonOut.toJson(outgoing);

			System.out.println("Outgoing JSON: " + jsonOut);
			return (jsonOut);
		}

		// String userInput = bufferRead.readLine();
		// return userInput;
		return null; // Sent as response to DHT
		// } catch (IOException e) {
		// throw new RuntimeException(e);
		// }
	}

	@OnClose
	public void onClose(Session session, CloseReason closeReason) {
		System.out.println("Session " + session.getId() + " closed because " + closeReason);
		latch.countDown();
	}

	// Print function

	/**
	 * Convert a CoAP response to a textual representation.
	 * 
	 * @param resp the response
	 * @return a textual representation
	 */
	public static String responseToText(CoapResponse resp) {
		StringBuilder sb = new StringBuilder();
		Response response = resp.advanced();

		sb.append("CoAP Response. ");
		sb.append(String.format("MID: %d. ", response.getMID()));
		sb.append(String.format("Token: %s. ", response.getTokenString()));
		sb.append(String.format("Type: %s. ", response.getType()));
		ResponseCode code = response.getCode();
		sb.append(String.format("Status: %s - %s. ", code, code.name()));
		Long rtt = response.getApplicationRttNanos();
		if (response.getOffloadMode() != null) {
			if (rtt != null) {
				sb.append(String.format("RTT: %d ms", TimeUnit.NANOSECONDS.toMillis(rtt)));
			}
			sb.append("(offloaded). ");
		} else {
			sb.append(String.format("Options: %s: ", response.getOptions()));
			if (rtt != null) {
				sb.append(String.format("RTT: %d ms. ", TimeUnit.NANOSECONDS.toMillis(rtt)));
			}
			sb.append(String.format("Payload: %d Bytes. ", response.getPayloadSize()));
			if (response.getPayloadSize() > 0
					&& MediaTypeRegistry.isPrintable(response.getOptions().getContentFormat())) {
				sb.append("Payload: " + response.getPayloadString());
			}
		}

		return sb.toString();
	}

}
