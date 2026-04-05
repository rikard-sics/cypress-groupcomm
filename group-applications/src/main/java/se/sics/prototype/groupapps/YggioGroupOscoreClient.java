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
package se.sics.prototype.groupapps;

import java.io.File;
import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.InstallCryptoProviders;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.Utility;
import org.eclipse.californium.oscore.group.GroupCtx;
import org.eclipse.paho.mqttv5.client.MqttClient;
import org.eclipse.paho.mqttv5.client.MqttConnectionOptions;
import org.eclipse.paho.mqttv5.common.MqttException;
import org.eclipse.paho.mqttv5.common.MqttMessage;


/**
 * Group OSCORE client application. Publishes responses from the servers to
 * Yggio using MQTT.
 * 
 * Topics:
 * 
 * yggio/generic/v2/rise-dev-server1/unique/topic/100
 * yggio/generic/v2/rise-dev-server2/unique/topic/100
 * yggio/generic/v2/rise-dev-server3/unique/topic/100
 * yggio/generic/v2/rise-dev-server4/unique/topic/100
 * yggio/generic/v2/rise-dev-server5/unique/topic/100
 * yggio/generic/v2/rise-dev-server6/unique/topic/100
 * 
 */
public class YggioGroupOscoreClient {

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
	static final String requestResource = "/temp";

	/**
	 * Payload in request sent (POST)
	 */
	// static final String requestPayload = "on";

	/**
	 * Indicate if the basic UI for the client should be enabled
	 */
	// static final boolean ui = true;

	/**
	 * OSCORE Security Context database (sender)
	 */
	private final static HashMapCtxDB db = new HashMapCtxDB();

	/**
	 * URI to perform request against.
	 */
	static String requestURI;

	private static CoapClient client;

	/**
	 * Initialize and start Group OSCORE client.
	 * 
	 * @param derivedCtx the Group OSCORE context
	 * @param multicastIP multicast IP to send to
	 * @param setClientName name of this client (Client1 / Client2)
	 * 
	 * @throws Exception on failure
	 */
	public static void start(GroupCtx derivedCtx, InetAddress multicastIP, String setClientName) throws Exception {

		// Create and connect MQTT client
		MqttClient mqttClient = createAndConnectClient(setClientName);

		/**
		 * URI to perform request against. Need to check for IPv6 to surround it
		 * with []
		 */
		if (multicastIP instanceof Inet6Address) {
			requestURI = "coap://" + "[" + multicastIP.getHostAddress() + "]" + ":" + destinationPort + requestResource;
		} else {
			requestURI = "coap://" + multicastIP.getHostAddress() + ":" + destinationPort + requestResource;
		}

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
		System.out.println("*Yggio Multicast sender");
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

		// Continously send requests every 2 minutes
		while (true) {
			Thread.sleep(2 * 60 * 1000);

			ArrayList<CoapResponse> responses = sendRequest();
			// Handle responses (publish to Yggio using MQTT)
			for (int i = 0; i < responses.size(); i++) {

				CoapResponse theResponse = responses.get(i);
				if (theResponse == null) {
					continue;
				}
				String payload = theResponse.getResponseText();
				if (payload == null || payload.isEmpty()) {
					continue;
				}

				// Extract server name, publish using MQTT to Yggio staging
				String serverName = extractJsonString(payload, "serverName");
				if (serverName == null) {
					System.out.println("Could not find serverName in payload: " + payload);
					continue;
				}
				serverName = serverName.toLowerCase();

				// Use topic based on the server name
				String mqttTopic = "yggio/generic/v2/rise-dev-" + serverName + "/unique/topic/100";

				// Actually publish it
				Thread.sleep(100);
				if (!mqttClient.isConnected()) {
					System.err.println(
							"[MQTT] Publish FAILED (not connected) -> server=" + serverName + " topic=" + mqttTopic);
				} else {
					try {
						MqttMessage msg = new MqttMessage(payload.getBytes(StandardCharsets.UTF_8));
						msg.setQos(0);
						mqttClient.publish(mqttTopic, msg);

						System.out.println("[MQTT] Published for -> server=" + serverName + " topic=" + mqttTopic
								+ " payload=" + payload);
					} catch (MqttException e) {
						System.err.println("[MQTT] Publish FAILED for -> server=" + serverName + " topic=" + mqttTopic);
						e.printStackTrace();
					}
				}
			}
		}

	}

	/**
	 * 
	 * /** Method for building and sending Group OSCORE requests.
	 * 
	 * @param client to use for sending
	 * @return list with responses from servers
	 */
	private static ArrayList<CoapResponse> sendRequest() {

		System.out.println("In sendRequest()");

		Request multicastRequest = Request.newGet();
		multicastRequest.setType(Type.NON);
		if (useOSCORE) {
			multicastRequest.getOptions().setOscore(Bytes.EMPTY);
			client.setURI(requestURI);
		}

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

	/**
	 * Extract a JSON string from JSON data
	 * 
	 * @param json the JSON data
	 * @param key the key for the string
	 * @return the extracted string
	 */
	private static String extractJsonString(String json, String key) {
		String search = "\"" + key + "\":\"";
		int start = json.indexOf(search);
		if (start < 0) {
			return null;
		}

		start += search.length();
		int end = json.indexOf("\"", start);
		if (end < 0) {
			return null;
		}

		return json.substring(start, end);
	}

	/**
	 * Create MQTT client and connect to Yggio staging
	 * 
	 * @param clientName the name of the client
	 * @return a connected MQTT client
	 * @throws MqttException on failure
	 */
	private static MqttClient createAndConnectClient(String clientName) throws MqttException, IOException {
		String broker = "tcp://mqtt.staging.yggio.net:1883";
		String clientId = "coap-bridge-" + clientName.toLowerCase();

		MqttClient client = new MqttClient(broker, clientId);

		MqttConnectionOptions options = new MqttConnectionOptions();
		options.setUserName("cypress-rise-basic");
		String password = readPassword("pw.txt");
		options.setPassword(password.getBytes(StandardCharsets.UTF_8));

		options.setAutomaticReconnect(true); // auto reconnect
		options.setCleanStart(true);

		client.connect(options);

		// Wait until actually connected (usually immediate, but safe)
		int retries = 0;
		while (!client.isConnected()) {
			try {
				Thread.sleep(100);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				throw new MqttException(e);
			}

			retries++;
			if (retries > 100) { // 10 seconds
				throw new MqttException(new Throwable("MQTT connection timeout"));
			}
		}

		System.out.println("MQTT connected with clientId: " + clientId);

		return client;
	}

	/**
	 * Read the MQTT password from a file
	 * 
	 * @param pathStr path to the file
	 * @return the password
	 * @throws IOException on failure
	 */
	private static String readPassword(String pathStr) throws IOException {
		Path path = Paths.get(pathStr);

		// Check if file exists
		if (!Files.exists(path)) {
			System.err.println("========================================");
			System.err.println(" ERROR: Password file not found!");
			System.err.println(" Expected file: " + path.toAbsolutePath());
			System.err.println(" Working dir : " + System.getProperty("user.dir"));
			System.err.println("========================================");
			throw new IOException("Missing password file: " + pathStr);
		}

		byte[] bytes = Files.readAllBytes(path);
		return new String(bytes, StandardCharsets.UTF_8).trim();
	}

}
