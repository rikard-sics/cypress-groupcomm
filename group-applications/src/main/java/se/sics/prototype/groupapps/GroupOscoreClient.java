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
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Scanner;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
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
import org.eclipse.californium.oscore.group.OptionEncoder;

import jakarta.websocket.ClientEndpoint;

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

		Scanner scanner = new Scanner(System.in);
		String command = "";

		while (!command.equals("q")) {

			System.out.println("Enter command: ");
			command = scanner.nextLine();

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

		System.out.println("In sendRequest()");

		// For sending a pairwise request
		boolean pairwise = false;
		byte[] targetRid = null;
		String unicastURI = "";

		// Shorthand form
		if (payload.startsWith("pairwise ")) {
			String[] parts = payload.split("\\s+", 3);

			if (parts.length >= 2) {
				String hexByte = parts[1];

				String rest = (parts.length == 3) ? parts[2].trim() : "";

				payload = "p " + hexByte + " coap://224.0.1.192:4683/toggle " + rest;
			}
		}

		// payload = "p 01 coap://224.0.1.192:4683/toggle on";
		if (payload.startsWith("p ")) {
			pairwise = true;

			// Split into 4 parts max: p, hex byte, URI, rest of payload
			String[] parts = payload.split("\\s+", 4);

			if (parts.length >= 2) {
				// Parse the one-byte hex value
				targetRid = new byte[] { (byte) Integer.parseInt(parts[1], 16) };
			}

			if (parts.length >= 3) {
				// Extract the URI
				unicastURI = parts[2].trim();
			}

			if (parts.length == 4) {
				payload = parts[3].trim();
			} else {
				payload = "";
			}
		}

		Request multicastRequest = Request.newPost();
		multicastRequest.setPayload(payload);
		multicastRequest.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
		multicastRequest.setType(Type.NON);
		if (useOSCORE) {
			if (pairwise == false) {
				multicastRequest.getOptions().setOscore(Bytes.EMPTY);
				client.setURI(requestURI);
			} else {
				multicastRequest.getOptions().setOscore(OptionEncoder.set(true, unicastURI, targetRid));
				client.setURI("coap://192.168.0.44:4683/toggle");
			}
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

}
