/*******************************************************************************
 * Copyright (c) 2025 RISE and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.

 * Contributors: 
 *    Tobias Andersson (RISE SICS)
 *    Marco Tiloca (RISE)
 *    Rikard Höglund (RISE)
 *    
 ******************************************************************************/
package se.sics.edhocapps;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Scanner;
import java.util.concurrent.CountDownLatch;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.elements.config.Configuration;
import org.glassfish.tyrus.client.ClientManager;

import jakarta.websocket.ClientEndpoint;
import jakarta.websocket.DeploymentException;

/**
 * 
 * CoAP-only Client
 *
 */
@ClientEndpoint
public class Phase0Client {

	private static CountDownLatch latch;
	static int HANDLER_TIMEOUT = 1000;
	static boolean useDht = false;
	static CoapClient c;

	// Default URI for DHT WebSocket connection. Can be changed using command
	// line arguments.
	private static String dhtWebsocketUri = "ws://localhost:3000/ws";

	// Set accordingly
	private static String serverUri;
	private final static String hello1 = "/light";
	private static String lightURI = serverUri + hello1;

	private static int COAP_PORT;

	static {
		CoapConfig.register();
	}


	/**
	 * Initiates and starts a simple CoAP-only client
	 * 
	 * @param args command line arguments
	 */
	public static void main(String[] args) {

		COAP_PORT = Configuration.getStandard().get(CoapConfig.COAP_PORT) + 10;
		serverUri = "coap://localhost" + ":" + COAP_PORT;

		System.out.println("Starting Phase0Client...");

		// Parse command line arguments
		for (int i = 0; i < args.length; i++) {
			if (args[i].equals("-server")) {
				serverUri = args[i + 1];

				// Set URI for light resource
				lightURI = serverUri + hello1;
				i++;

			} else if (args[i].toLowerCase().endsWith("-help")) {
				Support.printHelp();
				System.exit(0);
			}
		}

		// Wait for DHT to become available
		if (useDht) {
			Support.waitForDht(dhtWebsocketUri);
		}

		// Wait for Server to become available
		Support.waitForServer(lightURI);

		c = new CoapClient(lightURI);

		// Connect to DHT and continously retry if connection is lost
		while (useDht) {
			System.out.println("Using DHT");

			latch = new CountDownLatch(1);
			ClientManager dhtClient = ClientManager.createClient();
			try {
				// wss://socketsbay.com/wss/v2/2/demo/
				URI uri = new URI(dhtWebsocketUri);
				try {
					dhtClient.connectToServer(Phase0Client.class, uri);
				} catch (IOException e) {
					System.err.println("Failed to connect to DHT using WebSockets");
					e.printStackTrace();
				}
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

			Support.waitForDht(dhtWebsocketUri);
		}

		// Command line interface
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

		c.shutdown();
	}

	/**
	 * Method for building and sending CoAP requests.
	 * 
	 * @param client to use for sending
	 * @param payload of the CoAP request
	 * @return list with responses from servers
	 */
	private static ArrayList<CoapResponse> sendRequest(String payload) {
		Request r = new Request(Code.POST);
		r.setPayload(payload);
		r.setURI(lightURI);

		System.out.println("In sendrequest");

		handler.clearResponses();
		try {
			String host = new URI(c.getURI()).getHost();
			int port = new URI(c.getURI()).getPort();
			System.out.println("Sending to: " + host + ":" + port);
		} catch (URISyntaxException e) {
			System.err.println("Failed to parse destination URI");
			e.printStackTrace();
		}
		// System.out.println("Sending from: " +
		// client.getEndpoint().getAddress());
		System.out.println(Utils.prettyPrint(r));

		// sends a multicast request
		c.advanced(handler, r);
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
