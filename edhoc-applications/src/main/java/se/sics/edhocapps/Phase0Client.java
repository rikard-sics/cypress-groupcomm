/*******************************************************************************
 * Copyright (c) 2023 RISE and others.
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

import com.google.gson.Gson;

import jakarta.websocket.ClientEndpoint;
import jakarta.websocket.CloseReason;
import jakarta.websocket.DeploymentException;
import jakarta.websocket.OnClose;
import jakarta.websocket.OnMessage;
import jakarta.websocket.OnOpen;
import jakarta.websocket.Session;
import se.sics.edhocapps.json.incoming.JsonIn;
import se.sics.edhocapps.json.outgoing.JsonOut;
import se.sics.edhocapps.json.outgoing.OutValue;
import se.sics.edhocapps.json.outgoing.RequestPubMessage;

/**
 * 
 * CoAP-only Client
 *
 */
@ClientEndpoint
public class Phase0Client {

	private static final int COAP_PORT = Configuration.getStandard().get(CoapConfig.COAP_PORT) + 10;

	private static CountDownLatch latch;
	static int HANDLER_TIMEOUT = 1000;
	static boolean useDht = false;
	static CoapClient c;

	// Default URI for DHT WebSocket connection. Can be changed using command
	// line arguments.
	private static String dhtWebsocketUri = "ws://localhost:3000/ws";

	// Set accordingly
	private static String serverUri = "coap://localhost" + ":" + COAP_PORT;
	private final static String hello1 = "/light";
	private static String lightURI = serverUri + hello1;

	/**
	 * Initiates and starts a simple CoAP-only client
	 * 
	 * @param args command line arguments
	 */
	public static void main(String[] args) {

		System.out.println("Starting Phase0Client...");

		// Parse command line arguments
		for (int i = 0; i < args.length; i++) {
			if (args[i].equals("-server")) {
				serverUri = args[i + 1];

				// Set URI for light resource
				lightURI = serverUri + hello1;
				i++;

			} else if (args[i].toLowerCase().endsWith("-dht") || args[i].toLowerCase().endsWith("-usedht")) {
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
		// Topic to listen for messages on
		String topic = "command_co";

		// Do nothing if message does not contain the topic
		if (message.contains(topic) == false) {
			return null;
		}

		System.out.println("--- Received " + message);

		// Parse incoming JSON string from DHT
		Gson gson = new Gson();
		JsonIn parsed = gson.fromJson(message, JsonIn.class);

		String topicField = parsed.getVolatile().getValue().getTopic();
		String messageField = parsed.getVolatile().getValue().getMessage();

		// Device 1 filter
		if (topicField.equals(topic)) {
			System.out.println("Filter matched message (CoAP client)!");

			// Send group request and compile responses
			ArrayList<CoapResponse> responsesList = sendRequest(messageField);
			String responsesString = "";
			String toDhtString = "";
			for (int i = 0; i < responsesList.size(); i++) {
				responsesString += Utils.prettyPrint(responsesList.get(i)) + "\n|\n";
				toDhtString += "Response #" + (i + 1) + ": [" + Support.responseToText(responsesList.get(i)) + "] ";
			}
			responsesString = responsesString.replace(".", "").replace(":", " ").replace("=", "-").replace("[", "")
					.replace("]", "").replace("/", "-").replace("\"", "").replace(".", "").replace("{", "")
					.replace("}", "");
			System.out.println("Compiled responses: " + responsesString);

			// Build outgoing JSON to DHT
			JsonOut outgoing = new JsonOut();
			RequestPubMessage pubMsg = new RequestPubMessage();
			OutValue outVal = new OutValue();
			outVal.setTopic("output_co");
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

}
