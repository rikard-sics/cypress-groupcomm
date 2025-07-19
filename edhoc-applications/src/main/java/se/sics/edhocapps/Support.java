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
 *
 * Contributors: 
 *    Marco Tiloca (RISE)
 *    Rikard Höglund (RISE)
 *    
 ******************************************************************************/
package se.sics.edhocapps;

import java.io.IOException;
import java.net.Socket;
import java.net.URI;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;

/**
 * Supporting methods for the EDHOC applications.
 *
 */
public class Support {

	/**
	 * Simple method for "press enter to continue" functionality
	 */
	static void printPause(String message) {

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

	static void printIfNotNull(String str) {
		if (str != null) {
			System.out.println(str);
		}
	}

	/**
	 * Print help for EDHOC clients
	 */
	public static void printHelp() {
		System.out.println("Usage: [ -server URI ] [ -dht {URI} ] [ -help ]");

		System.out.println("Options:");

		System.out.print("-server");
		System.out.println("\t EDHOC Server base URI");

		System.out.print("-dht");
		System.out.println("\t Use DHT: Optionally specify its WebSocket URI");

		System.out.print("-help");
		System.out.println("\t Print help");
	}

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

	/**
	 * Wait for a connection to the DHT before proceeding
	 *
	 * @param dhtWebsocketUri the URI of the WebSocket interface for the DHT
	 * @return true when the connection succeeds
	 */
	public static boolean waitForDht(String dhtWebsocketUri) {
		int waitTime = 0;
		int maxWait = 10 * 1000;

		Socket soc = null;
		URI dhtUri = URI.create(dhtWebsocketUri);

		int count = 0;
		while (soc == null) {
			try {
				System.out.print("Attempting to reach DHT at: " + dhtWebsocketUri + " ...");
				if (count % 2 == 0) {
					System.out.print(".");
				}
				System.out.println("");

				count++;
				Thread.sleep(waitTime);
				if (waitTime < maxWait) {
					waitTime += 1000;
				}

				soc = new Socket(dhtUri.getHost(), dhtUri.getPort());
			} catch (Exception e) {
				// DHT is unavailable currently
			}
		}

		try {
			soc.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		System.out.println("DHT is available.");
		return true;
	}

	/**
	 * Wait for EDHOC Server to become available
	 * 
	 * @param edhocUri the URI of the EDHOC Server
	 * @return true when the EDHOC Server is available
	 * 
	 */
	public static boolean waitForEdhocServer(String edhocUri) {
		int waitTime = 0;
		int maxWait = 10 * 1000;

		boolean serverAvailable = false;
		int count = 0;
		do {
			System.out.print("Attempting to reach EDHOC Server at: " + edhocUri + " ...");
			if (count % 2 == 0) {
				System.out.print(".");
			}
			System.out.println("");

			try {
				count++;
				Thread.sleep(waitTime);
				if (waitTime < maxWait) {
					waitTime += 1000;
				}

				CoapClient checker = new CoapClient(edhocUri);
				serverAvailable = checker.ping();
			} catch (InterruptedException e) {
				System.err.println("Failed to sleep when waiting for EDHOC Server.");
				e.printStackTrace();
			} catch (IllegalArgumentException e) {
				System.err.println("EDHOC Server hostname not available. Retrying...");
			}
		} while (!serverAvailable);

		System.out.println("EDHOC Server is available.");
		return serverAvailable;
	}

	/**
	 * Wait for Server to become available
	 * 
	 * @param serverUri the URI of the Server
	 * @return true when the Server is available
	 * 
	 */
	public static boolean waitForServer(String serverUri) {
		int waitTime = 0;
		int maxWait = 10 * 1000;

		boolean serverAvailable = false;
		int count = 0;
		do {
			System.out.print("Attempting to reach Server at: " + serverUri + " ...");
			if (count % 2 == 0) {
				System.out.print(".");
			}
			System.out.println("");

			try {
				count++;
				Thread.sleep(waitTime);
				if (waitTime < maxWait) {
					waitTime += 1000;
				}

				CoapClient checker = new CoapClient(serverUri);
				serverAvailable = checker.ping();
			} catch (InterruptedException e) {
				System.err.println("Failed to sleep when waiting for Server.");
				e.printStackTrace();
			} catch (IllegalArgumentException e) {
				System.err.println("Server hostname not available. Retrying...");
			}
		} while (!serverAvailable);

		System.out.println("Server is available.");
		return serverAvailable;
	}

}
