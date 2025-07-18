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

import java.io.IOException;
import java.net.BindException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.util.Random;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.UdpMulticastConnector;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.InstallCryptoProviders;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.Utility;
import org.eclipse.californium.oscore.group.GroupCtx;
import org.eclipse.californium.oscore.group.MultiKey;

import se.sics.prototype.support.KeyStorage;

/**
 * Group OSCORE server application.
 */
public class GroupOscoreServer {

	/**
	 * Controls whether or not the receiver will reply to incoming multicast
	 * non-confirmable requests.
	 * 
	 * The receiver will always reply to confirmable requests (can be used with
	 * unicast).
	 * 
	 */
	static final boolean replyToNonConfirmable = true;

	/**
	 * Whether to use OSCORE or not.
	 */
	static final boolean useOSCORE = true;

	/**
	 * Give the receiver a random unicast IP (from the loopback 127.0.0.0/8
	 * range) FIXME: Communication does not work with this turned on
	 */
	static final boolean randomUnicastIP = false;

	/**
	 * Multicast address to listen to (set elsewhere)
	 */
	// static final InetAddress multicastIP = new
	// InetSocketAddress("FF01:0:0:0:0:0:0:FD", 0).getAddress();
	// static InetAddress multicastIP = null;

	// Use IPv4
	private static boolean ipv4 = true;
	private static final boolean LOOPBACK = false;

	/**
	 * Port to listen to (multicast port).
	 */
	static final int listenPort = CoAP.DEFAULT_COAP_PORT - 1000;

	/**
	 * Port to respond from (unicast port).
	 */
	static final int respondPort = CoAP.DEFAULT_COAP_PORT - 1000;

	/**
	 * ED25519 curve value.
	 * https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
	 */
	static final int ED25519 = KeyKeys.OKP_Ed25519.AsInt32(); // Integer value 6

	/**
	 * OSCORE Security Context database (receiver)
	 */
	private final static HashMapCtxDB db = new HashMapCtxDB();

	private final static String uriLocal = "coap://localhost";

	private static Random random;

	static int replayWindow = 32;

	// Python executable
	static String pythonCmd = "python3";

	/**
	 * Initialize and start Group OSCORE server.
	 * 
	 * @param derivedCtx the Group OSCORE context
	 * @param multicastIP multicast IP to send to
	 * 
	 * @throws Exception on failure
	 */
	public static void start(GroupCtx derivedCtx, InetAddress multicastIP) throws Exception {
		// Install cryptographic providers
		InstallCryptoProviders.installProvider();

		// If OSCORE is being used set the context information
		GroupCtx ctx = null;
		if (useOSCORE) {
			ctx = derivedCtx;

			// Add credentials for the 2 clients
			byte[] sidClient1 = KeyStorage.clientIds.get("Client1").getBytes();
			MultiKey keyClient1 = new MultiKey(KeyStorage.memberCcs.get("Client1"));
			ctx.addRecipientCtxCcs(sidClient1, replayWindow, keyClient1);

			byte[] sidClient2 = KeyStorage.clientIds.get("Client2").getBytes();
			MultiKey keyClient2 = new MultiKey(KeyStorage.memberCcs.get("Client2"));
			ctx.addRecipientCtxCcs(sidClient2, replayWindow, keyClient2);

			if (ctx.getSenderCtx().getContextIdString().toLowerCase().contains("bbbb")) {
				ctx.setPairwiseModeResponses(true);
			}

			// Add the completed context to the context database
			db.addContext(uriLocal, ctx);

			OSCoreCoapStackFactory.useAsDefault(db);

		}

		// Initialize random number generator
		random = new Random();

		Configuration config = Configuration.getStandard();
		CoapServer server = new CoapServer(config);
		createEndpoints(server, respondPort, listenPort, config, multicastIP);
		Endpoint serverEndpoint = server.getEndpoint(listenPort);
		// server.addEndpoint(endpoint);
		server.add(new HelloWorldResource());
		server.add(new ToggleResource());

		// Information about the receiver
		System.out.println("==================");
		System.out.println("*Multicast receiver");
		System.out.println("Uses OSCORE: " + useOSCORE);
		System.out.println("Respond to non-confirmable messages: " + replyToNonConfirmable);
		System.out.println("Listening to Multicast IP: " + multicastIP.getHostAddress());
		System.out.println("Unicast IP: " + serverEndpoint.getAddress().getHostString());
		System.out.println("Incoming port: " + serverEndpoint.getAddress().getPort());
		System.out.print("CoAP resources: ");
		for (Resource res : server.getRoot().getChildren()) {
			System.out.print(res.getURI() + " ");
		}
		System.out.println("");
		System.out.println("=");

		System.out.print("*");
		Utility.printContextInfo(ctx);
		System.out.println("==================");

		System.out.println("");
		System.out.println("Waiting for requests in the OSCORE group.");

		server.start();
	}

	/**
	 * Methods below from MulticastTestServer to set up multicast listening.
	 */

	// Resource
	private static class ToggleResource extends CoapResource {

		private int id;
		private int count = 0;
		private boolean stateOn = false;

		private ToggleResource() {
			// set resource identifier
			super("toggle"); // Changed

			// set display name
			getAttributes().setTitle("Toggle Resource");

			id = random.nextInt(1000);

			System.out.println("coap receiver: " + id);
		}

		// Added for handling GET
		@Override
		public void handleGET(CoapExchange exchange) {
			handlePOST(exchange);
		}

		@Override
		public void handlePOST(CoapExchange exchange) {

			System.out.println("Receiving request #" + count);
			count++;

			System.out.println("Receiving to: " + exchange.advanced().getEndpoint().getAddress());
			System.out.println("Receiving from: " + exchange.getSourceAddress() + ":" + exchange.getSourcePort());

			System.out.println(Utils.prettyPrint(exchange.advanced().getRequest()));

			if (exchange.getRequestText().toLowerCase().equals("off")
					|| exchange.getRequestText().toLowerCase().equals("open")
					|| exchange.getRequestText().toLowerCase().equals("unlock")
					|| exchange.getRequestText().toLowerCase().equals("0")) {
				System.out.println("*** Turning OFF LEDs/solenoids ***");
				stateOn = false;

				// Run script to turn off
				try {
					String command = pythonCmd + " LED-off.py";
					Runtime.getRuntime().exec(command);
				} catch (IOException e) {
					System.err.print("Failed to run python script: ");
					e.printStackTrace();
				}
			} else if (exchange.getRequestText().toLowerCase().equals("on")
					|| exchange.getRequestText().toLowerCase().equals("close")
					|| exchange.getRequestText().toLowerCase().equals("lock")
					|| exchange.getRequestText().toLowerCase().equals("1")) {
				System.out.println("*** Turning ON LEDs/solenoids ***");
				stateOn = true;

				// Run script to turn on
				try {
					String command = pythonCmd + " LED-on.py";
					Runtime.getRuntime().exec(command);
				} catch (IOException e) {
					System.err.print("Failed to run python script: ");
					e.printStackTrace();
				}
			} else { // Other payload prints status
				System.out.println("They are now turned on :" + stateOn);
			}

			boolean isConfirmable = exchange.advanced().getRequest().isConfirmable();

			// respond to the request if confirmable or replies are set to be
			// sent for non-confirmable payload is set to request payload
			// changed to uppercase plus the receiver ID
			if (isConfirmable || replyToNonConfirmable) {
				Response r = Response.createResponse(exchange.advanced().getRequest(), ResponseCode.CONTENT);
				r.setPayload(exchange.getRequestText().toUpperCase() + ". ID: " + id + ". Enabled: " + stateOn);
				r.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
				if (isConfirmable) {
					r.setType(Type.ACK);
				} else {
					r.setType(Type.NON);
				}

				System.out.println();
				System.out.println("Sending to: " + r.getDestinationContext().getPeerAddress());
				System.out.println("Sending from: " + exchange.advanced().getEndpoint().getAddress());
				System.out.println(Utils.prettyPrint(r));

				exchange.respond(r);
			}

		}

	}

	private static class HelloWorldResource extends CoapResource {

		private int id;
		private int count = 0;

		private HelloWorldResource() {
			// set resource identifier
			super("helloWorld"); // Changed

			// set display name
			getAttributes().setTitle("Hello-World Resource");

			id = random.nextInt(1000);

			System.out.println("coap receiver: " + id);
		}

		// Added for handling GET
		@Override
		public void handleGET(CoapExchange exchange) {
			handlePOST(exchange);
		}

		@Override
		public void handlePOST(CoapExchange exchange) {

			System.out.println("Receiving request #" + count);
			count++;

			System.out.println("Receiving to: " + exchange.advanced().getEndpoint().getAddress());
			System.out.println("Receiving from: " + exchange.getSourceAddress() + ":" + exchange.getSourcePort());

			System.out.println(Utils.prettyPrint(exchange.advanced().getRequest()));

			boolean isConfirmable = exchange.advanced().getRequest().isConfirmable();

			// respond to the request if confirmable or replies are set to be
			// sent for non-confirmable payload is set to request payload
			// changed to uppercase plus the receiver ID
			if (isConfirmable || replyToNonConfirmable) {
				Response r = Response.createResponse(exchange.advanced().getRequest(), ResponseCode.CONTENT);
				r.setPayload(exchange.getRequestText().toUpperCase() + ". ID: " + id);
				r.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
				if (isConfirmable) {
					r.setType(Type.ACK);
				} else {
					r.setType(Type.NON);
				}

				System.out.println();
				System.out.println("Sending to: " + r.getDestinationContext().getPeerAddress());
				System.out.println("Sending from: " + exchange.advanced().getEndpoint().getAddress());
				System.out.println(Utils.prettyPrint(r));

				exchange.respond(r);
			}

		}

	}

	/**
	 * Methods below from MulticastTestServer to set up multicast listening.
	 */

	/**
	 * From MulticastTestServer
	 * 
	 * @param server
	 * @param unicastPort
	 * @param multicastPort
	 * @param config
	 */
	private static void createEndpoints(CoapServer server, int unicastPort, int multicastPort, Configuration config,
			InetAddress multicastIP) {
		// UDPConnector udpConnector = new UDPConnector(new
		// InetSocketAddress(unicastPort));
		// udpConnector.setReuseAddress(true);
		// CoapEndpoint coapEndpoint = new
		// CoapEndpoint.Builder().setConfiguration(config).setConnector(udpConnector).build();

		NetworkInterface networkInterface = NetworkInterfacesUtil.getMulticastInterface();
		if (networkInterface == null) {
			System.out.println("No multicast network-interface found!");
			throw new Error("No multicast network-interface found!");
		}
		System.out.println("Multicast Network Interface: " + networkInterface.getDisplayName());

		UdpMulticastConnector.Builder builder = new UdpMulticastConnector.Builder();

		if (!ipv4 && NetworkInterfacesUtil.isAnyIpv6()) {
			Inet6Address ipv6 = NetworkInterfacesUtil.getMulticastInterfaceIpv6();
			System.out.println("Multicast: IPv6 Network Address: " + StringUtil.toString(ipv6));
			UDPConnector udpConnector = new UDPConnector(new InetSocketAddress(ipv6, unicastPort), config);
			udpConnector.setReuseAddress(true);
			CoapEndpoint coapEndpoint = new CoapEndpoint.Builder().setConfiguration(config).setConnector(udpConnector)
					.build();

			builder = new UdpMulticastConnector.Builder().setLocalAddress(multicastIP, multicastPort)
					.addMulticastGroup(multicastIP, networkInterface);
			createReceiver(builder, udpConnector);

			/*
			 * https://bugs.openjdk.java.net/browse/JDK-8210493 link-local
			 * multicast is broken
			 */
			builder = new UdpMulticastConnector.Builder().setLocalAddress(multicastIP, multicastPort)
					.addMulticastGroup(multicastIP, networkInterface);
			createReceiver(builder, udpConnector);

			server.addEndpoint(coapEndpoint);
			System.out.println("IPv6 - multicast");
		}

		if (ipv4 && NetworkInterfacesUtil.isAnyIpv4()) {
			Inet4Address ipv4 = NetworkInterfacesUtil.getMulticastInterfaceIpv4();
			System.out.println("Multicast: IPv4 Network Address: " + StringUtil.toString(ipv4));
			UDPConnector udpConnector = new UDPConnector(new InetSocketAddress(ipv4, unicastPort), config);
			udpConnector.setReuseAddress(true);
			CoapEndpoint coapEndpoint = new CoapEndpoint.Builder().setConfiguration(config).setConnector(udpConnector)
					.build();

			builder = new UdpMulticastConnector.Builder().setLocalAddress(multicastIP, multicastPort)
					.addMulticastGroup(multicastIP, networkInterface);
			createReceiver(builder, udpConnector);

			Inet4Address broadcast = NetworkInterfacesUtil.getBroadcastIpv4();
			if (broadcast != null) {
				// windows seems to fail to open a broadcast receiver
				builder = new UdpMulticastConnector.Builder().setLocalAddress(broadcast, multicastPort);
				createReceiver(builder, udpConnector);
			}
			server.addEndpoint(coapEndpoint);
			System.out.println("IPv4 - multicast");
		}
		UDPConnector udpConnector = new UDPConnector(
				new InetSocketAddress(InetAddress.getLoopbackAddress(), unicastPort), config);
		udpConnector.setReuseAddress(true);
		CoapEndpoint coapEndpoint = new CoapEndpoint.Builder().setConfiguration(config).setConnector(udpConnector)
				.build();
		server.addEndpoint(coapEndpoint);
		System.out.println("loopback");
	}

	/**
	 * From MulticastTestServer
	 * 
	 * @param builder
	 * @param connector
	 */
	private static void createReceiver(UdpMulticastConnector.Builder builder, UDPConnector connector) {
		UdpMulticastConnector multicastConnector = builder.setMulticastReceiver(true).build();
		multicastConnector.setLoopbackMode(LOOPBACK);
		try {
			multicastConnector.start();
		} catch (BindException ex) {
			// binding to multicast seems to fail on windows
			if (builder.getLocalAddress().getAddress().isMulticastAddress()) {
				int port = builder.getLocalAddress().getPort();
				builder.setLocalPort(port);
				multicastConnector = builder.build();
				multicastConnector.setLoopbackMode(LOOPBACK);
				try {
					multicastConnector.start();
				} catch (IOException e) {
					e.printStackTrace();
					multicastConnector = null;
				}
			} else {
				ex.printStackTrace();
				multicastConnector = null;
			}
		} catch (IOException e) {
			e.printStackTrace();
			multicastConnector = null;
		}
		if (multicastConnector != null && connector != null) {
			connector.addMulticastReceiver(multicastConnector);
		}
	}
}
