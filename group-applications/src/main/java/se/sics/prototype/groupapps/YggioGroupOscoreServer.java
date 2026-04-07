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
import java.net.SocketException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Enumeration;
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

import com.google.gson.JsonObject;

import se.sics.prototype.support.KeyStorage;

/**
 * Group OSCORE server application.
 */
public class YggioGroupOscoreServer {

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
	 * OSCORE Security Context database (receiver)
	 */
	private final static HashMapCtxDB db = new HashMapCtxDB();

	private final static String uriLocal = "coap://localhost";

	private static int replayWindow = 32;

	private static Random rand;

	/**
	 * Initialize and start Group OSCORE server.
	 * 
	 * @param derivedCtx the Group OSCORE context
	 * @param multicastIP multicast IP to send to
	 * @param serverName the name of this server (e.g. Server1)
	 * @param networkInterface the network interface for multicast listening
	 * 
	 * @throws Exception on failure
	 */
	public static void start(GroupCtx derivedCtx, InetAddress multicastIP, String serverName, String networkInterface)
			throws Exception {
		// Install cryptographic providers
		InstallCryptoProviders.installProvider();

		rand = new Random();

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

			// Add the completed context to the context database
			db.addContext(uriLocal, ctx);

			OSCoreCoapStackFactory.useAsDefault(db);

		}

		Configuration config = Configuration.getStandard();
		CoapServer server = new CoapServer(config);
		createEndpoints(server, respondPort, listenPort, config, multicastIP, networkInterface);
		Endpoint serverEndpoint = server.getEndpoint(listenPort);

		server.add(new TemperatureResource(serverName));

		// Information about the receiver
		System.out.println("==================");
		System.out.println("*Yggio Multicast receiver");
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
	private static class TemperatureResource extends CoapResource {

		private String serverName = "";
		private int count = 0;

		private TemperatureResource(String serverName) {
			// set resource identifier
			super("temp"); // Changed

			// set display name
			getAttributes().setTitle("Temperature Resource");

			this.serverName = serverName;
		}

		@Override
		public void handleGET(CoapExchange exchange) {

			count++;
			System.out.println("Receiving request #" + count);

			System.out.println("Receiving to: " + exchange.advanced().getEndpoint().getAddress());
			System.out.println("Receiving from: " + exchange.getSourceAddress() + ":" + exchange.getSourcePort());

			System.out.println(Utils.prettyPrint(exchange.advanced().getRequest()));

			boolean isConfirmable = exchange.advanced().getRequest().isConfirmable();

			// Respond to the request if confirmable or replies are set to be
			// sent for non-confirmable requests
			if (isConfirmable || replyToNonConfirmable) {
				Response r = Response.createResponse(exchange.advanced().getRequest(), ResponseCode.CONTENT);

				// Prepare response including server ID, msg count and
				// temperature
				double offset = Math.abs(serverName.hashCode() % 200) / 10.0;
				double temperatureC = simulateTemperatureCelsius(offset);
				if (serverName.equalsIgnoreCase("Server2")) {
					temperatureC -= 10.3;
				}
				if (serverName.equalsIgnoreCase("Server3")) {
					temperatureC -= 5.6;
				}

				JsonObject json = new JsonObject();
				json.addProperty("msgCount", count);
				json.addProperty("serverName", serverName);
				json.addProperty("temperature", temperatureC);

				r.setPayload(json.toString());
				r.getOptions().setContentFormat(MediaTypeRegistry.APPLICATION_JSON);

				if (isConfirmable) {
					r.setType(Type.ACK);
				} else {
					r.setType(Type.NON);
				}

				System.out.println();
				System.out.println("Sending to: " + r.getDestinationContext().getPeerAddress());
				System.out.println("Sending from: " + exchange.advanced().getEndpoint().getAddress());
				System.out.println(Utils.prettyPrint(r));

				int leisureTime = rand.nextInt(75);
				try {
					Thread.sleep(leisureTime);
				} catch (InterruptedException e) {
					System.err.println("Failed to sleep for leisure time");
					e.printStackTrace();
				}

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
	 * @param usedInterface
	 */
	private static void createEndpoints(CoapServer server, int unicastPort, int multicastPort, Configuration config,
			InetAddress multicastIP, String usedInterface) {
		// UDPConnector udpConnector = new UDPConnector(new
		// InetSocketAddress(unicastPort));
		// udpConnector.setReuseAddress(true);
		// CoapEndpoint coapEndpoint = new
		// CoapEndpoint.Builder().setConfiguration(config).setConnector(udpConnector).build();

		NetworkInterface networkInterface = null;
		if (usedInterface == null) {
			networkInterface = NetworkInterfacesUtil.getMulticastInterface();
		} else {
			try {
				networkInterface = NetworkInterface.getByName(usedInterface);
			} catch (SocketException e) {
				System.err.println("Failed to find network interface with name " + usedInterface);
				e.printStackTrace();
			}
		}

		if (networkInterface == null) {
			System.out.println("No multicast network-interface found!");
			throw new Error("No multicast network-interface found!");
		}
		System.out.println("Multicast Network Interface: " + networkInterface.getDisplayName());

		UdpMulticastConnector.Builder builder = new UdpMulticastConnector.Builder();

		if (!ipv4 && NetworkInterfacesUtil.isAnyIpv6()) {
			Inet6Address ipv6 = null;
			Enumeration<InetAddress> addresses = networkInterface.getInetAddresses();
			while (addresses.hasMoreElements()) {
				InetAddress addr = addresses.nextElement();
				if (addr instanceof Inet6Address && !addr.isLoopbackAddress()) {
					ipv6 = (Inet6Address) addr;
					break;
				}
			}
			if (ipv6 == null) {
				throw new RuntimeException("No IPv6 address found for interface " + networkInterface.getName());
			}

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
			Inet4Address ipv4 = null;
			Enumeration<InetAddress> addresses = networkInterface.getInetAddresses();
			while (addresses.hasMoreElements()) {
				InetAddress addr = addresses.nextElement();
				if (addr instanceof Inet4Address && !addr.isLoopbackAddress()) {
					ipv4 = (Inet4Address) addr;
					break;
				}
			}
			if (ipv4 == null) {
				throw new RuntimeException("No IPv4 address found for interface " + networkInterface.getName());
			}

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

	private static double simulateTemperatureCelsius(double offset) {
		LocalDateTime now = LocalDateTime.now(ZoneId.systemDefault());
		return simulateTemperatureCelsius(now, offset);
	}

	/**
	 * Simulate a temperature
	 * 
	 * @param now current time
	 * @param offset an offset for the temp
	 * @return the current simulated temp
	 */
	private static double simulateTemperatureCelsius(LocalDateTime now, double offset) {
		double hourOfDay = now.getHour() + now.getMinute() / 60.0 + now.getSecond() / 3600.0;

		double dayPosition = (now.getDayOfWeek().getValue() - 1) + hourOfDay / 24.0;

		double baseTempC = 20.0;

		double dailyVariationC = 3.5 * Math.sin(2.0 * Math.PI * (hourOfDay - 9.0 + offset) / 24.0);

		double weeklyVariationC = 1.5 * Math.sin(2.0 * Math.PI * (dayPosition + offset) / 7.0);

		double serverBiasC = offset * 0.5;

		double temperatureC = baseTempC + dailyVariationC + weeklyVariationC + serverBiasC;

		return Math.round(temperatureC * 10.0) / 10.0;
	}
}
