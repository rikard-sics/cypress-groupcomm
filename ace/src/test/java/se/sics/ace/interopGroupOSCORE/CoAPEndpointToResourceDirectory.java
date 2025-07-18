/*******************************************************************************
 * Copyright (c) 2020 RISE and others.
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
 * This class is based on org.eclipse.californium.examples.GETClient
 * 
 * Contributors: 
 *    Marco Tiloca (RISE)
 ******************************************************************************/
package se.sics.ace.interopGroupOSCORE;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.elements.exception.ConnectorException;

import se.sics.ace.Constants;

import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;

public class CoAPEndpointToResourceDirectory {
	
	private static boolean debug = true;
	
	private static final File CONFIG_FILE = new File("Californium.properties");
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Fileclient";
	private static final int DEFAULT_MAX_RESOURCE_SIZE = 2 * 1024 * 1024; // 2
																			// MB
	private static final int DEFAULT_BLOCK_SIZE = 512;
		
	private static DefinitionsProvider DEFAULTS = new DefinitionsProvider() {

		@Override
		public void applyDefinitions(Configuration config) {
			config.set(CoapConfig.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_SIZE);
			config.set(CoapConfig.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE);
			config.set(CoapConfig.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);

		}
	};

	private static final String resourceDirectoryURI = "coap://rd.coap.amsuess.com";
	
	private static final String endpointName = "gm1";
	private static final String securityGroupName = "feedca570000";
	private static final String applicationGroupName = "group1";
	private static final String multicastAddress = "[ff35:30:2001:db8:f1::8000:1]";
	private static final String gmAddress = "[2a01:4f8:190:3064::5]";
	private static final String gmPort = "58292";
	
	private static final String securityGroupRegistrationRequest = "" +
			/* Beginning of Link-Format payload */
	        "</ace-group/feedca570000>;ct=19;rt=\"core.osc.gm\";if=\"ace.group\";" + 
				"sec-gp=\"" + securityGroupName + "\";app-gp=\"" + applicationGroupName + "\";" + 
				"cs_alg=\"-8\";cs_alg_crv=\"6\";" + 
				"cs_kenc=\"1\";ecdh_alg=\"-27\";" + 
				"ecdh_alg_crv=\"4\"," +
			"<coap://as.example.com/token>;rel=\"authorization-server\";" +
				"anchor=\"coap://" + gmAddress + ":" + gmPort + "/ace-group/" + securityGroupName + "\"" +
			/* End of Link-Format payload */
			"";

	private static final String applicationGroupRegistrationRequest = "" + 
			/* Beginning of Link-Format payload */
			"</light>;rt=\"tag:example.com,2020:light\";if=\"tag:example.net,2020:actuator\"" +
			/* End of Link-Format payload */
			"";
	
	/*
	 * Application entry point.
	 * 
	 */
	public static void main(String args[]) {
		String path = "";
		String query = "";
		byte[] requestPayload = null;
		
		Configuration config = Configuration.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		Configuration.setStandard(config);
    	
		URI uri = null; // URI parameter of the request

		
		// Interact with the test server at coap://coap.me
		/*
		String defaultUri = "coap://coap.me";
		// input URI from command line arguments
		try {
			if (args.length == 0) {
				uri = new URI(defaultUri);
			} else {
				uri = new URI(args[0]);
			}
		} catch (URISyntaxException e) {
			System.err.println("Invalid URI: " + e.getMessage());
			System.exit(-1);
		}
		testServerExchange(args, uri);
		*/
		
		
		// Interact with the Resource Directory
		
		// Test reachability
		
		System.out.println("\n\n=============\nGET request to well-known/core");
		path = "/.well-known/core";
		query = "";
		uri = buildURI(resourceDirectoryURI + path);
		getRequestToResourceDirectory(args, path, query);
		
		
		// Test RD resource discovery
		
		System.out.println("\n\n=============\nGET request to well-known/core?rt=core.rd*");
		path = "/.well-known/core";
		query = "?rt=core.rd*";
		uri = buildURI(resourceDirectoryURI + path + query);
		getRequestToResourceDirectory(args, path, query);

		
		// Register an application group
		
		System.out.println("\n\n=============\nRegister an application group");
		path = "/rd";
		query = "?ep=" + applicationGroupName + "&et=core.rd-group&base=coap://" + multicastAddress;
		uri = buildURI(resourceDirectoryURI + path + query);
		requestPayload = applicationGroupRegistrationRequest.getBytes(Constants.charset);
		if (debug) {
			System.out.println("\nURI: " + resourceDirectoryURI + path + query +
					           "\nPayload: " + new String(requestPayload, Constants.charset) + "\n");
		}
		postRequestToResourceDirectory(args, uri, requestPayload);
		

		// Register an endpoint and a security group
		
		System.out.println("\n\n=============\nRegister an endpoint and a security group");
		path = "/rd";
		query = "?ep=" + endpointName;
		uri = buildURI(resourceDirectoryURI + path + query);
		requestPayload = securityGroupRegistrationRequest.getBytes(Constants.charset);
		if (debug) {
			System.out.println("\nURI: " + resourceDirectoryURI + path + query +
			                   "\nPayload: " + new String(requestPayload, Constants.charset) + "\n");
		}
		postRequestToResourceDirectory(args, uri, requestPayload);
		
		
		// Retrieve the registration entry for the endpoint
		
		System.out.println("\n\n=============\nRetrieve the endpoint registration entry");
		path = "/endpoint-lookup/";
		query = "?ep=" + endpointName;
		uri = buildURI(resourceDirectoryURI + path + query);
		if (debug) {
			System.out.println("\nURI: " + resourceDirectoryURI + path + query + "\n");
		}
		getRequestToResourceDirectory(args, path, query);
		
		
		// Discover the security group(s)
		
		System.out.println("\n\n=============\nDiscover the security group(s)");
		path = "/resource-lookup/";
		query = "?rt=core.osc.gm&app-gp=" + applicationGroupName;
		uri = buildURI(resourceDirectoryURI + path + query);
		if (debug) {
			System.out.println("\nURI: " + resourceDirectoryURI + path + query + "\n");
		}
		getRequestToResourceDirectory(args, path, query);
		
		
		// Discover the associated ACE Authorization Server
		
		System.out.println("\n\n=============\nDiscover the associated ACE Authorization Server");
		path = "/resource-lookup/";
		query = "?rel=authorization-server&anchor=coap://" + gmAddress + ":" + gmPort + "/ace-group/" + securityGroupName;
		uri = buildURI(resourceDirectoryURI + path + query);
		if (debug) {
			System.out.println("\nURI: " + resourceDirectoryURI + path + query + "\n");
		}
		getRequestToResourceDirectory(args, path, query);
		
		
		// Discover the multicast address of the application group
		
		System.out.println("\n\n=============\nDiscover the multicast address of the application group");
		path = "/endpoint-lookup/";
		query = "?et=core.rd-group&ep=" + applicationGroupName;
		uri = buildURI(resourceDirectoryURI + path + query);
		if (debug) {
			System.out.println("\nURI: " + resourceDirectoryURI + path + query + "\n");
		}
		getRequestToResourceDirectory(args, path, query);
		

	}
	
	private static void testServerExchange(final String args[], final URI targetUri) {
		
		CoapClient client = new CoapClient(targetUri);

		CoapResponse response = null;
		try {
			System.out.println("\n\nSending request to: " + targetUri + "\n");
			response = client.get();
		} catch (ConnectorException | IOException e) {
			System.err.println("Got an error: " + e);
		}

		if (response != null) {

			System.out.println(response.getCode());
			System.out.println(response.getOptions());
			if (args.length > 1) {
				try (FileOutputStream out = new FileOutputStream(args[1])) {
					out.write(response.getPayload());
				} catch (IOException e) {
					System.err.println("Error while writing the response payload to file: " +  e.getMessage());
				}
			} else {
				System.out.println(response.getResponseText());

				System.out.println(System.lineSeparator() + "ADVANCED" + System.lineSeparator());
				// access advanced API with access to more details through
				// .advanced()
				System.out.println(Utils.prettyPrint(response));
			}
		} else {
			System.out.println("No response received.");
		}
		client.shutdown();
		
	}

	
	private static void getRequestToResourceDirectory(final String args[], final String path, final String query) {

	       CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
	       Endpoint clientEndpoint = builder.build();
	       CoapClient client = new CoapClient(resourceDirectoryURI);
	       client.setEndpoint(clientEndpoint);

		   Request request = new Request(Code.GET);
		   request.getOptions().setUriPath(path);
	   
		   // If the last path segment of the URI ends with a '/' ,
		   // then append one more Uri-Path option with zero-length
	   	   if(path.charAt(path.length() - 1) == '/') {   		   
	   		   request.getOptions().addUriPath("");
	   	   }
	   	   
		   request.getOptions().setUriQuery(query);

		   
		   Response response = null;
	       try {        	
	    	   System.out.println("\n\nSending GET request to: " + client.getURI() + "\n");
	           response = client.advanced(request).advanced();
	       } catch (ConnectorException | IOException e) {
	    	   System.err.println("Error while sending the CoAP request to " + client.getURI() + "\n" +  e.getMessage());
	       }
			if (response != null) {

				System.out.println(response.getCode());
				System.out.println(response.getOptions());
				if (args.length > 1) {
					try (FileOutputStream out = new FileOutputStream(args[1])) {
						out.write(response.getPayload());
					} catch (IOException e) {
						System.err.println("Error while writing the response payload to file: " +  e.getMessage());
					}
				} else {
					System.out.println(System.lineSeparator() + "ADVANCED" + System.lineSeparator());
					// access advanced API with access to more details through
					// .advanced()
					System.out.println(Utils.prettyPrint(response));
				}
			} else {
				System.out.println("No response received.");
			}
			
			client.shutdown();
		
	}
	
	private static void postRequestToResourceDirectory(final String args[], final URI targetUri, final byte[] payload) {
		
		CoapClient client = new CoapClient(targetUri);

		CoapResponse response = null;
		try {
			System.out.println("\n\nSending POST request to: " + targetUri + "\n");
			response = client.post(payload, MediaTypeRegistry.APPLICATION_LINK_FORMAT);
		} catch (ConnectorException | IOException e) {
			System.err.println("Got an error: " + e);
		}

		if (response != null) {

			System.out.println(response.getCode());
			System.out.println(response.getOptions());
			if (args.length > 1) {
				try (FileOutputStream out = new FileOutputStream(args[1])) {
					out.write(response.getPayload());
				} catch (IOException e) {
					System.err.println("Error while writing the response payload to file: " +  e.getMessage());
				}
			} else {
				System.out.println(response.getResponseText());

				System.out.println(System.lineSeparator() + "ADVANCED" + System.lineSeparator());
				// access advanced API with access to more details through
				// .advanced()
				System.out.println(Utils.prettyPrint(response));
			}
		} else {
			System.out.println("No response received.");
		}
		client.shutdown();
		
	}
	
	private static URI buildURI(String uriString) {
		
		URI uri = null;
		
		try {
			uri = new URI(uriString);
		}
		catch (URISyntaxException e) {
			System.err.println("Invalid URI: " + e.getMessage());
			System.exit(-1);
		}
		
		return uri;
		
	}
	
}
