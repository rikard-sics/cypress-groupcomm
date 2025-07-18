/*******************************************************************************
 * Copyright (c) 2025, RISE AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, 
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/
package se.sics.ace.interop;

import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import org.apache.log4j.BasicConfigurator;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;

import org.eclipse.californium.oscore.OSCoreCoapStackFactory;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.MessageTag;
import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.TestConfig;
import se.sics.ace.coap.rs.CoapAuthzInfo;
import se.sics.ace.coap.rs.CoapDeliverer;
import se.sics.ace.coap.rs.oscoreProfile.OscoreAuthzInfo;
import se.sics.ace.coap.rs.oscoreProfile.OscoreCtxDbSingleton;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.KissValidator;
import se.sics.ace.rs.AsRequestCreationHints;

/**
 * Server for testing the DTLSProfileDeliverer class. 
 * 
 * The Junit tests are in TestDtlspClientGroupOSCORE, 
 * which will automatically start this server.
 * 
 * @author Marco Tiloca
 *
 */
public class TestRSoscoreProfile {
	
	static {
	    CoapConfig.register();
	}
	
	// OSCORE Security Context with the AS
	
	// Master Secret
    private static byte[] msecret_with_as = {(byte)0x51, (byte)0x52, (byte)0x53, (byte)0x04, (byte)0x05, (byte)0x06,
						    			     (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c,
						    		 	     (byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10};
    
    // Sender ID: 0x77
    private static byte[] senderIdWithAS = new byte[] {0x77};
    
    // Recipient ID: 0x01
    private static byte[] recipientIdWithAS = new byte[] {0x01};
    

    
	// PSK to encrypt access tokens issued for this Resource Server
    private static byte[] key128_token = {(byte)0xa1, (byte)0xa2, (byte)0xa3, (byte)0x04, (byte)0x05, (byte)0x06,
    									  (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c,
    									  (byte)0x0d, (byte)0x0e, (byte)0x0f, (byte)0x10};
    	
	private static int portNumber = 5690;
	
    /**
     * Definition of the Hello-World Resource
     */
    public static class HelloWorldResource extends CoapResource {
        
        /**
         * Constructor
         */
        public HelloWorldResource() {
            
            // set resource identifier
            super("helloWorld");
            
            // set display name
            getAttributes().setTitle("Hello-World Resource");
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            
            // respond to the request
            exchange.respond("Hello World!");
        }
    }
    
    /**
     * Definition of the Temp Resource
     */
    public static class TempResource extends CoapResource {
        
    	int temperature;
    	
        /**
         * Constructor
         */
        public TempResource() {
            
            // set resource identifier
            super("temp");
            
            // set display name
            getAttributes().setTitle("Temp Resource");
            
            temperature = 0;
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            
            // respond to the request
            exchange.respond(Integer.toString(this.temperature) + " C");
        }
        
        @Override
        public void handlePUT(CoapExchange exchange) {
            
        	int value;
        	String str = new String(exchange.getRequestPayload());
        	String errorStr = new String("Invalid payload\n");
        	
        	if (str == null || str.length() == 0) {
        		exchange.respond(ResponseCode.BAD_REQUEST, errorStr);
                return;
        	}
        	
        	try{
                value = Integer.parseInt(str);
            }
            catch (NumberFormatException ex){
                exchange.respond(ResponseCode.BAD_REQUEST, errorStr);
                return;
            }
        	
        	this.temperature = value;
        	
            // respond to the request
            exchange.respond(ResponseCode.CHANGED);
        }
        
        @Override
        public void handlePOST(CoapExchange exchange) {
            
        	int value;
        	String str = new String(exchange.getRequestPayload());
        	String errorStr = new String("Invalid payload\n");
        	
        	if (str == null || str.length() == 0) {
        		exchange.respond(ResponseCode.BAD_REQUEST, errorStr.getBytes(Constants.charset));
                return;
        	}
        	
        	try{
                value = Integer.parseInt(str);
            }
            catch (NumberFormatException ex){
                exchange.respond(ResponseCode.BAD_REQUEST, errorStr.getBytes(Constants.charset));
                return;
            }
        	
        	this.temperature = value;
        	
            // respond to the request
            exchange.respond(ResponseCode.CHANGED);
        }
        
    }
    
    /**
     * Definition of the Config Resource
     */
    public static class ConfigResource extends CoapResource {
        
    	String configuration;
    	
        /**
         * Constructor
         */
        public ConfigResource() {
            
            // set resource identifier
            super("config");
            
            // set display name
            getAttributes().setTitle("Config Resource");
            
            configuration = new String("Default");
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            
            // respond to the request
            exchange.respond(this.configuration);
        }
        
        @Override
        public void handlePUT(CoapExchange exchange) {
            
        	String str = new String(exchange.getRequestPayload());
        	String errorStr = new String("Invalid payload\n");
        	
        	if (str == null || str.length() == 0) {
        		exchange.respond(ResponseCode.BAD_REQUEST, errorStr);
                return;
        	}
        	
        	this.configuration = str;
        	
            // respond to the request
            exchange.respond(ResponseCode.CHANGED);
        }
        
        @Override
        public void handlePOST(CoapExchange exchange) {
            
        	String str = new String(exchange.getRequestPayload());
        	String errorStr = new String("Invalid payload\n");
        	
        	if (str == null || str.length() == 0) {
        		exchange.respond(ResponseCode.BAD_REQUEST, errorStr);
                return;
        	}
        	
        	this.configuration = str;
        	
            // respond to the request
            exchange.respond(ResponseCode.CHANGED);
        }
        
    }
    

    private static OscoreAuthzInfo ai = null;
    
    private static CoapServer rs = null;
    
    private static CoapDeliverer dpd = null;
    
    private static Map<String, Map<String, Set<Short>>> myScopes = new HashMap<>();
    
    private static KissValidator valid = null;
    
    
    /**
     * The CoAPs server for testing, run this before running the Junit tests.
     *  
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
    	
        //Set logging for slf4/blah
        BasicConfigurator.configure();
    	
        //Set java.util.logging
        Logger rootLogger = LogManager.getLogManager().getLogger("");
        rootLogger.setLevel(Level.FINEST);
        for (Handler h : rootLogger.getHandlers()) {
            h.setLevel(Level.FINEST);
        }
    	
    	new File(TestConfig.testFilePath + "tokens.json").delete();

    	
        // Setup the Resource Server name and its audience
        String rsId = "rs1";
        Set<String> auds = new HashSet<>();
        auds.add("aud1");

        
        // Set up the recognized scopes
        myScopes = new HashMap<>();
        
        // r_helloworld --> GET on /helloWorld
        Set<Short> actions = new HashSet<>();
        Map<String, Set<Short>> myResource = new HashMap<>();
        actions.add(Constants.GET);
        myResource.put("helloWorld", actions);
        myScopes.put("r_helloWorld", myResource);
        
        // r_temp --> GET on /temp
        Set<Short> actions2 = new HashSet<>();
        Map<String, Set<Short>> myResource2 = new HashMap<>();
        actions2.add(Constants.GET);
        myResource2.put("temp", actions2);
        myScopes.put("r_temp", myResource2);
        
        // rw_temp --> GET, POST and PUT on /temp
        Set<Short> actions3 = new HashSet<>();
        Map<String, Set<Short>> myResource3 = new HashMap<>();
        actions3.add(Constants.GET);
        actions3.add(Constants.POST);
        actions3.add(Constants.PUT);
        myResource3.put("temp", actions3);
        myScopes.put("rw_temp", myResource3);
        
        // r_config --> GET on /config
        Set<Short> actions4 = new HashSet<>();
        Map<String, Set<Short>> myResource4 = new HashMap<>();
        actions4.add(Constants.GET);
        myResource4.clear();
        myResource4.put("config", actions4);
        myScopes.put("r_config", myResource4);

        // rw_config --> GET, POST and PUT on /config
        Set<Short> actions5 = new HashSet<>();
        Map<String, Set<Short>> myResource5 = new HashMap<>();
        actions5.add(Constants.GET);
        actions5.add(Constants.POST);
        actions5.add(Constants.PUT);
        myResource5.clear();
        myResource5.put("config", actions5);
        myScopes.put("rw_config", myResource5);
        
        valid = new KissValidator(auds, myScopes);
        
        
    	String tokenFile = TestConfig.testFilePath + "tokens.json";
    	//Delete lingering old token files
    	new File(tokenFile).delete();
        
        //Setup COSE parameters
        COSEparams coseP = new COSEparams(MessageTag.Encrypt0, AlgorithmID.AES_CCM_16_64_128, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.encrypt0(key128_token, coseP.getAlg().AsCBOR());

        // Setup the inner Authz-Info library
    	ai = new OscoreAuthzInfo(Collections.singletonList("AS"), new KissTime(), null,
    							 rsId, valid, ctx, tokenFile, valid, false);
                
        // Setup the responder to unauthorized resource requests
  	    AsRequestCreationHints asi = new AsRequestCreationHints("coap://blah/authz-info/", null, false, false);
  	    
  	    
  	    Resource hello = new HelloWorldResource();
  	    Resource temp = new TempResource();
  	    Resource conf = new ConfigResource();
  	    Resource authzInfo = new CoapAuthzInfo(ai);
      
  	    rs = new CoapServer();
  	    rs.add(hello);
  	    rs.add(temp);
  	    rs.add(conf);
  	    rs.add(authzInfo);
  	    
  	    // Setup the OSCORE server
  	    CoapEndpoint cep = new CoapEndpoint.Builder()
              .setCoapStackFactory(new OSCoreCoapStackFactory())
              .setPort(portNumber)
              .setCustomCoapStackArgument(OscoreCtxDbSingleton.getInstance())
              .build();
  	    rs.addEndpoint(cep);
  	    
  	    dpd = new CoapDeliverer(rs.getRoot(), null, asi, cep);
  	    rs.setMessageDeliverer(dpd);
  	    
  	    rs.start();
  	    System.out.println("Server starting");
    }

    /**
     * Stops the server
     * 
     * @throws IOException 
     * @throws AceException 
     */
    public static void stop() throws IOException, AceException {
        rs.stop();
        ai.close();
        new File(TestConfig.testFilePath + "tokens.json").delete();
    }

}
