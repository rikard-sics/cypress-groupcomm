/*******************************************************************************
 * Copyright (c) 2019, RISE AB
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
package se.sics.ace.coap.client;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.oscore.CoapOSException;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import org.eclipse.californium.oscore.OSException;

import com.upokecenter.cbor.CBORException;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.Util;
import se.sics.ace.coap.rs.oscoreProfile.OscoreSecurityContext;


/**
 * Implements getting a token from the /token endpoint for a client 
 * using the OSCORE profile.
 * 
 * Also implements POSTing the token to the /authz-info endpoint at the 
 * RS.
 * 
 * Clients are expected to create an instance of this class when the want to
 * perform token requests from a specific AS.
 * 
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class OSCOREProfileRequests {
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(OSCOREProfileRequests.class.getName());

    /**
     * Sends a POST request to the /token endpoint of the AS to request an
     * access token.
     * 
     * @param asAddr  the full address of the /token endpoint
     *  (including scheme and hostname, and port if not default)
     * @param payload  the payload of the request.  Use the GetToken 
     *  class to construct this payload
     * @param ctx  the OSCORE context shared with the AS
     * @param db the database of the OSCORE contexts
     * 
     * @return  the response 
     *
     * @throws AceException 
     * @throws OSException 
     */
    public static Response getToken(String asAddr, CBORObject payload, 
            OSCoreCtx ctx, OSCoreCtxDB db) throws AceException, OSException {

        Request r = new Request(Code.POST);
        r.getOptions().setOscore(new byte[0]);
        r.setPayload(payload.EncodeToBytes());
        
        db.addContext(asAddr, ctx);
        
        CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
        builder.setCoapStackFactory(new OSCoreCoapStackFactory());
        builder.setCustomCoapStackArgument(db);
        Endpoint clientEndpoint = builder.build();
        CoapClient client = new CoapClient(asAddr);
        client.setEndpoint(clientEndpoint);  
        try {        	
            return client.advanced(r).advanced();
        } catch (ConnectorException | IOException e) {
            LOGGER.severe("Connector error: " + e.getMessage());
            throw new AceException(e.getMessage());
        }
    }
    
    /**
     * Sends a POST request to the /authz-info endpoint of the RS to submit an
     * access token.
     * 
     * @param rsAddr   the full address of the /authz-info endpoint
     *  (including scheme and hostname, and port if not default)
     * @param asResp   the response from the AS containing the token
     *      and the access information
     * @param db   the database of OSCORE Security Contexts
     * @param usedRecipientIds   the collection of already in use OSCORE Recipient IDs, it can be null when updating access rights
     * 
     * @return  the response 
     *
     * @throws AceException 
     * @throws OSException 
     */
    public static Response postToken(String rsAddr, Response asResp, OSCoreCtxDB db, List<Set<Integer>> usedRecipientIds) 
            throws AceException, OSException {
        if (asResp == null) {
            throw new AceException(
                    "asResp cannot be null when POSTing to authz-info");
        }
        
        CBORObject asPayload;
        
        try {
            asPayload = CBORObject.DecodeFromBytes(asResp.getPayload());
        } catch (CBORException e) {
            throw new AceException("Error parsing CBOR payload: " 
                    + e.getMessage());
        }
               
        if (!asPayload.getType().equals(CBORType.Map)) {
            throw new AceException("AS response was not a CBOR map");
        }
        
        CBORObject token = asPayload.get(CBORObject.FromObject(Constants.ACCESS_TOKEN));
        if (token == null) {
            throw new AceException("AS response did not contain a token");
        }
        if (token.getType() != CBORType.ByteString) {
            throw new AceException("The token must be a CBOR byte string");
        }
        
        CBORObject cnf = asPayload.get(
                CBORObject.FromObject(Constants.CNF));
        if (cnf == null) {
            throw new AceException("AS response did not contain a cnf");
        }
      
        if (!cnf.ContainsKey(Constants.OSCORE_Input_Material) || cnf.ContainsKey(Constants.COSE_KID_CBOR)) {
        	throw new AceException("Invalid format of cnf");
        }
        
        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token);
        
        byte[] n1 = new byte[8];
        new SecureRandom().nextBytes(n1);
        payload.Add(Constants.NONCE1, n1);
        
        byte[] recipientId = null;
		byte[] contextId = new byte[0];
        int recipientIdAsInt = -1;
        boolean found = false;
        
        // Determine an available Recipient ID to offer to the Resource Server as ID1
        synchronized(usedRecipientIds) {
        	synchronized(db) {
        	
	        	int maxIdValue;
	        	
    			if (cnf.get(Constants.OSCORE_Input_Material).ContainsKey(Constants.OS_CONTEXTID)) {
    				contextId = cnf.get(Constants.OSCORE_Input_Material).get(Constants.OS_CONTEXTID).GetByteString();
    			}
	        	
		        // Start with 1 byte as size of Recipient ID; try with up to 4 bytes in size        
		        for (int idSize = 1; idSize <= 4; idSize++) {
		        	
		        	if (idSize == 4)
		        		maxIdValue = (1 << 31) - 1;
		        	else
		        		maxIdValue = (1 << (idSize * 8)) - 1;
		        	
			        for (int j = 0; j <= maxIdValue; j++) {
			        	
	        			recipientId = Util.intToBytes(j, idSize);
	        			
	        			// This Recipient ID is marked as not available to use
	        			if (usedRecipientIds.get(idSize - 1).contains(j))
	        				continue;
	        			
	        			try {
				        	// This Recipient ID seems to be available to use 
			        		if (!usedRecipientIds.get(idSize - 1).contains(j)) {
			        			
			        			// Double check in the database of OSCORE Security Contexts
			        			if (db.getContext(recipientId, contextId) != null) {
			        				
			        				// A Security Context with this Recipient ID exists and was not tracked!
			        				// Update the local list of used Recipient IDs, then move on to the next candidate
			        				usedRecipientIds.get(idSize - 1).add(j);
			        				continue;
			        				
			        			}
			        			else {
			        				
			        				// This Recipient ID is actually available at the moment. Add it to the local list
			        				usedRecipientIds.get(idSize - 1).add(j);
			        				recipientIdAsInt = j;
			        				found = true;
			        				break;
			        			}
			        			
			        		}
	        			}
		        		catch(CoapOSException e) {
	        				// Multiple Security Contexts with this Recipient ID exist and it was not tracked!
	        				// Update the local list of used Recipient IDs, then move on to the next candidate
	        				usedRecipientIds.get(idSize - 1).add(j);
	        				continue;
		        		}
		        			
			        }
			        
			        if (found)
			        	break;
			        	
		        }
        	}
        }

        if (!found) {
            throw new AceException("No Recipient ID available to use");
        }
        payload.Add(Constants.ACE_CLIENT_RECIPIENTID, recipientId);
               
        CoapClient client = null;
        CBORObject rsPayload;
    	Response resp = null;
    	client = new CoapClient(rsAddr);

        try {
        	LOGGER.finest("Sending request payload: " + payload);
        	resp = client.post(
                    payload.EncodeToBytes(), 
                    Constants.APPLICATION_ACE_CBOR).advanced();
        } catch (ConnectorException | IOException ex) {
        	if (recipientIdAsInt != -1) {
        		usedRecipientIds.get(recipientId.length - 1).remove(recipientIdAsInt);
        	}
            LOGGER.severe("Connector error: " + ex.getMessage());
            throw new AceException(ex.getMessage());
        }
        
        if (resp == null) {
            throw new AceException("RS did not respond");
        }
        
        try {
            rsPayload = CBORObject.DecodeFromBytes(resp.getPayload());
        } catch (CBORException e) {
            throw new AceException("Error parsing CBOR payload: " + e.getMessage());
        }
                
        if (!rsPayload.getType().equals(CBORType.Map)) {
            throw new AceException("RS didn't respond with a CBOR map");
        }

        CBORObject n2C = rsPayload.get(
                CBORObject.FromObject(Constants.NONCE2));
        if (n2C == null || !n2C.getType().equals(CBORType.ByteString)) {
            throw new AceException("Missing or malformed 'nonce2' in RS response");
        }
        
        byte[] n2 = n2C.GetByteString();
        
        CBORObject senderIdCBOR = rsPayload.get(
                CBORObject.FromObject(Constants.ACE_SERVER_RECIPIENTID));
        if (senderIdCBOR == null || !senderIdCBOR.getType().equals(CBORType.ByteString)) {
            throw new AceException("Missing or malformed 'id2' in RS response");
        }
        
        byte[] senderId = senderIdCBOR.GetByteString();
            
		// The Recipient ID must be different than what offered by the Resource Server in the 'id2' parameter
		if(Arrays.equals(senderId, recipientId)) {
            throw new AceException("The Resource Server returned the ID offered by the Client");
		}
        	
    	cnf.get(Constants.OSCORE_Input_Material).Add(Constants.OS_CLIENTID, CBORObject.FromObject(senderId));
    	cnf.get(Constants.OSCORE_Input_Material).Add(Constants.OS_SERVERID, CBORObject.FromObject(recipientId));
        
        OscoreSecurityContext osc = new OscoreSecurityContext(cnf);
        
        OSCoreCtx ctx = osc.getContext(true, n1, n2);
        
        synchronized(db) {
        	
        	boolean install = true;
        	
			try {
        			
				// Double check in the database that the OSCORE Security Context
				// with the selected Recipient ID is actually still not present
    			if (db.getContext(recipientId, contextId) != null) {
    				// A Security Context with this Recipient ID exists!
    				install = false;
    			}        			
			}
    		catch(CoapOSException e) {
				// Multiple Security Contexts with this Recipient ID exist!
				install = false;
    		}
        	
			if (install)
				db.addContext(rsAddr, ctx);
			else
				throw new AceException("An OSCORE Security Context with the same Recipient ID"
						               + " has been installed while running the OSCORE profile");
        }
        
        return resp;
        
    }
    
    
    /**
     * Sends a POST request to the /authz-info endpoint of the RS to submit an
     * access token for updating access rights.
     * 
     * @param rsAddr   the full address of the /authz-info endpoint
     *  (including scheme and hostname, and port if not default)
     * @param asResp   the response from the AS containing the token
     *      and the access information
     * @param db   the database of OSCORE Security Contexts
     * 
     * @return  the response 
     *
     * @throws AceException 
     * @throws OSException 
     */
    public static CoapResponse postTokenUpdate(String rsAddr, Response asResp, OSCoreCtxDB db) 
            throws AceException, OSException {
        if (asResp == null) {
            throw new AceException("asResp cannot be null when POSTing to authz-info");
        }
        
        CBORObject asPayload;
        
        try {
            asPayload = CBORObject.DecodeFromBytes(asResp.getPayload());
        } catch (CBORException e) {
            throw new AceException("Error parsing CBOR payload: " + e.getMessage());
        }
               
        if (!asPayload.getType().equals(CBORType.Map)) {
            throw new AceException("AS response was not a CBOR map");
        }
        
        CBORObject token = asPayload.get(CBORObject.FromObject(Constants.ACCESS_TOKEN));
        if (token == null) {
            throw new AceException("AS response did not contain a token");
        }
        if (token.getType() != CBORType.ByteString) {
            throw new AceException("The token must be a CBOR byte string");
        }
        
        if (asPayload.ContainsKey(Constants.CNF)) {
            throw new AceException("AS response must not contain a cnf");
        }
        
        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.ACCESS_TOKEN, token);
        
    	CoapResponse resp = null;

    	// The Token has to be posted through an OSCORE-protected request
        LOGGER.finest("Sending request payload: " + payload);
        CoapClient client = OSCOREProfileRequests.getClient(new InetSocketAddress(
        		rsAddr, CoAP.DEFAULT_COAP_PORT), db);
    	
        Request req = new Request(CoAP.Code.POST);
        req.getOptions().setContentFormat(Constants.APPLICATION_ACE_CBOR);
        req.getOptions().setOscore(new byte[0]);
        req.setPayload(payload.EncodeToBytes());
        try {
        	resp = client.advanced(req);
		} catch (ConnectorException | IOException ex) {
            LOGGER.severe("Connector error: " + ex.getMessage());
            throw new AceException(ex.getMessage());
		}
        
        if (resp == null) {
            throw new AceException("RS did not respond");
        }
        
        return resp;
        
    }
    
    
    /**
     * Generates a Coap client for sending requests to an RS using OSCORE.
     * Note that the OSCORE context for the RS should already be configured 
     * in the OSCoreCtxDb at this point.
     * 
     * @param serverAddress  the address of the server and resource this client
     *  should talk to.
     * 
     * @return  a CoAP client configured to pass the access token through the
     *  psk-identity in the handshake 
     * @throws AceException 
     * @throws OSException 
     * @throws URISyntaxException 
     */
    public static CoapClient getClient(InetSocketAddress serverAddress, OSCoreCtxDB db) 
            throws AceException, OSException {
        if (serverAddress == null || serverAddress.getHostString() == null) {
            throw new IllegalArgumentException(
                    "Client requires a non-null server address");
        }

        if (db.getContext(serverAddress.getHostName()) == null) {
            throw new AceException("OSCORE context not set for address: " 
                    + serverAddress);
        }
        CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
        builder.setCoapStackFactory(new OSCoreCoapStackFactory());
        builder.setCustomCoapStackArgument(db);
        Endpoint clientEndpoint = builder.build();
        CoapClient client = new CoapClient(serverAddress.getHostString());
        client.setEndpoint(clientEndpoint);
        return client;    
    }
}
