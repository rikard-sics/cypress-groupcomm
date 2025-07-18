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
package se.sics.ace.as;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import org.eclipse.californium.cose.HeaderKeys;
import org.eclipse.californium.cose.OneKey;

import se.sics.ace.AccessToken;
import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.Endpoint;
import se.sics.ace.Message;
import se.sics.ace.ReferenceToken;
import se.sics.ace.TimeProvider;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;

/**
 * The OAuth 2.0 Introspection endpoint.
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class Introspect implements Endpoint, AutoCloseable {
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(Introspect.class.getName() );

    /**
     * Boolean for verify
     */
    private static boolean verify = true;
    
    /**
     * The PDP this endpoint uses to make access control decisions.
     */
    private PDP pdp;
    
    /**
     * The database connector for storing and retrieving stuff.
     */
    private DBConnector db;
    
    /**
     * The time provider for this AS.
     */
    private TimeProvider time;
    
    /**
     * The asymmetric key pair of the AS
     */
    private OneKey keyPair;
    
	 /**
	  * Mapping between security identities of the peers and their names; it can be null
	  * 
	  * This is relevant especially for the OSCORE profile, since all peers are registered in the
	  * AS database by nicknames. Instead, their OSCORE identities as retrieved from incoming OSCORE
	  * messages are structured base64 strings encoding the Context ID and Sender ID for that peer 
	 */ 
	private Map<String, String> peerIdentitiesToNames = null;
	
    
    /**
     * Constructor.
     * 
     * @param pdp   the PDP for deciding access
     * @param db  the database connector
     * @param time  the time provider
     * @param keyPair the asymmetric key pair of the AS or null
     * @param peerIdentitiesToNames  mapping between security identities of the peers and their names; it can be null
     *
     * @throws AceException  if fetching the cti from the database fails
     */
    public Introspect(PDP pdp, DBConnector db, 
            TimeProvider time, OneKey keyPair,
            Map<String, String> peerIdentitiesToNames) throws AceException {
        if (pdp == null) {
            LOGGER.severe("Introspect endpoint's PDP was null");
            throw new AceException(
                    "Introspect endpoint's PDP must be non-null");
        }
        if (db == null) {
            LOGGER.severe("Introspect endpoint's DBConnector was null");
            throw new AceException(
                    "Introspect endpoint's DBConnector must be non-null");
        }
        if (time == null) {
            LOGGER.severe("Introspect endpoint received a null TimeProvider");
            throw new AceException(
                    "Introspect endpoint requires a non-null TimeProvider");
        }
        this.pdp = pdp;
        this.db = db;
        this.time = time;  
        this.keyPair = keyPair;
        this.peerIdentitiesToNames = peerIdentitiesToNames;
    }
    
    
	@Override
    public Message processMessage(Message msg) {
		
	    if (msg == null) {
	    	//This should not happen
            LOGGER.severe("Introspect.processMessage() received null message");
            return null;
        }
	    LOGGER.log(Level.INFO, "Introspect received message: " + msg.getParameters());
        
	    
	    // Check that this RS is authorized and allowed to introspect
	    String id = msg.getSenderId();
	    
		if (peerIdentitiesToNames != null) {
		    id = peerIdentitiesToNames.get(id);
		    if (id == null) {
	            CBORObject map = CBORObject.NewMap();
	            map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
	            LOGGER.log(Level.INFO, "Message processing aborted: "
	                    + "unauthorized client: " + id);
	            return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
		    }
		}
	    
        PDP.IntrospectAccessLevel accessLevel;
        try {
            accessLevel = this.pdp.getIntrospectAccessLevel(id);
            if (accessLevel.equals(PDP.IntrospectAccessLevel.NONE)) {
                LOGGER.log(Level.INFO, "Message processing aborted: "
                        + "client: " + id + " does not have the right to introspect");
                return msg.failReply(Message.FAIL_FORBIDDEN, null);
            }
        } catch (AceException e) {
            LOGGER.severe("Database error: " + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }
	    
        
	    // Purge expired tokens from the database
        try {
            this.db.purgeExpiredTokens(this.time.getCurrentTime());
        } catch (AceException e) {
            LOGGER.severe("Database error: " + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }
        
        
	    // Get the token from the introspection request payload
        CBORObject tokenAsCborByteArray = msg.getParameter(Constants.TOKEN);
        if (tokenAsCborByteArray == null) {
            LOGGER.log(Level.INFO, "Request didn't provide 'token' parameter");
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, "Must provide 'token' parameter");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        }
        CBORObject tokenAsCbor = CBORObject.DecodeFromBytes(
                tokenAsCborByteArray.GetByteString());

        // Parse the token
        AccessToken token;
        try {
            token = parseToken(tokenAsCbor, id);
        } catch (AceException e) {
            LOGGER.log(Level.INFO, e.getMessage());
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, "Must provide non-null token");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        }


        // Check if token is still active. If it is not, return active=false
        String cti = null;
        try {
			cti = token.getCti();
		} catch (AceException e) {
            LOGGER.severe("Message processing aborted: " + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}
        if (cti == null) {
            LOGGER.log(Level.INFO, "Message processing aborted: the token does not include a valid cti or reference");
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, "Must provide a token including a valid cti or reference");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        }

        Map<Short, CBORObject> claims;
        CBORObject payload = CBORObject.NewMap();
        try {
            claims = this.db.getClaims(cti);
        } catch (AceException e) {
            LOGGER.severe("Database error: " + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }
        if (claims == null || claims.isEmpty()) {
        	LOGGER.log(Level.INFO, "Returning introspection result: inactive " + "for token: " + cti);
            payload.Add(Constants.ACTIVE, CBORObject.False);
            //No need to check for client token, the token is invalid anyways
            return msg.successReply(Message.CREATED, payload); 
        }
        
                
        // Check if this RS is allowed to introspect this particular Access Token.
        //
        // That is, check if the audience specified in the 'aud' claim of the Access Token
        // includes also this RS. This implies that the Access Token includes the 'aud' claim.
        CBORObject audCbor = claims.get(Constants.AUD);
        if (audCbor == null || audCbor.getType() != CBORType.TextString) {
            LOGGER.severe("Message processing aborted: retrieved token to introspect without a valid audience");
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }
        
        String aud = audCbor.AsString();
		Set<String> rsSet = new HashSet<>();
		try {
			rsSet = db.getRSS(aud);
		} catch (AceException e) {
            LOGGER.severe("Database error: " + e.getMessage());
		    return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}
		if (!rsSet.contains(id)) {
            LOGGER.log(Level.INFO, "RS " + id + " is not allowed to introspect token: " + cti);
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, "Can introspect only pertaining tokens");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		}

        
        // The NONE option was already checked. Now check if the RS is allowed to 
        // retrieve the full set of claims, or only to the activeness of the token.
        if (accessLevel.equals(PDP.IntrospectAccessLevel.ACTIVE_AND_CLAIMS)) {
            // We have access to all claims; add them to reply.
        	
        	if (claims.containsKey(Constants.LATE_ADDED_EXP)) {
        		// This Access Token was originally created with the EXI claim and without the
        		// EXP claim, which was later artificially added to enable purging upon expiration.
        		//
        		// In order to provide the Resource Server with the Access Token like it was
        		// originally created, such an EXP claim as well as the "sentinel claim" are removed.
        		claims.remove(Constants.LATE_ADDED_EXP);
        		claims.remove(Constants.EXP);
        	}
        	
            payload = Constants.getCBOR(claims);
        }
        else {
            // Only access to activeness.
            payload = CBORObject.NewMap();
        }

        LOGGER.log(Level.INFO, "Returning introspection result: " + payload.toString() + " for " + cti);
        
        payload.Add(Constants.ACTIVE, CBORObject.True);
        return msg.successReply(Message.CREATED, payload);
        
	}

    /**
     * Parses a CBOR object presumably containing an access token.
     * 
     * @param token  the object
     * @param senderId  the sender's id from the secure connection
     * 
     * @return  the parsed access token
     * 
     * @throws AceException 
     */
    public AccessToken parseToken(CBORObject token, String senderId)
            throws AceException {
        if (token == null) {
            throw new AceException("Access token parser indata was null");
        }
        if (token.getType().equals(CBORType.Array)) {
            try {
                // Get the RS id (audience) from the COSE KID header.
				org.eclipse.californium.cose.Message coseRaw = org.eclipse.californium.cose.Message
						.DecodeFromBytes(token.EncodeToBytes());
                CBORObject kid = coseRaw.findAttribute(HeaderKeys.KID);
                Set<String> aud = new HashSet<>();
                if(kid == null) {
                    if (senderId == null) {
                        throw new AceException("Cannot determine Audience"
                                + "of the token for introspection");
                    }
                    aud.add(senderId);
                } else {
                    CBORObject audArray = CBORObject.DecodeFromBytes(
                            kid.GetByteString());
                    for (int i=0; i<audArray.size();i++) {
                        aud.add(audArray.get(i).AsString());
                    }
                }            
                CwtCryptoCtx ctx = EndpointUtils.makeCommonCtx(aud, this.db,
                        this.keyPair, verify);
                return CWT.processCOSE(token.EncodeToBytes(), ctx);
            } catch (Exception e) {
                LOGGER.severe("Error while processing CWT: " + e.getMessage());
                throw new AceException(e.getMessage());
            }
        } else if (token.getType().equals(CBORType.ByteString)) {
            return ReferenceToken.parse(token);
        }
        throw new AceException("Unknown access token format");        
    }


    @Override
    public void close() throws AceException {
        this.db.close();        
    }
    
}
