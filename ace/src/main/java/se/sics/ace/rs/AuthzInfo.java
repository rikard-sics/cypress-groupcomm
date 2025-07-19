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
package se.sics.ace.rs;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.oscore.CoapOSException;
import org.eclipse.californium.oscore.OSCoreCtxDB;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import org.eclipse.californium.cose.CoseException;
import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.Endpoint;
import se.sics.ace.Message;
import se.sics.ace.TimeProvider;
import se.sics.ace.Util;
import se.sics.ace.coap.rs.oscoreProfile.OscoreCtxDbSingleton;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.LocalMessage;

/**
 * This class implements the /authz_info endpoint at the RS that receives
 * access tokens, verifies if they are valid and then stores them.
 * 
 * Note this implementation requires the following claims in a CWT:
 * iss, sub, scope, aud.
 * 
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class AuthzInfo implements Endpoint, AutoCloseable {
	
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(AuthzInfo.class.getName());

	/**
	 * The acceptable issuers
	 */
	private List<String> issuers;
	
	/**
	 * Provides system time
	 */
	private TimeProvider time;
	
	/**
	 * Handles introspection of tokens
	 */
	private IntrospectionHandler intro;
	
	/**
	 * Handles audience validation
	 */
	private AudienceValidator audience;
	
	/**
	 * The crypto context to use with the AS
	 */
	private CwtCryptoCtx ctx;
		
	/**
	 * Flag to indicate if we need to check cnonces
	 */
	private boolean checkCnonce;
	
	/**
	 * Each set of the list refers to a different size of Recipient IDs.
	 * The element with index 0 includes as elements Recipient IDs with size 1 byte.
	 */
	private static List<Set<Integer>> usedRecipientIds = new ArrayList<Set<Integer>>();
	
	/**
	 * Constructor. Needs an initialized TokenRepository.
	 * 
	 * @param issuers  the list of acceptable issuer of access tokens
	 * @param time  the time provider
	 * @param intro  the introspection handler (can be null)
	 * @param rsId  the identifier of the Resource Server
	 * @param audience  the audience validator
	 * @param ctx  the crypto context to use with the As
	 * @param keyDerivationKey  the key derivation key to use with the As, it can be null
	 * @param derivedKeySize  the size in bytes of symmetric keys derived with the key derivation key
	 * @param tokenFile  the file where to save tokens when persisting
	 * @param scopeValidator  the application specific scope validator 
	 * @param checkCnonce  true if this RS uses cnonces for freshness validation
	 * @throws AceException  if the token repository is not initialized
	 * @throws IOException 
	 */
	public AuthzInfo(List<String> issuers, 
			TimeProvider time, IntrospectionHandler intro, String rsId, 
			AudienceValidator audience, CwtCryptoCtx ctx, byte[] keyDerivationKey, int derivedKeySize,
			String tokenFile, ScopeValidator scopeValidator, boolean checkCnonce) 
			        throws AceException, IOException {
        if (TokenRepository.getInstance()==null) {     
            TokenRepository.create(scopeValidator, tokenFile, ctx, keyDerivationKey, derivedKeySize, time, rsId);
        }
		this.issuers = new ArrayList<>();
		this.issuers.addAll(issuers);
		this.time = time;
		this.intro = intro;
		this.audience = audience;
		this.ctx = ctx;
		this.checkCnonce = checkCnonce;
		
    	for (int i = 0; i < 4; i++) {
        	// Empty sets of assigned Sender IDs; one set for each possible Sender ID size in bytes.
        	// The set with index 0 refers to Sender IDs with size 1 byte
    		usedRecipientIds.add(new HashSet<Integer>());
    	}
    	
	}

	@Override
	public synchronized Message processMessage(Message msg) {
	    LOGGER.log(Level.INFO, "received message: " + msg);
	    CBORObject token = null;
	    try {
	        token = CBORObject.DecodeFromBytes(msg.getRawPayload());
	    } catch (Exception e) {
	        LOGGER.info("Invalid payload at authz-info: " + e.getMessage());
	        CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
	    }

	    // This particular method is invoked when using the DTLS profile in the base case, i.e.:
	    // - The POST request to /authz-info conveys the access token
	    // - The successful 2.01 response from /authz-info has an empty payload
	    
	    Message reply = processToken(token, msg); 
	    
	    if (msg instanceof LocalMessage) {
	        // The request is a cosmetic message generated by a Junit test,
	    	// thus the payload to return is not empty and includes
	    	// parameters not to be sent on the wire
	    	return reply;
	    }
	    
	    // Otherwise, the returned payload is empty as expected
	    return msg.successReply(reply.getMessageCode(), null);

	}
	
	protected synchronized Message processToken(CBORObject token,  Message msg) {
	    Map<Short, CBORObject> claims = null;
	    
        byte[] recipientId = null;
        boolean recipientIdFound = false;

		//1. Check whether it is a CWT or REF type
	    if (token.getType().equals(CBORType.ByteString)) {
	        try {
                claims = processReferenceToken(token);
            } catch (AceException e) {
                LOGGER.severe("Message processing aborted: " + e.getMessage());
                return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
            } catch (IntrospectionException e) {
                LOGGER.info("Introspection error, "
                         + "message processing aborted: " + e.getMessage());
                if (e.getMessage().isEmpty()) {
                    return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
                }
                CBORObject map = CBORObject.NewMap();
                map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
                map.Add(Constants.ERROR_DESCRIPTION, e.getMessage());
                return msg.failReply(e.getCode(), map);
            }
	    } else if (token.getType().equals(CBORType.Array)) {
	        try {
	            claims = processCWT(token);
	        } catch (IntrospectionException e) {
                LOGGER.info("Introspection error, "
                        + "message processing aborted: " + e.getMessage());
               if (e.getMessage().isEmpty()) {
                   return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
               }
               CBORObject map = CBORObject.NewMap();
               map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
               map.Add(Constants.ERROR_DESCRIPTION, e.getMessage());
               return msg.failReply(e.getCode(), map);
	        } catch (AceException | CoseException 
	                | InvalidCipherTextException e) {
	            LOGGER.info("Token invalid: " + e.getMessage());
	            CBORObject map = CBORObject.NewMap();
	            map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
	            map.Add(Constants.ERROR_DESCRIPTION, "Token is invalid");
                return msg.failReply(Message.FAIL_BAD_REQUEST, map);
	        } catch (Exception e) {
	            LOGGER.severe("Unsupported key wrap algorithm in token: " 
	                    + e.getMessage());
	            return msg.failReply(Message.FAIL_NOT_IMPLEMENTED, null);
            } 
	    } else {
	        CBORObject map = CBORObject.NewMap();
	        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, "Unknown token format");
	        LOGGER.info("Message processing aborted: invalid request");
	        return msg.failReply(Message.FAIL_BAD_REQUEST, map);
	    }
	    
	    //2. Check if the token is active, this will only be present if we 
	    // did introspect
	    CBORObject active = claims.get(Constants.ACTIVE);
        if (active != null && active.isFalse()) {
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
            map.Add(Constants.ERROR_DESCRIPTION, "Token is not active");
            LOGGER.info("Message processing aborted: Token is not active");
            return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
        }

	    //3. Check that the token is not expired (exp)
	    CBORObject exp = claims.get(Constants.EXP);
	    if (exp != null && exp.AsNumber().ToInt64Checked() < this.time.getCurrentTime()) { 
	        CBORObject map = CBORObject.NewMap();
	        map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
            map.Add(Constants.ERROR_DESCRIPTION, "Token is expired");
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "Token is expired");
	        return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
	    }   
      
	    //4. Check if we accept the issuer (iss)
	    CBORObject iss = claims.get(Constants.ISS);
	    if (iss != null) {
	        if (!this.issuers.contains(iss.AsString())) {
	            CBORObject map = CBORObject.NewMap();
	            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
	            map.Add(Constants.ERROR_DESCRIPTION, "Token issuer unknown");
	            LOGGER.log(Level.INFO, "Message processing aborted: "
	                    + "Token issuer unknown");

				return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
	        }
	    }
	    
	    //5. Check if we are the audience (aud)
	    CBORObject audCbor = claims.get(Constants.AUD);
	    if (audCbor == null) {
	        CBORObject map = CBORObject.NewMap();
	        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
	        map.Add(Constants.ERROR_DESCRIPTION, "Token has no audience");
	        LOGGER.log(Level.INFO, "Message processing aborted: "
	                + "Token has no audience");
	        return msg.failReply(Message.FAIL_BAD_REQUEST, map);
	    }

	    String aud;
	    if (audCbor.getType().equals(CBORType.TextString)) {
	        aud = audCbor.AsString();   
	    } else {//Error
	        CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, "Audience malformed");
	        LOGGER.log(Level.INFO, "Message processing aborted: "
	                + "audience malformed");
	        return msg.failReply(Message.FAIL_BAD_REQUEST, map);
	    }
	    
	    boolean audMatch = false;
	    if (this.audience.match(aud)) {
            audMatch = true;
        }
	    if (!audMatch) { 
	        CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
            map.Add(Constants.ERROR_DESCRIPTION, "Audience does not apply");
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "Audience does not apply");

	        return msg.failReply(Message.FAIL_FORBIDDEN, map);
	    }

	    //6. Check if the token has a scope
	    CBORObject scope = claims.get(Constants.SCOPE);
	    if (scope == null) {
	        CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_SCOPE);
            map.Add(Constants.ERROR_DESCRIPTION, "Token has no scope");
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "Token has no scope");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
	    }
	    
	    //7. Check if any part of the scope is meaningful to us
	    boolean meaningful = false;
	    try {
	    	if(scope.getType().equals(CBORType.TextString)) {
	    		meaningful = TokenRepository.getInstance().checkScope(scope);
	    	}
	    	else {
	    		// The version of checkScope() with two arguments is invoked
	    		// This is currently expecting a structured scope for operations at the OSCORE Group Manager
	    		meaningful = TokenRepository.getInstance().checkScope(scope, aud);
	    	}
	    } catch (AceException e) {
	        LOGGER.info("Invalid scope, "
                    + "message processing aborted: " + e.getMessage());
	        CBORObject map = CBORObject.NewMap();
	        map.Add(Constants.ERROR, Constants.INVALID_SCOPE);
            map.Add(Constants.ERROR_DESCRIPTION, "Scope has invalid format");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map); 
	    }
	    if (!meaningful) {
	        CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_SCOPE);
            map.Add(Constants.ERROR_DESCRIPTION, "Scope does not apply");
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "Token's scope does not apply");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
	    }
	    
	    //8. Handle EXI if present
	    int exiSeqNum = handleExi(claims);
	    if (exiSeqNum < -1) {
	    	// The 'exi' claim is present, but an error occurs during its processing
	        CBORObject map = CBORObject.NewMap();
	        String errStr = null;
	        switch (exiSeqNum) {
	        	case -2: // the 'cti' claim is not present in the Access Token as a CBOR byte string
	        		errStr = "The Access Token includes the 'exi' claim, but the 'cti' claim is not present as a CBOR byte string";
	        		break;
	        	case -3: // the 'cti' claim is present but it is not formatted as expected
	        		errStr = "The Access Token includes the 'exi' claim, but the 'cti' claim is not formatted as expected";
	        		break;	
	        	case -4: // the Sequence Number encoded in the 'cti' claim is not greater than the stored highest Sequence Number
	        		errStr = "The Access Token includes the 'exi' claim, but the Sequence Number value is too little";
	        }
	        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, errStr);
            LOGGER.log(Level.INFO, "Message processing aborted: " + errStr);
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
	    }
	    
	    //9. Handle cnonce if required
	    try {
	        handleCnonce(claims);
	    } catch (AceException e) {
	        CBORObject map = CBORObject.NewMap();
	        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, e.getMessage());
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "error while checking cnonce: " + e.getMessage());
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
	    }
	    
		CBORObject cnf = claims.get(Constants.CNF);
		try {
	        if (cnf == null) {
	            LOGGER.severe("Token has not cnf");
	            throw new AceException("Token has no cnf");
	        }
		}
	    catch (Exception e) {
	    	LOGGER.info("Token has not cnf");
	        return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
	        
	    }
        
		boolean firstOscoreAccessToken = false;
		
	    // The OSCORE profile is being used. The Resource Server has to determine
	    // an available Recipient ID to offer to the Client.
    	if (cnf.getKeys().contains(Constants.OSCORE_Input_Material)) {
	    
    		if (msg.getSenderId() != null) {
    	        LOGGER.info("OSCORE Input Material provided over a protected POST request");
                CBORObject map = CBORObject.NewMap();
                map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
                map.Add(Constants.ERROR_DESCRIPTION, 
                        "OSCORE_Input_Material provided over a protected POST request");
    	        return msg.failReply(Message.FAIL_BAD_REQUEST, map);
    		}
    		
        	CBORObject osc = cnf.get(Constants.OSCORE_Input_Material);
        	try {
	            if (osc == null || !osc.getType().equals(CBORType.Map)) {
	                LOGGER.info("Missing or invalid parameter type for "
	                        + "'OSCORE_Input_Material', must be CBOR-map");
	                throw new AceException("invalid/missing OSCORE_Input_Material");
	            }
    		}
    	    catch (Exception e) {
    	        LOGGER.info("Invalid/missing OSCORE_Input_Material");
                CBORObject map = CBORObject.NewMap();
                map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
                map.Add(Constants.ERROR_DESCRIPTION, 
                        "invalid/missing OSCORE_Input_Material");
    	        return msg.failReply(Message.FAIL_BAD_REQUEST, map);
    	        
    	    }
    		
	    	CBORObject cbor = CBORObject.DecodeFromBytes(msg.getRawPayload());
	    	byte[] senderId = cbor.get(Constants.ACE_CLIENT_RECIPIENTID).GetByteString();
	    	
	        OSCoreCtxDB db = OscoreCtxDbSingleton.getInstance();
	        
	        // Determine an available Recipient ID to offer to the Client as ID2 (i.e., as Client's Sender ID)
	        synchronized(usedRecipientIds) {
	        	synchronized(db) {
	        	
		        	int maxIdValue;
		        	
	    			byte[] contextId = new byte[0];
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
		        			
		        			// The Recipient ID must be different than what offered by the Client in the 'id1' parameter
		        			if(Arrays.equals(senderId, recipientId))
		        				continue;
		        			
		        			// This Recipient ID is marked as not available to use
		        			if (usedRecipientIds.get(idSize - 1).contains(j))
		        				continue;
		        			
		        			try {
					        	// This Recipient ID seems to be available to use 
				        		if (!usedRecipientIds.get(idSize - 1).contains(j)) {
				        			
				        			// Double check in the database of OSCORE Security Contexts
				        			if (db.getContext(recipientId,  contextId) != null) {
				        				
				        				// A Security Context with this Recipient ID exists and was not tracked!
				        				// Update the local list of used Recipient IDs, then move on to the next candidate
				        				usedRecipientIds.get(idSize - 1).add(j);
				        				continue;
				        				
				        			}
				        			else {
				        				
				        				// This Recipient ID is actually available at the moment. Add it to the local list
				        				usedRecipientIds.get(idSize - 1).add(j);
				        				recipientIdFound = true;
				        				break;
				        			}
				        			
				        		}
		        			}
			        		catch(RuntimeException e) {
		        				// Multiple Security Contexts with this Recipient ID exist and it was not tracked!
		        				// Update the local list of used Recipient IDs, then move on to the next candidate
		        				usedRecipientIds.get(idSize - 1).add(j);
		        				continue;
			        		} catch (CoapOSException e) {
			    		        LOGGER.severe("Error while accessing the database of OSCORE Security Contexts");
			    	            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
							}
			        			
				        }
				        
				        if (recipientIdFound)
				        	break;
				        	
			        }
	        	}
	        }
	        
		    try {
		    	if (!recipientIdFound) {
		            throw new AceException("No Recipient ID available to use");
		        }
		    } catch (Exception e) {
		        LOGGER.info("No Recipient ID available to use");
	            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
	            
		    }
	
	    	claims.get(Constants.CNF).get(Constants.OSCORE_Input_Material).Add(Constants.OS_CLIENTID, CBORObject.FromObject(recipientId));
	    	claims.get(Constants.CNF).get(Constants.OSCORE_Input_Material).Add(Constants.OS_SERVERID, CBORObject.FromObject(senderId));
		    
	    	// This is not a Token for updating access rights,
	    	// but rather to establish a new OSCORE Security Context
	    	firstOscoreAccessToken = true;
	    	
	    }
	    
	    //9. Extension point for handling other special claims in the future
	    processOther(claims);
	    
	    //10. Store the claims of this token
	    CBORObject cti = null;
	    
	    //Check if we have a sid
	    String sid = msg.getSenderId();
	    try {
            cti = TokenRepository.getInstance().addToken(token, claims, this.ctx, sid, exiSeqNum);
        } catch (AceException e) {
            LOGGER.severe("Message processing aborted: " + e.getMessage());
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, e.getMessage());
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        }
	    
	    //11. Create success message
	    //Return the cti or the local identifier assigned to the token
	    CBORObject rep = CBORObject.NewMap();
	    rep.Add(Constants.CTI, cti);
	    
	    // The following enables this class to return to the specific AuthzInfo instance also the
	    // Sender Identifier associated to this Access Token, as 'SUB' parameter of the response.
	    String assignedKid = null;
	    String assignedSid;
	    try {
	    	String ctiStr = Base64.getEncoder().encodeToString(cti.GetByteString());
	    	
	    	cnf = claims.get(Constants.CNF);
	    		    	
	    	// This should really not happen for a previously validated and stored Access Token
	    	if (cnf == null) {
	            LOGGER.severe("Token has not cnf");
	            throw new AceException("Token has no cnf");
	        }
	    	// This should really not happen for a previously validated and stored Access Token
	    	if (!cnf.getType().equals(CBORType.Map)) {
	            LOGGER.severe("Malformed cnf in token");
	            throw new AceException("cnf claim malformed in token");
	        }
	    	
	    	// Rebuild the 'kid' leveraging what already happened in the Token Repository
	    	assignedKid = TokenRepository.getInstance().getKidByCti(ctiStr);
	    	
	    	// This should really not happen for a previously validated and stored Access Token
	    	if (assignedKid == null) {
	            LOGGER.severe("kid not found");
	            throw new AceException("kid not found");
	        }
	    	
	    	assignedSid = TokenRepository.getInstance().getSid(assignedKid);
	    }
	    catch (Exception e) {
	    	LOGGER.info("Unable to retrieve kid after token addition: " + e.getMessage());
	        CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, e.getMessage());
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
	    }

	    if (assignedSid != null)
	    	rep.Add(Constants.SUB, assignedSid);

	    // If the OSCORE profile is being used, and especially a new OSCORE Security Context is
	    // being established, return also the selected Recipient ID to the specific AuthzInfo instance.
	    //
	    // This is not the case when a Token is posted to update access rights, by superseding an
	    // existing Token from which the original 'cnf' claim is inherited and retained in the new Token
    	if (firstOscoreAccessToken == true) {
    		
    		String recipientIdString = Base64.getEncoder().encodeToString(recipientId);
	    	rep.Add(Constants.CLIENT_ID, recipientIdString);
	    	
    	}
    	
	    LOGGER.info("Successfully processed token");
        return msg.successReply(Message.CREATED, rep);
	}
	
	/**
	 * Extension point for handling other special claims.
	 * 
	 * @param claims all claims
	 */
	protected synchronized void processOther(Map<Short, CBORObject> claims) {
	    //No processing needed
    }

    /**
	 * Process a message containing a CWT.
	 * 
	 * Note: The behavior implemented here is the following:
	 * If we have an introspection handler, we try to introspect,
	 * if introspection fails we just return the claims from the CWT,
	 * otherwise we add the claims returned by introspection 
	 * to those of the CWT, possibly overwriting CWT claims with
	 * "fresher" introspection claim having the same id.
	 * 
	 * @param token  the token as CBOR
	 * 
	 * @return  the claims of the CWT
	 * 
	 * @throws AceException 
	 * @throws IntrospectionException 
	 * @throws CoseException
	 * 
	 * @throws Exception  when using a not supported key wrap
	 */
	protected synchronized Map<Short,CBORObject> processCWT(CBORObject token)
	        throws IntrospectionException, AceException, 
	        CoseException, Exception {
	    CWT cwt = CWT.processCOSE(token.EncodeToBytes(), this.ctx);
	    //Check if we can introspect this token
	    Map<Short, CBORObject> claims = cwt.getClaims();
	   if (this.intro != null) {
	       CBORObject cti = claims.get(Constants.CTI);
	       if (cti != null && cti.getType().equals(CBORType.ByteString)) {
	           Map<Short, CBORObject> introClaims 
	               = this.intro.getParams(cti.GetByteString());
	           if (introClaims != null) {
	               claims.putAll(introClaims);
	           }
	       }
	   }
	   return claims;
    }
    
	/**
	 * Process a message containing a reference token.
	 * 
	 * @param token  the token as CBOR
	 * 
	 * @return  the claims of the reference token
	 * @throws AceException
	 * @throws IntrospectionException 
	 */
    protected synchronized Map<Short, CBORObject> processReferenceToken(CBORObject token)
                throws AceException, IntrospectionException {
		// This should be a CBOR String
        if (token.getType() != CBORType.ByteString) {
            throw new AceException("Reference Token processing error");
        }
        
        // Try to introspect the token
        if (this.intro == null) {
            throw new AceException("Introspection handler not found");
        }
        Map<Short, CBORObject> params 
            = this.intro.getParams(token.GetByteString());        
        if (params == null) {
            params = new HashMap<>();
            params.put(Constants.ACTIVE, CBORObject.False);
        }
       
        return params;
	}
    
    /**
     * Handle exi claim, if present.
     * This is done by internally translating it to a exp claim in sync with the local time.
     * 
     * Additional checks are also performed, to ensure that the Sequence Number
     * encoded in the 'cti' claim is strictly greater than the highest Sequence Number
     * received by this Resource Server in Access Tokens that include the 'exi' claim.
     * 
     * @param claims
     * 
     * @return  It returns a positive integer if the Sequence Number is successfully extracted from the 'cti' claim
     * 		    It returns a negative integer in the following cases:
     * 			-1 : the 'exi' claim is not present
     * 		    -2 : the 'cti' claim is not present in the Access Token as a CBOR byte string
     *          -3 : the 'cti' claim is present but it is not formatted as expected
     *          -4 : the Sequence Number encoded in the 'cti' claim is not greater than the stored highest Sequence Number
     */
    private synchronized int handleExi(Map<Short, CBORObject> claims) {
    	
        CBORObject exi = claims.get(Constants.EXI);
        if (exi == null) {
        	return -1;
        }
        
        // Determine the expiration time and add it to the Access Token as value of an 'exp' claim
        Long now = this.time.getCurrentTime();
        Long exp = now + exi.AsNumber().ToInt64Checked();
        claims.put(Constants.EXP, CBORObject.FromObject(exp));
        
        // Check that the 'cti' claim is also present
        CBORObject cticb = claims.get(Constants.CTI);
        if (cticb == null || cticb.getType() != CBORType.ByteString) {
        	// The 'cti' claim is not included in the Access Token as a CBOR byte string.
    		return -2;
        }
        
        // Retrieve the Sequence Number from the 'cti' claim
        int seqNum = TokenRepository.getInstance().getExiSeqNumFromCti(cticb.GetByteString());
        
        if (seqNum < 0) {
        	// The 'cti' claim is malformed
        	return -3;
        }        
        if (seqNum <= TokenRepository.getInstance().getTopExiSequenceNumber()) {
        	// The Sequence Number encoded in the 'cti' claim is not greater than the stored highest Sequence Number
        	return -4;
        }
        
        return seqNum;
        
    }
    
    /**
     * Handle cnonce if required
     * @throws AceException 
     */
    private synchronized void handleCnonce(Map<Short, CBORObject> claims) throws AceException {
        if (this.checkCnonce) {
            CnonceHandler.getInstance().checkNonce(claims);
        }
    }
    
    @Override
    public void close() throws AceException {
        if (TokenRepository.getInstance() != null) {
            TokenRepository.getInstance().close();
        }       
    }	
}
