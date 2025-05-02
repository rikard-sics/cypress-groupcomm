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
package se.sics.ace.oscore.rs;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import org.eclipse.californium.oscore.OSException;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.Message;
import se.sics.ace.TimeProvider;
import se.sics.ace.coap.CoapReq;
import se.sics.ace.coap.rs.oscoreProfile.OscoreCtxDbSingleton;
import se.sics.ace.coap.rs.oscoreProfile.OscoreSecurityContext;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.oscore.GroupInfo;
import se.sics.ace.rs.AudienceValidator;
import se.sics.ace.rs.AuthzInfo;
import se.sics.ace.rs.IntrospectionHandler;
import se.sics.ace.rs.ScopeValidator;
import se.sics.ace.rs.TokenRepository;


/**
 * This class implements the /authz_info endpoint at the RS that receives
 * access tokens, verifies if they are valid and then stores them.
 * 
 * Note this implementation requires the following claims in a CWT:
 * iss, sub, scope, aud.
 * 
 * @author Marco Tiloca
 *
 */
public class OscoreAuthzInfoGroupOSCORE extends AuthzInfo {
	
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(OscoreAuthzInfoGroupOSCORE.class.getName());

    /**
     * Temporary storage for the CNF claim
     */
    private CBORObject cnf;
    
    /**
	 * Handles audience validation
	 */
	private GroupOSCOREJoinValidator audience;
    
    /**
     * OSCORE groups active under the Group Manager
     */

	private Map<String, GroupInfo> activeGroups;
	
	private final String rootGroupMembershipResource = "ace-group";
	
	/**
	 * Constructor.
	 * 
	 * @param tr  a token repository
	 * @param issuers  the list of acceptable issuer of access tokens
	 * @param time  the time provider
	 * @param intro  the introspection handler (can be null)
	 * @param rsId  the identifier of the Resource Server
	 * @param audience  the audience validator
	 * @param ctx  the crypto context to use with the As
	 * @param tokenFile  the file where to save tokens when persisting
     * @param scopeValidator  the application specific scope validator 
	 * @param checkCnonce  true if this RS uses cnonces for freshness validation
	 * @throws IOException 
	 * @throws AceException 
	 */
	public OscoreAuthzInfoGroupOSCORE(List<String> issuers, 
			TimeProvider time, IntrospectionHandler intro, String rsId, 
			AudienceValidator audience, CwtCryptoCtx ctx, String tokenFile,
			ScopeValidator scopeValidator, boolean checkCnonce) 
			        throws AceException, IOException {

		super(issuers, time, intro, rsId, audience, ctx, null, 0, tokenFile, 
		        scopeValidator, checkCnonce);
		
		this.audience = (GroupOSCOREJoinValidator) audience;
		
	}

	@Override
	public synchronized Message processMessage(Message msg) {
	    LOGGER.log(Level.INFO, "received message: " + msg);
	    CBORObject token = null;
	    CBORObject cbor = null;
	    boolean provideSignInfo = false;
	    boolean provideEcdhInfo = false;
	    boolean invalid = false;
	    
		if (msg instanceof CoapReq) {
			// Check that the content-format is application/ace+cbor
			if (((CoapReq) msg).getOptions().getContentFormat() != Constants.APPLICATION_ACE_CBOR) {
				LOGGER.info("Invalid content-format");
				CBORObject map = CBORObject.NewMap();
				map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
				map.Add(Constants.ERROR_DESCRIPTION, "Invalid content-format");
				return msg.failReply(Message.FAIL_BAD_REQUEST, map);
			}
		}
	    
        try {
            cbor = CBORObject.DecodeFromBytes(msg.getRawPayload());
        } catch (Exception e) {
            LOGGER.info("Invalid payload at authz-info: " + e.getMessage());
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, "Invalid payload");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        }
        
        if (!cbor.getType().equals(CBORType.Map)) {
            LOGGER.info("Invalid payload at authz-info: not a cbor map");
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, 
                    "Payload to authz-info must be a CBOR map");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        }
        
        CBORObject nonce = null;
        CBORObject senderIdCBOR = null;
        
        String subject = msg.getSenderId();
        
        // This Token POST is not protected; then the parameters Nonce1 and Id1 have to be present.
        // Otherwise, if the Token POST is protected, these parameters are not expected, and are silently ignored if present
        if (subject == null) {
	        nonce = cbor.get(CBORObject.FromObject(Constants.NONCE1));
	        if (nonce == null || !nonce.getType().equals(CBORType.ByteString)) {
	            LOGGER.info("Missing or invalid parameter type for:"
	                    + "'nonce1', must be present and byte-string");
	            CBORObject map = CBORObject.NewMap();
	            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
	            map.Add(Constants.ERROR_DESCRIPTION, 
	                    "Malformed or missing parameter 'nonce1'");
	            return msg.failReply(Message.FAIL_BAD_REQUEST, map); 
	        }
	        
	        senderIdCBOR = cbor.get(CBORObject.FromObject(Constants.ACE_CLIENT_RECIPIENTID));
	        if (senderIdCBOR == null || !senderIdCBOR.getType().equals(CBORType.ByteString)) {
	            LOGGER.info("Missing or invalid parameter type for:"
	                    + "'id1', must be present and byte-string");
	            CBORObject map = CBORObject.NewMap();
	            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
	            map.Add(Constants.ERROR_DESCRIPTION, 
	                    "Malformed or missing parameter 'id1'");
	            return msg.failReply(Message.FAIL_BAD_REQUEST, map); 
	        }
        }
        
        token = cbor.get(CBORObject.FromObject(Constants.ACCESS_TOKEN));
        if (token == null) {
            LOGGER.info("Missing parameter 'access_token'");
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, "Missing mandatory parameter 'access_token'");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        }
        if (!token.getType().equals(CBORType.ByteString)) {
            LOGGER.info("Invalid parameter type for 'access_token', it must be a byte-string");
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, "Unknown token format");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        }

        CBORObject tokenAsCbor = CBORObject.DecodeFromBytes(token.GetByteString());
        if (!tokenAsCbor.getType().equals(CBORType.ByteString) && !tokenAsCbor.getType().equals(CBORType.Array)) {
            LOGGER.info("Invalid parameter type for 'access_token', must be present and byte-string");
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION,"Failed deserialization of parameter 'access_token'");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        }        
        
        if (cbor.ContainsKey(CBORObject.FromObject(Constants.SIGN_INFO))) {
    		if (cbor.get(CBORObject.FromObject(Constants.SIGN_INFO)).equals(CBORObject.Null)) {
    			provideSignInfo = true;
    		}
    		else invalid = true;
    	}
    	
        if (cbor.ContainsKey(CBORObject.FromObject(Constants.ECDH_INFO))) {
    		if (cbor.get(CBORObject.FromObject(Constants.ECDH_INFO)).equals(CBORObject.Null)) {
    			provideEcdhInfo = true;
    		}
    		else invalid = true;
    	}
        
        if (invalid) {
            LOGGER.info("Invalid format for 'sign_info'");
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, 
                    "Invalid format for 'sign_info'");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        }
        
        Message reply = super.processToken(tokenAsCbor, msg);
        if (reply.getMessageCode() != Message.CREATED) {
            return reply;
        }
        
        if (this.cnf == null) { //Should never happen, caught in TokenRepository
            LOGGER.info("Missing required parameter 'cnf'");
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            return msg.failReply(Message.FAIL_BAD_REQUEST, map); 
        }
        
        CBORObject payload = CBORObject.NewMap();
        
        CBORObject authzInfoResponse = CBORObject.DecodeFromBytes(reply.getRawPayload());
        
        
        // If the Token POST was a non protected request, then Nonces and IDs have
        // to be exchanged, and a new OSCORE Security Context has to be established
        if (subject == null) {
	        String recipientIdString = authzInfoResponse.get(
	                CBORObject.FromObject(Constants.CLIENT_ID)).AsString();
	        if (recipientIdString == null) {
	            LOGGER.info("Missing mandatory parameter 'client_id'");
	            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
	        }
	        byte[] recipientId = Base64.getDecoder().decode(recipientIdString);
	        
	        byte[] n1 = nonce.GetByteString();
	        byte[] n2 = new byte[8];
	        new SecureRandom().nextBytes(n2);
	                
	        OscoreSecurityContext osc;
	        try {
	            osc = new OscoreSecurityContext(this.cnf);
	        } catch (AceException e) {
	            CBORObject map = CBORObject.NewMap();
	            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
	            map.Add(Constants.ERROR_DESCRIPTION, e.getMessage());
	            return msg.failReply(Message.FAIL_BAD_REQUEST, map); 
	        }
	            
	        OSCoreCtx ctx;
	        try {
	            ctx = osc.getContext(false, n1, n2);
	
	            OSCoreCtxDB db = OscoreCtxDbSingleton.getInstance();
	            
	            synchronized(db) {
	            	
	            	boolean install = true;
					byte[] idContext = null;
	            	
					CBORObject responseMap = CBORObject.DecodeFromBytes(reply.getRawPayload());
					CBORObject subjectCbor = responseMap.get(Constants.SUB);
					String subjectStr = subjectCbor.AsString();
					int index = subjectStr.indexOf(":");

					if (index >= 0) {
						// Extract the OSCORE ID Context
						String idContextStr = subjectStr.substring(0, index);
						idContext = Base64.getDecoder().decode(idContextStr);
					}
	            	
	    			try {
    					
	    				// Double check in the database that the OSCORE Security Context
	    				// with the selected Recipient ID is actually still not present
						if (idContext == null && db.getContext(recipientId) != null) {
	        				// A Security Context with this Recipient ID exists!
	        				install = false;
	        			}
						else if (idContext != null && db.getContext(recipientId, idContext) != null) {
							// A Security Context with this ID Context and Recipient ID exists!
							install = false;
						}

	    			}
	        		catch(RuntimeException e) {
	    				// Multiple Security Contexts with this Recipient ID exist!
	    				install = false;
	        		}
	            	
	    			if (install)
	    				db.addContext(ctx);
	    			else {
	    	            LOGGER.info("An OSCORE Security Context with the same Recipient ID"
					               + " has been installed while running the OSCORE profile");
	    	            
	    	            // Delete the stored Access Token to prevent a deadlock
	    	    	    CBORObject ctiCbor = responseMap.get(Constants.CTI);
	    	    	    String cti = Base64.getEncoder().encodeToString(ctiCbor.GetByteString());
	    	    	    try {
	    	    	    	TokenRepository.getInstance().removeToken(cti);
	    	    	    }
	    	    	    catch (AceException e) {
	    	                LOGGER.info("Error while deleting an Access Token: " + e.getMessage());
	    	    	    }
	    	            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
	    			}
	            }
	
	        } catch (OSException e) {
	            LOGGER.info("Error while creating OSCORE context: " 
	                    + e.getMessage());
	            CBORObject map = CBORObject.NewMap();
	            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
	            map.Add(Constants.ERROR_DESCRIPTION, 
	                    "Error while creating OSCORE security context: "
	                    + e.getMessage());
	            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
	        }
	        
	        payload.Add(Constants.NONCE2, n2);
	        payload.Add(Constants.ACE_SERVER_RECIPIENTID, recipientId);
        
        }
        
        //Return the cti or the local identifier assigned to the token
	    CBORObject responseMap = CBORObject.DecodeFromBytes(reply.getRawPayload());
	    CBORObject cti = responseMap.get(CBORObject.FromObject(Constants.CTI));
	    payload.Add(Constants.CTI, cti);
	    	
    	boolean error = true;
    	
	    String ctiStr = Base64.getEncoder().encodeToString(cti.GetByteString());
	    Map<Short, CBORObject> claims = TokenRepository.getInstance().getClaims(ctiStr);
    	
    	// Check that audience and scope are consistent with the access to a join resource.
	    // Consistency checks have been already performed when processing the Token upon posting
	    
    	CBORObject scope = claims.get(Constants.SCOPE);
    	
    	if (scope.getType().equals(CBORType.ByteString)) {
    		
    		Set<String> myGMAudiences = this.audience.getAllGMAudiences();
    		Set<String> myJoinResources = this.audience.getAllJoinResources();
    		
    		CBORObject audCbor = claims.get(Constants.AUD);
    		String aud = audCbor.AsString();
    		
    		
    		byte[] rawScope = scope.GetByteString();
    		CBORObject cborScope = CBORObject.DecodeFromBytes(rawScope);
    		Set<String> groupNames = new HashSet<>();
    		
    		// Check that the audience is in fact a Group Manager
			if (myGMAudiences.contains(aud)) {
				error = false;
	    	}
    		
      	  	for (int entryIndex = 0; entryIndex < cborScope.size(); entryIndex++)
      	  		groupNames.add(cborScope.get(entryIndex).get(0).AsString());
    		
    		// Check that all the group names in scope refer to group-membership resources
    		if (error == false) {
    			for (String groupName : groupNames) {
    				if (myJoinResources.contains(rootGroupMembershipResource + "/" + groupName) == false) {
    					error = true;
    					break;
    				}
    			}
    		}
    		
    		if (error == true) {
                LOGGER.info("The audience must be a Group Manager; group name must point at group-membership resources of that Group Manager");
                CBORObject map = CBORObject.NewMap();
                map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
                return msg.failReply(Message.FAIL_BAD_REQUEST, map); 
            }
    		
        	// Add the nonce for PoP of the Client's private key in the Join Request
            byte[] rsnonce = new byte[8];
            new SecureRandom().nextBytes(rsnonce);
            payload.Add(Constants.KDCCHALLENGE, rsnonce);
            
    	    CBORObject sid = responseMap.get(CBORObject.FromObject(Constants.SUB));
    	    
    	    if (sid == null) { // This should never happen, as handled in TokenRepository.
                LOGGER.info("Missing Sender ID after valid Access Token Posting");
                CBORObject map = CBORObject.NewMap();
                map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
                return msg.failReply(Message.FAIL_BAD_REQUEST, map); 
            }
    	    
    	    // Add to the Token Repository an entry (sid, rsnonce)
    	    TokenRepository.getInstance().setRsnonce(sid.AsString(), Base64.getEncoder().encodeToString(rsnonce));
    	    
	    	if (provideSignInfo || provideEcdhInfo) {
	    	    
	    		CBORObject signInfo = CBORObject.NewArray();
	    		CBORObject ecdhInfo = CBORObject.NewArray();
	    	
				for (String groupName : groupNames) {
					
		        	// Retrieve the entry for the target group, using the name of the OSCORE group
		        	GroupInfo myGroup = this.activeGroups.get(groupName);
					
		        	// The group uses the group mode
		        	if (provideSignInfo && myGroup.getMode() != Constants.GROUP_OSCORE_PAIRWISE_MODE_ONLY) {
		        	
						CBORObject signInfoEntry = CBORObject.NewArray();
						
						// 'id' element
						signInfoEntry.Add(CBORObject.FromObject(groupName));
						
						// 'sign_alg' element
						signInfoEntry.Add(myGroup.getSignAlg().AsCBOR());
				    	
						// 'sign_parameters' element (The algorithm capabilities)
				    	CBORObject arrayElem = myGroup.getSignParams().get(0);
				    	if (arrayElem == null)
				    		signInfoEntry.Add(CBORObject.Null);
				    	else
				    		signInfoEntry.Add(arrayElem);
				    	
				    	// 'sign_key_parameters' element (The key type capabilities)
				    	arrayElem = myGroup.getSignParams().get(1);
				    	if (arrayElem == null)
				    		signInfoEntry.Add(CBORObject.Null);
				    	else
				    		signInfoEntry.Add(arrayElem);
				    	
				    	// 'cred_fmt' element
				    	signInfoEntry.Add(myGroup.getAuthCredFormat());
	
					    signInfo.Add(signInfoEntry);
		        	}
		        	
		        	// The group uses the pairwise mode
		        	if (provideEcdhInfo && myGroup.getMode() != Constants.GROUP_OSCORE_GROUP_MODE_ONLY) {
		        	
						CBORObject ecdhEntry = CBORObject.NewArray();
						
						// 'id' element
						ecdhEntry.Add(CBORObject.FromObject(groupName));
						
						// 'ecdh_alg' element
						ecdhEntry.Add(myGroup.getEcdhAlg().AsCBOR());
				    	
						// 'ecdh_parameters' element (The algorithm capabilities)
				    	CBORObject arrayElem = myGroup.getEcdhParams().get(0);
				    	if (arrayElem == null)
				    		ecdhEntry.Add(CBORObject.Null);
				    	else
				    		ecdhEntry.Add(arrayElem);
				    	
				    	// 'ecdh_key_parameters' element (The key type capabilities)
				    	arrayElem = myGroup.getEcdhParams().get(1);
				    	if (arrayElem == null)
				    		ecdhEntry.Add(CBORObject.Null);
				    	else
				    		ecdhEntry.Add(arrayElem);
				    	
				    	// 'cred_fmt' element
				    	ecdhEntry.Add(myGroup.getAuthCredFormat());
	
					    ecdhInfo.Add(ecdhEntry);
		        	}
				    
				}

				if (provideSignInfo && signInfo.size() != 0)
					payload.Add(Constants.SIGN_INFO, signInfo);
				
				if (provideEcdhInfo && ecdhInfo.size() != 0)
					payload.Add(Constants.ECDH_INFO, ecdhInfo);
		    
	    	}
    		
    	}
    	
        LOGGER.info("Successfully processed OSCORE token");
        return msg.successReply(reply.getMessageCode(), payload);
	}

	/**
	 * @param activeGroups
	 */
	public synchronized void setActiveGroups(Map<String, GroupInfo> activeGroups) {
		this.activeGroups = activeGroups;
	}
	
	@Override
	protected synchronized void processOther(Map<Short, CBORObject> claims) {
	    this.cnf = claims.get(Constants.CNF);
	}

    @Override
    public void close() throws AceException {
       super.close();
        
    }	
}
