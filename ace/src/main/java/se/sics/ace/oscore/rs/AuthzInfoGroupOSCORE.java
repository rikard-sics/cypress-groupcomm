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

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.Message;
import se.sics.ace.TimeProvider;
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
public class AuthzInfoGroupOSCORE extends AuthzInfo {
	
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(AuthzInfo.class.getName());
	
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
	
	private final String rootGroupMembershipResource;
	
	/**
	 * Constructor.
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
	 * @param activeGroups   OSCORE groups active under the Group Manager
	 * @throws AceException  if the token repository is not initialized
	 * @throws IOException 
	 */
	public AuthzInfoGroupOSCORE(List<String> issuers, 
			TimeProvider time, IntrospectionHandler intro, String rsId,
			AudienceValidator audience, CwtCryptoCtx ctx, byte[] keyDerivationKey, int derivedKeySize,
			String tokenFile, ScopeValidator scopeValidator, boolean checkCnonce) 
			        throws AceException, IOException {
		
		super(issuers, time, intro, rsId, audience, ctx, keyDerivationKey, derivedKeySize, tokenFile, 
		        scopeValidator, checkCnonce);
		
		this.audience = (GroupOSCOREJoinValidator) audience;
		
		this.rootGroupMembershipResource = this.audience.getRootGroupMembershipResource();
		
	}

	@Override
	public synchronized Message processMessage(Message msg) {
	    LOGGER.log(Level.INFO, "received message: " + msg);
	    CBORObject token = null;
	    CBORObject cbor = null;
	    boolean provideSignInfo = false;
	    boolean provideEcdhInfo = false;
	    boolean invalid = false;
	    
	    try {
	    	cbor = CBORObject.DecodeFromBytes(msg.getRawPayload());
	    }
	    catch (Exception e) {
            LOGGER.info("Invalid payload at authz-info: " + e.getMessage());
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, "Invalid payload");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        }
	    	
	    // The payload of the Token POST message is a map. Retrieve the Token from it.
	    // This is a possible case when the joining node asks the Group Manager for
	    // information on the algorithms and parameters used in the OSCORE group.
	    if (cbor.getType().equals(CBORType.Map)) {
	    		
	    	token = cbor.get(CBORObject.FromObject(Constants.ACCESS_TOKEN));
	    		
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
	    	
	    }
	    // The payload of the Token POST message consists of the Access Token only.
	    // This is the expected usual case, when the client does not include additional parameters.
	    else {
	    		
	    	token = cbor;
	    		
	    }
	    
        if (token == null) {
            LOGGER.info("Missing mandatory parameter 'access_token'");
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, 
                    "Missing mandatory parameter 'access_token'");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        }
        
        if (invalid) {
            LOGGER.info("Invalid format for 'sign_info'");
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, 
                    "Invalid format for 'sign_info'");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        }
	    
	    Message reply = super.processToken(token, msg);
        if (reply.getMessageCode() != Message.CREATED) {
            return reply;
        }
        
        if (this.cnf == null) {//Should never happen, caught in TokenRepository.
            LOGGER.info("Missing required parameter 'cnf'");
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            return msg.failReply(Message.FAIL_BAD_REQUEST, map); 
        }
	    
	    //Return the cti or the local identifier assigned to the token
	    CBORObject rep = CBORObject.NewMap();
	    CBORObject responseMap = CBORObject.DecodeFromBytes(reply.getRawPayload());
	    CBORObject cti = responseMap.get(CBORObject.FromObject(Constants.CTI));
	    rep.Add(Constants.CTI, cti);
	    	
    	boolean error = true;
    	
	    String ctiStr = Base64.getEncoder().encodeToString(cti.GetByteString());
	    Map<Short, CBORObject> claims = TokenRepository.getInstance().getClaims(ctiStr);
    	
    	// Check that audience and scope are consistent with the access to a group-membership resource.
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
            rep.Add(Constants.KDCCHALLENGE, rsnonce);
            
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
    	            rep.Add(Constants.SIGN_INFO, signInfo);
    	        
    	        if (provideEcdhInfo && ecdhInfo.size() != 0)
    	            rep.Add(Constants.ECDH_INFO, ecdhInfo);

    	    }
    		
    	}
	    
	    
	    LOGGER.info("Successfully processed token");
        return msg.successReply(reply.getMessageCode(), rep);
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
