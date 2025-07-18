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
package se.sics.ace.oscore.rs.oscoreGroupManager;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.GroupcommErrors;
import se.sics.ace.GroupcommParameters;
import se.sics.ace.Util;
import se.sics.ace.coap.CoapReq;
import se.sics.ace.oscore.GroupInfo;
import se.sics.ace.oscore.GroupOSCOREInputMaterialObjectParameters;
import se.sics.ace.oscore.OSCOREInputMaterialObjectParameters;
import se.sics.ace.oscore.rs.GroupOSCOREValidator;
import se.sics.ace.rs.TokenRepository;

/**
 * Definition of the Group OSCORE group-membership resource
 */
public class GroupOSCOREGroupMembershipResource extends CoapResource {
	
	private Map<String, GroupInfo> existingGroupInfo = new HashMap<>();
	
	private final String rootGroupMembershipResourcePath; 
	
	private Map<String, Map<String, Set<Short>>> myScopes;
	
	private GroupOSCOREValidator valid;
	
	/**
     * Constructor
     * @param resId  the resource identifier
     * @param existingGroupInfo  the set of information of the existing OSCORE groups
     * @param rootGroupMembershipResourcePath  the path of the root group-membership resource
     * @param myScopes  the scopes of this OSCORE Group Manager
     * @param valid  the access validator of this OSCORE Group Manager
     */
    public GroupOSCOREGroupMembershipResource(String resId,
    										  Map<String, GroupInfo> existingGroupInfo,
    										  String rootGroupMembershipResourcePath,
    										  Map<String, Map<String, Set<Short>>> myScopes,
    										  GroupOSCOREValidator valid) {
        
        // set resource identifier
        super(resId);
        
        // set display name
        getAttributes().setTitle("Group OSCORE Group-Membership Resource " + resId);
     
        this.existingGroupInfo = existingGroupInfo;
        this.rootGroupMembershipResourcePath = rootGroupMembershipResourcePath;
        this.myScopes = myScopes;
        this.valid = valid;
    }
    
    @Override
    public void handleGET(CoapExchange exchange) {
    	System.out.println("GET request reached the GM");
    	
    	// Retrieve the entry for the target group, using the last path segment
    	// of the URI path as the name of the OSCORE group
    	GroupInfo targetedGroup = existingGroupInfo.get(this.getName());
    	
    	// This should never happen if existing groups are maintained properly
    	if (targetedGroup == null) {
        	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE,
        					 "Error when retrieving material for the OSCORE group");
        	return;
    	}
    	
    	String groupName = targetedGroup.getGroupName();
    	
    	// This should never happen if active groups are maintained properly
	  		if (!groupName.equals(this.getName())) {
        	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE,
        					 "Error when retrieving material for the OSCORE group");
				return;
			}  
    	
    	String subject = null;
    	Request request = exchange.advanced().getCurrentRequest();
        
        try {
			subject = CoapReq.getInstance(request).getSenderId();
		} catch (AceException e) {
		    System.err.println("Error while retrieving the client identity: " + e.getMessage());
		}
        if (subject == null) {
        	// At this point, this should not really happen,
        	// due to the earlier check at the Token Repository
        	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED,
        					 "Unauthenticated client tried to get access");
        	return;
        }
    	
    	if (!targetedGroup.isGroupMember(subject)) {	
    		// The requester is not a current group member.
    		CBORObject responseMap = CBORObject.NewMap();
    		
    		CBORObject aceGroupcommError = CBORObject.NewMap();
    		aceGroupcommError.Add(0, GroupcommErrors.ONLY_FOR_GROUP_MEMBERS);
    		responseMap.Add(Constants.PROBLEM_DETAIL_ACE_GROUPCOMM_ERROR, aceGroupcommError);
    		responseMap.Add(Constants.PROBLEM_DETAIL_KEY_TITLE, GroupcommErrors.DESCRIPTION[GroupcommErrors.ONLY_FOR_GROUP_MEMBERS]);

    		byte[] responsePayload = responseMap.EncodeToBytes();
    		exchange.respond(CoAP.ResponseCode.FORBIDDEN,
    						 responsePayload,
    						 Constants.APPLICATION_CONCISE_PROBLEM_DETAILS_CBOR);
    		
    		return;
    	}
        
    	// Respond to the Key Distribution Request
        
    	CBORObject myResponse = CBORObject.NewMap();
    	
    	// Key Type Value assigned to the Group_OSCORE_Input_Material object.
    	myResponse.Add(GroupcommParameters.GKTY, CBORObject.FromObject(GroupcommParameters.GROUP_OSCORE_INPUT_MATERIAL_OBJECT));
    	
    	// This map is filled as the Group_OSCORE_Input_Material object
    	CBORObject myMap = CBORObject.NewMap();
    	
    	// Fill the 'key' parameter
    	// Note that no Sender ID is included
    	myMap.Add(OSCOREInputMaterialObjectParameters.hkdf, targetedGroup.getHkdf().AsCBOR());
    	myMap.Add(OSCOREInputMaterialObjectParameters.salt, targetedGroup.getMasterSalt());
    	myMap.Add(OSCOREInputMaterialObjectParameters.ms, targetedGroup.getMasterSecret());
    	myMap.Add(OSCOREInputMaterialObjectParameters.contextId, targetedGroup.getGroupId());
    	myMap.Add(GroupOSCOREInputMaterialObjectParameters.cred_fmt, targetedGroup.getAuthCredFormat());
    	if (targetedGroup.getMode() != GroupcommParameters.GROUP_OSCORE_PAIRWISE_MODE_ONLY) {
    		// The group mode is used
    		myMap.Add(GroupOSCOREInputMaterialObjectParameters.gp_enc_alg, targetedGroup.getGpEncAlg().AsCBOR());
        	myMap.Add(GroupOSCOREInputMaterialObjectParameters.sign_alg, targetedGroup.getSignAlg().AsCBOR());
        	if (targetedGroup.getSignParams().size() != 0)
        		myMap.Add(GroupOSCOREInputMaterialObjectParameters.sign_params, targetedGroup.getSignParams());
    	}
    	if (targetedGroup.getMode() != GroupcommParameters.GROUP_OSCORE_GROUP_MODE_ONLY) {
    		// The pairwise mode is used
    		myMap.Add(OSCOREInputMaterialObjectParameters.alg, targetedGroup.getAlg().AsCBOR());
        	myMap.Add(GroupOSCOREInputMaterialObjectParameters.ecdh_alg, targetedGroup.getEcdhAlg().AsCBOR());
        	if (targetedGroup.getEcdhParams().size() != 0)
        		myMap.Add(GroupOSCOREInputMaterialObjectParameters.ecdh_params, targetedGroup.getEcdhParams());
    	}
    	myResponse.Add(GroupcommParameters.KEY, myMap);
    	
    	// The current version of the symmetric keying material
    	myResponse.Add(GroupcommParameters.NUM, CBORObject.FromObject(targetedGroup.getVersion()));
    	
    	// CBOR Value assigned to the coap_group_oscore profile.
    	myResponse.Add(GroupcommParameters.ACE_GROUPCOMM_PROFILE, CBORObject.FromObject(GroupcommParameters.COAP_GROUP_OSCORE_APP));
    	
    	long expValue = targetedGroup.getExp();
    	long exiValue = expValue - (System.currentTimeMillis() / 1000L);
    	
    	// Expiration time in seconds, after which the OSCORE Security Context
    	// derived from the 'k' parameter is not valid anymore.
    	myResponse.Add(GroupcommParameters.EXP, CBORObject.FromObject(expValue));
    	
    	// Number of seconds after which the OSCORE Security Context
    	// derived from the 'k' parameter is not valid anymore.
    	myResponse.Add(GroupcommParameters.EXI, CBORObject.FromObject(exiValue));

    	byte[] responsePayload = myResponse.EncodeToBytes();
    	
    	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);
    	coapResponse.setPayload(responsePayload);
    	coapResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);

    	exchange.respond(coapResponse);

    }
    
    @Override
    public void handlePOST(CoapExchange exchange) {
        
    	System.out.println("POST request reached the GM");
    	
    	String groupName;
    	Set<String> roles = new HashSet<>();
    	boolean provideAuthCreds = false;
    	
    	String subject = null;
    	Request request = exchange.advanced().getCurrentRequest();
        
        try {
			subject = CoapReq.getInstance(request).getSenderId();
		} catch (AceException e) {
		    System.err.println("Error while retrieving the client identity: " + e.getMessage());
		}
        if (subject == null) {
        	// At this point, this should not really happen, due to the earlier check at the Token Repository
        	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED,
        				     "Unauthenticated client tried to get access");
        	return;
        }
        
        String rsNonceString = TokenRepository.getInstance().getRsnonce(subject);
        
        if(rsNonceString == null) {
        	// Return an error response, with a new nonce for PoP of
        	// the Client's private key in the next Join Request
    	    CBORObject responseMap = CBORObject.NewMap();
            byte[] rsnonce = new byte[8];
            new SecureRandom().nextBytes(rsnonce);
            responseMap.Add(GroupcommParameters.KDCCHALLENGE, rsnonce);
            TokenRepository.getInstance().setRsnonce(subject, Base64.getEncoder().encodeToString(rsnonce));
            byte[] responsePayload = responseMap.EncodeToBytes();
        	exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
        					 responsePayload,
        					 Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        	return;
        }
                    
        byte[] rsnonce = Base64.getDecoder().decode(rsNonceString);
    	
    	byte[] requestPayload = exchange.getRequestPayload();
    	
    	if(requestPayload == null) {
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
    						 "A payload must be present");
    		return;
    	}
    	
    	CBORObject joinRequest = CBORObject.DecodeFromBytes(requestPayload);
    	
		CBORObject errorResponseMap = CBORObject.NewMap();
    	
    	// Prepare the 'sign_info' and 'ecdh_info' parameter,
		// to possibly return it in a 4.00 (Bad Request) response        	
		CBORObject signInfo = CBORObject.NewArray();
    	CBORObject ecdhInfo = CBORObject.NewArray();
			
    	// Retrieve the entry for the target group, using the last path segment of
    	// the URI path as the name of the OSCORE group
    	GroupInfo targetedGroup = existingGroupInfo.get(this.getName());
		
    	// This should never happen if existing groups are maintained properly
    	if (targetedGroup == null) {
        	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE,
        					 "Error when retrieving material for the OSCORE group");
        	return;
    	}
    	
    	if (!targetedGroup.getStatus()) {
    		// The group is currently inactive and no new members are admitted
    		CBORObject responseMap = CBORObject.NewMap();
    		
    		CBORObject aceGroupcommError = CBORObject.NewMap();
    		aceGroupcommError.Add(0, GroupcommErrors.GROUP_NOT_ACTIVE);
    		responseMap.Add(Constants.PROBLEM_DETAIL_ACE_GROUPCOMM_ERROR, aceGroupcommError);
    		responseMap.Add(Constants.PROBLEM_DETAIL_KEY_TITLE, GroupcommErrors.DESCRIPTION[GroupcommErrors.GROUP_NOT_ACTIVE]);
    		
    		byte[] responsePayload = responseMap.EncodeToBytes();
    		exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE,
    						 responsePayload,
    						 Constants.APPLICATION_CONCISE_PROBLEM_DETAILS_CBOR);
    		
    		return;
    	}
    	
    	// The group mode is used
    	if (targetedGroup.getMode() != GroupcommParameters.GROUP_OSCORE_PAIRWISE_MODE_ONLY) {
			CBORObject signInfoEntry = CBORObject.NewArray();
			signInfoEntry.Add(CBORObject.FromObject(targetedGroup.getGroupName())); // 'id' element
			signInfoEntry.Add(targetedGroup.getSignAlg().AsCBOR()); // 'sign_alg' element
			
			// 'sign_parameters' element (The algorithm capabilities)
	    	CBORObject arrayElem = targetedGroup.getSignParams().get(0);
	    	if (arrayElem == null)
	    		signInfoEntry.Add(CBORObject.Null);
	    	else
	    		signInfoEntry.Add(arrayElem);
	    	
	    	// 'sign_key_parameters' element (The key type capabilities)
	    	arrayElem = targetedGroup.getSignParams().get(1);
	    	if (arrayElem == null)
	    		signInfoEntry.Add(CBORObject.Null);
	    	else
	    		signInfoEntry.Add(arrayElem);
	    	
	    	// 'cred_fmt' element
	    	signInfoEntry.Add(targetedGroup.getAuthCredFormat());
		    signInfo.Add(signInfoEntry);
		    errorResponseMap.Add(GroupcommParameters.SIGN_INFO, signInfo);
    	}
    	
    	// The pairwise mode is used
    	if (targetedGroup.getMode() != GroupcommParameters.GROUP_OSCORE_GROUP_MODE_ONLY) {
			CBORObject ecdhInfoEntry = CBORObject.NewArray();
			ecdhInfoEntry.Add(CBORObject.FromObject(targetedGroup.getGroupName())); // 'id' element
			ecdhInfoEntry.Add(targetedGroup.getEcdhAlg().AsCBOR()); // 'ecdh_alg' element
			
			// 'ecdh_parameters' element (The algorithm capabilities)
	    	CBORObject arrayElem = targetedGroup.getEcdhParams().get(0);
	    	if (arrayElem == null)
	    		ecdhInfoEntry.Add(CBORObject.Null);
	    	else
	    		ecdhInfoEntry.Add(arrayElem);
	    	
	    	// 'ecdh_key_parameters' element (The key type capabilities)
	    	arrayElem = targetedGroup.getEcdhParams().get(1);
	    	if (arrayElem == null)
	    		ecdhInfoEntry.Add(CBORObject.Null);
	    	else
	    		ecdhInfoEntry.Add(arrayElem);
	    	
	    	// 'cred_fmt' element
	    	ecdhInfoEntry.Add(targetedGroup.getAuthCredFormat());
		    ecdhInfo.Add(ecdhInfoEntry);
		    errorResponseMap.Add(GroupcommParameters.ECDH_INFO, ecdhInfo);
    	}
	    
	    
    	// The payload of the join request must be a CBOR Map
    	if (!joinRequest.getType().equals(CBORType.Map)) {
    		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
    						 errorResponsePayload,
    						 Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
    		return;
    	}
    		
    	// More steps follow:
    	//
    	// Retrieve 'scope' from the map; check the GroupID against the name of the resource, just for consistency.
    	//
    	// Retrieve the role(s) to possibly reduce the set of material to provide to the joining node.
    	//
    	// Any other check is performed through the method canAccess() of the TokenRepository, which is
    	// in turn invoked by the deliverRequest() method of CoapDeliverer, upon getting the join request.
    	// The actual checks of legitimate access are performed by scopeMatchResource() and scopeMatch()
    	// of the GroupOSCOREJoinValidator used as Scope/Audience Validator.
    	
    	// Retrieve scope
    	CBORObject scope = joinRequest.get(CBORObject.FromObject(GroupcommParameters.SCOPE));
    	
    	// Scope must be included for joining OSCORE groups
    	if (scope == null) {
    		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
    						 errorResponsePayload,
    						 Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
    		return;
    	}
    	// Scope must be wrapped in a binary string for joining OSCORE groups
    	if (!scope.getType().equals(CBORType.ByteString)) {
    		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
    						 errorResponsePayload,
    						 Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
    		return;
        }
    	
    	byte[] rawScope = scope.GetByteString();
    	CBORObject cborScope = CBORObject.DecodeFromBytes(rawScope);
    	
    	// Invalid scope format for joining OSCORE groups
    	if (!cborScope.getType().equals(CBORType.Array)) {
    		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
    						 errorResponsePayload,
    						 Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
    		return;
        }
    	
    	// Invalid scope format for joining OSCORE groups
    	if (cborScope.size() != 2) {
    		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
    						 errorResponsePayload,
    						 Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
    		return;
        }
    	
    	// Retrieve the name of the OSCORE group
  	  	CBORObject scopeElement = cborScope.get(0);
  	  	if (scopeElement.getType().equals(CBORType.TextString)) {
  	  		groupName = scopeElement.AsString();

  	  		// The group name in 'scope' is not pertinent for this group-membership resource
  	  		if (!groupName.equals(this.getName())) {
        		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
  				exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
  								 errorResponsePayload,
  								 Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
  				return;
  			}      	  		
  	  	}
  	  	// Invalid scope format for joining OSCORE groups
  	  	else {
    		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
  	  		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
  	  				 		 errorResponsePayload,
  	  						 Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
    		return;
  	  	}
  	  	
  	  	// Retrieve the role or list of roles
  	  	scopeElement = cborScope.get(1);
  	  	
  	  	int roleSet = 0;
  	  	
    	if (scopeElement.getType().equals(CBORType.Integer)) {
    		roleSet = scopeElement.AsInt32();
    		
    		// Invalid format of roles
    		if (roleSet < 0) {
        		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
  	  			exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
  	  							 errorResponsePayload,
  	  							 Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        		return;
    		}
 	  		// Invalid combination of roles
    		if(!GroupcommParameters.getValidGroupOSCORERoleCombinations().contains(roleSet)) {
        		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
					exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
									 errorResponsePayload,
									 Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
					return;
    		}
    		Set<Integer> roleIdSet = new HashSet<Integer>();
    		try {
        		roleIdSet = Util.getGroupOSCORERoles(roleSet);
    		}
    		catch(AceException e) {
    			System.err.println(e.getMessage());
    		}
    		short[] roleIdArray = new short[roleIdSet.size()];
    		int index = 0;
    		for (Integer elem : roleIdSet)
    		    roleIdArray[index++] = elem.shortValue(); 
    		for (int i=0; i<roleIdArray.length; i++) {
    			short roleIdentifier = roleIdArray[i];
    			// Silently ignore unrecognized roles
    			if (roleIdentifier < GroupcommParameters.GROUP_OSCORE_ROLES.length)
    				roles.add(GroupcommParameters.GROUP_OSCORE_ROLES[roleIdentifier]);
    		}
    		  
    	}
  	  	
  	  	
    	// Invalid format of roles
  	  	else {
    		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
  	  		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
  	  						 errorResponsePayload,
  	  						 Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
    		return;
  	  	}
    
    	// Check that the indicated roles for this group are actually allowed by the Access Token 
    	boolean allowed = false;
    	int[] roleSetToken = Util.getGroupOSCORERolesFromToken(subject, groupName);
    	if (roleSetToken == null) {
    		exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR,
    						 "Error when retrieving allowed roles from Access Tokens");
    		return;
    	}
    	else {
    		for (int index = 0; index < roleSetToken.length; index++) {
        		if ((roleSet & roleSetToken[index]) == roleSet) {
        			// 'scope' in at least one Access Token admits all the roles indicated
        			// for this group in the Joining Request
        			allowed = true;
        			break;
        		}
    		}	
    	}
    	
    	if (!allowed) {
    		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
    		exchange.respond(CoAP.ResponseCode.FORBIDDEN,
    						 errorResponsePayload,
    						 Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
    		return;
    	}
    	
		// Retrieve the nonce from the Client
		CBORObject cnonce = joinRequest.get(CBORObject.FromObject(GroupcommParameters.CNONCE));
    	
		// A client nonce must be included for proof-of-possession for joining OSCORE groups
    	if (cnonce == null) {
    		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload,
    						 Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
    		return;
    	}

    	// The client nonce must be wrapped in a binary string for joining OSCORE groups
    	if (!cnonce.getType().equals(CBORType.ByteString)) {
    		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload,
    						 Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
    		return;
        }
    	
    	byte[] serializedCNonceCBOR = cnonce.EncodeToBytes();
    	
    	// Retrieve 'get_creds'
    	// If present, this parameter must be a CBOR array or the CBOR simple value Null
    	CBORObject getCreds = joinRequest.get(CBORObject.FromObject((GroupcommParameters.GET_CREDS)));
    	if (getCreds != null) {
    		
    		// Invalid format of 'get_creds'
    		if (!getCreds.getType().equals(CBORType.Array) && !getCreds.equals(CBORObject.Null)) {
        		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
    			exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
    							 errorResponsePayload,
    							 Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        		return;
    		}

    		// Invalid format of 'get_creds'
    		if (getCreds.getType().equals(CBORType.Array)) {
        		if ( getCreds.size() != 3 ||
        	        !getCreds.get(0).getType().equals(CBORType.Boolean) ||
        	         getCreds.get(0).AsBoolean() != true ||
        			!getCreds.get(1).getType().equals(CBORType.Array) ||
        			!getCreds.get(2).getType().equals(CBORType.Array) || 
        			 getCreds.get(2).size() != 0) {
            		
            		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
        			exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
        							 errorResponsePayload,
        							 Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
            		return;
            		
        		}
    		}

    		// Invalid format of 'get_creds'
    		if (getCreds.getType().equals(CBORType.Array)) {
    			for (int i = 0; i < getCreds.get(1).size(); i++) {
    				// Possible elements of the first array have to be all integers and
    				// express a valid combination of roles encoded in the AIF data model
    				if (!getCreds.get(1).get(i).getType().equals(CBORType.Integer) ||
    					!GroupcommParameters.getValidGroupOSCORERoleCombinations().contains(getCreds.get(1).get(i).AsInt32())) {
    					
                		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
            			exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
            							 errorResponsePayload,
            							 Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
                		return;
    					
    				}
    			}
    		}

    		provideAuthCreds = true;
    		
    	}
    	
    	// Retrieve the entry for the target OSCORE group, using the group name
    	GroupInfo myGroup = existingGroupInfo.get(groupName);
    	
    	String nodeName = null;
    	byte[] senderId = null;
        int signKeyCurve = 0;

    	// Assign a Sender ID to the joining node, unless it is a monitor
    	if (roleSet != (1 << GroupcommParameters.GROUP_OSCORE_MONITOR)) {
        	// For the sake of testing, a particular Sender ID is used as known to be available.
            senderId = new byte[] { (byte) 0x25 };
            
        	myGroup.allocateSenderId(senderId);
    	}

    	if (senderId == null) {
    		// All possible values are already in use for this OSCORE group
    		CBORObject responseMap = CBORObject.NewMap();
    		
    		CBORObject aceGroupcommError = CBORObject.NewMap();
    		aceGroupcommError.Add(0, GroupcommErrors.UNAVAILABLE_INDIVIDUAL_KEYING_MATERIAL);
    		responseMap.Add(Constants.PROBLEM_DETAIL_ACE_GROUPCOMM_ERROR, aceGroupcommError);
    		responseMap.Add(Constants.PROBLEM_DETAIL_KEY_TITLE, GroupcommErrors.DESCRIPTION[GroupcommErrors.UNAVAILABLE_INDIVIDUAL_KEYING_MATERIAL]);

    		byte[] responsePayload = responseMap.EncodeToBytes();
    		exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE,
    						 responsePayload,
    						 Constants.APPLICATION_CONCISE_PROBLEM_DETAILS_CBOR);
    		
    		return;
    	}
    	
    	nodeName = myGroup.allocateNodeName(senderId);
    	
    	if (nodeName == null) {
    		exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR, "Error when assigning a node name");
    		return;
    	}

    	// Retrieve 'client_cred'
    	CBORObject clientCred = joinRequest.get(CBORObject.FromObject(GroupcommParameters.CLIENT_CRED));
    	
    	if (clientCred == null && (roleSet != (1 << GroupcommParameters.GROUP_OSCORE_MONITOR))) {
    		
    		// TODO: check if the Group Manager already owns this client's public key
    		
    	}
    	if (clientCred == null && (roleSet != (1 << GroupcommParameters.GROUP_OSCORE_MONITOR))) {
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
    						 "A public key was neither provided nor found as already stored");
    		return;
    	}
    	
    	// Process the public key of the joining node
    	else if (roleSet != (1 << GroupcommParameters.GROUP_OSCORE_MONITOR)) {
    		
    		OneKey publicKey = null;
    		boolean valid = false;
    		
    		if (clientCred.getType() != CBORType.ByteString) {
        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
						 			 "The parameter 'client_cred' must be a CBOR byte string");
        		return;
    		}
    		
    		byte[] clientCredBytes = clientCred.GetByteString();
    		switch(myGroup.getAuthCredFormat()) {
    		    case Constants.COSE_HEADER_PARAM_KCCS:
    		        CBORObject ccs = CBORObject.DecodeFromBytes(clientCredBytes);
    		        if (ccs.getType() == CBORType.Map) {
    		            // Retrieve the public key from the CCS
    		            publicKey = Util.ccsToOneKey(ccs);
    		            valid = true;
    		        }
    		        else {
    	        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
					 			 "Invalid format of authentication credential");
    	        		return;
    		        }
    		        break;
    		    case Constants.COSE_HEADER_PARAM_KCWT:
    		        CBORObject cwt = CBORObject.DecodeFromBytes(clientCredBytes);
    		        if (cwt.getType() == CBORType.Array) {
    		            // Retrieve the public key from the CWT
    		            // TODO
    		        }
    		        else {
    	        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
					 			 "Invalid format of authentication credential");
    	        		return;
    		        }
    		        break;
    		    case Constants.COSE_HEADER_PARAM_X5CHAIN:
    		        // Retrieve the public key from the certificate
    		        if (clientCred.getType() == CBORType.ByteString) {
    		            // TODO
    		        }
    		        else {
    	        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
					 			 "Invalid format of authentication credential");
    	        		return;
    		        }
    		        break;
    		    default:
	        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
				 			 "Invalid format of authentication credential");
	        		return;
    		}
    		if (publicKey == null ||  valid == false) {
        		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload,
        						 Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        		return;
    		}
    		
    		        		
    		// Sanity check on the type of public key        		
    		if (myGroup.getSignAlg().equals(AlgorithmID.ECDSA_256) ||
    		    myGroup.getSignAlg().equals(AlgorithmID.ECDSA_384) ||
    		    myGroup.getSignAlg().equals(AlgorithmID.ECDSA_512)) {
    			
    			// Invalid public key format
    			if (!publicKey.get(KeyKeys.KeyType).
    					equals(myGroup.getSignParams().get(0).get(0)) || // alg capability: key type
               		!publicKey.get(KeyKeys.KeyType).
               			equals(myGroup.getSignParams().get(1).get(0)) || // key capability: key type
               		!publicKey.get(KeyKeys.EC2_Curve).
               			equals(myGroup.getSignParams().get(1).get(1)))   // key capability: curve
    			{ 
    					
            			myGroup.deallocateSenderId(senderId);
            			
            			CBORObject aceGroupcommError = CBORObject.NewMap();
            			aceGroupcommError.Add(0, GroupcommErrors.INCOMPATIBLE_CRED);
            			errorResponseMap.Add(Constants.PROBLEM_DETAIL_ACE_GROUPCOMM_ERROR, aceGroupcommError);
            			errorResponseMap.Add(Constants.PROBLEM_DETAIL_KEY_TITLE, GroupcommErrors.DESCRIPTION[GroupcommErrors.INCOMPATIBLE_CRED]);
            			
                		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
                		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
                						 errorResponsePayload,
                						 Constants.APPLICATION_CONCISE_PROBLEM_DETAILS_CBOR);
            			return;
                    		
            	}

    		}
    		
    		if (myGroup.getSignAlg().equals(AlgorithmID.EDDSA)) {
    			
    			// Invalid public key format
    			if (!publicKey.get(KeyKeys.KeyType).
    					equals(myGroup.getSignParams().get(0).get(0)) || // alg capability: key type
           			!publicKey.get(KeyKeys.KeyType).
           				equals(myGroup.getSignParams().get(1).get(0)) || // key capability: key type
           			!publicKey.get(KeyKeys.OKP_Curve).
           				equals(myGroup.getSignParams().get(1).get(1)))   // key capability: curve
    			{
	            			
						myGroup.deallocateSenderId(senderId);

						CBORObject aceGroupcommError = CBORObject.NewMap();
						aceGroupcommError.Add(0, GroupcommErrors.INCOMPATIBLE_CRED);
						errorResponseMap.Add(Constants.PROBLEM_DETAIL_ACE_GROUPCOMM_ERROR, aceGroupcommError);
						errorResponseMap.Add(Constants.PROBLEM_DETAIL_KEY_TITLE, GroupcommErrors.DESCRIPTION[GroupcommErrors.INCOMPATIBLE_CRED]);
						
                		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
                		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
                						 errorResponsePayload,
                						 Constants.APPLICATION_CONCISE_PROBLEM_DETAILS_CBOR);
                		
            			return;
                		
        		}
    				
    		}
        	        		
    		// Check the proof-of-possession evidence over
        	// (scope | rsnonce | cnonce), using the Client's public key
        	CBORObject clientPopEvidence = joinRequest.
        				get(CBORObject.FromObject(GroupcommParameters.CLIENT_CRED_VERIFY));
        	
        	// A client PoP evidence must be included
        	if (clientPopEvidence == null) {
        		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload,
        						 Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        		return;
        	}

        	// The client PoP evidence must be wrapped in a binary string
        	if (!clientPopEvidence.getType().equals(CBORType.ByteString)) {
        		byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorResponsePayload,
        						 Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
        		return;
            }
        	
        	byte[] rawClientPopEvidence = clientPopEvidence.GetByteString();
    		
        	PublicKey pubKey = null;
            try {
				pubKey = publicKey.AsPublicKey();
			} catch (CoseException e) {
				System.out.println(e.getMessage());
				exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR,
								 "Failed to use the Client's public key to verify the PoP evidence");
        		return;
			}
            if (pubKey == null) {
            	exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR,
            					 "Failed to use the Client's public key to verify the PoP evidence");
        		return;
            }

            int offset = 0;
            
            byte[] serializedScopeCBOR = CBORObject.FromObject(scope).EncodeToBytes();
            byte[] serializedGMNonceCBOR = CBORObject.FromObject(rsnonce).EncodeToBytes();
            byte[] popInput = new byte [serializedScopeCBOR.length +
                                        serializedGMNonceCBOR.length +
                                        serializedCNonceCBOR.length];
            System.arraycopy(serializedScopeCBOR, 0, popInput, offset, serializedScopeCBOR.length);
            offset += serializedScopeCBOR.length;
            System.arraycopy(serializedGMNonceCBOR, 0, popInput, offset, serializedGMNonceCBOR.length);
            offset += serializedGMNonceCBOR.length;
            System.arraycopy(serializedCNonceCBOR, 0, popInput, offset, serializedCNonceCBOR.length);


            // The group mode is used. The PoP evidence is a signature
            if (targetedGroup.getMode() != GroupcommParameters.GROUP_OSCORE_PAIRWISE_MODE_ONLY) {
                
                if (publicKey.get(KeyKeys.KeyType).equals(org.eclipse.californium.cose.KeyKeys.KeyType_EC2))
                    signKeyCurve = publicKey.get(KeyKeys.EC2_Curve).AsInt32();
                else if (publicKey.get(KeyKeys.KeyType).equals(org.eclipse.californium.cose.KeyKeys.KeyType_OKP))
                    signKeyCurve = publicKey.get(KeyKeys.OKP_Curve).AsInt32();

                // This should never happen, due to the previous sanity checks
                if (signKeyCurve == 0) {
                    exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR,
                    				 "Error when setting up the signature verification");
                    return;
                }

                // Invalid Client's PoP signature
                if (!Util.verifySignature(signKeyCurve, pubKey, popInput, rawClientPopEvidence)) {
                	
                	CBORObject aceGroupcommError = CBORObject.NewMap();
                	aceGroupcommError.Add(0, GroupcommErrors.INVALID_POP_EVIDENCE);
                	errorResponseMap.Add(Constants.PROBLEM_DETAIL_ACE_GROUPCOMM_ERROR, aceGroupcommError);
                	errorResponseMap.Add(Constants.PROBLEM_DETAIL_KEY_TITLE, GroupcommErrors.DESCRIPTION[GroupcommErrors.INVALID_POP_EVIDENCE]);
                	
                	byte[] errorResponsePayload = errorResponseMap.EncodeToBytes();
                	exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
                					 errorResponsePayload,
                					 Constants.APPLICATION_CONCISE_PROBLEM_DETAILS_CBOR);
                	
                    return;
                }
            }
            // Only the pairwise mode is used. The PoP evidence is a MAC
            else {
                // TODO
            }
    		        		
            if (!myGroup.storeAuthCred(senderId, clientCred)) {
    			myGroup.deallocateSenderId(senderId);
				exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR,
								 "Error when storing the authentication credential");
        		return;
    			
    		}
    		
    	}
    	
    	boolean rejoin = false;
    	if (myGroup.isGroupMember(subject) == true) {
    		// This node is re-joining the group without having left
    		
    		rejoin = true;
        	String oldNodeName = myGroup.getGroupMemberName(subject);
        	
        	Resource staleResource = getChild("nodes").getChild(oldNodeName);
    		this.getChild("nodes").getChild(oldNodeName).delete(staleResource);
    		
    		myGroup.removeGroupMemberBySubject(subject);

    	}
    	
    	if (!myGroup.addGroupMember(senderId, nodeName, roleSet, subject)) {
    		// The joining node is not a monitor; its node name is its Sender ID encoded as a String
			if (senderId != null) {
				myGroup.deallocateSenderId(senderId);
				
				// Add the old Sender ID to the set of stale Sender IDs for this version of the symmetric keying material
	    		myGroup.addStaleSenderId(senderId);
			}
			// The joining node is a monitor; it got a node name but not a Sender ID
			else {
				myGroup.deallocateNodeName(nodeName);
			}
			myGroup.deleteBirthGid(nodeName);
			exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR,
							 "Error when adding the new group member");
    		return;
    	}
    	
    	// Create and add the sub-resource associated to the new group member
    	try {
    		valid.setGroupMembershipResources(Collections.singleton(rootGroupMembershipResourcePath + "/" +
    							   			  groupName + "/nodes/" + nodeName));
    		valid.setGroupMembershipResources(Collections.singleton(rootGroupMembershipResourcePath + "/" +
    							   			  groupName + "/nodes/" + nodeName + "/cred"));
		}
		catch(AceException e) {
			myGroup.removeGroupMemberBySubject(subject);
			
			// The joining node is not a monitor
			if (senderId != null) {
    			myGroup.deallocateSenderId(senderId);
    			myGroup.deleteAuthCred(senderId);
			}
			
			exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR,
							 "Error when creating the node sub-resource");
    		return;
		}

    	Set<Short> actions = new HashSet<>();
    	actions.add(Constants.GET);
    	actions.add(Constants.POST);
    	actions.add(Constants.DELETE);
    	myScopes.get(rootGroupMembershipResourcePath + "/" + groupName)
    	        .put(rootGroupMembershipResourcePath + "/" + groupName + "/nodes/" + nodeName, actions);
    	Resource nodeCoAPResource = new GroupOSCORESubResourceNodename(nodeName, existingGroupInfo);
    	this.getChild("nodes").add(nodeCoAPResource);
    	
    	actions = new HashSet<>();
    	actions.add(Constants.POST);
    	myScopes.get(rootGroupMembershipResourcePath + "/" + groupName)
                .put(rootGroupMembershipResourcePath + "/" + groupName + "/nodes/" + nodeName + "/cred", actions);
    	nodeCoAPResource = new GroupOSCORESubResourceNodenameCred("cred", existingGroupInfo);
    	this.getChild("nodes").getChild(nodeName).add(nodeCoAPResource);
    	
    	
        // Respond to the Join Request
        
    	CBORObject joinResponse = CBORObject.NewMap();
    	
    	// Key Type Value assigned to the Group_OSCORE_Input_Material object.
    	joinResponse.Add(GroupcommParameters.GKTY, CBORObject.FromObject(GroupcommParameters.GROUP_OSCORE_INPUT_MATERIAL_OBJECT));
    	
    	// This map is filled as the Group_OSCORE_Input_Material object
    	CBORObject myMap = CBORObject.NewMap();
    	
    	// Fill the 'key' parameter
    	if (senderId != null) {
			// The joining node is not a monitor
    		myMap.Add(GroupOSCOREInputMaterialObjectParameters.group_SenderID, senderId);
    	}
    	myMap.Add(OSCOREInputMaterialObjectParameters.hkdf, targetedGroup.getHkdf().AsCBOR());
    	myMap.Add(OSCOREInputMaterialObjectParameters.salt, targetedGroup.getMasterSalt());
    	myMap.Add(OSCOREInputMaterialObjectParameters.ms, targetedGroup.getMasterSecret());
    	myMap.Add(OSCOREInputMaterialObjectParameters.contextId, targetedGroup.getGroupId());
    	myMap.Add(GroupOSCOREInputMaterialObjectParameters.cred_fmt, targetedGroup.getAuthCredFormat());
    	if (targetedGroup.getMode() != GroupcommParameters.GROUP_OSCORE_PAIRWISE_MODE_ONLY) {
    	    // The group mode is used
    	    myMap.Add(GroupOSCOREInputMaterialObjectParameters.gp_enc_alg, targetedGroup.getGpEncAlg().AsCBOR());
    	    myMap.Add(GroupOSCOREInputMaterialObjectParameters.sign_alg, targetedGroup.getSignAlg().AsCBOR());
    	    if (targetedGroup.getSignParams().size() != 0)
    	        myMap.Add(GroupOSCOREInputMaterialObjectParameters.sign_params, targetedGroup.getSignParams());
    	}
    	if (targetedGroup.getMode() != GroupcommParameters.GROUP_OSCORE_GROUP_MODE_ONLY) {
    	    // The pairwise mode is used
    	    myMap.Add(OSCOREInputMaterialObjectParameters.alg, targetedGroup.getAlg().AsCBOR());
    	    myMap.Add(GroupOSCOREInputMaterialObjectParameters.ecdh_alg, targetedGroup.getEcdhAlg().AsCBOR());
    	    if (targetedGroup.getEcdhParams().size() != 0)
    	        myMap.Add(GroupOSCOREInputMaterialObjectParameters.ecdh_params, targetedGroup.getEcdhParams());
    	}
    	int detHashAlg = targetedGroup.getDetHashAlg();
    	if (detHashAlg != 0) {
    		byte[] detClientSenderId = targetedGroup.getDetClientSenderId();
    		if (detClientSenderId != null) {
    			// At this point, there must really be a Sender ID allocated to the Deterministic Client
	    		myMap.Add(GroupOSCOREInputMaterialObjectParameters.det_senderId, detClientSenderId);
	    		myMap.Add(GroupOSCOREInputMaterialObjectParameters.det_hash_alg, detHashAlg);
    		}
    	}
    	
    	joinResponse.Add(GroupcommParameters.KEY, myMap);
    	
    	// If backward security has to be preserved:
    	//
    	// 1) The Epoch part of the Group ID should be incremented
    	// myGroup.incrementGroupIdEpoch();
    	//
    	// 2) The OSCORE group should be rekeyed

    	// The current version of the symmetric keying material
    	joinResponse.Add(GroupcommParameters.NUM, CBORObject.FromObject(myGroup.getVersion()));
    	
    	// CBOR Value assigned to the coap_group_oscore profile.
    	joinResponse.Add(GroupcommParameters.ACE_GROUPCOMM_PROFILE, CBORObject.FromObject(GroupcommParameters.COAP_GROUP_OSCORE_APP));
    	
    	long expValue = targetedGroup.getExp();
    	long exiValue = expValue - (System.currentTimeMillis() / 1000L);
    	
    	// Expiration time in seconds, after which the OSCORE Security Context
    	// derived from the 'k' parameter is not valid anymore.
    	joinResponse.Add(GroupcommParameters.EXP, CBORObject.FromObject(expValue));
    	
    	// Number of seconds after which the OSCORE Security Context
    	// derived from the 'k' parameter is not valid anymore.
    	joinResponse.Add(GroupcommParameters.EXI, CBORObject.FromObject(exiValue));
    	
    	if (provideAuthCreds) {

    		CBORObject authCredsArray = CBORObject.NewArray();        		
    		CBORObject peerRoles = CBORObject.NewArray();
    		CBORObject peerIdentifiers = CBORObject.NewArray();
    		
    		Map<CBORObject, CBORObject> authCreds = myGroup.getAuthCreds();
        	
    		for (CBORObject sid : authCreds.keySet()) {
    			// This should never happen; silently ignore
    			if (authCreds.get(sid) == null)
    				continue;

    			byte[] peerSenderId = sid.GetByteString();
    			// Skip the authentication credential of the just-added joining node
    			if ((senderId != null) && Arrays.equals(senderId, peerSenderId))
    				continue;
    			
    			boolean includeAuthCred = false;
            	
    			// Authentication credentials of all group members are requested
    			if (getCreds.equals(CBORObject.Null)) {
    				includeAuthCred = true;
    			}
    			// Only authentication credentials of group members with certain roles are requested
    			else {
    				for (int i = 0; i < getCreds.get(1).size(); i++) {
    					int filterRoles = getCreds.get(1).get(i).AsInt32();
    					int memberRoles = myGroup.getGroupMemberRoles(peerSenderId);
    					// The owner of this authentication credential does not have all its roles
    					// indicated in this AIF integer filter
    					if (filterRoles != (filterRoles & memberRoles)) {
    						continue;
    					}
    					else {
    						includeAuthCred = true;
    						break;
    					}
    				}
    			}
    			
    			if (includeAuthCred) {
    				authCredsArray.Add(authCreds.get(sid));
        			peerRoles.Add(myGroup.getGroupMemberRoles(peerSenderId));
        			peerIdentifiers.Add(peerSenderId);
    			}

    		}
    		    			
    		joinResponse.Add(GroupcommParameters.CREDS, authCredsArray);
			joinResponse.Add(GroupcommParameters.PEER_ROLES, peerRoles);
			joinResponse.Add(GroupcommParameters.PEER_IDENTIFIERS, peerIdentifiers);
    			
    		
    		// Debug:
    		// 1) Print 'kid' as equal to the Sender ID of the key owner
    		// 2) Print 'kty' of each public key
    		/*
    		for (int i = 0; i < coseKeySet.size(); i++) {
    			byte[] kid = coseKeySet.get(i).get(KeyKeys.KeyId.AsCBOR()).GetByteString();
    			for (int j = 0; j < kid.length; j++)
    				System.out.printf("0x%02X", kid[j]);
    			System.out.println("\n" + coseKeySet.get(i).get(KeyKeys.KeyType.AsCBOR()));
    		}
    		*/
    		
    	}
    	
    	// Group Policies
    	joinResponse.Add(GroupcommParameters.GROUP_POLICIES, myGroup.getGroupPolicies());
    	
    	
    	// Authentication Credential of the Group Manager together with proof-of-possession evidence
    	byte[] kdcNonce = new byte[8];
    	new SecureRandom().nextBytes(kdcNonce);
    	joinResponse.Add(GroupcommParameters.KDC_NONCE, kdcNonce);
    	
    	CBORObject authCred = CBORObject.FromObject(targetedGroup.getGmAuthCred());
    	
    	joinResponse.Add(GroupcommParameters.KDC_CRED, authCred);
    	
    	PrivateKey gmPrivKey;
		try {
			gmPrivKey = targetedGroup.getGmKeyPair().AsPrivateKey();
		} catch (CoseException e) {
			System.err.println("Error when computing the GM PoP evidence " + e.getMessage());
			exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR,
							 "Error when computing the GM PoP evidence");
    		return;
		}

		int offset =  0;
		byte[] serializedGMNonceCBOR = CBORObject.FromObject(kdcNonce).EncodeToBytes();
    	byte[] popInput = new byte[serializedCNonceCBOR.length + serializedGMNonceCBOR.length];
    	System.arraycopy(serializedCNonceCBOR, 0, popInput, offset, serializedCNonceCBOR.length);
    	offset += serializedCNonceCBOR.length;
    	System.arraycopy(serializedGMNonceCBOR, 0, popInput, offset, serializedGMNonceCBOR.length);
    	
		byte[] gmSignature = Util.computeSignature(signKeyCurve, gmPrivKey, popInput);
    	
    	if (gmSignature != null) {
    	    joinResponse.Add(GroupcommParameters.KDC_CRED_VERIFY, gmSignature);
    	}
    	else {
			exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR,
							 "Error when computing the GM PoP evidence");
    		return;
    	}
    	
    	byte[] responsePayload = joinResponse.EncodeToBytes();
    	String uriNodeResource = new String(rootGroupMembershipResourcePath + "/" +
    										groupName + "/nodes/" + nodeName);
    	
    	CoAP.ResponseCode responseCode = rejoin ? CoAP.ResponseCode.CHANGED : CoAP.ResponseCode.CREATED;
    	
    	Response coapJoinResponse = new Response(responseCode);
    	coapJoinResponse.setPayload(responsePayload);
    	coapJoinResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
    	coapJoinResponse.getOptions().setLocationPath(uriNodeResource);

    	// Store cnonce for this joining node
    	TokenRepository.getInstance().setCnonce(subject, Base64.getEncoder().encodeToString(cnonce.GetByteString()));
    	
    	exchange.respond(coapJoinResponse);
    	
    }
}
