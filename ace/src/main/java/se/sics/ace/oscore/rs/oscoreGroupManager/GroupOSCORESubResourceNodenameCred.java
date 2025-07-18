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

import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.server.resources.CoapExchange;

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
import se.sics.ace.rs.TokenRepository;

/**
 * Definition of the Group OSCORE group-membership sub-resource /nodes/NODENAME/cred
 * for the group members with node name "NODENAME"
 */
public class GroupOSCORESubResourceNodenameCred extends CoapResource {
	
	private Map<String, GroupInfo> existingGroupInfo = new HashMap<>();
	
	/**
     * Constructor
     * @param resId  the resource identifier
     * @param existingGroupInfo  the set of information of the existing OSCORE groups
     */
    public GroupOSCORESubResourceNodenameCred(String resId, Map<String, GroupInfo> existingGroupInfo) {
        
        // set resource identifier
        super(resId);
        
        // set display name
        getAttributes().setTitle("Group OSCORE Group-Membership Sub-Resource \"nodes/NODENAME/cred\" " + resId);
        
        this.existingGroupInfo = existingGroupInfo;
        
    }

    @Override
    public void handlePOST(CoapExchange exchange) {
    	System.out.println("POST request reached the GM");
    	
    	// Retrieve the entry for the target group, using the last path segment of
    	// the URI path as the name of the OSCORE group
    	GroupInfo targetedGroup = existingGroupInfo.get(this.getParent().getParent().getParent().getName());
    	
    	// This should never happen if existing groups are maintained properly
    	if (targetedGroup == null) {
        	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE,
        					 "Error when retrieving material for the OSCORE group");
        	return;
    	}
    	
    	if (targetedGroup.getStatus() == false) {
    		// The group is currently not active
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
    	
    	String groupName = targetedGroup.getGroupName();
    	
    	// This should never happen if active groups are maintained properly
  		if (!groupName.equals(this.getParent().getParent().getParent().getName())) {
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
    	
    	if (!(targetedGroup.getGroupMemberName(subject)).equals(this.getParent().getName())) {
    		// The requester is not the group member associated to this sub-resource.
    		exchange.respond(CoAP.ResponseCode.FORBIDDEN,
    						 "Operation permitted only to the group member associated to this sub-resource");
    		return;
    	}
    	
    	if (targetedGroup.getGroupMemberRoles((targetedGroup.getGroupMemberName(subject))) ==
    		(1 << GroupcommParameters.GROUP_OSCORE_MONITOR)) {
    		// The requester is a monitor, hence it is not supposed to have a Sender ID.
    		CBORObject responseMap = CBORObject.NewMap();
    		
    		CBORObject aceGroupcommError = CBORObject.NewMap();
    		aceGroupcommError.Add(0, GroupcommErrors.INCONSISTENCY_WITH_ROLES);
    		responseMap.Add(Constants.PROBLEM_DETAIL_ACE_GROUPCOMM_ERROR, aceGroupcommError);
    		responseMap.Add(Constants.PROBLEM_DETAIL_KEY_TITLE, GroupcommErrors.DESCRIPTION[GroupcommErrors.INCONSISTENCY_WITH_ROLES]);
    		
    		byte[] responsePayload = responseMap.EncodeToBytes();
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
    						 responsePayload,
    						 Constants.APPLICATION_CONCISE_PROBLEM_DETAILS_CBOR);
    		
    		return;
    	}
    	
    	byte[] requestPayload = exchange.getRequestPayload();
    	
    	if(requestPayload == null) {
    	    exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
    	    				 "A payload must be present");
    	    return;
    	}

    	CBORObject AuthCredUpdateRequest = CBORObject.DecodeFromBytes(requestPayload);

    	// The payload of the Authentication Credential Update Request must be a CBOR Map
    	if (!AuthCredUpdateRequest.getType().equals(CBORType.Map)) {
    	    exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
    	    				 "The payload must be a CBOR map");
    	    return;
    	}
    	
    	if (!AuthCredUpdateRequest.ContainsKey(GroupcommParameters.CLIENT_CRED)) {
    	    exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
    	    				 "Missing parameter: 'client_cred'");
    	    return;
    	}
    	
    	if (!AuthCredUpdateRequest.ContainsKey(GroupcommParameters.CNONCE)) {
    	    exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
    	    				 "Missing parameter: 'cnonce'");
    	    return;
    	}
    	
    	if (!AuthCredUpdateRequest.ContainsKey(GroupcommParameters.CLIENT_CRED_VERIFY)) {
    	    exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
    	    				 "Missing parameter: 'client_cred_verify'");
    	    return;
    	}
    	
    	// Retrieve 'client_cred'
    	CBORObject clientCred = AuthCredUpdateRequest.get(CBORObject.FromObject(GroupcommParameters.CLIENT_CRED));
    	
		// client_cred cannot be Null
		if (clientCred == null) {
		    exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
		    				 "The parameter 'client_cred' cannot be Null");
		    return;
		}

		OneKey publicKey = null;
		boolean valid = false;
		
		if (clientCred.getType() != CBORType.ByteString) {
		    exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
		                     "The parameter 'client_cred' must be a CBOR byte string");
		    return;
		}
		
		byte[] clientCredBytes = clientCred.GetByteString();
		switch(targetedGroup.getAuthCredFormat()) {
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
    	    exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
    	    				 "Invalid public key format");
		    return;
		}
		
		// Sanity check on the type of public key        		
		if (targetedGroup.getSignAlg().equals(AlgorithmID.ECDSA_256) ||
		    targetedGroup.getSignAlg().equals(AlgorithmID.ECDSA_384) ||
			targetedGroup.getSignAlg().equals(AlgorithmID.ECDSA_512)) {
			
			// Invalid public key format
			if (!publicKey.get(KeyKeys.KeyType).
					equals(targetedGroup.getSignParams().get(0).get(0)) || // alg capability: key type
			    !publicKey.get(KeyKeys.KeyType).
			    	equals(targetedGroup.getSignParams().get(1).get(0)) || // key capability: key type
			    !publicKey.get(KeyKeys.EC2_Curve).
			    	equals(targetedGroup.getSignParams().get(1).get(1)))   // key capability: curve
			{ 
			        
				CBORObject errorResponseMap = CBORObject.NewMap();
				
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
		
		if (targetedGroup.getSignAlg().equals(AlgorithmID.EDDSA)) {
		
			// Invalid public key format
			if (!publicKey.get(KeyKeys.KeyType).
					equals(targetedGroup.getSignParams().get(0).get(0)) || // alg capability: key type
			    !publicKey.get(KeyKeys.KeyType).
			    	equals(targetedGroup.getSignParams().get(1).get(0)) || // key capability: key type
			    !publicKey.get(KeyKeys.OKP_Curve).
			    	equals(targetedGroup.getSignParams().get(1).get(1)))   // key capability: curve
			{
			            
				CBORObject errorResponseMap = CBORObject.NewMap();
				
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
    	
		// Retrieve the proof-of-possession nonce from the Client
		CBORObject cnonce = AuthCredUpdateRequest.get(CBORObject.FromObject(GroupcommParameters.CNONCE));

		// A client nonce must be included for proof-of-possession
		if (cnonce == null) {
		    exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
		    				 "The parameter 'cnonce' cannot be Null");
		    return;
		}

		// The client nonce must be wrapped in a binary string
		if (!cnonce.getType().equals(CBORType.ByteString)) {
		    exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
		    				 "The parameter 'cnonce' must be a CBOR byte string");
		    return;
		}

		
		
		// Check the PoP evidence over (scope | rsnonce | cnonce), using the Client's public key
		CBORObject clientPopEvidence = AuthCredUpdateRequest.get(CBORObject.FromObject(GroupcommParameters.CLIENT_CRED_VERIFY));

		// A client PoP evidence must be included
		if (clientPopEvidence == null) {
		    exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
		    				 "The parameter 'client_cred_verify' cannot be Null");
		    return;
		}

		// The client PoP evidence must be wrapped in a binary string for joining OSCORE groups
		if (!clientPopEvidence.getType().equals(CBORType.ByteString)) {
		    exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
		    				 "The parameter 'client_cred_verify' must be a CBOR byte string");
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

		// Rebuild the original 'scope' from the Join Request
        CBORObject cborArrayScope = CBORObject.NewArray();
        int myRoles = targetedGroup.getGroupMemberRoles((targetedGroup.getGroupMemberName(subject)));
        cborArrayScope.Add(groupName);
        cborArrayScope.Add(myRoles);
        byte[] scope = cborArrayScope.EncodeToBytes();

		// Retrieve the original 'rsnonce' specified in the Token POST response
		String rsNonceString = TokenRepository.getInstance().getRsnonce(subject);
        if(rsNonceString == null) {
        	// Return an error response, with a new nonce for PoP of the Client's private key
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
		
		int offset = 0;
		
		byte[] serializedScopeCBOR = CBORObject.FromObject(scope).EncodeToBytes();
		byte[] serializedGMNonceCBOR = CBORObject.FromObject(rsnonce).EncodeToBytes();
		byte[] serializedCNonceCBOR = cnonce.EncodeToBytes();
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
			int signKeyCurve = 0;

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
				CBORObject errorResponseMap = CBORObject.NewMap();
				
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
		
		
		byte[] senderId = targetedGroup.getGroupMemberSenderId(subject).GetByteString();
		
		if (!targetedGroup.storeAuthCred(senderId, clientCred)) {
		    exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR,
		    				 "Error when storing the authentication credential");
		    return;
		}
		
    	// Respond to the Authentication Credential Update Request     	
    	
    	Response coapResponse = new Response(CoAP.ResponseCode.CHANGED);
    	
    	exchange.respond(coapResponse);
    	
    }
    
}
