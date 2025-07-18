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

import java.util.HashMap;
import java.util.Map;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.server.resources.CoapExchange;

import com.upokecenter.cbor.CBORObject;

import net.i2p.crypto.eddsa.Utils;
import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.GroupcommErrors;
import se.sics.ace.GroupcommParameters;
import se.sics.ace.coap.CoapReq;
import se.sics.ace.oscore.GroupInfo;
import se.sics.ace.oscore.GroupOSCOREInputMaterialObjectParameters;
import se.sics.ace.oscore.OSCOREInputMaterialObjectParameters;
import se.sics.ace.rs.TokenRepository;

/**
 * Definition of the Group OSCORE group-membership sub-resource /nodes/NODENAME
 * for the group members with node name "NODENAME"
 */
public class GroupOSCORESubResourceNodename extends CoapResource {
	
	private Map<String, GroupInfo> existingGroupInfo = new HashMap<>();
	
	/**
     * Constructor
     * @param resId  the resource identifier
     * @param existingGroupInfo  the set of information of the existing OSCORE groups
     */
    public GroupOSCORESubResourceNodename(String resId, Map<String, GroupInfo> existingGroupInfo) {
        
        // set resource identifier
        super(resId);
        
        // set display name
        getAttributes().setTitle("Group OSCORE Group-Membership Sub-Resource \"nodes/NODENAME\" " + resId);
        
        this.existingGroupInfo = existingGroupInfo;
        
    }

    @Override
    public void handleGET(CoapExchange exchange) {
    	System.out.println("GET request reached the GM");
    	
    	// Retrieve the entry for the target group, using the last path segment of
    	// the URI path as the name of the OSCORE group
    	GroupInfo targetedGroup = existingGroupInfo.get(this.getParent().getParent().getName());
    	
    	// This should never happen if existing groups are maintained properly
    	if (targetedGroup == null) {
        	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE,
        					 "Error when retrieving material for the OSCORE group");
        	return;
    	}
    	
    	String groupName = targetedGroup.getGroupName();
    	
    	// This should never happen if active groups are maintained properly
	  		if (!groupName.equals(this.getParent().getParent().getName())) {
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
        	// At this point, this should not really happen
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
    		
    	if (!(targetedGroup.getGroupMemberName(subject)).equals(this.getName())) {
    		// The requester is not the group member associated to this sub-resource.
    		exchange.respond(CoAP.ResponseCode.FORBIDDEN,
    						 "Operation permitted only to the group member associated to this sub-resource");
    		return;
    	}
        	
    	// Respond to the Key Distribution Request
        
    	CBORObject myResponse = CBORObject.NewMap();
    	
    	// Key Type Value assigned to the Group_OSCORE_Input_Material object.
    	myResponse.Add(GroupcommParameters.GKTY, CBORObject.FromObject(GroupcommParameters.GROUP_OSCORE_INPUT_MATERIAL_OBJECT));
    	
    	// This map is filled as the Group_OSCORE_Input_Material object
    	CBORObject myMap = CBORObject.NewMap();
    	
        byte[] senderId = null;
		String myString = targetedGroup.getGroupMemberName(subject);
        
    	if (targetedGroup.getGroupMemberRoles((targetedGroup.getGroupMemberName(subject))) !=
    		(1 << GroupcommParameters.GROUP_OSCORE_MONITOR)) {
    		// The requester is not a monitor, hence it has a Sender ID
    		senderId = Utils.hexToBytes(myString.substring(myString.indexOf(targetedGroup.getNodeNameSeparator()) + 1));
    	}
    	
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
    	
    	// Retrieve the entry for the target group, using the last path segment of
    	// the URI path as the name of the OSCORE group
    	GroupInfo targetedGroup = existingGroupInfo.get(this.getParent().getParent().getName());
    	
    	// This should never happen if existing groups are maintained properly
    	if (targetedGroup == null) {
        	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE,
        					 "Error when retrieving material for the OSCORE group");
        	return;
    	}
    	
    	String groupName = targetedGroup.getGroupName();
    	
    	// This should never happen if active groups are maintained properly
	  	if (!groupName.equals(this.getParent().getParent().getName())) {
        	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE,
        					 "Error when retrieving material for the OSCORE group");
			return;
			}
    	
    	String subject = null;
    	Request request = exchange.advanced().getCurrentRequest();
        
    	if (request.getPayloadSize() != 0) {
    		// This request must not have a payload
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
    						 "This request must not have a payload");
    		return;
    	}
    	
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
    	
    	if (!(targetedGroup.getGroupMemberName(subject)).equals(this.getName())) {
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
    	
    	
    	// Here the Group Manager simply assigns a new Sender ID to this group member.
    	// More generally, the Group Manager may alternatively or additionally rekey the whole OSCORE group 
    	// Note that the node name does not change.
    	
    	byte[] oldSenderId = targetedGroup.getGroupMemberSenderId(subject).GetByteString();
    	
    	byte[] senderId = targetedGroup.allocateSenderId();
    	
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
    	
    	int roles = targetedGroup.getGroupMemberRoles((targetedGroup.getGroupMemberName(subject)));
    	targetedGroup.setGroupMemberRoles(senderId, roles);
    	targetedGroup.setSenderIdToIdentity(subject, senderId);
    	
    	CBORObject publicKey = targetedGroup.getAuthCred(oldSenderId);
    	
    	// Store this client's authentication credential under the new Sender ID
    	if (!targetedGroup.storeAuthCred(senderId, publicKey)) {
    	    exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR,
    	    				 "Error when storing the authentication credential");
    	    return;
    	}
    	// Delete this client's authentication credential under the old Sender ID
    	targetedGroup.deleteAuthCred(oldSenderId);
    	
    	// Add the old Sender ID to the set of stale Sender IDs for this version of the symmetric keying material
    	targetedGroup.addStaleSenderId(oldSenderId);
    	
    	
    	// Respond to the Key Renewal Request
    	
    	CBORObject myResponse = CBORObject.NewMap();
    	
    	// The new Sender ID assigned to the group member
    	myResponse.Add(GroupcommParameters.GROUP_SENDER_ID, CBORObject.FromObject(senderId));
    	        	
    	byte[] responsePayload = myResponse.EncodeToBytes();
    	
    	Response coapResponse = new Response(CoAP.ResponseCode.CHANGED);
    	coapResponse.setPayload(responsePayload);
    	coapResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);

    	exchange.respond(coapResponse);
    	
    }
    
    
    @Override
    public void handleDELETE(CoapExchange exchange) {
    	System.out.println("DELETE request reached the GM");
    	
    	// Retrieve the entry for the target group, using the last path segment of
    	// the URI path as the name of the OSCORE group
    	GroupInfo targetedGroup = existingGroupInfo.get(this.getParent().getParent().getName());
    	
    	// This should never happen if existing groups are maintained properly
    	if (targetedGroup == null) {
        	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE,
        					 "Error when retrieving material for the OSCORE group");
        	return;
    	}
    	
    	String groupName = targetedGroup.getGroupName();
    	
    	// This should never happen if active groups are maintained properly
  		if (!groupName.equals(this.getParent().getParent().getName())) {
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
    	
    	if (!(targetedGroup.getGroupMemberName(subject)).equals(this.getName())) {
    		// The requester is not the group member associated to this sub-resource.
    		exchange.respond(CoAP.ResponseCode.FORBIDDEN,
    						 "Operation permitted only to the group member associated to this sub-resource");
    		return;
    	}
    	
    	targetedGroup.removeGroupMemberBySubject(subject);
    	TokenRepository.getInstance().deleteNonces(subject);
    	
    	// Respond to the Group Leaving Request
        
    	Response coapResponse = new Response(CoAP.ResponseCode.DELETED);

    	delete();
    	exchange.respond(coapResponse);
    	
    }
    
}
