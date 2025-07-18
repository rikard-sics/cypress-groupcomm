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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.server.resources.CoapExchange;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.GroupcommParameters;
import se.sics.ace.Util;
import se.sics.ace.coap.CoapReq;
import se.sics.ace.oscore.GroupInfo;

/**
 * Definition of the root group-membership resource for Group OSCORE
 * 
 * Children of this resource are the group-membership resources,
 * whose implementation is provided by the class GroupOSCOREGroupMembershipResource
 */
public class GroupOSCORERootGroupMembershipResource extends CoapResource {
    
	private Map<String, GroupInfo> existingGroupInfo = new HashMap<>();
	
    /**
     * Constructor
     * @param resId  the resource identifier
     * @param existingGroupInfo  the set of information of the existing OSCORE groups
     */
    public GroupOSCORERootGroupMembershipResource(String resId, Map<String, GroupInfo> existingGroupInfo) {
        
        // set resource identifier
        super(resId);
        
        // set display name
        getAttributes().setTitle("Group OSCORE Group-Membership Resource " + resId);
        
        this.existingGroupInfo = existingGroupInfo;
    }
    
    @Override
    public void handleFETCH(CoapExchange exchange) {
    	System.out.println("FETCH request reached the GM");
    	
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
        
    	byte[] requestPayload = exchange.getRequestPayload();
    	
    	if(requestPayload == null) {
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
    						 "A payload must be present");
    		return;
    	}
    	
    	CBORObject requestCBOR = CBORObject.DecodeFromBytes(requestPayload);
		
    	// The payload of the request must be a CBOR Map
    	if (!requestCBOR.getType().equals(CBORType.Map)) {
			exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
							 "Invalid payload format");
    		return;
    	}
    	
    	// The CBOR Map must include exactly one element, i.e. 'gid'
    	if ((requestCBOR.size() != 1) || (!requestCBOR.ContainsKey(GroupcommParameters.GID))) {
			exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
							 "Invalid payload format");
    		return;
    	}
    	
    	// The 'gid' element must be a CBOR array, with at least one element
    	if (requestCBOR.get(GroupcommParameters.GID).getType() != CBORType.Array ||
    		requestCBOR.get(GroupcommParameters.GID).size() == 0) {
			exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
							 "Invalid payload format");
    		return;
    	}
    	
    	// Each element of 'gid' element must be a CBOR byte string
    	for (int i = 0 ; i < requestCBOR.get(GroupcommParameters.GID).size(); i++) {
        	if (requestCBOR.get(GroupcommParameters.GID).get(i).getType() != CBORType.ByteString) {
				exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
								 "Invalid payload format");
	    		return;
        	}
    	}
    	    		
		List<CBORObject> inputGroupIds = new ArrayList<CBORObject> ();
		for (int i = 0; i < requestCBOR.get(GroupcommParameters.GID).size(); i++) {
			inputGroupIds.add(requestCBOR.get(GroupcommParameters.GID).get(i));
		}
		
		List<String> preliminaryGroupNames = new ArrayList<String>();
		List<CBORObject> finalGroupNames = new ArrayList<CBORObject>();
		List<CBORObject> finalGroupIds = new ArrayList<CBORObject>();
		List<CBORObject> finalGroupURIs = new ArrayList<CBORObject>();
		
		// Navigate the list of existing OSCORE groups
    	for (String groupName : existingGroupInfo.keySet()) {
    		
    		GroupInfo myGroup = existingGroupInfo.get(groupName);
    		byte[] storedGid = myGroup.getGroupId();
    		
    		// Navigate the list of Group IDs specified in the request
    		for (int i = 0; i < inputGroupIds.size(); i ++) {
    			byte[] inputGid = inputGroupIds.get(i).GetByteString();
    			
    			// A match is found with the examined OSCORE group
    			if (Arrays.equals(storedGid, inputGid)) {
        			// Store the used Group Name for future inspection
    				preliminaryGroupNames.add(groupName);
    				// No need to further consider this Group ID value
    				inputGroupIds.remove(i);
    				break;
    			}
    		}
    		
    		if (inputGroupIds.isEmpty())
    			break;
    		
    	}
		
    	// Selects only names of groups where the requesting client is
    	// a current member or is authorized to have any role about
    	for (String groupName : preliminaryGroupNames) {
    		
    		GroupInfo targetedGroup = existingGroupInfo.get(groupName);
    		
        	if (!targetedGroup.isGroupMember(subject)) {
        		
        		// The requester is not a current group member.
        		//
        		// This is still fine, as long as at least one Access Token allows
        		// the requesting client to have any role with respect to the group
        		
        		if (Util.getGroupOSCORERolesFromToken(subject, groupName) == null) {
        	    	// No Access Token allows the requesting client node to have
        	    	// to have any role with respect to the group
        			
        			// Move to considering the next group
        			continue;
        		}
            	
        	}
        	
        	finalGroupNames.add(CBORObject.FromObject(groupName));
        	byte[] gid = targetedGroup.getGroupId();
        	finalGroupIds.add(CBORObject.FromObject(gid));
        	finalGroupURIs.add(CBORObject.FromObject(this.getURI() + "/" + groupName));
        	
    	}
    	
        
        // Respond to the Group Name and URI Retrieval Request
        
    	byte[] responsePayload = null;
    	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);
    	
    	// The response is an empty CBOR byte string
    	if (finalGroupNames.size() == 0) {
    		byte[] emptyArray = new byte[0];
    		responsePayload = CBORObject.FromObject(emptyArray).EncodeToBytes();
    	}
    	// The response is a CBOR may including three CBOR arrays
    	else {
    		CBORObject myResponse = CBORObject.NewMap();

    		CBORObject gnameArray = CBORObject.NewArray();
    		CBORObject gidArray = CBORObject.NewArray();
    		CBORObject guriArray = CBORObject.NewArray();
    		
    		for (int i = 0; i < finalGroupNames.size(); i++) {
    			gnameArray.Add(finalGroupNames.get(i));
    			gidArray.Add(finalGroupIds.get(i));
    			guriArray.Add(finalGroupURIs.get(i));
    		}
    		
    		myResponse.Add(GroupcommParameters.GID, gidArray);
    		myResponse.Add(GroupcommParameters.GNAME, gnameArray);
    		myResponse.Add(GroupcommParameters.GURI, guriArray);
    		
    		responsePayload = myResponse.EncodeToBytes();
        	coapResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);
    	} 
        
    	coapResponse.setPayload(responsePayload);

    	exchange.respond(coapResponse);
    	
    }
    
}

