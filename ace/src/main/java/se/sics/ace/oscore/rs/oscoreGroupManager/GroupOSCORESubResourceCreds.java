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

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

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
 * Definition of the Group OSCORE group-membership sub-resource /creds
 */
public class GroupOSCORESubResourceCreds extends CoapResource {
	
	private Map<String, GroupInfo> existingGroupInfo = new HashMap<>();
	
	/**
     * Constructor
     * @param resId  the resource identifier
     * @param existingGroupInfo  the set of information of the existing OSCORE groups
     */
    public GroupOSCORESubResourceCreds(String resId, Map<String, GroupInfo> existingGroupInfo) {
        
        // set resource identifier
        super(resId);
        
        // set display name
        getAttributes().setTitle("Group OSCORE Group-Membership Sub-Resource \"creds\" " + resId);
        
        this.existingGroupInfo = existingGroupInfo;
        
    }

    @Override
    public void handleGET(CoapExchange exchange) {
    	System.out.println("GET request reached the GM");
    	
    	// Retrieve the entry for the target group, using the last path segment
    	// of the URI path as the name of the OSCORE group
    	GroupInfo targetedGroup = existingGroupInfo.get(this.getParent().getName());
    	
    	// This should never happen if existing groups are maintained properly
    	if (targetedGroup == null) {
        	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE,
        					 "Error when retrieving material for the OSCORE group");
        	return;
    	}
    	
    	String groupName = targetedGroup.getGroupName();
    	
    	// This should never happen if active groups are maintained properly
	  		if (!groupName.equals(this.getParent().getName())) {
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
    		//
    		// This is still fine, as long as at least one Access Tokens
    		// of the requester allows also the role "Verifier" in this group
    		
    		// Check that at least one of the Access Tokens for this node
    		// allows (also) the Verifier role for this group
        	
    		int role = 1 << GroupcommParameters.GROUP_OSCORE_VERIFIER;
    		boolean allowed = false;
        	int[] roleSetToken = Util.getGroupOSCORERolesFromToken(subject, groupName);
        	if (roleSetToken == null) {
        		exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR,
        						 "Error when retrieving allowed roles from Access Tokens");
        		return;
        	}
        	else {
        		for (int index = 0; index < roleSetToken.length; index++) {
        			if ((role & roleSetToken[index]) != 0) {
            			// 'scope' in this Access Token admits (also) the role "Verifier" for this group.
        				// This makes it fine for the requester.
        				allowed = true;
        				break;
        			}
        		}
        	}
        	
        	if (!allowed) {
        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
        						 "Operation not permitted to a non-member which is not a Verifier");
        		return;
        	}
        	
    	}
        
    	// Respond to the Authentication Credential Request
        
    	CBORObject myResponse = CBORObject.NewMap();
    	
    	CBORObject authCredsArray = CBORObject.NewArray();        	
		CBORObject peerRoles = CBORObject.NewArray();
		CBORObject peerIdentifiers = CBORObject.NewArray();
		
		Map<CBORObject, CBORObject> authCreds = targetedGroup.getAuthCreds();
		
		for (CBORObject sid : authCreds.keySet()) {
			
			// This should never happen; silently ignore
			if (authCreds.get(sid) == null)
				continue;
			
			byte[] peerSenderId = sid.GetByteString();
			// This should never happen; silently ignore
			if (peerSenderId == null)
				continue;
			
			authCredsArray.Add(authCreds.get(sid));
			peerRoles.Add(targetedGroup.getGroupMemberRoles(peerSenderId));
			peerIdentifiers.Add(peerSenderId);
			
		}
		
		myResponse.Add(GroupcommParameters.NUM, CBORObject.FromObject(targetedGroup.getVersion()));

		myResponse.Add(GroupcommParameters.CREDS, authCredsArray);			
		myResponse.Add(GroupcommParameters.PEER_ROLES, peerRoles);
		myResponse.Add(GroupcommParameters.PEER_IDENTIFIERS, peerIdentifiers);

    	byte[] responsePayload = myResponse.EncodeToBytes();
    	
    	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);
    	coapResponse.setPayload(responsePayload);
    	coapResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);

    	exchange.respond(coapResponse);

    }
    
    @Override
    public void handleFETCH(CoapExchange exchange) {
    	System.out.println("FETCH request reached the GM");
    	
    	// Retrieve the entry for the target group, using the last path segment of
    	// the URI path as the name of the OSCORE group
    	GroupInfo targetedGroup = existingGroupInfo.get(this.getParent().getName());
    	
    	// This should never happen if existing groups are maintained properly
    	if (targetedGroup == null) {
        	exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE,
        					 "Error when retrieving material for the OSCORE group");
        	return;
    	}
    	
    	String groupName = targetedGroup.getGroupName();
    	
    	// This should never happen if active groups are maintained properly
	  		if (!groupName.equals(this.getParent().getName())) {
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
    		//
    		// This is still fine, as long as at least one Access Tokens
    		// of the requester allows also the role "Verifier" in this group
    		
    		// Check that at least one of the Access Tokens for this node
    		// allows (also) the Verifier role for this group
        	
    		int role = 1 << GroupcommParameters.GROUP_OSCORE_VERIFIER;
    		boolean allowed = false;
        	int[] roleSetToken = Util.getGroupOSCORERolesFromToken(subject, groupName);
        	if (roleSetToken == null) {
        		exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR,
        						 "Error when retrieving allowed roles from Access Tokens");
        		return;
        	}
        	else {
        		for (int index = 0; index < roleSetToken.length; index++) {
        			if ((role & roleSetToken[index]) != 0) {
            			// 'scope' in this Access Token admits (also) the role "Verifier" for this group.
        				// This makes it fine for the requester.
        				allowed = true;
        				break;
        			}
        		}
        	}
        	
        	if (!allowed) {
        		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
        						 "Operation not permitted to a non-member which is not a Verifier");
        		return;
        	}
        	
    	}
    	        	
    	byte[] requestPayload = exchange.getRequestPayload();
    	
    	if(requestPayload == null) {
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
    						 "A payload must be present");
    		return;
    	}
    	
    	CBORObject requestCBOR = CBORObject.DecodeFromBytes(requestPayload);
		
    	boolean valid = true;
	    
    	// The payload of the request must be a CBOR Map
    	if (!requestCBOR.getType().equals(CBORType.Map)) {
    		valid = false;
    		
    	}

    	// The CBOR Map must include exactly one element, i.e. 'get_creds'
    	if ((requestCBOR.size() != 1) || (!requestCBOR.ContainsKey(GroupcommParameters.GET_CREDS))) {
    		valid = false;
    		
    	}

    	// Invalid format of 'get_creds'
		if (!valid) {
			exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Invalid format of 'get_creds'");
    		return;
		}
		
    	// Retrieve 'get_creds'
    	// This parameter must be a CBOR array or the CBOR simple value Null
    	CBORObject getCreds = requestCBOR.get(CBORObject.FromObject((GroupcommParameters.GET_CREDS)));
    	
	    // Invalid format of 'get_creds'
	    if (!getCreds.getType().equals(CBORType.Array) && !getCreds.equals(CBORObject.Null)) {
			exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Invalid format of 'get_creds'");
    		return;
	    }
			    
	    if (getCreds.getType().equals(CBORType.Array)) {
	    
    		// 'get_creds' must include exactly two elements, both of which CBOR arrays
    		if ( getCreds.size() != 3 ||
    			!getCreds.get(0).getType().equals(CBORType.Boolean) ||
    			!getCreds.get(1).getType().equals(CBORType.Array) ||
    			!getCreds.get(2).getType().equals(CBORType.Array)) {
    			
    			valid = false;
        		
    		}

    		// Invalid format of 'get_creds'
    		if (valid && getCreds.get(1).size() == 0 && getCreds.get(2).size() == 0) {
    			valid = false;
    		}
    		
    		// Invalid format of 'get_creds'
    		if (valid) {
				for (int i = 0; i < getCreds.get(1).size(); i++) {
					// Possible elements of the first array have to be all integers and
					// express a valid combination of roles encoded in the AIF data model
					if (!getCreds.get(1).get(i).getType().equals(CBORType.Integer) ||
						!GroupcommParameters.getValidGroupOSCORERoleCombinations().contains(getCreds.get(1).get(i).AsInt32())) {
							valid = false;
							break;
							
					}
				}
    		}
    		
    		// Invalid format of 'get_creds'
    		if (valid) {
				for (int i = 0; i < getCreds.get(2).size(); i++) {
					// Possible elements of the second array have to be all
					// byte strings, specifying Sender IDs of other group members
					if (!getCreds.get(2).get(i).getType().equals(CBORType.ByteString)) {
						valid = false;
						break;
						
					}			
				}
    		}
			
    		// Invalid format of 'get_creds'
    		if (!valid) {
				exchange.respond(CoAP.ResponseCode.BAD_REQUEST, "Invalid format of 'get_creds'");
	    		return;
    		}
		
	    }
		
		
    	// Respond to the Authentication Credential Request
        
    	CBORObject myResponse = CBORObject.NewMap();
    	
    	CBORObject authCredsArray = CBORObject.NewArray();
		CBORObject peerRoles = CBORObject.NewArray();
		CBORObject peerIdentifiers = CBORObject.NewArray();
		Set<Integer> requestedRoles = new HashSet<Integer>();
		Set<ByteBuffer> requestedSenderIDs = new HashSet<ByteBuffer>();
		
		Map<CBORObject, CBORObject> authCreds = targetedGroup.getAuthCreds();
		
		// Provide the authentication credentials of all the group members
		if (getCreds.equals(CBORObject.Null)) {
			
			for (CBORObject sid : authCreds.keySet()) {
				
    			// This should never happen; silently ignore
    			if (authCreds.get(sid) == null)
    				continue;
    			
    			byte[] memberSenderId = sid.GetByteString();
    			// This should never happen; silently ignore
    			if (memberSenderId == null)
    				continue;

    			int memberRoles = targetedGroup.getGroupMemberRoles(memberSenderId);
    			
    			authCredsArray.Add(authCreds.get(sid));
    			peerRoles.Add(memberRoles);
    			peerIdentifiers.Add(memberSenderId);
    			
			}
			
		}
		// Provide the authentication credentials based on the specified filtering
		else {
		
    		// Retrieve the inclusion flag
			boolean inclusionFlag = getCreds.get(0).getType().equals(CBORType.Boolean);
    		
    		// Retrieve and store the combination of roles specified in the request
    		for (int i = 0; i < getCreds.get(1).size(); i++) {
    			requestedRoles.add((getCreds.get(1).get(i).AsInt32()));
    		}
    		
    		// Retrieve and store the Sender IDs specified in the request
    		for (int i = 0; i < getCreds.get(2).size(); i++) {
    			byte[] myArray = getCreds.get(2).get(i).GetByteString();
    			ByteBuffer myBuffer = ByteBuffer.wrap(myArray);
    			requestedSenderIDs.add(myBuffer);
    		}
		
    		for (CBORObject sid : authCreds.keySet()) {
    			
    			// This should never happen; silently ignore
    			if (authCreds.get(sid) == null)
    				continue;
    			
    			byte[] memberSenderId = sid.GetByteString();
    			// This should never happen; silently ignore
    			if (memberSenderId == null)
    				continue;

    			int memberRoles = targetedGroup.getGroupMemberRoles(memberSenderId);
    			
    			boolean include = false;
    			boolean earlyStop = false;
    			
				for (Integer filter : requestedRoles) {
					int filterRoles = filter.intValue();
					
					// The role(s) of the key owner match with the role filter
					if (filterRoles == (filterRoles & memberRoles)) {
						
						// This authentication credential has to be included anyway,
						// regardless of the Sender ID of the key owner
						if (inclusionFlag) {
							include = true;
						}
						// This authentication credential has to be included only if the Sender ID
						// of the key owner is not in the node identifier filter
						else if (!requestedSenderIDs.contains(ByteBuffer.wrap(memberSenderId))) {
							include = true;
						}
						
						// No need to check the Sender ID filter
						if (include == false) {
							earlyStop = true;
						}
						
						// Stop going through the role filter anyway
						break;
					}	
				}
    			
    			if(!include && !earlyStop) {
    				// This authentication credential has to be included if the Sender ID of
    				// the key owner is in the node identifier filter
    				if (inclusionFlag && requestedSenderIDs.contains(ByteBuffer.wrap(memberSenderId))) {
    					include = true;
    				}
    				// This authentication credential has to be included if the Sender ID of
    				// the key owner is not in the node identifier filter, and the role filter was empty
    				else if (!inclusionFlag && !requestedSenderIDs.contains(ByteBuffer.wrap(memberSenderId))) {
    					if (requestedRoles.size() == 0) {
    						include = true;
    					}
    				}
    			}
    			
    			if (include) {
    				
    				authCredsArray.Add(authCreds.get(sid));
	    			peerRoles.Add(memberRoles);
	    			peerIdentifiers.Add(memberSenderId);
	    			
    			}
    			
    		}
		}
		
		myResponse.Add(GroupcommParameters.NUM, CBORObject.FromObject(targetedGroup.getVersion()));
		
		myResponse.Add(GroupcommParameters.CREDS, authCredsArray);
		myResponse.Add(GroupcommParameters.PEER_ROLES, peerRoles);
		myResponse.Add(GroupcommParameters.PEER_IDENTIFIERS, peerIdentifiers);
    	
    	byte[] responsePayload = myResponse.EncodeToBytes();
    	
    	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);
    	coapResponse.setPayload(responsePayload);
    	coapResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);

    	exchange.respond(coapResponse);

    }
    
}
