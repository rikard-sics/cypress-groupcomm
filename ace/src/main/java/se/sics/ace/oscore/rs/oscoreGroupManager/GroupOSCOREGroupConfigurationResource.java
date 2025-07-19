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
import java.util.List;
import java.util.Map;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.util.Bytes;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.KeyKeys;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.GroupcommErrors;
import se.sics.ace.GroupcommParameters;
import se.sics.ace.GroupcommPolicies;
import se.sics.ace.Util;
import se.sics.ace.coap.CoapReq;
import se.sics.ace.oscore.GroupInfo;

/**
 * Definition of the Group OSCORE group-collection resource
 */
public class GroupOSCOREGroupConfigurationResource extends CoapResource {

	private final static String rootGroupMembershipResourcePath = "ace-group";
	
	private final static String groupCollectionResourcePath = "manage";
	
	private CBORObject groupConfiguration;
	
	private Map<String, GroupOSCOREGroupConfigurationResource> groupConfigurationResources;
	
	private Map<String, GroupInfo> existingGroupInfo;
	
	/**
     * Constructor
     * @param resId  the resource identifier
     * @param groupConfiguration  the group configuration, as a CBOR map
     * @param existingGroupInfo  the set of information of the existing OSCORE groups
     */
    public GroupOSCOREGroupConfigurationResource(String resId,
    											 CBORObject groupConfiguration,
    											 Map<String, GroupOSCOREGroupConfigurationResource> groupConfigurationResources,
			  									 Map<String, GroupInfo> existingGroupInfo) {
        
        // set resource identifier
        super(resId);
        
        // set display name
        getAttributes().setTitle("Group OSCORE Group Configuration Resource " + resId);
     
        this.groupConfiguration = groupConfiguration;
        this.groupConfigurationResources = groupConfigurationResources;
        this.existingGroupInfo = existingGroupInfo;

    }

    @Override
    public synchronized void handleGET(CoapExchange exchange) {

    	System.out.println("GET request reached the GM at /" + groupCollectionResourcePath + "/" + this.getName());
        
    	// Process the request for retrieving the Group Configuration
    	
    	String subject = null;
    	String errorString = null;
    	
    	Request request = exchange.advanced().getCurrentRequest();
        
        try {
			subject = CoapReq.getInstance(request).getSenderId();
		} catch (AceException e) {
		    System.err.println("Error while retrieving the client identity: " + e.getMessage());
		}
        if (subject == null) {
        	// At this point, this should not really happen, due to the earlier check at the Token Repository
        	errorString = new String("Unauthenticated client tried to get access");
        	System.err.println(errorString);
        	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, errorString);
        	return;
        }
    	
        // Check that at least one scope entry in the access token allows
        // the "Read" admin permission for this group-configuration resource
        boolean permitted = false;
        CBORObject[] adminScopeEntries = Util.getGroupOSCOREAdminPermissionsFromToken(subject, this.getName());
        if (adminScopeEntries == null) {
            errorString = new String("Operation not permitted");
            System.err.println(errorString);
            exchange.respond(CoAP.ResponseCode.FORBIDDEN, errorString);
            return;
        }
        for (int i = 0; i < adminScopeEntries.length; i++) {
            try {
                short permissions = (short) adminScopeEntries[i].get(1).AsInt32();
		        if (Util.checkGroupOSCOREAdminPermission(permissions, GroupcommParameters.GROUP_OSCORE_ADMIN_READ)) {
		        	permitted = Util.matchingGroupOscoreName(this.getName(), adminScopeEntries[i].get(0));
		        }
            } catch (AceException e) {
                System.err.println("Error while verifying the admin permissions: " + e.getMessage());
            }
            if (permitted) {
                break;
            }
        }
        if (!permitted) {
            errorString = new String("Operation not permitted");
            System.err.println(errorString);
            exchange.respond(CoAP.ResponseCode.FORBIDDEN, errorString);
            return;
        }        
        
    	// Respond to the request for retrieving the Group Configuration
        
    	CBORObject myResponse = CBORObject.NewMap();
    	for (CBORObject elemKey : this.groupConfiguration.getKeys()) {
    		myResponse.Add(elemKey, this.groupConfiguration.get(elemKey));
    	}
    	
    	// Fill in the response

    	byte[] responsePayload = myResponse.EncodeToBytes();
    	
    	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);
    	coapResponse.setPayload(responsePayload);
    	coapResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);

    	exchange.respond(coapResponse);

    }
    
    @Override
    public synchronized void handleFETCH(CoapExchange exchange) {

    	System.out.println("FETCH request reached the GM at /" + groupCollectionResourcePath + "/" + this.getName());
        
    	// Process the request for retrieving part of a Group Configuration by filters
    	
    	String subject = null;
    	String errorString = null;
    	
    	Request request = exchange.advanced().getCurrentRequest();
        
        try {
			subject = CoapReq.getInstance(request).getSenderId();
		} catch (AceException e) {
		    System.err.println("Error while retrieving the client identity: " + e.getMessage());
		}
        if (subject == null) {
        	// At this point, this should not really happen, due to the earlier check at the Token Repository
        	errorString = new String("Unauthenticated client tried to get access");
        	System.err.println(errorString);
        	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, errorString);
        	return;
        }
        
        // Check that at least one scope entry in the access token allows
        // the "Read" admin permission for this group-configuration resource
        boolean permitted = false;
        CBORObject[] adminScopeEntries = Util.getGroupOSCOREAdminPermissionsFromToken(subject, this.getName());
        if (adminScopeEntries == null) {
	        errorString = new String("Operation not permitted");
	        System.err.println(errorString);
	        exchange.respond(CoAP.ResponseCode.FORBIDDEN, errorString);
	        return;
        }
        for (int i = 0; i < adminScopeEntries.length; i++) {
        	try {
        		short permissions = (short) adminScopeEntries[i].get(1).AsInt32();
	            if (Util.checkGroupOSCOREAdminPermission(permissions, GroupcommParameters.GROUP_OSCORE_ADMIN_READ)) {
	                 permitted = Util.matchingGroupOscoreName(this.getName(), adminScopeEntries[i].get(0));
	            }
	        } catch (AceException e) {
	        	System.err.println("Error while verifying the admin permissions: " + e.getMessage());
	        }
	        if (permitted) {
	        	break;
	        }
        }
		if (!permitted) {
			errorString = new String("Operation not permitted");
			System.err.println(errorString);
			exchange.respond(CoAP.ResponseCode.FORBIDDEN, errorString);
			return;
		}
        
    	byte[] requestPayload = exchange.getRequestPayload();
    	
    	if(requestPayload == null || (requestPayload.length == 0)) {
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
    						 "A payload must be present");
    		return;
    	}

    	if(exchange.getRequestOptions().hasContentFormat() == false ||
    	   exchange.getRequestOptions().getContentFormat() != Constants.APPLICATION_ACE_GROUPCOMM_CBOR) {
        	errorString = new String("The CoAP option Content-Format must be present, with value application/ace-groupcomm+cbor");
    		System.err.println(errorString);
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
    		return;
    	}
    	
    	CBORObject requestCBOR = CBORObject.DecodeFromBytes(requestPayload);
		
    	// The payload of the request must be a CBOR Map
    	if (!requestCBOR.getType().equals(CBORType.Map)) {
			exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
							 "Invalid payload format");
    		return;
    	}
    	
    	// The CBOR Map in the payload must have only one element
    	if (requestCBOR.size() != 1) {
			exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
							 "Invalid payload format");
    		return;
    	}
    	
    	// The element of the CBOR Map must be 'conf_filter'
    	if (requestCBOR.ContainsKey(GroupcommParameters.CONF_FILTER) == false) {
			exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
							 "Invalid payload format");
    		return;
    	}

    	// The 'conf_filter' element of the CBOR Map must be a CBOR array
    	if (requestCBOR.get(GroupcommParameters.CONF_FILTER).getType() != CBORType.Array) {
			exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
							 "Invalid payload format");
    		return;
    	}
    	
    	// Check that the payload does not contain unexpected parameters
    	for (CBORObject elem : requestCBOR.getKeys()) {
    		if (!elem.equals(GroupcommParameters.CONF_FILTER)) {
    			exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
						 "Invalid payload format");
    	    	System.err.println("XXX4");
    			return;
    		}
    	}
    	
    	// Respond to the request for retrieving part of a Group Configuration by filters
        
    	CBORObject myResponse = CBORObject.NewMap();
    	
    	// Fill in the response

    	CBORObject confFilter = requestCBOR.get(GroupcommParameters.CONF_FILTER);
    	for (int i = 0; i < confFilter.size(); i++) {
    		CBORObject elemKey = confFilter.get(i);
    		if (this.groupConfiguration.ContainsKey(elemKey)) {
    			myResponse.Add(elemKey, this.groupConfiguration.get(elemKey));
    		}
    	}
    	
    	byte[] responsePayload = myResponse.EncodeToBytes();
    	
    	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);
    	coapResponse.setPayload(responsePayload);
    	coapResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);

    	exchange.respond(coapResponse);

    }
    
    @Override
    public synchronized void handlePOST(CoapExchange exchange) {
        
    	System.out.println("POST request reached the GM at /" + groupCollectionResourcePath + "/" + this.getName());
    	
    	// Process the request for overwriting a Group Configuration
    	
    	String subject = null;
    	String errorString = null;
    	
    	Request request = exchange.advanced().getCurrentRequest();
        
        try {
			subject = CoapReq.getInstance(request).getSenderId();
		} catch (AceException e) {
		    System.err.println("Error while retrieving the client identity: " + e.getMessage());
		}
        if (subject == null) {
        	// At this point, this should not really happen, due to the earlier check at the Token Repository
        	errorString = new String("Unauthenticated client tried to get access");
        	System.err.println(errorString);
        	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, errorString);
        	return;
        }
        
        // Check that at least one scope entry in the access token allows
        // the "Write" admin permission for this group-configuration resource
        boolean permitted = false;
        CBORObject[] adminScopeEntries = Util.getGroupOSCOREAdminPermissionsFromToken(subject, this.getName());
        if (adminScopeEntries == null) {
	        errorString = new String("Operation not permitted");
	        System.err.println(errorString);
	        exchange.respond(CoAP.ResponseCode.FORBIDDEN, errorString);
	        return;
        }
        for (int i = 0; i < adminScopeEntries.length; i++) {
        	try {
        		short permissions = (short) adminScopeEntries[i].get(1).AsInt32();
	            if (Util.checkGroupOSCOREAdminPermission(permissions, GroupcommParameters.GROUP_OSCORE_ADMIN_WRITE)) {
	                 permitted = Util.matchingGroupOscoreName(this.getName(), adminScopeEntries[i].get(0));
	            }
	        } catch (AceException e) {
	        	System.err.println("Error while verifying the admin permissions: " + e.getMessage());
	        }
	        if (permitted) {
	        	break;
	        }
        }
		if (!permitted) {
			errorString = new String("Operation not permitted");
			System.err.println(errorString);
			exchange.respond(CoAP.ResponseCode.FORBIDDEN, errorString);
			return;
		}
        
    	byte[] requestPayload = exchange.getRequestPayload();
    	
    	if(requestPayload == null || (requestPayload.length == 0)) {
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
    						 "A payload must be present");
    		return;
    	}

    	if(exchange.getRequestOptions().hasContentFormat() == false ||
    	   exchange.getRequestOptions().getContentFormat() != Constants.APPLICATION_ACE_GROUPCOMM_CBOR) {
        	errorString = new String("The CoAP option Content-Format must be present, with value application/ace-groupcomm+cbor");
    		System.err.println(errorString);
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
    		return;
    	}
    	
    	CBORObject requestCBOR = CBORObject.DecodeFromBytes(requestPayload);
    	
    	// The payload of the request must be a CBOR Map
    	if (!requestCBOR.getType().equals(CBORType.Map)) {
        	errorString = new String("Invalid payload format");
    		System.err.println(errorString);
			exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
    		return;
    	}
    	
    	// The payload of the request must not include:
    	// - The configuration parameters 'group_mode' and 'pairwise_mode'
    	// - The status parameters 'rt', 'ace_groupcomm_profile', 'joining_uri', 'group_name', and 'gid_reuse'
    	// - The parameters 'conf_filter' and 'app_groups_diff', as not pertaining to this request
    	if (requestCBOR.getKeys().contains(GroupcommParameters.GROUP_MODE) ||
    		requestCBOR.getKeys().contains(GroupcommParameters.PAIRWISE_MODE) ||
    		requestCBOR.getKeys().contains(GroupcommParameters.RT) ||
    		requestCBOR.getKeys().contains(GroupcommParameters.ACE_GROUPCOMM_PROFILE) ||
    		requestCBOR.getKeys().contains(GroupcommParameters.JOINING_URI) ||
    		requestCBOR.getKeys().contains(GroupcommParameters.GROUP_NAME) ||
    		requestCBOR.getKeys().contains(GroupcommParameters.GID_REUSE) ||
    		requestCBOR.getKeys().contains(GroupcommParameters.CONF_FILTER) ||
    		requestCBOR.getKeys().contains(GroupcommParameters.APP_GROUPS_DIFF)) {
			errorString = new String("Invalid set of parameters in the request");
    		System.err.println(errorString);
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
    		return;
    	}
    	
    	// This Group Manager does not support RSA an signature algorithm
    	if (requestCBOR.getKeys().contains(GroupcommParameters.SIGN_ALG)) {
    		CBORObject signAlg = requestCBOR.get(GroupcommParameters.SIGN_ALG);
    		if (signAlg.equals(AlgorithmID.RSA_PSS_256.AsCBOR()) ||
    			signAlg.equals(AlgorithmID.RSA_PSS_384.AsCBOR()) ||
    			signAlg.equals(AlgorithmID.RSA_PSS_512.AsCBOR())) {
    			
    		CBORObject myResponse = CBORObject.NewMap();
				errorString = new String("RSA is not supported as signature algorithm");
    		
    		CBORObject aceGroupcommError = CBORObject.NewMap();
    		aceGroupcommError.Add(0, GroupcommErrors.UNSUPPORTED_GROUP_CONF);
    		myResponse.Add(Constants.PROBLEM_DETAIL_ACE_GROUPCOMM_ERROR, aceGroupcommError);
    		myResponse.Add(Constants.PROBLEM_DETAIL_KEY_TITLE, GroupcommErrors.DESCRIPTION[GroupcommErrors.UNSUPPORTED_GROUP_CONF]);
    		myResponse.Add(Constants.PROBLEM_DETAIL_KEY_DETAIL, errorString);
    		
    		System.err.println(errorString);
    		exchange.respond(CoAP.ResponseCode.SERVICE_UNAVAILABLE,
    						 myResponse.EncodeToBytes(),
    						 Constants.APPLICATION_CONCISE_PROBLEM_DETAILS_CBOR);
    		
    		return;
			}
    	}
    	
    	for (CBORObject key : requestCBOR.getKeys()) {
    		if (!GroupcommParameters.isAdminRequestParameterMeaningful(key, requestCBOR.get(key))) {
    			errorString = new String("Malformed or unrecognized paramemeter with CBOR abbreviation: " + key.AsInt32());
    			System.err.println(errorString);
    			exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
    			return;
    		}
    	}
    	
    	// Build a the updated version of the group configuration, starting from the current version
    	
    	CBORObject buildOutput = null;
    	
    	synchronized (this.groupConfiguration) {
    		buildOutput = buildGroupConfiguration(requestCBOR, this.groupConfiguration);
    				
			// In case of success, update the group configuration
			if (buildOutput.size() == 4) {
				
				// For the three parameters 'group_name', 'joining_uri', and 'as_uri', the updated
				// configuration always inherits the same value from the current configuration
				buildOutput.get(3).Add(GroupcommParameters.GROUP_NAME, groupConfiguration.get(GroupcommParameters.GROUP_NAME));
				buildOutput.get(3).Add(GroupcommParameters.JOINING_URI, groupConfiguration.get(GroupcommParameters.JOINING_URI));
				buildOutput.get(3).Add(GroupcommParameters.AS_URI, groupConfiguration.get(GroupcommParameters.AS_URI));
				
				this.groupConfiguration = buildOutput.get(3);
			}
    	}
    	
    	// Update the group information in the corresponding group-membership resource 
    	
    	
    	// Prepare the set of parameters that are relevant for updating the group-memberhsip resource
    	CBORObject updatedParameterValues = CBORObject.NewMap();
    	
    	updatedParameterValues.Add(GroupcommParameters.HKDF, this.groupConfiguration.get(GroupcommParameters.HKDF));
    	updatedParameterValues.Add(GroupcommParameters.CRED_FMT, this.groupConfiguration.get(GroupcommParameters.CRED_FMT));
    	updatedParameterValues.Add(GroupcommParameters.GP_ENC_ALG, this.groupConfiguration.get(GroupcommParameters.GP_ENC_ALG));
    	updatedParameterValues.Add(GroupcommParameters.SIGN_ALG, this.groupConfiguration.get(GroupcommParameters.SIGN_ALG));
    	updatedParameterValues.Add(GroupcommParameters.SIGN_PARAMS, this.groupConfiguration.get(GroupcommParameters.SIGN_PARAMS));
    	updatedParameterValues.Add(GroupcommParameters.ALG, this.groupConfiguration.get(GroupcommParameters.ALG));
    	updatedParameterValues.Add(GroupcommParameters.ECDH_ALG, this.groupConfiguration.get(GroupcommParameters.ECDH_ALG));
    	updatedParameterValues.Add(GroupcommParameters.ECDH_PARAMS, this.groupConfiguration.get(GroupcommParameters.ECDH_PARAMS));
    	updatedParameterValues.Add(GroupcommParameters.GROUP_POLICIES, this.groupConfiguration.get(GroupcommParameters.GROUP_POLICIES));
    	updatedParameterValues.Add(GroupcommParameters.MAX_STALE_SETS, this.groupConfiguration.get(GroupcommParameters.MAX_STALE_SETS));
    	updatedParameterValues.Add(GroupcommParameters.ACTIVE, this.groupConfiguration.get(GroupcommParameters.ACTIVE));
    	
    	if (this.groupConfiguration.get(GroupcommParameters.DET_HASH_ALG) != null) {
    		updatedParameterValues.Add(this.groupConfiguration.get(GroupcommParameters.DET_HASH_ALG));
    	}

    	CBORObject changedParameters = existingGroupInfo.get(this.getName()).updateGroupInfo(updatedParameterValues);
    	
    	if (changedParameters == null) {
    		// This should never happen
			errorString = new String("Error while updating the group-membership resource");
			System.err.println(errorString);
			exchange.respond(CoAP.ResponseCode.INTERNAL_SERVER_ERROR, errorString);
			return;
    	}
    	
    	// Depending on the parameters that have been changed, the Group Manager may take particular actions 
    	
    	
    	// Respond to the request for overwriting a Group Configuration
		
    	ResponseCode responseCode = CoAP.ResponseCode.valueOf(buildOutput.get(0).AsInt32());
    	Response coapResponse = new Response(responseCode);
    	if (buildOutput.get(1) != null) {
    		int contentFormat = buildOutput.get(1).AsInt32();
        	coapResponse.getOptions().setContentFormat(contentFormat);
    	}
    	byte[] responsePayload = null;
    	if (buildOutput.get(2) == null) {
    		responsePayload = Bytes.EMPTY;
    	}
    	else if (buildOutput.get(2).getType() == CBORType.Map) {
    	   	// Prepare the information to return to the Administrator
    	   	CBORObject finalPayloadCBOR = CBORObject.NewMap();
        	
        	finalPayloadCBOR = buildOutput.get(2);    	
        	finalPayloadCBOR.Add(GroupcommParameters.GROUP_NAME, this.groupConfiguration.get(GroupcommParameters.GROUP_NAME));
        	finalPayloadCBOR.Add(GroupcommParameters.JOINING_URI, this.groupConfiguration.get(GroupcommParameters.JOINING_URI));
        	finalPayloadCBOR.Add(GroupcommParameters.AS_URI, this.groupConfiguration.get(GroupcommParameters.AS_URI));
    		
    		responsePayload = buildOutput.get(2).EncodeToBytes();
    	}
    	else if (buildOutput.get(2).getType() == CBORType.TextString) {
    		responsePayload = buildOutput.get(2).AsString().getBytes(Constants.charset);
    	}
    	coapResponse.setPayload(responsePayload);

    	exchange.respond(coapResponse);
    	
    }
    
    // TODO - This is just a stub
    @Override
    public synchronized void handlePATCH(CoapExchange exchange) {
        
    	System.out.println("PATCH request reached the GM at /" + groupCollectionResourcePath + "/" + this.getName());
    	
    	// Process the request for selectively updating a Group Configuration
    	
    	String subject = null;
    	String errorString = null;
    	
    	Request request = exchange.advanced().getCurrentRequest();
        
        try {
			subject = CoapReq.getInstance(request).getSenderId();
		} catch (AceException e) {
		    System.err.println("Error while retrieving the client identity: " + e.getMessage());
		}
        if (subject == null) {
        	// At this point, this should not really happen, due to the earlier check at the Token Repository
        	errorString = new String("Unauthenticated client tried to get access");
        	System.err.println(errorString);
        	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, errorString);
        	return;
        }
        
        // Check that at least one scope entry in the access token allows
        // the "Write" admin permission for this group-configuration resource
        boolean permitted = false;
        CBORObject[] adminScopeEntries = Util.getGroupOSCOREAdminPermissionsFromToken(subject, this.getName());
        if (adminScopeEntries == null) {
	        errorString = new String("Operation not permitted");
	        System.err.println(errorString);
	        exchange.respond(CoAP.ResponseCode.FORBIDDEN, errorString);
	        return;
        }
        for (int i = 0; i < adminScopeEntries.length; i++) {
        	try {
        		short permissions = (short) adminScopeEntries[i].get(1).AsInt32();
	            if (Util.checkGroupOSCOREAdminPermission(permissions, GroupcommParameters.GROUP_OSCORE_ADMIN_WRITE)) {
	                 permitted = Util.matchingGroupOscoreName(this.getName(), adminScopeEntries[i].get(0));
	            }
	        } catch (AceException e) {
	        	System.err.println("Error while verifying the admin permissions: " + e.getMessage());
	        }
	        if (permitted) {
	        	break;
	        }
        }
		if (!permitted) {
			errorString = new String("Operation not permitted");
			System.err.println(errorString);
			exchange.respond(CoAP.ResponseCode.FORBIDDEN, errorString);
			return;
		}
        
    	byte[] requestPayload = exchange.getRequestPayload();
    	
    	if(requestPayload == null || (requestPayload.length == 0)) {
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
    						 "A payload must be present");
    		return;
    	}

    	if(exchange.getRequestOptions().hasContentFormat() == false ||
    	   exchange.getRequestOptions().getContentFormat() != Constants.APPLICATION_ACE_GROUPCOMM_CBOR) {
        	errorString = new String("The CoAP option Content-Format must be present, with value application/ace-groupcomm+cbor");
    		System.err.println(errorString);
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
    		return;
    	}
    	
    	CBORObject requestCBOR = CBORObject.DecodeFromBytes(requestPayload);
    	
    	// TODO
    	
    	
    	// Respond to the request for selectively updating a Group Configuration
        
    	CBORObject myResponse = CBORObject.NewMap();
    	
    	// Fill in the response

    	byte[] responsePayload = myResponse.EncodeToBytes();
    	
    	Response coapResponse = new Response(CoAP.ResponseCode.CHANGED);
    	coapResponse.setPayload(responsePayload);
    	coapResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);

    	exchange.respond(coapResponse);
    	
    }
    
    // TODO - This is just a stub
    @Override
    public synchronized void handleIPATCH(CoapExchange exchange) {
        
    	System.out.println("iPATCH request reached the GM at /" + groupCollectionResourcePath + "/" + this.getName());
    	
    	// Process the request for selectively updating a Group Configuration
    	
    	String subject = null;
    	String errorString = null;
    	
    	Request request = exchange.advanced().getCurrentRequest();
        
        try {
			subject = CoapReq.getInstance(request).getSenderId();
		} catch (AceException e) {
		    System.err.println("Error while retrieving the client identity: " + e.getMessage());
		}
        if (subject == null) {
        	// At this point, this should not really happen, due to the earlier check at the Token Repository
        	errorString = new String("Unauthenticated client tried to get access");
        	System.err.println(errorString);
        	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, errorString);
        	return;
        }
        
        // Check that at least one scope entry in the access token allows
        // the "Write" admin permission for this group-configuration resource
        boolean permitted = false;
        CBORObject[] adminScopeEntries = Util.getGroupOSCOREAdminPermissionsFromToken(subject, this.getName());
        if (adminScopeEntries == null) {
	        errorString = new String("Operation not permitted");
	        System.err.println(errorString);
	        exchange.respond(CoAP.ResponseCode.FORBIDDEN, errorString);
	        return;
        }
        for (int i = 0; i < adminScopeEntries.length; i++) {
        	try {
        		short permissions = (short) adminScopeEntries[i].get(1).AsInt32();
	            if (Util.checkGroupOSCOREAdminPermission(permissions, GroupcommParameters.GROUP_OSCORE_ADMIN_WRITE)) {
	                 permitted = Util.matchingGroupOscoreName(this.getName(), adminScopeEntries[i].get(0));
	            }
	        } catch (AceException e) {
	        	System.err.println("Error while verifying the admin permissions: " + e.getMessage());
	        }
	        if (permitted) {
	        	break;
	        }
        }
		if (!permitted) {
			errorString = new String("Operation not permitted");
			System.err.println(errorString);
			exchange.respond(CoAP.ResponseCode.FORBIDDEN, errorString);
			return;
		}
        
    	byte[] requestPayload = exchange.getRequestPayload();
    	
    	if(requestPayload == null || (requestPayload.length == 0)) {
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST,
    						 "A payload must be present");
    		return;
    	}

    	if(exchange.getRequestOptions().hasContentFormat() == false ||
    	   exchange.getRequestOptions().getContentFormat() != Constants.APPLICATION_ACE_GROUPCOMM_CBOR) {
        	errorString = new String("The CoAP option Content-Format must be present, with value application/ace-groupcomm+cbor");
    		System.err.println(errorString);
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
    		return;
    	}
    	
    	CBORObject requestCBOR = CBORObject.DecodeFromBytes(requestPayload);
    	
    	// TODO
    	
    	
    	// Respond to the request for selectively updating a Group Configuration
        
    	CBORObject myResponse = CBORObject.NewMap();
    	
    	// Fill in the response

    	byte[] responsePayload = myResponse.EncodeToBytes();
    	
    	Response coapResponse = new Response(CoAP.ResponseCode.CHANGED);
    	coapResponse.setPayload(responsePayload);
    	coapResponse.getOptions().setContentFormat(Constants.APPLICATION_ACE_GROUPCOMM_CBOR);

    	exchange.respond(coapResponse);
    	
    }
    
    @Override
    public synchronized void handleDELETE(CoapExchange exchange) {
        
    	System.out.println("DELETE request reached the GM at /" + groupCollectionResourcePath + "/" + this.getName());
    	
    	// Process the request for deleting a Group Configuration
    	
    	String subject = null;
    	String errorString = null;
    	
    	Request request = exchange.advanced().getCurrentRequest();
        
        try {
			subject = CoapReq.getInstance(request).getSenderId();
		} catch (AceException e) {
		    System.err.println("Error while retrieving the client identity: " + e.getMessage());
		}
        if (subject == null) {
        	// At this point, this should not really happen, due to the earlier check at the Token Repository
        	errorString = new String("Unauthenticated client tried to get access");
        	System.err.println(errorString);
        	exchange.respond(CoAP.ResponseCode.UNAUTHORIZED, errorString);
        	return;
        }
    	
        // Check that at least one scope entry in the access token allows
        // the "Delete" admin permission for this group-configuration resource
        boolean permitted = false;
        CBORObject[] adminScopeEntries = Util.getGroupOSCOREAdminPermissionsFromToken(subject, this.getName());
        if (adminScopeEntries == null) {
	        errorString = new String("Operation not permitted");
	        System.err.println(errorString);
	        exchange.respond(CoAP.ResponseCode.FORBIDDEN, errorString);
	        return;
        }
        for (int i = 0; i < adminScopeEntries.length; i++) {
        	try {
        		short permissions = (short) adminScopeEntries[i].get(1).AsInt32();
	            if (Util.checkGroupOSCOREAdminPermission(permissions, GroupcommParameters.GROUP_OSCORE_ADMIN_DELETE)) {
	                 permitted = Util.matchingGroupOscoreName(this.getName(), adminScopeEntries[i].get(0));
	            }
	        } catch (AceException e) {
	        	System.err.println("Error while verifying the admin permissions: " + e.getMessage());
	        }
	        if (permitted) {
	        	break;
	        }
        }
		if (!permitted) {
			errorString = new String("Operation not permitted");
			System.err.println(errorString);
			exchange.respond(CoAP.ResponseCode.FORBIDDEN, errorString);
			return;
		}
        
		// Delete the entry associated with this group configuration
		// from the set stored at the group-collection resource
		synchronized(groupConfigurationResources) {
			this.groupConfigurationResources.remove(this.getName());
		}
		
		// Delete the corresponding group-membership resource
		synchronized(existingGroupInfo) {
			existingGroupInfo.remove(this.getName());
			
			CoapResource res = (CoapResource) this.getParent().getParent().getChild(rootGroupMembershipResourcePath).getChild(this.getName());
			if (res != null) {
				res.delete();
			}
		}
		
    	// Respond to the request for deleting a Group Configuration
        
    	Response coapResponse = new Response(CoAP.ResponseCode.DELETED);

    	delete();
    	exchange.respond(coapResponse);
    	
    }
    
	/**
     * Return the group configuration as a CBOR map
     * 
     * @return  the group configuration
     */
    public CBORObject getConfigurationParameters() {
    	return this.groupConfiguration;
    }

	/**
     * Return the default value for a certain parameter
     * 
     * @param paramAbbreviation  the abbreviation parameter for which to retrieve the default value, as CBOR integer
     * @return  the default value, or null in case of invalid parameter
     */
    public static CBORObject getDefaultValue(CBORObject paramAbbreviation) {
    	
    	if (paramAbbreviation.equals(GroupcommParameters.HKDF)) {
    		return CBORObject.FromObject(AlgorithmID.HMAC_SHA_256.AsCBOR().AsInt32()); // HMAC 256/256 for HKDF SHA-256
    	}
    	if (paramAbbreviation.equals(GroupcommParameters.CRED_FMT)) {
    		return CBORObject.FromObject(Constants.COSE_HEADER_PARAM_KCCS); // CWT Claims Set (CCS)
    	}
    	if (paramAbbreviation.equals(GroupcommParameters.MAX_STALE_SETS)) {
    		return CBORObject.FromObject(3);
    	}
    	if (paramAbbreviation.equals(GroupcommParameters.GROUP_MODE)) {
			return CBORObject.True;
    	}
    	if (paramAbbreviation.equals(GroupcommParameters.GP_ENC_ALG)) {
    		return CBORObject.FromObject(AlgorithmID.AES_CCM_16_64_128.AsCBOR().AsInt32()); // AES-CCM-16-64-128
    	}
    	if (paramAbbreviation.equals(GroupcommParameters.SIGN_ALG)) {
    		return CBORObject.FromObject(AlgorithmID.EDDSA.AsCBOR().AsInt32Value()); // EdDSA
    	}
    	if (paramAbbreviation.equals(GroupcommParameters.DET_REQ)) {
			return CBORObject.False;
    	}
    	if (paramAbbreviation.equals(GroupcommParameters.DET_HASH_ALG)) {
			return CBORObject.FromObject(-16); // SHA-256
    	}
    	if (paramAbbreviation.equals(GroupcommParameters.PAIRWISE_MODE)) {
			return CBORObject.True;
    	}
    	if (paramAbbreviation.equals(GroupcommParameters.ALG)) {
    		return CBORObject.FromObject(AlgorithmID.AES_CCM_16_64_128.AsCBOR().AsInt32Value()); // AES-CCM-16-64-128
    	}
    	if (paramAbbreviation.equals(GroupcommParameters.ECDH_ALG)) {
			return CBORObject.FromObject(AlgorithmID.ECDH_SS_HKDF_256.AsCBOR().AsInt32Value()); // ECDH-SS + HKDF-256
    	}
    	if (paramAbbreviation.equals(GroupcommParameters.ACTIVE)) {
    		return CBORObject.False;
    	}
    	if (paramAbbreviation.equals(GroupcommParameters.GROUP_DESCRIPTION)) {
    		return CBORObject.Null;
    	}
    	if (paramAbbreviation.equals(GroupcommParameters.GID_REUSE)) {
    		return CBORObject.False;
    	}
    	if (paramAbbreviation.equals(GroupcommParameters.APP_GROUPS)) {
    		return CBORObject.NewArray();
    	}
    	if (paramAbbreviation.equals(GroupcommParameters.GROUP_POLICIES)) {
			CBORObject ret = CBORObject.NewMap();
			ret.Add(GroupcommPolicies.KEY_CHECK_INTERVAL, 3600);
			ret.Add(GroupcommPolicies.EXP_DELTA, 0);
			return ret;
    	}
    	if (paramAbbreviation.equals(GroupcommParameters.EXP)) {
    		long currentUnixTime = System.currentTimeMillis() / 1000L;
    		long lifetime = 3600 * 24 * 365; // Set the lifetime of the group for 1 year from now
    		CBORObject ret = CBORObject.FromObject(currentUnixTime + lifetime); 
    		return ret;
    	}
    	
    	return null;
    	
    }
    
	/**
     * Return the default value for the 'sign_params' parameter
     * 
     * @param signAlg  the value of the parameter sign_alg
     * @return  the default value, or null in case of invalid parameter
     */
    public static CBORObject getDefaultValueSignParams(CBORObject signAlg) {
    	CBORObject ret = null;
    	if (signAlg.equals(CBORObject.FromObject(AlgorithmID.EDDSA.AsCBOR()))) {
    		ret = CBORObject.NewArray();
        	ret.Add(CBORObject.NewArray());
        	ret.Add(CBORObject.NewArray());
        	ret.get(0).Add(KeyKeys.KeyType_OKP);
        	ret.get(1).Add(KeyKeys.KeyType_OKP);
        	ret.get(1).Add(KeyKeys.OKP_Ed25519);
    		return ret;
    	}
    	if (signAlg.equals(CBORObject.FromObject(AlgorithmID.ECDSA_256.AsCBOR()))) {
    		ret = CBORObject.NewArray();
        	ret.Add(CBORObject.NewArray());
        	ret.Add(CBORObject.NewArray());
        	ret.get(0).Add(KeyKeys.KeyType_EC2);
        	ret.get(1).Add(KeyKeys.KeyType_EC2);
        	ret.get(1).Add(KeyKeys.EC2_P256);
    		return ret;
    	}
    	if (signAlg.equals(CBORObject.FromObject(AlgorithmID.ECDSA_384.AsCBOR()))) {
    		ret = CBORObject.NewArray();
        	ret.Add(CBORObject.NewArray());
        	ret.Add(CBORObject.NewArray());
        	ret.get(0).Add(KeyKeys.KeyType_EC2);
        	ret.get(1).Add(KeyKeys.KeyType_EC2);
        	ret.get(1).Add(KeyKeys.EC2_P384);
    		return ret;
    	}
    	if (signAlg.equals(CBORObject.FromObject(AlgorithmID.ECDSA_512.AsCBOR()))) {
    		ret = CBORObject.NewArray();
        	ret.Add(CBORObject.NewArray());
        	ret.Add(CBORObject.NewArray());
        	ret.get(0).Add(KeyKeys.KeyType_EC2);
        	ret.get(1).Add(KeyKeys.KeyType_EC2);
        	ret.get(1).Add(KeyKeys.EC2_P521);
    		return ret;
    	}
    	if (signAlg.equals(CBORObject.FromObject(AlgorithmID.RSA_PSS_256.AsCBOR())) ||
    		signAlg.equals(CBORObject.FromObject(AlgorithmID.RSA_PSS_384.AsCBOR())) ||
    		signAlg.equals(CBORObject.FromObject(AlgorithmID.RSA_PSS_512.AsCBOR()))) {
    		ret = CBORObject.NewArray();
        	ret.Add(CBORObject.NewArray());
        	ret.Add(CBORObject.NewArray());
        	ret.get(0).Add(KeyKeys.KeyType_RSA);
        	ret.get(1).Add(KeyKeys.KeyType_RSA);
    		return ret;
    	}
    	return ret;
    }
    
	/**
     * Return the default value for the 'ecdh_params' parameter
     * 
     * @param signAlg  the value of the parameter sign_alg
     * @param groupMode  true if the group uses the group mode, or false otherwise
     * @return  the default value, or null in case of invalid parameter
     */
    public static CBORObject getDefaultValueEcdhParams(CBORObject signAlg, boolean groupMode) {
    	CBORObject ret = null;
    	if (signAlg.equals(CBORObject.FromObject(AlgorithmID.EDDSA.AsCBOR())) || (groupMode == false)) {
    		ret = CBORObject.NewArray();
        	ret.Add(CBORObject.NewArray());
        	ret.Add(CBORObject.NewArray());
        	ret.get(0).Add(KeyKeys.KeyType_OKP);
        	ret.get(1).Add(KeyKeys.KeyType_OKP);
        	ret.get(1).Add(KeyKeys.OKP_X25519);
    		return ret;
    	}
    	if (signAlg.equals(CBORObject.FromObject(AlgorithmID.ECDSA_256.AsCBOR()))) {
    		ret = CBORObject.NewArray();
        	ret.Add(CBORObject.NewArray());
        	ret.Add(CBORObject.NewArray());
        	ret.get(0).Add(KeyKeys.KeyType_EC2);
        	ret.get(1).Add(KeyKeys.KeyType_EC2);
        	ret.get(1).Add(KeyKeys.EC2_P256);
    		return ret;
    	}
    	if (signAlg.equals(CBORObject.FromObject(AlgorithmID.ECDSA_384.AsCBOR()))) {
    		ret = CBORObject.NewArray();
        	ret.Add(CBORObject.NewArray());
        	ret.Add(CBORObject.NewArray());
        	ret.get(0).Add(KeyKeys.KeyType_EC2);
        	ret.get(1).Add(KeyKeys.KeyType_EC2);
        	ret.get(1).Add(KeyKeys.EC2_P384);
    		return ret;
    	}
    	if (signAlg.equals(CBORObject.FromObject(AlgorithmID.ECDSA_512.AsCBOR()))) {
    		ret = CBORObject.NewArray();
        	ret.Add(CBORObject.NewArray());
        	ret.Add(CBORObject.NewArray());
        	ret.get(0).Add(KeyKeys.KeyType_EC2);
        	ret.get(1).Add(KeyKeys.KeyType_EC2);
        	ret.get(1).Add(KeyKeys.EC2_P521);
    		return ret;
    	}
    	
    	return ret;
    }
    
	/**
     * Create a preliminary group configuration
     * 
     * @param requestCBOR  the payload of the request from the administrator, as a CBOR map
     * @param baseConfiguration  the current group configuration, if the request was a PUT request to the group-configuration resource;
     *                           or null, if the request was a POST request to the group-collection resource 
     * @return  a CBOR array with up to four elements, in this order
     * 			- The CoAP response code for the response to the Administrator, as a CBOR integer
     * 			- The CoAP Content-Format to use in the response to the Administrator, as a CBOR integer. It can be null
     * 			- The payload for the response to the Administrator, as a CBOR map or a CBOR text string. It can be null
     * 			- Present only in case of success, the preliminary group configuration, as a CBOR map
     * 
    */
    static public CBORObject buildGroupConfiguration(final CBORObject requestCBOR, final CBORObject baseConfiguration) {
    	
    	CBORObject parameterName;
		CBORObject parameterValue = null;
    	CBORObject newGroupConfiguration = CBORObject.NewMap();
    	CBORObject ret = CBORObject.NewArray();
    	int responseCode = -1;
    	int contentFormat = -1;
    	CBORObject responsePayload = null;
    	String errorString = null;
    	
    	List<Integer> parameterList = new ArrayList<>();
    	
    	// Configuration parameters
    	parameterList.add(GroupcommParameters.HKDF.AsInt32());
    	parameterList.add(GroupcommParameters.CRED_FMT.AsInt32());
    	parameterList.add(GroupcommParameters.GROUP_MODE.AsInt32());
    	parameterList.add(GroupcommParameters.GP_ENC_ALG.AsInt32());
    	parameterList.add(GroupcommParameters.SIGN_ALG.AsInt32());
    	parameterList.add(GroupcommParameters.SIGN_PARAMS.AsInt32());
    	parameterList.add(GroupcommParameters.PAIRWISE_MODE.AsInt32());
    	parameterList.add(GroupcommParameters.ALG.AsInt32());
    	parameterList.add(GroupcommParameters.ECDH_ALG.AsInt32());
    	parameterList.add(GroupcommParameters.ECDH_PARAMS.AsInt32());
    	parameterList.add(GroupcommParameters.DET_REQ.AsInt32());
    	parameterList.add(GroupcommParameters.DET_HASH_ALG.AsInt32());
    	
    	// Status parameters
    	parameterList.add(GroupcommParameters.RT.AsInt32());
    	parameterList.add(GroupcommParameters.ACTIVE.AsInt32());
    	parameterList.add(GroupcommParameters.GROUP_NAME.AsInt32());
    	parameterList.add(GroupcommParameters.GROUP_DESCRIPTION.AsInt32());
    	parameterList.add(GroupcommParameters.ACE_GROUPCOMM_PROFILE.AsInt32());
    	parameterList.add(GroupcommParameters.MAX_STALE_SETS.AsInt32());
    	parameterList.add(GroupcommParameters.EXP.AsInt32());
    	parameterList.add(GroupcommParameters.GROUP_POLICIES.AsInt32());
    	parameterList.add(GroupcommParameters.GID_REUSE.AsInt32());
    	parameterList.add(GroupcommParameters.APP_GROUPS.AsInt32());
    	parameterList.add(GroupcommParameters.JOINING_URI.AsInt32());
    	parameterList.add(GroupcommParameters.AS_URI.AsInt32());

    	for (Integer i : parameterList) {
    		parameterName = CBORObject.FromObject(i.intValue());
    		
    		// Some parameters require additional, special handling
    		boolean omit = false;
    		boolean postpone = false;
    		CBORObject forcedValue = null;
    		
    		if (parameterName.equals(GroupcommParameters.GP_ENC_ALG) ||
    			parameterName.equals(GroupcommParameters.SIGN_ALG)   ||
    			parameterName.equals(GroupcommParameters.SIGN_PARAMS)) {
    			if (newGroupConfiguration.get(GroupcommParameters.GROUP_MODE).equals(CBORObject.False)) {
    				forcedValue = CBORObject.Null;
    			}
    		}
    		else if (parameterName.equals(GroupcommParameters.ALG) ||
    				 parameterName.equals(GroupcommParameters.ECDH_ALG)   ||
    				 parameterName.equals(GroupcommParameters.ECDH_PARAMS)) {
        		if (newGroupConfiguration.get(GroupcommParameters.PAIRWISE_MODE).equals(CBORObject.False)) {
        			forcedValue = CBORObject.Null;
        		}
        	}
    		else if (parameterName.equals(GroupcommParameters.DET_REQ)) {
        		if (newGroupConfiguration.get(GroupcommParameters.GROUP_MODE).equals(CBORObject.False) ||
        			newGroupConfiguration.get(GroupcommParameters.PAIRWISE_MODE).equals(CBORObject.False)) {
        			omit = true;
        		}
        	}
    		else if (parameterName.equals(GroupcommParameters.DET_HASH_ALG)) {
        		if ((newGroupConfiguration.ContainsKey(GroupcommParameters.DET_REQ) == false) ||
        			(newGroupConfiguration.get(GroupcommParameters.DET_REQ).equals(CBORObject.False))) {
        			omit = true;
        		}
        	}
    		else if (parameterName.equals(GroupcommParameters.RT)) {
    			forcedValue = CBORObject.FromObject("core.osc.gconf");
    		}
    		else if (parameterName.equals(GroupcommParameters.GROUP_NAME)) {
    			// The group name will be assigned later
    			postpone = true;
    		}
    		else if (parameterName.equals(GroupcommParameters.ACE_GROUPCOMM_PROFILE)) {
    			forcedValue = CBORObject.FromObject(GroupcommParameters.COAP_GROUP_OSCORE_APP);
    		}
    		else if (parameterName.equals(GroupcommParameters.JOINING_URI)) {
    			// The URI of the group-membership resource will be assigned later
    			postpone = true;
    		}
    		else if (parameterName.equals(GroupcommParameters.AS_URI)) {
    			// The URI of the associated Authorization Server will be assigned later
    			
    			// (This Group Manager is not going to accept any Authorization Server
    			//  suggested by the Administrator, and always force its preferred one)
    			postpone = true;
    		}
    		
			if ((requestCBOR.ContainsKey(parameterName)) && (postpone == false)) {
				// The Administrator has specified a value for this parameter,
				// which also has to be included now in the group configuration
				
				parameterValue = requestCBOR.get(parameterName);
				
				boolean inconsistentValue = ((forcedValue != null) && (parameterValue.equals(forcedValue) == false));
				
				if (omit || inconsistentValue) {
					// The Administrator has specified a parameter that was not supposed to be specified at all,
					// or a parameter with a value different than the value that must be taken by such a parameter					
					errorString = new String(
							"1 Invalid use of the parameter with abbreviation' " + parameterName + "'");
					responseCode = CoAP.ResponseCode.BAD_REQUEST.value;
					contentFormat = Constants.APPLICATION_CONCISE_PROBLEM_DETAILS_CBOR;
					
					responsePayload = CBORObject.NewMap();
					CBORObject aceGroupcommError = CBORObject.NewMap();
					aceGroupcommError.Add(0, GroupcommErrors.UNSUPPORTED_GROUP_CONF);
					responsePayload.Add(Constants.PROBLEM_DETAIL_ACE_GROUPCOMM_ERROR, aceGroupcommError);
					responsePayload.Add(Constants.PROBLEM_DETAIL_KEY_TITLE, GroupcommErrors.DESCRIPTION[GroupcommErrors.UNSUPPORTED_GROUP_CONF]);
					responsePayload.Add(Constants.PROBLEM_DETAIL_KEY_DETAIL, errorString);
					
					System.err.println(errorString);
					break;
				}

				boolean isMeaningful = GroupcommParameters.isAdminParameterValueMeaningful(parameterName, parameterValue);
				
				if (isMeaningful == false) {
					// The value of the parameter is not valid
					errorString = new String(
							"2 Invalid use of the parameter with abbreviation' " + parameterName + "'");
					responseCode = CoAP.ResponseCode.BAD_REQUEST.value;
					responsePayload = CBORObject.FromObject(errorString);
					System.err.println(errorString);
					break;
				}
				
			}
			else {
				if (postpone || omit) {
					// This parameter does not have to be included
					// now or at all in the group configuration
					continue;
				}
				
				// This parameter has to be included now in the group configuration
				
				if (forcedValue != null) {
					parameterValue = forcedValue;
				}
				else {
					boolean useDefaultValue = true;

					if (baseConfiguration != null) {
						// This request was sent to overwrite the current group configuration
						
						// These parameters do not change in case of group configuration update.
						// They must keep the same value that they have in the current group configuration.
						if (parameterName.equals(GroupcommParameters.GROUP_MODE) ||
							parameterName.equals(GroupcommParameters.PAIRWISE_MODE) ||
							parameterName.equals(GroupcommParameters.GID_REUSE) ||
							parameterName.equals(GroupcommParameters.EXP)) {
							parameterValue = baseConfiguration.get(parameterName);
							useDefaultValue = false;
						}
					}
					
					if (useDefaultValue == true) {
						// Retrieve the default value for this parameter
						if (parameterName.equals(GroupcommParameters.SIGN_PARAMS)) {
							parameterValue = getDefaultValueSignParams(newGroupConfiguration.get(GroupcommParameters.SIGN_ALG));
						}
						else if (parameterName.equals(GroupcommParameters.ECDH_PARAMS)) {
							boolean groupMode = newGroupConfiguration.get(GroupcommParameters.GROUP_MODE).equals(CBORObject.True) ? true : false;
							parameterValue = getDefaultValueEcdhParams(newGroupConfiguration.get(GroupcommParameters.SIGN_ALG), groupMode);
						}
						else {
							parameterValue = getDefaultValue(parameterName);
						}
					}
					
					if (parameterValue == null) {
						// This should never happen
						errorString = new String("Error determining the default value for the parameter with abbreviation' " + parameterName + "'");
						responseCode = CoAP.ResponseCode.INTERNAL_SERVER_ERROR.value;
						responsePayload = CBORObject.FromObject(errorString);
						System.err.println(errorString);
						break;
					}
				}
			}

			// No error has occurred; include the parameter in the group configuration
			newGroupConfiguration.Add(parameterName, parameterValue);
				
    	}
    	
    	// Failure
    	if (responseCode != -1) {
    		ret.Add(responseCode);
	    	ret.Add((contentFormat == -1) ? null : CBORObject.FromObject(contentFormat));
			ret.Add(responsePayload);
    	}
    	// Success
    	else {
	    	responseCode = (baseConfiguration == null) ? CoAP.ResponseCode.CREATED.value : CoAP.ResponseCode.CHANGED.value;
	    	contentFormat = Constants.APPLICATION_ACE_GROUPCOMM_CBOR;
	    	responsePayload = CBORObject.NewMap();
	    	ret.Add(responseCode);
			ret.Add(contentFormat);
			ret.Add(responsePayload);
			ret.Add(newGroupConfiguration);
    	}
    	
    	return ret;
    	
    }
    
}
