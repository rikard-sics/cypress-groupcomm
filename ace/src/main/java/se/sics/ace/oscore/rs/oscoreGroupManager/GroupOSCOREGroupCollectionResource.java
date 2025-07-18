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

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.elements.util.Bytes;

import com.mifmif.common.regex.Generex;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.OneKey;
import net.i2p.crypto.eddsa.Utils;
import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.GroupcommErrors;
import se.sics.ace.GroupcommParameters;
import se.sics.ace.Util;
import se.sics.ace.coap.CoapReq;
import se.sics.ace.oscore.GroupInfo;
import se.sics.ace.oscore.rs.GroupOSCOREValidator;

/**
 * Definition of the Group OSCORE group-collection resource
 */
public class GroupOSCOREGroupCollectionResource extends CoapResource {
	
	private Map<String, GroupOSCOREGroupConfigurationResource> groupConfigurationResources = new HashMap<>();
	
	Resource groupOSCORERootGroupMembership;
	
	private int groupIdPrefixSize;
	
	private Set<CBORObject> usedGroupIdPrefixes = new HashSet<>();
	
	private String prefixMonitorNames;
	
	private String nodeNameSeparator;
	
	private Map<String, GroupInfo> existingGroupInfo = new HashMap<>();
	
	private Map<String, Map<String, Set<Short>>> myScopes;
	
	private GroupOSCOREValidator valid;

    // The map key is the cryptographic curve; the map value is the hex string of the key pair
    private Map<CBORObject, String> gmSigningKeyPairs;
    
    // For the outer map, the map key is the type of authentication credential
    // For the inner map, the map key is the cryptographic curve, while the map value is the hex string of the authentication credential
    private Map<Integer,  Map<CBORObject, String>> gmSigningPublicAuthCred;
    
    // The map key is the cryptographic curve; the map value is the hex string of the key pair
    private Map<CBORObject, String> gmKeyAgreementKeyPairs;
    
    // For the outer map, the map key is the type of authentication credential
    // For the inner map, the map key is the cryptographic curve, while the map value is the hex string of the authentication credential
    private Map<Integer,  Map<CBORObject, String>> gmKeyAgreementPublicAuthCred;
    
	private final String asUri = new String("coap://as.example.com/token");
	
    private final static String rootGroupMembershipResourcePath = "ace-group";
    
    private final static String groupCollectionResourcePath = "manage";
    
	private final int maxRandomGroupNameLength = 20;
	private final int maxRandomGroupNameAttempts = 1000;
	private final int maxRandomGroupNameAttemptsPerPattern = 50;
		
	/**
     * Constructor
     * @param resId  the resource identifier
     * @param groupOSCORERootGroupMembership  the root group-membership resource
     * @param groupIdPrefixSize  the size in bytes of the Group ID prefixes
     * @param usedGroupIdPrefixes  the set of currently used Group ID prefixes
     * @param prefixMonitorNames  initial part of the node name for monitors
     * @param nodeNameSeparator  for non-monitor members, separator between the two components of the node name
     * @param existingGroupInfo  the set of information of the existing OSCORE groups
     * @param gmSigningKeyPairs  the signing key pairs of the Group Manager
     * @param gmSigningPublicAuthCred  the signing public authentication credentials of the Group Manager
     * @param gmKeyAgreementKeyPairs  the key agreement key pairs of the Group Manager
     * @param gmKeyAgreementPublicAuthCred  the key agreement public authentication credentials of the Group Manager
     * @param myScopes  the scopes of this OSCORE Group Manager
     * @param valid  the access validator of this OSCORE Group Manager
     */
    public GroupOSCOREGroupCollectionResource(String resId,
    										  Resource groupOSCORERootGroupMembership,
    										  final int groupIdPrefixSize,
    										  Set<CBORObject> usedGroupIdPrefixes,
    										  String prefixMonitorNames,
    										  String nodeNameSeparator,
    										  Map<String, GroupInfo> existingGroupInfo,
    										  Map<CBORObject, String> gmSigningKeyPairs,
    										  Map<Integer,  Map<CBORObject, String>> gmSigningPublicAuthCred,
    										  Map<CBORObject, String> gmKeyAgreementKeyPairs,
    										  Map<Integer,  Map<CBORObject, String>> gmKeyAgreementPublicAuthCred,
    										  Map<String, Map<String, Set<Short>>> myScopes,
    										  GroupOSCOREValidator valid) {
        
        // set resource identifier
        super(resId);
        
        // set display name
        getAttributes().setTitle("Group OSCORE Group Collection Resource " + resId);
     
        this.groupOSCORERootGroupMembership = groupOSCORERootGroupMembership;
        
        this.groupIdPrefixSize = groupIdPrefixSize;
        this.usedGroupIdPrefixes = usedGroupIdPrefixes;
        
        this.prefixMonitorNames = prefixMonitorNames;
        this.nodeNameSeparator = nodeNameSeparator;
        
        this.existingGroupInfo = existingGroupInfo;
        
        this.gmSigningKeyPairs = gmSigningKeyPairs;
        this.gmSigningPublicAuthCred = gmSigningPublicAuthCred;
        this.gmKeyAgreementKeyPairs = gmKeyAgreementKeyPairs;
        this.gmKeyAgreementPublicAuthCred = gmKeyAgreementPublicAuthCred;
        
        this.myScopes = myScopes;
        this.valid = valid;
        
        // TODO: remove
        // ============
        // Force the presence of an already existing group configuration for early testing
        GroupOSCOREGroupConfigurationResource testConf = new GroupOSCOREGroupConfigurationResource(
        													"gp500", CBORObject.NewMap(),
        													this.groupConfigurationResources,
        													this.existingGroupInfo);
        testConf.getConfigurationParameters().Add(GroupcommParameters.GROUP_NAME, CBORObject.FromObject("gp500"));
        this.groupConfigurationResources.put("gp500", testConf);
        // ============
        
    }

    @Override
    public synchronized void handleGET(CoapExchange exchange) {
    	
    	System.out.println("GET request reached the GM at /" + groupCollectionResourcePath);
        
    	// Process the request for retrieving the full list of Group Configurations
    	
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
        
    	// Check that at least one scope entry in the access token allows the "List" admin permission
    	CBORObject[] permissionSetToken = Util.getGroupOSCOREAdminPermissionsFromToken(subject, null);
    	if (permissionSetToken == null) {
        	errorString = new String("Operation not permitted");
    		System.err.println(errorString);
    		exchange.respond(CoAP.ResponseCode.FORBIDDEN, errorString);
    		return;
    	}
    	
    	String auxString = new String("");
    	
    	for (String groupName : this.groupConfigurationResources.keySet()) {
    		boolean selected = false;
    		
    		for (int i = 0; i < permissionSetToken.length; i++) {
    			if (Util.matchingGroupOscoreName(groupName, permissionSetToken[i].get(0))) {
    				try {
        				int permissions = permissionSetToken[i].get(1).AsInt32();
    					if (Util.checkGroupOSCOREAdminPermission(permissions, GroupcommParameters.GROUP_OSCORE_ADMIN_LIST)) {
    						// One match has been found
    						selected = true;
    						break;
    					}
					} catch (AceException e) {
						System.err.println("Error while checking the group name against the group name pattern: " + e.getMessage());
					}
    			}
    		}
    		
    		if (selected == false) {
    			// Move to the next group-configuration resource
    			continue;
    		}
    		
    		// This group configuration has passed the filtering and has been selected
    		if (auxString.equals("") == false) {
    			auxString += ",";
    		}
    		
    		auxString += "<" + request.getURI() + "/" + groupName + ">;rt=\"core.osc.gconf\"";
    	}
    	
    	// Respond to the request for retrieving the full list of Group Configurations

    	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);

    	if (this.existingGroupInfo.size() != 0) {
        	byte[] responsePayload = auxString.getBytes(Constants.charset);
        	coapResponse.setPayload(responsePayload);
    		coapResponse.getOptions().setContentFormat(MediaTypeRegistry.APPLICATION_LINK_FORMAT);
    	}

    	exchange.respond(coapResponse);

    }
    
    @Override
    public synchronized void handleFETCH(CoapExchange exchange) {

    	System.out.println("FETCH request reached the GM at /" + groupCollectionResourcePath);
        
    	// Process the request for retrieving a list of Group Configurations by filters
    	
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
    	
    	// Check that at least one scope entry in the access token allows the "List" admin permission
    	CBORObject[] permissionSetToken = Util.getGroupOSCOREAdminPermissionsFromToken(subject, null);
    	if (permissionSetToken == null) {
        	errorString = new String("Operation not permitted");
    		System.err.println(errorString);
    		exchange.respond(CoAP.ResponseCode.FORBIDDEN, errorString);
    		return;
    	}
        
    	byte[] requestPayload = exchange.getRequestPayload();
    	
    	if(requestPayload == null || (requestPayload.length == 0)) {
        	errorString = new String("A payload must be present");
    		System.err.println(errorString);
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
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
    	
    	for (CBORObject key : requestCBOR.getKeys()) {
    		boolean error = false;
    		
    		if (!GroupcommParameters.isAdminRequestParameterMeaningful(key, requestCBOR.get(key))) {
    			error = true;
    		}
    		if (!error && key.equals(GroupcommParameters.GROUP_NAME) && requestCBOR.get(key).isTagged()) {
    			 if (!requestCBOR.get(key).HasOneTag() || !requestCBOR.get(key).HasTag(21065)) {
    				 error = true;
    			 }
    		}

    		if (error) {
            	errorString = new String("Invalid format of paramemeter with CBOR abbreviation: " + key.AsInt32());
        		System.err.println(errorString);
    			exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
    			return;
    		}
    	}
    	
    	String auxString = new String("");
    	
    	for (String groupName : this.groupConfigurationResources.keySet()) {
    		
			boolean selected = false;
    		
		    for (int i = 0; i < permissionSetToken.length; i++) {
		        if (Util.matchingGroupOscoreName(groupName, permissionSetToken[i].get(0))) {
		            try {
			            int permissions = permissionSetToken[i].get(1).AsInt32();
		                if (Util.checkGroupOSCOREAdminPermission(permissions, GroupcommParameters.GROUP_OSCORE_ADMIN_LIST)) {
		                    // One match has been found
		                    selected = true;
		                    break;
		                }
		            } catch (AceException e) {
		                System.err.println("Error while checking the group name against the group name pattern: " + e.getMessage());
		            }
		        }
		    }
		    
		    if (selected == false) {
		        // Move to the next group-configuration resource
		        continue;
		    }
		    
			CBORObject configurationParameters = this.groupConfigurationResources.get(groupName).getConfigurationParameters();
		    
    		// Perform the filtering based on the specified filter criteria
    		for (CBORObject elemKey : requestCBOR.getKeys()) {
    			
    			// The parameter in the filter must be present in the configuration
    			if (configurationParameters.ContainsKey(elemKey) == false) {
    				selected = false;
    				break;
    			}
    			
    			if (elemKey.equals(GroupcommParameters.GROUP_NAME)) {
    				if (!Util.matchingGroupOscoreName(groupName, requestCBOR.get(elemKey))) {
    					selected = false;
    					break;
    				}
    			}
    			else if (requestCBOR.get(elemKey).equals(configurationParameters.get(elemKey)) == false) {
					selected = false;
					break;
    			}
    			
    		}
    		
			if (selected == true) {
    			// This group configuration has passed the filtering and has been selected
	    		if (auxString.equals("") == false) {
	    			auxString += ",";
	    		}
        		auxString += "<" + request.getURI() + "/" + groupName + ">;rt=\"core.osc.gconf\"";
			}

    	}
    	
    	
    	// Respond to the request for retrieving a list of Group Configurations by filters
        
    	Response coapResponse = new Response(CoAP.ResponseCode.CONTENT);

    	if (this.existingGroupInfo.size() != 0) {
        	byte[] responsePayload = auxString.getBytes(Constants.charset);
        	coapResponse.setPayload(responsePayload);
    		coapResponse.getOptions().setContentFormat(MediaTypeRegistry.APPLICATION_LINK_FORMAT);
    	}

    	exchange.respond(coapResponse);

    }
    
    @Override
    public synchronized void handlePOST(CoapExchange exchange) {
        
    	System.out.println("POST request reached the GM at /" + groupCollectionResourcePath);
    	
    	// Process the request for creating a new Group Configuration
    	
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
        
    	// Check that at least one scope entry in the access token allows the "Create" admin permission
        boolean permitted = false;
    	CBORObject[] adminScopeEntries = Util.getGroupOSCOREAdminPermissionsFromToken(subject, null);
    	if (adminScopeEntries == null) {
        	errorString = new String("Operation not permitted");
    		System.err.println(errorString);
    		exchange.respond(CoAP.ResponseCode.FORBIDDEN, errorString);
    		return;
    	}

    	for (int i = 0; i < adminScopeEntries.length; i++) {
    		try {
        		short permissions = (short) adminScopeEntries[i].get(1).AsInt32(); 
        		permitted = Util.checkGroupOSCOREAdminPermission(permissions, GroupcommParameters.GROUP_OSCORE_ADMIN_CREATE);
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
        	errorString = new String("A payload must be present");
    		System.err.println(errorString);
    		exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
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
    	
    	// The payload of the request must include the status parameter 'group_name'
    	if (!requestCBOR.getKeys().contains(GroupcommParameters.GROUP_NAME)) {
    		errorString = new String("The status parameter 'group_name' must be present");
    		System.err.println(errorString);
			exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
    		return;
    	}
    	
    	// The payload of the request must not include:
    	// - The status parameters 'rt', 'ace_groupcomm_profile', and 'joining_uri'
    	// - The parameters 'conf_filter' and 'app_groups_diff', as not pertaining to this request
    	if (requestCBOR.getKeys().contains(GroupcommParameters.RT) ||
    		requestCBOR.getKeys().contains(GroupcommParameters.ACE_GROUPCOMM_PROFILE) ||
    		requestCBOR.getKeys().contains(GroupcommParameters.JOINING_URI) ||
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
    			
    		}
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
    	
    	for (CBORObject key : requestCBOR.getKeys()) {
    		if (!GroupcommParameters.isAdminRequestParameterMeaningful(key, requestCBOR.get(key))) {
    			errorString = new String("Malformed or unrecognized paramemeter with CBOR abbreviation: " + key.AsInt32());
    			System.err.println(errorString);
    			exchange.respond(CoAP.ResponseCode.BAD_REQUEST, errorString);
    			return;
    		}
    	}

    	CBORObject ret = createNewGroupConfiguration(request, adminScopeEntries);
    	    	
    	// Respond to the request for creating a new Group Configuration
        
    	ResponseCode responseCode = CoAP.ResponseCode.valueOf(ret.get(0).AsInt32());
    	Response coapResponse = new Response(responseCode);
    	if (ret.get(1) != null) {
    		int contentFormat = ret.get(1).AsInt32();
        	coapResponse.getOptions().setContentFormat(contentFormat);
    	}
    	byte[] responsePayload = null;
    	if (ret.get(2) == null) {
    		responsePayload = Bytes.EMPTY;
    	}
    	else if (ret.get(2).getType() == CBORType.Map) {
    		responsePayload = ret.get(2).EncodeToBytes();
    	}
    	else if (ret.get(2).getType() == CBORType.TextString) {
    		responsePayload = ret.get(2).AsString().getBytes(Constants.charset);
    	}
    	coapResponse.setPayload(responsePayload);

    	exchange.respond(coapResponse);
    	
    }
    
	/**
     * Create a new group-configuration resource
     * 
     * @param requestCBOR  the POST request to the group-collection resource
     * @param adminScopeEntries  the adminScopeEntries retrieved from the access token for the requester Administrator
     * @return  a CBOR array with three elements, in this order
     * 			- The CoAP response code for the response to the Administrator, as a CBOR integer
     * 			- The CoAP Content-Format to use in the response to the Administrator, as a CBOR integer. It can be null
     * 			- The payload for the response to the Administrator, as a CBOR map or a CBOR text string. It can be null
     * 
     */
    private CBORObject createNewGroupConfiguration(final Request request, final CBORObject[] adminScopeEntries) {
    	
    	String groupName = null;
    	CBORObject ret = CBORObject.NewArray();
    	
    	CBORObject requestCBOR = CBORObject.DecodeFromBytes(request.getPayload());

    	// Build a preliminary group configuration, with the final name still to be determined
    	CBORObject buildOutput = GroupOSCOREGroupConfigurationResource.buildGroupConfiguration(requestCBOR, null);
    	
    	// In case of failure, return the information to return an error response to the Administrator
    	if (buildOutput.size() == 3) {

    		for (int i = 0; i < buildOutput.size(); i++) {
    			ret.Add(buildOutput.get(i));
    		}
    		return ret;
    	}
    	
    	// Determine the group name to use
    	String proposedName = requestCBOR.get(GroupcommParameters.GROUP_NAME).AsString();
    	groupName = allocateGroupName(proposedName, adminScopeEntries);
    	
    	if (groupName == null) {
    		// No available and suitable name could be allocated for the new group.
    		//
    		// Return the information for replying with an error response.
    		ret.Add(CoAP.ResponseCode.INTERNAL_SERVER_ERROR.value);
    		ret.Add(Constants.APPLICATION_CONCISE_PROBLEM_DETAILS_CBOR);
    		CBORObject payloadCBOR = CBORObject.NewMap();
    		
    		CBORObject aceGroupcommError = CBORObject.NewMap();
    		aceGroupcommError.Add(0, GroupcommErrors.GROUP_NAME_NOT_DETERMINED);
    		payloadCBOR.Add(Constants.PROBLEM_DETAIL_ACE_GROUPCOMM_ERROR, aceGroupcommError);
    		payloadCBOR.Add(Constants.PROBLEM_DETAIL_KEY_TITLE, GroupcommErrors.DESCRIPTION[GroupcommErrors.GROUP_NAME_NOT_DETERMINED]);

    		ret.Add(payloadCBOR);
    		return ret;
    	}
    	
    	// The new name is available and suitable. Add the group configuration to the collection
    	
    	// Complete the group configuration with the selected group name
    	CBORObject groupConfiguration = buildOutput.get(3);
    	groupConfiguration.Add(GroupcommParameters.GROUP_NAME, groupName);
    	
    	// Complete the group configuration with the URI of the associated group-membership resource
    	String requestUri = request.getURI();
    	int index = requestUri.lastIndexOf(super.getURI());
    	String baseUri = request.getURI().substring(0, index + 1);
    	String joiningUri = baseUri + rootGroupMembershipResourcePath + "/" + groupName;
    	groupConfiguration.Add(GroupcommParameters.JOINING_URI, joiningUri);
    	
    	// Complete the group configuration with the URI of the associated Authorization Server
    	groupConfiguration.Add(GroupcommParameters.AS_URI, this.asUri);
    	
    	GroupOSCOREGroupConfigurationResource groupConfigurationResource = null;
    	
    	synchronized(groupConfigurationResources) {
            groupConfigurationResource =  new GroupOSCOREGroupConfigurationResource(groupName, groupConfiguration,
            																		this.groupConfigurationResources,
														  							this.existingGroupInfo);
            groupConfigurationResources.put(groupName, groupConfigurationResource);
            	
    	}

    	Set<Short> actions = new HashSet<>();
    	actions.add(Constants.GET);
    	actions.add(Constants.FETCH);
    	actions.add(Constants.POST);
    	actions.add(Constants.PATCH);
    	actions.add(Constants.iPATCH);
    	actions.add(Constants.DELETE);
    	this.myScopes.get(groupCollectionResourcePath).put(groupCollectionResourcePath + "/" + groupName, actions);
    	
    	try {
			this.valid.setGroupAdminResources(Collections.singleton(groupCollectionResourcePath + "/" + groupName));
		} catch (AceException e) {
			groupConfigurationResources.remove(groupName); // rollback
			myScopes.get(groupCollectionResourcePath).remove(groupCollectionResourcePath + "/" + groupName); // rollback
			
			String errorString = new String ("Error while initializing the group-configuration resource");			
    		ret.Add(CoAP.ResponseCode.INTERNAL_SERVER_ERROR.value);
    		ret.Add(null);
    		CBORObject payloadCBOR = CBORObject.FromObject(errorString);
    		ret.Add(payloadCBOR);
    		System.err.println(errorString + "\n" + e.getMessage());
    		return ret;
		}

    	this.add(groupConfigurationResource);
    	
    	
    	// Create the group-membership resource and make it actually accessible
    	
    	createGroupMembershipResource(groupConfigurationResource.getConfigurationParameters());
    	
    	
    	// Finalize the payload for the response to the Administrator
    	
    	CBORObject finalPayloadCBOR = CBORObject.NewMap();
    	
    	finalPayloadCBOR = buildOutput.get(2);    	
    	finalPayloadCBOR.Add(GroupcommParameters.GROUP_NAME, groupName);
    	finalPayloadCBOR.Add(GroupcommParameters.JOINING_URI, joiningUri);
    	finalPayloadCBOR.Add(GroupcommParameters.AS_URI, this.asUri);
    	
    	ret.Add(buildOutput.get(0));
    	ret.Add(buildOutput.get(1));
    	ret.Add(finalPayloadCBOR);
    	
    	return ret;
    	
    }

	/**
     * Check whether the group name proposed by the requesting Administrator can be used for the new group to be created.
     * 
     * If that is not the case, attempt to find an alternative group name. If the originally proposed name can be used
     * or an alternative group name is found, confirm it as the name of the new group to be created.
     * 
     * @param proposedGroupName  the group name originally proposed in the POST request from the Administrator
     * @param adminScopeEntries  the adminScopeEntries retrieved from the access token for the requester Administrator
     * @return  the new, alternative name to assign to the group, or null if it was not possible to determine one
     * 
     */
    private String allocateGroupName(final String proposedGroupName, final CBORObject[] adminScopeEntries) {
    	
    	String newName = null;
    	
    	synchronized (groupConfigurationResources) {
    		
        	if (!groupConfigurationResources.containsKey(proposedGroupName)) {
        		// The proposed name is available.
        		
        		// Check if there is at least one scope entry such that the name matches the name pattern
        		// and the set of permissions includes the "Create" admin permission
        		boolean permitted = false;
        		
        		for (int i = 0; i < adminScopeEntries.length; i++) {
        		    try {
        		        short permissions = (short) adminScopeEntries[i].get(1).AsInt32();
        		        if (Util.checkGroupOSCOREAdminPermission(permissions, GroupcommParameters.GROUP_OSCORE_ADMIN_CREATE)) {
        		        	permitted = Util.matchingGroupOscoreName(proposedGroupName, adminScopeEntries[i].get(0));
        		        }
        		    } catch (AceException e) {
        		        System.err.println("Error while verifying the admin permissions: " + e.getMessage());
        		    }
        		    if (permitted) {
        		        break;
        		    }
        		}
        		if (permitted) {
	        		// Reserve the proposed name, by adding a dummy entry
	        		// in the collection of group-configuration resources
	        		newName = new String(proposedGroupName);
	        		groupConfigurationResources.put(newName, null);
	        		return newName;
        		}
        	}
        	// The proposed group name is not available, or the requesting Administrator does not
        	// have the permission to create a new group with that name. Try to find a new name.
        	
        	// The result is either a group name that is available and can be given to a group
        	// created by the requesting Administrator, or null if no group name could be found
        	newName = findAlternativeGroupName(proposedGroupName, adminScopeEntries);
        	
    		if (newName != null) {
        		// Reserve the proposed name, by adding a dummy entry
        		// in the collection of group-configuration resources
        		groupConfigurationResources.put(newName, null);
    		}
    		
    	}
    	
    	return newName;
    	
    }
    
	/**
     * Try to find an alternative name for a new group to be created
     * 
     * @param proposedGroupName  the group name originally proposed in the POST request from the Administrator
     * @param adminScopeEntries  the adminScopeEntries retrieved from the access token for the requester Administrator
     * @return  the new, alternative name to assign to the group, or null if it was not possible to determine one
     * 
     */
    private String findAlternativeGroupName(final String proposedGroupName, final CBORObject[] adminScopeEntries) {

    	// The set of permissions resulting from the union of the Tperm of all the admin scope entries whose Toid is the
    	// wildcard name pattern. That is, any possible group name is associated with at least this set of permissions.
    	int basePermissions = 0;
    	
    	// The set of permissions that the requesting Administrator has for the originally proposed group name 'proposedGroupName'.
    	// This is the union of the Tperm values from the admin scope entries against whose Toid 'proposedGroupName' matches.
    	// If an alternative group name is found, this must be associated with exactly the same set of permissions (no more, no less).
    	int targetPermissions = 0;   
    	
    	// The admin scope entries for this Administrator such that their Toid is a literal name pattern.
    	// This does not include the entry whose Toid is equal to the originally proposed group name.
    	Set<CBORObject> literalPatternEntries = new HashSet<>();

    	// The admin scope entries for this Administrator such that their Toid is a complex name pattern (I-Regexp regular expressions).
    	Set<CBORObject> complexPatternEntries = new HashSet<>();
    	    	
    	
    	// PHASE 1 - Fill data structures
    	
    	// Go through all the admin scope entries for this Administrator
    	for (int i = 0; i < adminScopeEntries.length; i++) {
    		
    		CBORObject toid = adminScopeEntries[i].get(0);
    		short tperm = (short) adminScopeEntries[i].get(1).AsInt32();
    		
    		// Toid is the wildcard pattern
    		if (toid.equals(CBORObject.True)) {
    			basePermissions |= tperm;
    			targetPermissions |= tperm;
    		}

    		if ((toid.getType() == CBORType.TextString)) {

    			String pattern = toid.AsString();
    			
        		// Toid is a literal pattern
    			if (toid.isTagged() == false) {
    				if (pattern.equals(proposedGroupName)) {
    					targetPermissions |= tperm;
    				}
    				else {
    					literalPatternEntries.add(adminScopeEntries[i]);
    				}
    			}
    			
    			// Toid is a complex pattern (I-Regexp regular expression)
    			if (toid.HasTag(21065)) {
    				Pattern pat = Pattern.compile(pattern);
    				Matcher myMatcher = pat.matcher(proposedGroupName);
    				if (myMatcher.matches()) {
    					// The originally proposed name matches against this complex name pattern
    					targetPermissions |= tperm;
    				}
    				complexPatternEntries.add(adminScopeEntries[i]);
    			}
    			
    		}
    		
    	}
    	
    	
    	// PHASE 2 - Check if a group name from a stored literal pattern works
    	
    	for (CBORObject entryLiteral : literalPatternEntries) {
    		
    		String newName = new String(entryLiteral.get(0).AsString());
    		
    		int newPermissions = basePermissions;
    		newPermissions |= entryLiteral.get(1).AsInt32();
    		
    		if ((groupConfigurationResources.containsKey(newName)) || (newPermissions > targetPermissions)) {
    			continue;
    		}

    		for (CBORObject entryComplex : complexPatternEntries) {
    			String pattern = entryComplex.get(0).AsString();
				Pattern pat = Pattern.compile(pattern);
				Matcher myMatcher = pat.matcher(newName);
				if (myMatcher.matches()) {
					// The possible new name matches against this complex name pattern
    				newPermissions |= entryComplex.get(1).AsInt32();
    				if (newPermissions > targetPermissions) {
    					break;
    				}
				}
    		}

    		if ((newPermissions == targetPermissions) && (!groupConfigurationResources.containsKey(newName))) {
    			return newName;
    		}
    		
    	}
    	
    	
    	// PHASE 3 - Try random strings
    	
    	for (int i = 0; i < maxRandomGroupNameAttempts; i++) {
    		
    		String newName = generateRandomGroupName();
    		if ((groupConfigurationResources.containsKey(newName))) {
    			continue;
    		}
    		
    		int newPermissions = basePermissions;
    		
    		// Go through the admin scope entries for this Administrator where Toid is a literal name pattern
    		boolean invalid = false;
    		for (CBORObject entryLiteral : literalPatternEntries) {
    			
    			if (newName.equals(entryLiteral.get(0).AsString())) {
    				newPermissions |= entryLiteral.get(1).AsInt32();
    				if (newPermissions > targetPermissions) {
    					// There is a match, but this group name cannot be considered, since
    					// it would give the Administrator more permissions than intended
    					invalid = true;
    				}
    				// Stop inspecting the admin scope entries where Toid is a literal name pattern.
					// In fact, there cannot be another entry with the same Toid again.
    				break;
    			}

    		}
    		if (invalid) {
    			// Move on and generate a new group name to consider altogether
    			continue;
    		}
    		
    		// Go through the admin scope entries for this Administrator where
    		// Toid is a complex name pattern (I-Regexp regular expressions).
    		for (CBORObject entryComplex : complexPatternEntries) {
    			
      			String pattern = entryComplex.get(0).AsString();
				Pattern pat = Pattern.compile(pattern);
				Matcher myMatcher = pat.matcher(newName);
				if (myMatcher.matches()) {
					newPermissions |= entryComplex.get(1).AsInt32();
    				if (newPermissions > targetPermissions) {
    					// There is a match, but this group name cannot be considered, since
    					// it would give the Administrator more permissions than intended
    					invalid = true;
    					
        				// Stop inspecting the admin scope entries where Toid is
    					// a complex name pattern (I-Regexp regular expression).
        				break;
    				}

				}
    			
    		}
    		if (invalid) {
    			// Move on and generate a new group name to consider altogether
    			continue;
    		}
    		
    		if ((newPermissions == targetPermissions) && (!groupConfigurationResources.containsKey(newName))) {
    			return newName;
    		}
    		
    	}
    	
    	
    	// PHASE 4 - Try random strings that match with the available complex name patterns by construction
    	
		// Go through the admin scope entries for this Administrator where
		// Toid is a complex name pattern (I-Regexp regular expressions).
    	for (CBORObject entryComplex : complexPatternEntries) {
    		
    		Generex generex = new Generex(entryComplex.get(0).AsString());
    		
        	for (int i = 0; i < maxRandomGroupNameAttemptsPerPattern; i++) {
	    		
        		String newName = generex.random(1, maxRandomGroupNameLength);
        		
        		if ((groupConfigurationResources.containsKey(newName))) {
        			continue;
        		}
        		
        		int newPermissions = basePermissions;
        		newPermissions |= entryComplex.get(1).AsInt32();
        		
        		if (newPermissions > targetPermissions) {
        			// This group name cannot be considered, since it would
					// give the Administrator more permissions than intended
        			
        			// Move on and generate a new new that matches with
        			// this same complex name pattern by construction
        			continue;
        		}
        		
        		// Go through the admin scope entries for this Administrator where Toid is a literal name pattern
        		boolean invalid = false;
        		for (CBORObject entryLiteral : literalPatternEntries) {
        			
        			if (newName.equals(entryLiteral.get(0).AsString())) {
        				newPermissions |= entryLiteral.get(1).AsInt32();
        				if (newPermissions > targetPermissions) {
        					// There is a match, but this group name cannot be considered, since
        					// it would give the Administrator more permissions than intended
        					invalid = true;
        				}
        				// Stop inspecting the admin scope entries where Toid is a literal name pattern.
    					// In fact, there cannot be another entry with the same Toid again.
        				break;
        			}
        			
        		}
        		if (invalid) {
        			// Move on and generate a new group name to consider altogether,
        			// still matching with this same complex name pattern by construction
        			continue;
        		}
        		
        		// Go through the OTHER admin scope entries for this Administrator where
        		// Toid is a complex name pattern (I-Regexp regular expressions).
        		for (CBORObject entryComplexAlt : complexPatternEntries) {
        			
        			if (entryComplexAlt.equals(entryComplex))
        				continue;
        			
          			String patternAlt = entryComplexAlt.get(0).AsString();
    				Pattern patAlt = Pattern.compile(patternAlt);
    				Matcher myMatcherAlt = patAlt.matcher(newName);
    				if (myMatcherAlt.matches()) {
    					newPermissions |= entryComplexAlt.get(1).AsInt32();
        				if (newPermissions > targetPermissions) {
        					// There is a match, but this group name cannot be considered, since
        					// it would give the Administrator more permissions than intended
        					invalid = true;
        					
            				// Stop inspecting the admin scope entries where Toid is
        					// a complex name pattern (I-Regexp regular expression).
            				break;
        				}

    				}
        			
        		}
        		if (invalid) {
        			// Move on and generate a new group name to consider altogether,
        			// still matching with this same complex name pattern by construction
        			continue;
        		}
        		
        		if ((newPermissions == targetPermissions) && (!groupConfigurationResources.containsKey(newName))) {
        			return newName;
        		}
        		
        	}

    	}

    	return null;

    }

	/**
     * Generate a random group name
     * 
     * @return  the generated group name
     * 
     */
    private String generateRandomGroupName() {
    	
    	final String[] validCharacters = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
				  						  "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
				  						  "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
				  						  "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
				  						  "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "-", ".", "_",
				  						  "~", "!", "$", "&", "'", "(", ")", "*", "+", ",", ";", "=", ":", "@"};

		SecureRandom secureRandom1 = new SecureRandom();
		SecureRandom secureRandom2 = new SecureRandom();

		StringBuilder newName = new StringBuilder();
		int length = secureRandom1.nextInt(maxRandomGroupNameLength) + 1;

		for (int j = 0; j < length; j++) {
			int index = secureRandom2.nextInt(validCharacters.length);
			newName.append(validCharacters[index]);
		}

		return newName.toString();

    }
    
    /**
      * Create a new group-membership resource, following the creation of the corresponding group-configuration resource
      * 
      * @param groupConfiguration  the group configuration
      * 
      * @return  true if the creation succeeds, false otherwise
     */
    private boolean createGroupMembershipResource(final CBORObject groupConfiguration) {
    	
    	String groupName = groupConfiguration.get(GroupcommParameters.GROUP_NAME).AsString();
    	
    	// Include a new scope associated with the new group-membership resource and its sub-resources
    	
    	Map<String, Set<Short>> scopeDescription = new HashMap<>();
    	Set<Short> actions = new HashSet<>();
    	actions.add(Constants.FETCH);
    	scopeDescription.put(rootGroupMembershipResourcePath, actions);
    	actions = new HashSet<>();
    	actions.add(Constants.GET);
    	actions.add(Constants.POST);
    	scopeDescription.put(rootGroupMembershipResourcePath + "/" + groupName, actions);
    	actions = new HashSet<>();
    	actions.add(Constants.GET);
    	actions.add(Constants.FETCH);
    	scopeDescription.put(rootGroupMembershipResourcePath + "/" + groupName + "/creds", actions);
    	actions = new HashSet<>();
    	actions.add(Constants.GET);
    	scopeDescription.put(rootGroupMembershipResourcePath + "/" + groupName + "/kdc-cred", actions);
    	scopeDescription.put(rootGroupMembershipResourcePath + "/" + groupName + "/verif-data", actions);
    	scopeDescription.put(rootGroupMembershipResourcePath + "/" + groupName + "/num", actions);
    	scopeDescription.put(rootGroupMembershipResourcePath + "/" + groupName + "/active", actions);
    	scopeDescription.put(rootGroupMembershipResourcePath + "/" + groupName + "/policies", actions);
    	actions = new HashSet<>();
    	actions.add(Constants.FETCH);
    	scopeDescription.put(rootGroupMembershipResourcePath + "/" + groupName + "/stale-sids", actions);
    	myScopes.put(rootGroupMembershipResourcePath + "/" + groupName, scopeDescription);
    	
    	
    	// Mark the new group-membership resource and its sub-resources as such for the access Validator
    	
    	try {
	    	valid.setGroupMembershipResources(Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName));
	    	valid.setGroupMembershipResources(Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName + "/creds"));
	    	valid.setGroupMembershipResources(Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName + "/kdc-cred"));
	    	valid.setGroupMembershipResources(Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName + "/verif-data"));
	    	valid.setGroupMembershipResources(Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName + "/num"));
	    	valid.setGroupMembershipResources(Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName + "/active"));
	    	valid.setGroupMembershipResources(Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName + "/policies"));
	    	valid.setGroupMembershipResources(Collections.singleton(rootGroupMembershipResourcePath + "/" + groupName + "/stale-sids"));
    	}
    	catch (AceException e) {
    		System.err.println("Error while verifying the admin permissions: " + e.getMessage());
    		return false;
    	}
    	
    	
    	// Create the actual associated group-membership resource and its sub-resources

    	// Group-membership resource - The name of the OSCORE group is used as resource name
    	Resource groupMembershipResource = new GroupOSCOREGroupMembershipResource(groupName,
    	                                                                          this.existingGroupInfo,
    	                                                                          rootGroupMembershipResourcePath,
    	                                                                          this.myScopes,
    	                                                                          this.valid);
    	// Add the /creds sub-resource
    	Resource credsSubResource = new GroupOSCORESubResourceCreds("creds", existingGroupInfo);
    	groupMembershipResource.add(credsSubResource);

    	// Add the /kdc-cred sub-resource
    	Resource kdcCredSubResource = new GroupOSCORESubResourceKdcCred("kdc-cred", existingGroupInfo);
    	groupMembershipResource.add(kdcCredSubResource);

    	// Add the /verif-data sub-resource
    	Resource verifDataSubResource = new GroupOSCORESubResourceVerifData("verif-data", existingGroupInfo);
    	groupMembershipResource.add(verifDataSubResource);

    	// Add the /num sub-resource
    	Resource numSubResource = new GroupOSCORESubResourceNum("num", existingGroupInfo);
    	groupMembershipResource.add(numSubResource);

    	// Add the /active sub-resource
    	Resource activeSubResource = new GroupOSCORESubResourceActive("active", existingGroupInfo);
    	groupMembershipResource.add(activeSubResource);

    	// Add the /policies sub-resource
    	Resource policiesSubResource = new GroupOSCORESubResourcePolicies("policies", existingGroupInfo);
    	groupMembershipResource.add(policiesSubResource);

    	// Add the /stale-sids sub-resource
    	Resource staleSidsSubResource = new GroupOSCORESubResourceStaleSids("stale-sids", existingGroupInfo);
    	groupMembershipResource.add(staleSidsSubResource);

    	// Add the /nodes sub-resource, as root to actually accessible per-node sub-resources
    	Resource nodesSubResource = new GroupOSCORESubResourceNodes("nodes");
    	groupMembershipResource.add(nodesSubResource);
    	
    	
    	// Create the GroupInfo object according to the group configuration
    	
    	final byte[] masterSecret = new byte[16];
    	try {
			SecureRandom.getInstanceStrong().nextBytes(masterSecret);
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Error when generating the OSCORE Master Secret for the OSCORE group with name \"" + groupName + "\"");
			e.printStackTrace();
			return false;
		}
    	
    	final byte[] masterSalt = new byte[8];
    	try {
			SecureRandom.getInstanceStrong().nextBytes(masterSalt);
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Error when generating the OSCORE Master Salt for the OSCORE group with name \"" + groupName + "\"");
			e.printStackTrace();
			return false;
		}
    	
    	final AlgorithmID hkdf;
    	try {
			hkdf = AlgorithmID.FromCBOR(groupConfiguration.get(GroupcommParameters.HKDF));
		} catch (CoseException e) {
			System.err.println("Error when setting the HKDF Algorithm for the OSCORE group with name \"" + groupName + "\"");
			e.printStackTrace();
			return false;
		}
    	
    	final int credFmt = groupConfiguration.get(GroupcommParameters.CRED_FMT).AsInt32();
    	
    	final AlgorithmID gpEncAlg;
    	try {
			gpEncAlg = AlgorithmID.FromCBOR(groupConfiguration.get(GroupcommParameters.GP_ENC_ALG));
		} catch (CoseException e) {
			System.err.println("Error when setting the Group Encryption Algorithm for the OSCORE group with name \"" + groupName + "\"");
			e.printStackTrace();
			return false;
		}
    	
    	final AlgorithmID signAlg;
    	try {
			signAlg = AlgorithmID.FromCBOR(groupConfiguration.get(GroupcommParameters.SIGN_ALG));
		} catch (CoseException e) {
			System.err.println("Error when setting the Signature Algorithm for the OSCORE group with name \"" + groupName + "\"");
			e.printStackTrace();
			return false;
		}
    	
    	final CBORObject signParams = groupConfiguration.get(GroupcommParameters.SIGN_PARAMS);

    	final AlgorithmID alg;
    	try {
			alg = AlgorithmID.FromCBOR(groupConfiguration.get(GroupcommParameters.ALG));
		} catch (CoseException e) {
			System.err.println("Error when setting the AEAD Algorithm for the OSCORE group with name \"" + groupName + "\"");
			e.printStackTrace();
			return false;
		}
    	
    	final AlgorithmID ecdhAlg;
    	try {
			ecdhAlg = AlgorithmID.FromCBOR(groupConfiguration.get(GroupcommParameters.ECDH_ALG));
		} catch (CoseException e) {
			System.err.println("Error when setting the Pairwise Key Agreement Algorithm for the OSCORE group with name \"" + groupName + "\"");
			e.printStackTrace();
			return false;
		}
    	
    	final CBORObject ecdhParams = groupConfiguration.get(GroupcommParameters.ECDH_PARAMS);
    	
    	    	
    	// Generate the Group ID, according to the following rationale:
    	//
    	// - The Prefix uniquely identifies an OSCORE group throughout its rekeying occurrences.
    	//   The Prefix size is the same for all the OSCORE groups and is up to 4 bytes.
    	//
    	// - The Epoch of an Group ID changes each time the group is rekeyed. Its size is up to 4 bytes.
    	// - The initial value of Epoch is all zeroes.
    	
    	boolean available = false;
    	byte[] groupIdPrefix = new byte[this.groupIdPrefixSize];
    	byte[] groupIdEpoch = new byte[] { (byte) 0x00, (byte) 0x00 };
    	
    	synchronized (this.usedGroupIdPrefixes) {
    		
        	int sizeLimit = (int) Math.pow(2, this.groupIdPrefixSize);
        	if (this.usedGroupIdPrefixes.size() == sizeLimit) {
        		// Rollback
    			groupConfigurationResources.remove(groupName);
    			myScopes.get(groupCollectionResourcePath).remove(groupCollectionResourcePath + "/" + groupName);
        		
    			System.err.println("No available Group IDs for creating the OSCORE group with name \"" + groupName + "\"");
    			return false;
        	}
        	        	
        	CBORObject groupIdPrefixCbor = null;
        	while(available == false) {
            	try {
        			SecureRandom.getInstanceStrong().nextBytes(groupIdPrefix);
        		} catch (NoSuchAlgorithmException e) {
        			System.err.println("Error when generating the OSCORE Group ID for the OSCORE group with name \"" + groupName + "\"");
        			e.printStackTrace();
        			return false;
        		}
            	groupIdPrefixCbor = CBORObject.FromObject(groupIdPrefix);
            	available = (this.usedGroupIdPrefixes.contains(groupIdPrefixCbor) == false);
        	}
        	
        	this.usedGroupIdPrefixes.add(groupIdPrefixCbor);
        	
    	}

    	
    	// Set the asymmetric key pair and public key of the Group Manager
    	
    	// Asymmetric key pair, as a OneKey object
    	
    	OneKey gmKeyPair = null;
    	CBORObject parameters;
    	
    	boolean useGroupMode = groupConfiguration.get(GroupcommParameters.GROUP_MODE).AsBoolean();
    	if (useGroupMode == true) {
    		parameters = groupConfiguration.get(GroupcommParameters.SIGN_PARAMS);
    	}
    	else {
    		parameters = groupConfiguration.get(GroupcommParameters.ECDH_PARAMS);
    	}
    	gmKeyPair = Util.retrieveGmKeyPair(gmSigningKeyPairs, gmKeyAgreementKeyPairs, useGroupMode, parameters);
    	
    	if (gmKeyPair == null) {
    		// This should never happen
    		
    		// Rollback
			groupConfigurationResources.remove(groupName);
			myScopes.get(groupCollectionResourcePath).remove(groupCollectionResourcePath + "/" + groupName);
    		
			System.err.println("Error when setting up the Group Manager's authentication credential" +
							   "for the OSCORE group with name \"" + groupName + "\"");
			return false;
    	}
    	    	
    	// Serialization of the public authentication credential, according to the format used in the group
    	
    	byte[] gmAuthCred = Util.retrieveGmAuthCred(credFmt, gmSigningPublicAuthCred, gmKeyAgreementPublicAuthCred, useGroupMode, parameters);


    	int mode = GroupcommParameters.GROUP_OSCORE_GROUP_PAIRWISE_MODE;
    	boolean usePairwiseMode = groupConfiguration.get(GroupcommParameters.PAIRWISE_MODE).AsBoolean();
    	if (useGroupMode == true && usePairwiseMode == true) {
    		mode = GroupcommParameters.GROUP_OSCORE_GROUP_PAIRWISE_MODE;
    	}
    	else if (useGroupMode == true && usePairwiseMode == false) {
    		mode = GroupcommParameters.GROUP_OSCORE_GROUP_MODE_ONLY;
    	}
    	else if (useGroupMode == false && usePairwiseMode == true) {
    		mode = GroupcommParameters.GROUP_OSCORE_PAIRWISE_MODE_ONLY;
    	}
    	
    	CBORObject groupPolicies = groupConfiguration.get(GroupcommParameters.GROUP_POLICIES);
    	
    	boolean groupIdReuse = groupConfiguration.get(GroupcommParameters.GID_REUSE).AsBoolean();
    	
    	int maxStaleIdsSets = groupConfiguration.get(GroupcommParameters.MAX_STALE_SETS).AsInt32();
    	
    	int detHashAlg = 0;
    	if (groupConfiguration.get(GroupcommParameters.DET_REQ) != null) {
    		if (groupConfiguration.get(GroupcommParameters.DET_REQ).equals(CBORObject.True)) {
    			if (groupConfiguration.get(GroupcommParameters.DET_HASH_ALG) != null) {
    				detHashAlg = groupConfiguration.get(GroupcommParameters.DET_HASH_ALG).AsInt32();
    			}
    			else {
    				detHashAlg = -16; // SHA-256
    			}
    		}	
    	}
    	
    	GroupInfo myGroupInfo = new GroupInfo(groupName,
										      masterSecret,
										      masterSalt,
										      groupIdPrefixSize,
										      groupIdPrefix,
										      groupIdEpoch.length,
										      Util.bytesToInt(groupIdEpoch),
										      groupIdReuse,
										      prefixMonitorNames,
										      nodeNameSeparator,
										      hkdf,
										      credFmt,
										      mode,
										      gpEncAlg,
										      signAlg,
										      signParams,
										      alg,
										      ecdhAlg,
										      ecdhParams,
										      groupPolicies,
										      gmKeyPair,
										      gmAuthCred,
										      gmSigningKeyPairs,
										      gmSigningPublicAuthCred,
										      gmKeyAgreementKeyPairs,
										      gmKeyAgreementPublicAuthCred,
										      maxStaleIdsSets,
										      detHashAlg);
    	
    	boolean initialStatus = groupConfiguration.get(GroupcommParameters.ACTIVE).AsBoolean();
    	myGroupInfo.setStatus(initialStatus);
    	
    	if (groupConfiguration.get(GroupcommParameters.EXP) != null) {
    		Long exp = groupConfiguration.get(GroupcommParameters.EXP).AsInt64Value();
    		myGroupInfo.setExp(exp);
    	}

    	
		// Store the information on this OSCORE group
    	this.existingGroupInfo.put(groupName, myGroupInfo);
    	
    	// Finally make the group-membership resource accessible
    	this.groupOSCORERootGroupMembership.add(groupMembershipResource);
    	
    	return true;
    	
    }

}
