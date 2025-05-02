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

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.Util;
import se.sics.ace.rs.AudienceValidator;
import se.sics.ace.rs.ScopeValidator;

/**
 * Audience and scope validator for testing purposes.
 * This validator expects the scopes to be either Strings as in OAuth 2.0,
 * or Byte Arrays to join OSCORE groups as per draft-ietf-ace-key-groupcomm-oscore
 * 
 * The actions are expected to be integers corresponding to the 
 * values for RESTful actions in <code>Constants</code>.
 * 
 * @author Marco Tiloca
 *
 */
public class GroupOSCOREJoinValidator implements AudienceValidator, ScopeValidator {

    /**
     * The audiences we recognize
     */
	private Set<String> myAudiences;
	
	/**
     * The audiences acting as OSCORE Group Managers
     * Each of these audiences is also included in the main set "myAudiences"
     */
	private Set<String> myGMAudiences;
	
	/**
     * The group-membership resources exported by the OSCORE Group Manager to access an OSCORE group.
     * 
     * Each entry of the list contains the full path to a group-membership resource and the last
     * path segment is the name of the associated OSCORE group, e.g. ace-group/GROUP_NAME
     */
	private Set<String> myJoinResources;
	
	private String rootGroupMembershipResource;
	
	/**
	 * Maps the scopes to a map that maps the scope's resources to the actions 
	 * allowed on that resource
	 */
	private Map<String, Map<String, Set<Short>>> myScopes;
	
	/**
	 * Constructor.
	 * 
	 * @param myAudiences  the audiences that this validator should accept
	 * @param myScopes  the scopes that this validator should accept
	 * @param rootGroupMemberResource  the path of the root Group Membership Resource, i.e., "ace-group"
	 */
	public GroupOSCOREJoinValidator(Set<String> myAudiences,
	        Map<String, Map<String, Set<Short>>> myScopes,
	        String rootGroupMemberResource) {
		this.myAudiences = new HashSet<>();
		this.myGMAudiences = new HashSet<>();
		this.myJoinResources = new HashSet<>();
		this.myScopes = new HashMap<>();
		if (myAudiences != null) {
		    this.myAudiences.addAll(myAudiences);
		} else {
		    this.myAudiences = Collections.emptySet();
		}
		if (myScopes != null) {
		    this.myScopes.putAll(myScopes);
		} else {
		    this.myScopes = Collections.emptyMap();
		}
    	this.rootGroupMembershipResource = rootGroupMemberResource;
	}
	
	/**
	 * Get a string including the common URI path to all group-membership
	 * resources, i.e. the full URI path minus the group name
	 * 
	 * @return the common URI path to all group-membership resources
	 */
	public String getRootGroupMembershipResource() {
        return this.rootGroupMembershipResource;
	}
	
	/**
	 * Get the list of audiences acting as OSCORE Group Managers.
	 * 
	 * @return the audiences that this validator considers as OSCORE Group Managers
	 */
	public synchronized Set<String> getAllGMAudiences() {
		if (this.myGMAudiences != null) {
			return this.myGMAudiences;
		}
        return Collections.emptySet();
	}
	
	/**
	 * Set the list of audiences acting as OSCORE Group Managers.
	 * Check that each of those audiences are in the main set "myAudiences".
	 * 
	 * @param myGMAudiences  the audiences that this validator considers as OSCORE Group Managers
	 * 
	 * @throws AceException  if the group manager is not an accepted audience
	 */
	public synchronized void setGMAudiences(Set<String> myGMAudiences) throws AceException {
		if (myGMAudiences != null) {
			for (String foo : myGMAudiences) {
				if (!this.myAudiences.contains(foo)) {
					throw new AceException("This OSCORE Group Manager is not an accepted audience");
				}
                this.myGMAudiences.add(foo);
			}
		} else {
		    this.myGMAudiences = Collections.emptySet();
		}
	}

	/**
	 * Remove an audience acting as OSCORE Group Manager from "myGMAudiences".
	 * This method does not remove the audience from the main set "myAudiences".
	 * 
	 * @param GMAudience  the audience acting as OSCORE Group Manager to be removed
	 * 
	 * @return true if the specified audience was included and has been removed, false otherwise.
	 */
	public synchronized boolean removeGMAudience(String GMAudience){
		if (GMAudience != null)
			return this.myGMAudiences.remove(GMAudience);
		return false;
	}
	
	/**
	 * Remove all the audiences acting as OSCORE Group Manager from "myGMAudiences".
	 * This method does not remove the audiences from the main set "myAudiences".
	 * 
	 */
	public synchronized void removeAllGMAudiences(){
		this.myGMAudiences.clear();
	}
	
	/**
	 * Get the list of group-membership resources to access an OSCORE group.
	 * 
	 * Each entry of the list contains the full path to a group-membership resource, and the last
     * path segment is the name of the associated OSCORE group, e.g. ace-group/GROUP_NAME
	 * 
	 * @return the resources that this validator considers as group-membership resources to access an OSCORE group
	 */
	public synchronized Set<String> getAllJoinResources() {
		if (this.myJoinResources != null) {
			return this.myJoinResources;
		}
        return Collections.emptySet();
	}
	
	/**
	 * Set the list of group-membership resources to access an OSCORE group.
	 * 
	 * Each entry of the list contains the full path to a group-membership resource, and the last
     * path segment is the name of the associated OSCORE group, e.g. ace-group/GROUP_NAME
     * 
	 * @param myJoinResources  the resources that this validator considers as group-membership resources to access an OSCORE group
	 * .
	 * @throws AceException FIXME: when thrown?
	 */
	public synchronized void setJoinResources(Set<String> myJoinResources) throws AceException {
		if (myJoinResources != null) {
			for (String foo : myJoinResources)
				this.myJoinResources.add(foo);
		} else {
		    this.myJoinResources = Collections.emptySet();
		}
	}
	
	/**
	 * Remove a group-membership resource to access an OSCORE group from "myJoinResources".
	 * 
	 * The group-membership resource to remove is specified by its full path, where the last
     * path segment is the name of the associated OSCORE group, e.g. ace-group/GROUP_NAME
	 * 
	 * @param joinResource  the group-membership resource to remove.
	 * 
	 * @return true if the specified resource was included and has been removed, false otherwise.
	 */
	public synchronized boolean removeJoinResource(String joinResource){
		if (joinResource != null)
			return this.myJoinResources.remove(joinResource);
		return false;
	}
	
	/**
	 * Remove all the group-membership resources to access an OSCORE group from "myJoinResources".
	 * 
	 */
	public synchronized void removeAllJoinResources(){
		this.myJoinResources.clear();
	}
	
	@Override
	public boolean match(String aud) {
		return this.myAudiences.contains(aud);
	}

    @Override
    public boolean scopeMatch(CBORObject scope, String resourceId, Object actionId)
            throws AceException {
    	
        if (!scope.getType().equals(CBORType.TextString) && !scope.getType().equals(CBORType.ByteString)) {
            throw new AceException("Scope must be a Text String or a Byte String");
        }
        
        String scopeStr;
        boolean isJoinResource = false;
    	boolean scopeMustBeBinary = false;
    	
    	if (this.myJoinResources.contains(resourceId))
    		isJoinResource = true;
    	
    	scopeMustBeBinary = isJoinResource;
        
    	if (scope.getType().equals(CBORType.TextString)) {
        	if (scopeMustBeBinary)
        		return false;
    	
        	String[] scopes = scope.AsString().split(" ");
            for (String subscope : scopes) {
                Map<String, Set<Short>> resources = this.myScopes.get(subscope);
                if (resources == null) {
                    continue;
                }
                if (resources.containsKey(resourceId)) {
                    if (resources.get(resourceId).contains(actionId)) {
                        return true;
                    }
                }
            }
            return false;
    	}
    	
    	else if (scope.getType().equals(CBORType.ByteString) && isJoinResource) {
    		
        	byte[] rawScope = scope.GetByteString();
        	CBORObject cborScope = CBORObject.DecodeFromBytes(rawScope);
        	
        	if (!cborScope.getType().equals(CBORType.Array)) {
                throw new AceException("Invalid scope format for joining OSCORE groups");
            }
        	
        	for (int entryIndex = 0; entryIndex < cborScope.size(); entryIndex++) {
        	
        		CBORObject scopeEntry = cborScope.get(entryIndex);
	        	
	        	if (scopeEntry.size() != 2)
	        		throw new AceException("Scope must have two elements, i.e. Group ID and list of roles");
	        	
	        	// Retrieve the Group ID of the OSCORE group
	      	  	CBORObject scopeElement = scopeEntry.get(0);
	      	  	if (scopeElement.getType().equals(CBORType.TextString)) {
	      	  		scopeStr = scopeElement.AsString();
	      	  	}
	      	  	else {throw new AceException("The Group Name must be a CBOR Text String");}
	        	
	      	  	// Retrieve the role or list of roles
	      	  	scopeElement = scopeEntry.get(1);
	      	  	
	        	if (scopeElement.getType().equals(CBORType.Integer)) {
	        		int roleSet = scopeElement.AsInt32();
	        		
	        		if (roleSet <= 0)
	        			throw new AceException("The roles must be encoded as a CBOR Unsigned Integer greater than 0");
	        		
	        		Set<Integer> roleIdSet = Util.getGroupOSCORERoles(roleSet);
	        		for (Integer elem : roleIdSet) {
	        			if (elem.intValue() < Constants.GROUP_OSCORE_ROLES.length)
	        				continue;
	        			else {
	        				throw new AceException("Unrecognized role");
	        			}
	        		}
	        		  
	        	}
	      	  	
	      	  	else {throw new AceException("Invalid format of roles");}
	      	  	
	      	  	Map<String, Set<Short>> resources = this.myScopes.get(rootGroupMembershipResource + "/" + scopeStr);
	      	  		      	  	
	      	  	// resourceId is the name of the OSCORE group
	      	  	if (resources != null && resources.containsKey(resourceId)) {
	      	  		if (resources.get(resourceId).contains(actionId)) {
	      	  			return true;
	      	  		}
	      	  	}
	      	  	
        	}
      	  	
      	  	return false;
      	  	
        }
        
    	// This includes the case where the scope is encoded as a CBOR Byte String,
    	// but the targeted resource is not a group-membership resource to access an OSCORE group.
    	// In fact, no processing for byte string scopes are defined, other than
    	// the one implemented above according to draft-ietf-ace-key-groupcomm-oscore
        else if (scope.getType().equals(CBORType.ByteString))
        	throw new AceException("Unknown processing for this byte string scope");
        
        return false;
    	
    }

    @Override
    public boolean scopeMatchResource(CBORObject scope, String resourceId)
            throws AceException {
    	
        if (!scope.getType().equals(CBORType.TextString) && !scope.getType().equals(CBORType.ByteString)) {
            throw new AceException("Scope must be a Text String or a Byte String");
        }
        
        String scopeStr;
        boolean isJoinResource = false;
    	boolean scopeMustBeBinary = false;
    	
    	if (this.myJoinResources.contains(resourceId))
    		isJoinResource = true;
    	
    	scopeMustBeBinary = isJoinResource;
    	
    	if (scope.getType().equals(CBORType.TextString)) {
        	if (scopeMustBeBinary)
        		return false;
        
        	String[] scopes = scope.AsString().split(" ");
            for (String subscope : scopes) {           
                Map<String, Set<Short>> resources = this.myScopes.get(subscope);
                if (resources == null) {
                    continue;
                }
                if (resources.containsKey(resourceId)) {
                    return true;
                }
            }
            return false;
        	
    	}
    	
    	else if (scope.getType().equals(CBORType.ByteString) && isJoinResource) {
    		
        	byte[] rawScope = scope.GetByteString();
        	CBORObject cborScope = CBORObject.DecodeFromBytes(rawScope);
        	
        	if (!cborScope.getType().equals(CBORType.Array)) {
                throw new AceException("Invalid scope format for joining OSCORE groups");
            }
        	
        	for (int entryIndex = 0; entryIndex < cborScope.size(); entryIndex++) {
        	
        		CBORObject scopeEntry = cborScope.get(entryIndex);
        		
	        	if (scopeEntry.size() != 2)
	        		throw new AceException("Scope must have two elements, i.e. Group ID and list of roles");
	        	
	        	// Retrieve the group name of the OSCORE group
	      	  	CBORObject scopeElement = scopeEntry.get(0);
	      	  	if (scopeElement.getType().equals(CBORType.TextString)) {
	      	  		scopeStr = scopeElement.AsString();
	      	  	}
	      	  	else {throw new AceException("The Group ID must be a CBOR Text String");}
	        	
	      	  	// Retrieve the role or list of roles
	      	  	scopeElement = scopeEntry.get(1);
	      	  	
	        	if (scopeElement.getType().equals(CBORType.Integer)) {
	        		int roleSet = scopeElement.AsInt32();
	        		
	        		if (roleSet <= 0)
	        			throw new AceException("The roles must be encoded as a CBOR Unsigned Integer greater than 0");
	        		
	        		Set<Integer> roleIdSet = Util.getGroupOSCORERoles(roleSet);
	        		for (Integer elem : roleIdSet) {
	        			if (elem.intValue() < Constants.GROUP_OSCORE_ROLES.length)
	        				continue;
	        			else {
	        				throw new AceException("Unrecognized role");
	        			}
	        		}
	        			        		  
	        	}
	     	
	      	  	else {throw new AceException("Invalid format of roles");}
	      	  	
	      	  	Map<String, Set<Short>> resources = this.myScopes.get(rootGroupMembershipResource + "/" + scopeStr);
	      	  	
	      	  	// resourceId is the name of the OSCORE group
	      	  	if (resources != null && resources.containsKey(resourceId))
	      	  			return true;
	      	  	
        	}
      	  	
      	  	return false;
      	  	
        }
        
    	// This includes the case where the scope is encoded as a CBOR Byte String,
    	// but the targeted resource is not a group-membership resource to access an OSCORE group.
    	// In fact, no processing for byte string scopes are defined, other than
    	// the one implemented above according to draft-ietf-ace-key-groupcomm-oscore
        else if (scope.getType().equals(CBORType.ByteString))
        	throw new AceException("Unknown processing for this byte string scope");
    	
    	return false;
    }

    @Override
    public boolean isScopeMeaningful(CBORObject scope) throws AceException {
        if (!scope.getType().equals(CBORType.TextString)) {
            throw new AceException("Scope must be a String if no audience is specified");
        }
        return this.myScopes.containsKey(scope.AsString());
    }
    
    @Override
    public boolean isScopeMeaningful(CBORObject scope, String aud) throws AceException {
    	
        if (!scope.getType().equals(CBORType.TextString) && !scope.getType().equals(CBORType.ByteString)) {
            throw new AceException("Scope must be a Text String or a Byte String");
        }
        
        String scopeStr;
    	boolean scopeMustBeBinary = false;
    	boolean rsOSCOREGroupManager = false;
    	
    	if (this.myGMAudiences.contains(aud)) {
    		rsOSCOREGroupManager = true;
    	}
    	
    	scopeMustBeBinary = rsOSCOREGroupManager;
           	
        if (scope.getType().equals(CBORType.TextString)) {
        	if (scopeMustBeBinary)
        		return false;
        	
        	return this.myScopes.containsKey(scope.AsString());
        	// The audiences are silently ignored
        }
        	
        else if (scope.getType().equals(CBORType.ByteString) && rsOSCOREGroupManager) {
        	
        	byte[] rawScope = scope.GetByteString();
        	CBORObject cborScope = CBORObject.DecodeFromBytes(rawScope);
        	
        	if (!cborScope.getType().equals(CBORType.Array)) {
                throw new AceException("Invalid scope format for joining OSCORE groups");
            }
        	
      	  	for (int entryIndex = 0; entryIndex < cborScope.size(); entryIndex++) {
        	
      	  		CBORObject scopeEntry = cborScope.get(entryIndex);
	      	  		
	      	  	if (!scopeEntry.getType().equals(CBORType.Array)) {
	                throw new AceException("Invalid scope format for joining OSCORE groups");
	            }
      	  		
	        	if (scopeEntry.size() != 2)
	        		throw new AceException("A scope entry must have two elements, i.e. group name and list of roles");
	        	
	        	// Retrieve the Group ID of the OSCORE group
	      	  	CBORObject scopeElement = scopeEntry.get(0);
	      	  	if (scopeElement.getType().equals(CBORType.TextString)) {
	      	  		scopeStr = scopeElement.AsString();
	      	  	}
	      	  	else {throw new AceException("The group name must be a CBOR Text String");}
	        	  
	         	// Retrieve the role or list of roles
	    	    scopeElement = scopeEntry.get(1);
	    	  
	    	    if (scopeElement.getType().equals(CBORType.Integer)) {
	    		    int roleSet = scopeElement.AsInt32();
	    		 
	        	    if (roleSet <= 0)
	        		    throw new AceException("The roles must be encoded as a CBOR Unsigned Integer greater than 0");
	        		
	        	    Set<Integer> roleIdSet = Util.getGroupOSCORERoles(roleSet);
	    	  	    for (Integer elem : roleIdSet) {
	    	  		    if (elem.intValue() < Constants.GROUP_OSCORE_ROLES.length)
	    	  			    continue;
	    	  		    else {
	    				    throw new AceException("Unrecognized role");
	    			    }
	    		    }
	    	  	    
	    	    }
	      	  	
	      	  	else {throw new AceException("Invalid format of roles");}
	    	    
	        	if (this.myScopes.containsKey(rootGroupMembershipResource + "/" + scopeStr) == false)
	        		return false;
      	  	}
      	  	
      	  	return true;
      	  	
        }
        
    	// This includes the case where the scope is encoded as a CBOR Byte String,
    	// but the audience is not related to an OSCORE Group Manager.
    	// In fact, no processing for byte string scopes are defined, other than
    	// the one implemented above according to draft-ietf-ace-key-groupcomm-oscore
        else if (scope.getType().equals(CBORType.ByteString))
        	throw new AceException("Unknown processing for this byte string scope");
        
        return false;
        
    }

    @Override
    public CBORObject getScope(String resource, short action) {
        // TODO Auto-generated method stub
        return null;
    }
}
