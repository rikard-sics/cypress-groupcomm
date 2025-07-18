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
package se.sics.ace.oscore.rs;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import se.sics.ace.AceException;
import se.sics.ace.GroupcommParameters;
import se.sics.ace.Util;
import se.sics.ace.rs.AudienceValidator;
import se.sics.ace.rs.ScopeValidator;

/**
 * Audience and scope validator for testing purposes.
 * 
 * This validator expects the scopes to be either Strings as in OAuth 2.0, or
 * Byte Arrays for operations at the OSCORE Group Manager as per
 * draft-ietf-ace-key-groupcomm-oscore and draft-ietf-ace-oscore-gm-admin
 * 
 * The actions are expected to be integers corresponding to the 
 * values for RESTful actions in <code>Constants</code>.
 * 
 * @author Marco Tiloca
 *
 */
public class GroupOSCOREValidator implements AudienceValidator, ScopeValidator {

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
     * path segment is the name of the associated OSCORE group, e.g., ace-group/GROUPNAME
     */
	private Set<String> myGroupMembershipResources;
	
	/**
     * The group-collections and group-configuration resources
     * exported by the OSCORE Group Manager for managing OSCORE groups.
     * 
     * Each entry of the list contains the full path to a group-collection or a group-configuration resource.
     * For a group-configuration resource, the last path segment is the name of the associated OSCORE group, e.g., admin/GROUPNAME
     */
	private Set<String> myGroupAdminResources;
	
	private String rootGroupMembershipResourcePath;
	
	private String groupCollectionResourcePath;
	
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
	 * @param rootGroupMembershipResource  the path of the root Group Membership Resource, i.e., "ace-group"
	 * @param groupCollectionResource  the path of the Group Collection Resource, i.e., "manage"
	 */
	public GroupOSCOREValidator(Set<String> myAudiences,
	        Map<String, Map<String, Set<Short>>> myScopes,
	        String rootGroupMembershipResourcePath,
	        String groupCollectionResourcePath) {
		this.myAudiences = new HashSet<>();
		this.myGMAudiences = new HashSet<>();
		this.myGroupMembershipResources = new HashSet<>();
		this.myGroupAdminResources = new HashSet<>();
		this.myScopes = new HashMap<>();
		if (myAudiences != null) {
		    this.myAudiences = myAudiences;
		    
		} else {
		    this.myAudiences = Collections.emptySet();
		}
		if (myScopes != null) {
			this.myScopes = myScopes;
		} else {
		    this.myScopes = Collections.emptyMap();
		}
    	this.rootGroupMembershipResourcePath = rootGroupMembershipResourcePath;
    	this.groupCollectionResourcePath = groupCollectionResourcePath;
	}
	
	/**
	 * Get a string including the common URI path to all group-membership
	 * resources, i.e. the full URI path minus the group name
	 * 
	 * @return the common URI path to all group-membership resources
	 */
	public String getRootGroupMembershipResource() {
        return this.rootGroupMembershipResourcePath;
	}
	
	/**
	 * Get a string including the URI path of the group-collection resource
	 * 
	 * @return the URI path of the group-collection resource
	 */
	public String getGroupCollectionResource() {
        return this.groupCollectionResourcePath;
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
     * path segment is the name of the associated OSCORE group, e.g., ace-group/GROUPNAME
	 * 
	 * @return the resources that this validator considers as group-membership resources to access an OSCORE group
	 */
	public synchronized Set<String> getAllGroupMembershipResources() {
		if (this.myGroupMembershipResources != null) {
			return this.myGroupMembershipResources;
		}
        return Collections.emptySet();
	}
	
	/**
	 * Set the list of group-membership resources to access an OSCORE group.
	 * 
	 * Each entry of the list contains the full path to a group-membership resource, and the last
     * path segment is the name of the associated OSCORE group, e.g., ace-group/GROUPNAME
     * 
	 * @param myGroupMembershipResources  the resources that this validator considers as group-membership resources to access an OSCORE group
	 * .
	 * @throws AceException FIXME: when thrown?
	 */
	public synchronized void setGroupMembershipResources(Set<String> myGroupMembershipResources) throws AceException {
		if (myGroupMembershipResources != null) {
			for (String foo : myGroupMembershipResources)
				this.myGroupMembershipResources.add(foo);
		} else {
		    this.myGroupMembershipResources = Collections.emptySet();
		}
	}
	
	/**
	 * Remove a group-membership resource to access an OSCORE group from "myGroupMembershipResources".
	 * 
	 * The group-membership resource to remove is specified by its full path, where the last
     * path segment is the name of the associated OSCORE group, e.g., ace-group/GROUPNAME
	 * 
	 * @param groupMembershipResource  the group-membership resource to remove.
	 * 
	 * @return true if the specified resource was included and has been removed, false otherwise.
	 */
	public synchronized boolean removeGroupMembershipResource(String groupMembershipResource){
		if (groupMembershipResource != null)
			return this.myGroupMembershipResources.remove(groupMembershipResource);
		return false;
	}
	
	/**
	 * Remove all the group-membership resources to access an OSCORE group from "myGroupMembershipResources".
	 * 
	 */
	public synchronized void removeAllGroupMembershipResources(){
		this.myGroupMembershipResources.clear();
	}
	
	/**
	 * Get the list of group-collection and group-configuration resources for managing OSCORE groups
	 * 
     * Each entry of the list contains the full path to a group-collection or a group-configuration resource.
     * For a group-configuration resource, the last path segment is the name of the associated OSCORE group, e.g., admin/GROUPNAME
	 * 
	 * @return the resources that this validator considers as group-collection or group-configuration resources
	 */
	public synchronized Set<String> getAllGroupAdminResources() {
		if (this.myGroupAdminResources != null) {
			return this.myGroupAdminResources;
		}
        return Collections.emptySet();
	}
	
	/**
	 * Set the list of group-collection and group-configuration resources for managing OSCORE groups
	 * 
     * Each entry of the list contains the full path to a group-collection or a group-configuration resource.
     * For a group-configuration resource, the last path segment is the name of the associated OSCORE group, e.g., admin/GROUPNAME
     * 
	 * @param myGroupAdminResources  the resources that this validator considers as group-collection or group-configuration resources
	 * .
	 * @throws AceException FIXME: when thrown?
	 */
	public synchronized void setGroupAdminResources(Set<String> myGroupAdminResources) throws AceException {
		if (myGroupAdminResources != null) {
			for (String foo : myGroupAdminResources)
				this.myGroupAdminResources.add(foo);
		} else {
		    this.myGroupAdminResources = Collections.emptySet();
		}
	}
	
	/**
	 * Remove a group-collection or group-configuration resource from "myGroupAdminResources".
	 * 
	 * The group-collection or group-configuration resource to remove is specified by its full path.
	 * For a group-configuration resource, the last path segment is the name of the associated OSCORE group, e.g., admin/GROUPNAME
	 * 
	 * @param groupAdminResource  the group-collection or group-configuration resource to remove.
	 * 
	 * @return true if the specified resource was included and has been removed, false otherwise.
	 */
	public synchronized boolean removeGroupAdminResource(String groupAdminResource){
		if (groupAdminResource != null)
			return this.myGroupAdminResources.remove(groupAdminResource);
		return false;
	}
	
	/**
	 * Remove all the group-configuration and group-collection resources from "myGroupAdminResources".
	 * 
	 */
	public synchronized void removeAllGroupAdminResources(){
		this.myGroupAdminResources.clear();
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
        boolean isGroupMembershipResource = false;
        boolean isGroupAdminResource = false;
    	boolean scopeMustBeBinary = false;
    	boolean scopeForOscoreGroupManager = false;
    	
    	if (this.myGroupMembershipResources.contains(resourceId))
    		isGroupMembershipResource = true;
    	
    	if (this.myGroupAdminResources.contains(resourceId))
    		isGroupAdminResource = true;
    	
    	scopeMustBeBinary = isGroupMembershipResource | isGroupAdminResource;
    	scopeForOscoreGroupManager = isGroupMembershipResource | isGroupAdminResource;
        
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
    	
    	else if (scope.getType().equals(CBORType.ByteString) && scopeForOscoreGroupManager) {
    		
        	byte[] rawScope = scope.GetByteString();
        	CBORObject cborScope = CBORObject.DecodeFromBytes(rawScope);
        	
        	if (!cborScope.getType().equals(CBORType.Array)) {
                throw new AceException("Invalid scope format for the AIF-OSCORE-GROUPCOMM data model");
            }
        	
        	for (int entryIndex = 0; entryIndex < cborScope.size(); entryIndex++) {
        	
        		CBORObject scopeEntry = cborScope.get(entryIndex);
	        
	      	  	if (!scopeEntry.getType().equals(CBORType.Array)) {
	                throw new AceException("Invalid scope for entry the AIF-OSCORE-GROUPCOMM data model");
	      	  	}
        		
	        	if (scopeEntry.size() != 2)
	        		throw new AceException("A scope entry must have two elements, i.e., Toid and Tperm");
	        	
      	  		if (scopeEntry.get(1).getType() != CBORType.Integer) {
      	  			throw new AceException("Tperm must be a CBOR integer");
      	  		}
      	  		
      	  		int tperm = scopeEntry.get(1).AsInt32();
	      	  	if (tperm <= 0) {
	  	  			throw new AceException("Tperm must have a positive integer value");
	  	  		}
	        	
	        	if ((tperm % 2) == 0) {
	        		// This is a user scope entry
	        		
		        	// Retrieve the group name of the OSCORE group
		      	  	CBORObject scopeElement = scopeEntry.get(0);
		      	  	if (scopeElement.getType().equals(CBORType.TextString)) {
		      	  		scopeStr = scopeElement.AsString();
		      	  	}
		      	  	else {
		      	  		throw new AceException("The group name must be a CBOR Text String");
		      	  	}
		        	
		      	  	// Retrieve the role or list of roles
	        		Set<Integer> roleIdSet = Util.getGroupOSCORERoles(tperm);
	        		for (Integer elem : roleIdSet) {
	        			if (elem.intValue() < GroupcommParameters.GROUP_OSCORE_ROLES.length)
	        				continue;
	        			else {
	        				throw new AceException("Unrecognized role");
	        			}
	        		}
			      	  	
		      	  	Map<String, Set<Short>> resources = this.myScopes.get(rootGroupMembershipResourcePath + "/" + scopeStr);
		      	  		      	  	
		      	  	if (resources != null && resources.containsKey(resourceId)) {
		      	  		if (resources.get(resourceId).contains(actionId)) {
		      	  			return true;
		      	  		}
		      	  	}
	      	  	
	        	} // end of handling a user scope entry
	        	
	        	else {
	        		// This is an admin scope entry
	        		
      	  			if (cborScope.get(entryIndex).get(0).getType() != CBORType.TextString &&
      	  				cborScope.get(entryIndex).get(0).equals(CBORObject.True) == false) {
      	  				throw new AceException("Toid must be a CBOR text string or the CBOR simple value true");
    	      	  	}
      	  			
		      	  	// Retrieve the list of admin permissions
	        		Set<Integer> permissionIdSet = Util.getGroupOSCOREAdminPermissions(tperm);
	        		for (Integer elem : permissionIdSet) {
	        			if (elem.intValue() < GroupcommParameters.GROUP_OSCORE_ADMIN_PERMISSIONS.length) {
	        				continue;
	        			}
	        			else {
	        				throw new AceException("Unrecognized admin permission");
	        			}
	        		}
	        		
		      	  	Map<String, Set<Short>> resources = this.myScopes.get(groupCollectionResourcePath);
	  		      	  	
		      	  	if (resources != null && resources.containsKey(resourceId)) {
		      	  		if (resources.get(resourceId).contains(actionId)) {
		      	  			return true;
		      	  		}
		      	  	}
	        		
	        	} // end of handling an admin scope entry
	      	  	
        	} // end of checking all the scope entries in the scope claim of the access token
      	  	
      	  	return false;
      	  	
        }
        
    	// This includes the case where the scope is encoded as a CBOR Byte String,
    	// but the targeted resource is not a group-membership resource, a group-collection resource or a group-configuration resource.
    	// In fact, no processing for byte string scopes are defined, other than the one implemented above according to
    	// draft-ietf-ace-key-groupcomm-oscore and draft-ietf-ace-oscore-gm-admin
        else if (scope.getType().equals(CBORType.ByteString)) {
        	throw new AceException("Unknown processing for this byte string scope");
        }
        
        return false;
    	
    }

    @Override
    public boolean scopeMatchResource(CBORObject scope, String resourceId)
            throws AceException {
    	
        if (!scope.getType().equals(CBORType.TextString) && !scope.getType().equals(CBORType.ByteString)) {
            throw new AceException("Scope must be a Text String or a Byte String");
        }
        
        String scopeStr;
        boolean isGroupMembershipResource = false;
        boolean isGroupAdminResource = false;
    	boolean scopeMustBeBinary = false;
    	boolean scopeForOscoreGroupManager = false;
    	
    	if (this.myGroupMembershipResources.contains(resourceId))
    		isGroupMembershipResource = true;
    	
    	if (this.myGroupAdminResources.contains(resourceId))
    		isGroupAdminResource = true;
    	
    	scopeMustBeBinary = isGroupMembershipResource | isGroupAdminResource;
    	scopeForOscoreGroupManager = isGroupMembershipResource | isGroupAdminResource;
    	
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
    	
    	else if (scope.getType().equals(CBORType.ByteString) && scopeForOscoreGroupManager) {
    		
        	byte[] rawScope = scope.GetByteString();
        	CBORObject cborScope = CBORObject.DecodeFromBytes(rawScope);
        	
        	if (!cborScope.getType().equals(CBORType.Array)) {
                throw new AceException("Invalid scope format for the AIF-OSCORE-GROUPCOMM data model");
            }
        	
        	for (int entryIndex = 0; entryIndex < cborScope.size(); entryIndex++) {
        	
        		CBORObject scopeEntry = cborScope.get(entryIndex);
        		
	      	  	if (!scopeEntry.getType().equals(CBORType.Array)) {
	                throw new AceException("Invalid scope for entry the AIF-OSCORE-GROUPCOMM data model");
	      	  	}
        		
	        	if (scopeEntry.size() != 2)
	        		throw new AceException("A scope entry must have two elements, i.e., Toid and Tperm");
	        	
      	  		if (scopeEntry.get(1).getType() != CBORType.Integer) {
      	  			throw new AceException("Tperm must be a CBOR integer");
      	  		}
	        	
      	  		int tperm = scopeEntry.get(1).AsInt32();
	      	  	if (tperm <= 0) {
	  	  			throw new AceException("Tperm must have a positive integer value");
	  	  		}

	        	if ((tperm % 2) == 0) {
	        		// This is a user scope entry

		        	// Retrieve the group name of the OSCORE group
		      	  	CBORObject scopeElement = scopeEntry.get(0);
		      	  	if (scopeElement.getType().equals(CBORType.TextString)) {
		      	  		scopeStr = scopeElement.AsString();
		      	  	}
		      	  	else {
		      	  		throw new AceException("The group name must be a CBOR Text String");
		      	  	}
		        	
		      	  	// Retrieve the role or list of roles
	        		Set<Integer> roleIdSet = Util.getGroupOSCORERoles(tperm);
	        		for (Integer elem : roleIdSet) {
	        			if (elem.intValue() < GroupcommParameters.GROUP_OSCORE_ROLES.length) {
	        				continue;
	        			}
	        			else {
	        				throw new AceException("Unrecognized role");
	        			}
	        		}
		        	
		      	  	Map<String, Set<Short>> resources = this.myScopes.get(rootGroupMembershipResourcePath + "/" + scopeStr);
		      	  	
		      	  	if (resources != null && resources.containsKey(resourceId)) {
		      	  			return true;
		      	  	}
	      	  	
	        	}  // end of handling a user scope entry
	      	  	
	        	else {
	        		// This is an admin scope entry
	        		
      	  			if (cborScope.get(entryIndex).get(0).getType() != CBORType.TextString &&
      	  				cborScope.get(entryIndex).get(0).equals(CBORObject.True) == false) {
      	  				throw new AceException("Toid must be a CBOR text string or the CBOR simple value true");
    	      	  	}
      	  			
		      	  	// Retrieve the list of admin permissions
	        		Set<Integer> permissionIdSet = Util.getGroupOSCOREAdminPermissions(tperm);
	        		for (Integer elem : permissionIdSet) {
	        			if (elem.intValue() < GroupcommParameters.GROUP_OSCORE_ADMIN_PERMISSIONS.length)
	        				continue;
	        			else {
	        				throw new AceException("Unrecognized admin permission");
	        			}
	        		}
	        		
		      	  	Map<String, Set<Short>> resources = this.myScopes.get(groupCollectionResourcePath);
	  		      	
		      	  	if (resources != null && resources.containsKey(resourceId)) {
		      	  			return true;
		      	  	}

	        	} // end of handling an admin scope entry
	        	
        	} // end of checking all the scope entries in the scope claim of the access token
      	  	
      	  	return false;
      	  	
        }
        
    	// This includes the case where the scope is encoded as a CBOR Byte String,
    	// but the targeted resource is not a group-membership resource, a group-collection resource or a group-configuration resource.
    	// In fact, no processing for byte string scopes are defined, other than the one implemented above according to
    	// draft-ietf-ace-key-groupcomm-oscore and draft-ietf-ace-oscore-gm-admin
        else if (scope.getType().equals(CBORType.ByteString)) {
        	throw new AceException("Unknown processing for this byte string scope");
        }
    	
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
                throw new AceException("Invalid scope format for the AIF-OSCORE-GROUPCOMM data model");
            }
        	
      	  	for (int entryIndex = 0; entryIndex < cborScope.size(); entryIndex++) {
        	
      	  		CBORObject scopeEntry = cborScope.get(entryIndex);
	      	  		
	      	  	if (!scopeEntry.getType().equals(CBORType.Array)) {
	                throw new AceException("Invalid scope for entry the AIF-OSCORE-GROUPCOMM data model");
	            }
      	  		
	        	if (scopeEntry.size() != 2)
	        		throw new AceException("A scope entry must have two elements, i.e., Toid and Tperm");
	        	
      	  		if (scopeEntry.get(1).getType() != CBORType.Integer) {
      	  			throw new AceException("Tperm must be a CBOR integer");
      	  		}
      	  		
      	  		int tperm = scopeEntry.get(1).AsInt32();
	      	  	if (tperm <= 0) {
	  	  			throw new AceException("Tperm must have a positive integer value");
	  	  		}
	        	
	        	if ((tperm % 2) == 0) {
	        		// This is a user scope entry
	        		
		        	// Retrieve the group name of the OSCORE group
		      	  	CBORObject scopeElement = scopeEntry.get(0);
		      	  	if (scopeElement.getType().equals(CBORType.TextString)) {
		      	  		scopeStr = scopeElement.AsString();
		      	  	}
		      	  	else {
		      	  		throw new AceException("The group name must be a CBOR Text String");
		      	  	}
		        	  
		         	// Retrieve the role or list of roles
	        	    Set<Integer> roleIdSet = Util.getGroupOSCORERoles(tperm);
	    	  	    for (Integer elem : roleIdSet) {
	    	  		    if (elem.intValue() < GroupcommParameters.GROUP_OSCORE_ROLES.length) {
	    	  			    continue;
	    	  		    }
	    	  		    else {
	    				    throw new AceException("Unrecognized role");
	    			    }
	    		    }
		    	  			    	    
		        	if (this.myScopes.containsKey(rootGroupMembershipResourcePath + "/" + scopeStr) == false) {
		        		return false;
		        	}
	        	
      	  		} // end of handling a user scope entry
	        	
	        	else {
	        		// This is an admin scope entry
	        		
      	  			if (cborScope.get(entryIndex).get(0).getType() != CBORType.TextString &&
      	  				cborScope.get(entryIndex).get(0).equals(CBORObject.True) == false) {
      	  				throw new AceException("Toid must be a CBOR text string or the CBOR simple value true");
    	      	  	}
      	  			
		      	  	// Retrieve the list of admin permissions
	        		Set<Integer> permissionIdSet = Util.getGroupOSCOREAdminPermissions(tperm);
	        		for (Integer elem : permissionIdSet) {
	        			if (elem.intValue() < GroupcommParameters.GROUP_OSCORE_ADMIN_PERMISSIONS.length)
	        				continue;
	        			else {
	        				throw new AceException("Unrecognized admin permission");
	        			}
	        		}
	        		
		        	if (this.myScopes.containsKey(groupCollectionResourcePath) == false) {
		        		// More fine-grained checks are not possible at this point in time
		        		// (i.e., upon checking an uploaded access token), since the list of valid
		        		// scopes may not comprise OSCORE groups whose name matches with the Toid
		        		// of some scope entries in the access token, but still have to be created
		        		return false;
		        	}
		      	  	
	        	} // end of handling an admin scope entry
	        	
      	  	} // end of checking all the scope entries in the scope claim of the access token
      	  	
      	  	return true;
      	  	
        }
        
    	// This includes the case where the scope is encoded as a CBOR Byte String,
    	// but the targeted resource is not a group-membership resource, a group-collection resource or a group-configuration resource.
    	// In fact, no processing for byte string scopes are defined, other than the one implemented above according to
    	// draft-ietf-ace-key-groupcomm-oscore and draft-ietf-ace-oscore-gm-admin
        else if (scope.getType().equals(CBORType.ByteString)) {
        	throw new AceException("Unknown processing for this byte string scope");
        }
        
        return false;
        
    }

    @Override
    public CBORObject getScope(String resource, short action) {
        // TODO Auto-generated method stub
        return null;
    }
}
