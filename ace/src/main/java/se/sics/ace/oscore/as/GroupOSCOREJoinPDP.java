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
package se.sics.ace.oscore.as;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import se.sics.ace.AceException;
import se.sics.ace.as.DBConnector;
import se.sics.ace.as.PDP;
import se.sics.ace.GroupcommParameters;
import se.sics.ace.Util;
import se.sics.ace.examples.SQLConnector;

/**
 * A PDP implementation supporting scopes as Text Strings or Byte Strings. A byte string scope is used to join OSCORE groups. 
 * 
 * This PDP backs up it's ACL's in the database.
 * 
 * NOTE: This PDP needs a SQL connector it won't work with other DBConnectors.
 * 
 * @author Marco Tiloca
 *
 */
public class GroupOSCOREJoinPDP implements PDP, AutoCloseable {

    private SQLConnector db = null;
    
    /**
     * The name of the Token access control table 
     */
    public static String tokenTable = "PdpToken";
    
    /**
     * The name of the Introspect access control table
     */
    public static String introspectTable = "PdpIntrospect";
    
    /**
     * The name of the ACL table 
     */    
    public static String accessTable = "PdpAccess";
 
    /**
     * The name of the OSCORE Group Managers table
     */    
    public static String oscoreGroupManagersTable = "OSCOREGroupManagersTable";
    
    /**
     * The name of the column that indicates if this device has access to all detailed claims when introspecting.
     */
    public static String introspectClaimsColumn = "claimsAccess";
    
    private PreparedStatement canToken;    
    private PreparedStatement canIntrospect;
    private PreparedStatement canAccess;
    
    private PreparedStatement addTokenAccess;
    private PreparedStatement addIntrospectAccess;
    private PreparedStatement addAccess;
    
    private PreparedStatement deleteTokenAccess;
    private PreparedStatement deleteIntrospectAccess;
    private PreparedStatement deleteAccess;
    private PreparedStatement deleteAllAccess;
    private PreparedStatement deleteAllRsAccess;

    private PreparedStatement getAllAccess;
    
    private PreparedStatement addOSCOREGroupManager;
    
    private PreparedStatement deleteOSCOREGroupManagers;
    
    private PreparedStatement selectOSCOREGroupManagers;
    
    private Map<String, Short> rolesToInt = new HashMap<>();
    
    private Map<String, Short> permissionsToInt = new HashMap<>();

	/**
	 * Constructor, can supply an initial configuration.
	 * All configuration parameters that are null are expected
	 * to already be in the database.
	 * 
	 * @param connection  the database connector
	 * @throws AceException 
	 */
	public GroupOSCOREJoinPDP(SQLConnector connection) throws AceException {
        this.db = connection;
	    
	    String createToken = this.db.getAdapter().updateEngineSpecificSQL(
	            "CREATE TABLE IF NOT EXISTS "
                + tokenTable + "("
                + DBConnector.idColumn + " varchar(255) NOT NULL);");
	    
	    String createIntrospect = this.db.getAdapter().updateEngineSpecificSQL(
                "CREATE TABLE IF NOT EXISTS "
                + introspectTable + "("
                + DBConnector.idColumn + " varchar(255) NOT NULL,"
                + introspectClaimsColumn + " boolean NOT NULL);");
	            
	    String createAccess = this.db.getAdapter().updateEngineSpecificSQL(
                "CREATE TABLE IF NOT EXISTS "
                + accessTable + "("
                + DBConnector.idColumn + " varchar(255) NOT NULL,"
                + DBConnector.rsIdColumn + " varchar(255) NOT NULL,"
                + DBConnector.scopeColumn + " varchar(255) NOT NULL);");

        String createOSCOREGroupManagers = this.db.getAdapter().updateEngineSpecificSQL(
        		"CREATE TABLE IF NOT EXISTS "
        		+ oscoreGroupManagersTable + "("
        		+ DBConnector.rsIdColumn + " varchar(255) NOT NULL,"
                + DBConnector.audColumn + " varchar(255) NOT NULL);");
	    
	    try (Connection conn = this.db.getAdapter().getDBConnection();
             Statement stmt = conn.createStatement()) {
	        stmt.execute(createToken);
	        stmt.execute(createIntrospect);
	        stmt.execute(createAccess);
	        stmt.execute(createOSCOREGroupManagers);
	    } catch (SQLException e) {
	        e.printStackTrace();
	        throw new AceException(e.getMessage());
	    }
	    
	    this.canToken = this.db.prepareStatement(
                this.db.getAdapter().updateEngineSpecificSQL("SELECT * FROM "
                        + tokenTable
                        + " WHERE " + DBConnector.idColumn + "=?;"));
	    
	    
        this.canIntrospect = this.db.prepareStatement(
                this.db.getAdapter().updateEngineSpecificSQL("SELECT * FROM "
                        + introspectTable
                        + " WHERE " + DBConnector.idColumn + "=?;"));
        
        //Gets only the access of the client, the PDP sorts out the audiences and scopes
        this.canAccess = this.db.prepareStatement(
                this.db.getAdapter().updateEngineSpecificSQL("SELECT * FROM "
                        + accessTable
                        + " WHERE " + DBConnector.idColumn + "=?"
                        + " AND " + DBConnector.rsIdColumn + "=?;"));
        
        
        this.addTokenAccess = this.db.prepareStatement(
                this.db.getAdapter().updateEngineSpecificSQL("INSERT INTO "
                      + tokenTable + " VALUES (?);"));
        
        this.addIntrospectAccess = this.db.prepareStatement(
                this.db.getAdapter().updateEngineSpecificSQL("INSERT INTO "
                        + introspectTable + " VALUES (?,?);"));
        
        this.addAccess = this.db.prepareStatement(
                this.db.getAdapter().updateEngineSpecificSQL("INSERT INTO "
                        + accessTable + " VALUES (?,?,?);"));
        
        this.addOSCOREGroupManager = this.db.prepareStatement(
                this.db.getAdapter().updateEngineSpecificSQL("INSERT INTO "
                        + oscoreGroupManagersTable + " VALUES (?,?);"));
        
        this.deleteTokenAccess = this.db.prepareStatement(
                this.db.getAdapter().updateEngineSpecificSQL("DELETE FROM "
                        + tokenTable + " WHERE " 
                        + DBConnector.idColumn + "=?;"));
        
        this.deleteIntrospectAccess = this.db.prepareStatement(
                this.db.getAdapter().updateEngineSpecificSQL("DELETE FROM "
                        + introspectTable + " WHERE " 
                        + DBConnector.idColumn + "=?;"));
        
        this.deleteAccess = this.db.prepareStatement(
                this.db.getAdapter().updateEngineSpecificSQL("DELETE FROM "
                        + accessTable + " WHERE " 
                        + DBConnector.idColumn + "=?"
                        + " AND " + DBConnector.rsIdColumn + "=?"
                        + " AND " + DBConnector.scopeColumn + "=?;"));
        
        this.deleteAllAccess = this.db.prepareStatement(
                this.db.getAdapter().updateEngineSpecificSQL("DELETE FROM "
                        + accessTable + " WHERE " 
                        + DBConnector.idColumn + "=?;"));

        this.deleteAllRsAccess = this.db.prepareStatement(
                this.db.getAdapter().updateEngineSpecificSQL("DELETE FROM "
                        + accessTable + " WHERE " 
                        + DBConnector.idColumn + "=?"
                        + " AND " + DBConnector.rsIdColumn + "=?;"));

        this.deleteOSCOREGroupManagers = this.db.prepareStatement(
        		this.db.getAdapter().updateEngineSpecificSQL("DELETE FROM "
        				+ oscoreGroupManagersTable + " WHERE "
        				+ DBConnector.rsIdColumn + "=?;"));
        
        this.getAllAccess = this.db.prepareStatement(
                this.db.getAdapter().updateEngineSpecificSQL("SELECT * FROM "
                        + accessTable + " WHERE "
                        + DBConnector.idColumn + "=?;"));
        
        this.selectOSCOREGroupManagers = this.db.prepareStatement(
                this.db.getAdapter().updateEngineSpecificSQL("SELECT "
                		+ DBConnector.audColumn + " FROM "
                		+ oscoreGroupManagersTable + " WHERE "
                        + DBConnector.rsIdColumn + "=? ORDER BY " 
		                + DBConnector.audColumn +";"));
        
        rolesToInt.put("requester", GroupcommParameters.GROUP_OSCORE_REQUESTER);
        rolesToInt.put("responder", GroupcommParameters.GROUP_OSCORE_RESPONDER);
        rolesToInt.put("monitor", GroupcommParameters.GROUP_OSCORE_MONITOR);
        rolesToInt.put("verifier", GroupcommParameters.GROUP_OSCORE_VERIFIER);

        permissionsToInt.put("list", GroupcommParameters.GROUP_OSCORE_ADMIN_LIST);
        permissionsToInt.put("create", GroupcommParameters.GROUP_OSCORE_ADMIN_CREATE);
        permissionsToInt.put("read", GroupcommParameters.GROUP_OSCORE_ADMIN_READ);
        permissionsToInt.put("write", GroupcommParameters.GROUP_OSCORE_ADMIN_WRITE);
        permissionsToInt.put("delete", GroupcommParameters.GROUP_OSCORE_ADMIN_DELETE);
        
	}
	
	@Override
	public boolean canAccessToken(String clientId) throws AceException {
	    if (clientId == null) {
            throw new AceException(
                    "canAccessToken() requires non-null clientId");
        }
        try {
            this.canToken.setString(1, clientId);
            ResultSet result = this.canToken.executeQuery();
            this.canToken.clearParameters();
            if (result.next()) {
                result.close();
                return true;
            }
            result.close();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
        return false;
	}
	
	/**
	 * Determine whether a Resource Server is specifically an OSCORE Group Manager
	 * 
	 * @param rsId  the identifier of the Resource Server
	 * @param aud   the audience for which the requested Access Token has to be issued
	 * @return  true if the Resource Server is an OSCORE Group Manager, or false otherwise 
	 * @throws AceException
	 */
	public boolean isOSCOREGroupManager(String rsId, Set<String> aud) throws AceException {
		if (rsId == null || rsId.isEmpty()) {
            throw new AceException("RS must have non-null, non-empty identifier");
        }
		
		if (aud == null) {
	        throw new AceException("Audience must be non-null");
	    }
		
		for (String audE : aud) {
		
			try {
            	this.selectOSCOREGroupManagers.setString(1, rsId);
            	ResultSet result = this.selectOSCOREGroupManagers.executeQuery();
            	this.selectOSCOREGroupManagers.clearParameters();
            	while (result.next()) {
            		if (result.getString(DBConnector.audColumn).equals(audE)) {
            			result.close();
                		return true;
            		}
            	}
            	result.close();
        	} catch (SQLException e) {
        		throw new AceException(e.getMessage());
        	}
		}
        return false;
	}

	@Override
	public IntrospectAccessLevel getIntrospectAccessLevel(String rsId) throws AceException {
	      if (rsId == null) {
	            throw new AceException(
	                    "getIntrospectAccessLevel() requires non-null rsId");
	        }
	        try {
	            this.canIntrospect.setString(1, rsId);
	            ResultSet result = this.canIntrospect.executeQuery();
	            this.canIntrospect.clearParameters();
	            if (result.next()) {
	                boolean canAccessClaims = result.getBoolean(introspectClaimsColumn);
	                result.close();
	                if (canAccessClaims)
                    {
                        return IntrospectAccessLevel.ACTIVE_AND_CLAIMS;
                    }
                    return IntrospectAccessLevel.ACTIVE_ONLY;
	            }
	            result.close();
	        } catch (SQLException e) {
	            throw new AceException(e.getMessage());
	        }
	        return IntrospectAccessLevel.NONE;
	}

	@Override
	public Object canAccess(String clientId, Set<String> aud, Object scope) 
				throws AceException {
	    if (clientId == null) {
            throw new AceException(
                    "canAccess() requires non-null clientId");
        }

	    if (aud == null) {
	        throw new AceException(
	                "canAccess() requires non-null audience");
	    }
	    
	    if (scope == null) {
	        throw new AceException(
	                "canAccess() requires non-null scope");
	    }
	    
	    Set<String> rss = new HashSet<>();
        for (String audE : aud) {
            rss.addAll(this.db.getRSS(audE));
        }
        if (rss.isEmpty()) {
            return null;
        }
            
	    Set<Set<String>> clientACL = new HashSet<>();
	    
	    for (String rs : rss) {
	        Set<String> scopes = new HashSet<>();
	        try {
	            this.canAccess.setString(1, clientId);
	            this.canAccess.setString(2, rs);
	            ResultSet result = this.canAccess.executeQuery();
	            this.canAccess.clearParameters();
	            while (result.next()) {
	                scopes.add(result.getString(DBConnector.scopeColumn));
	            }
	            result.close();
	        } catch (SQLException e) {
	            throw new AceException(e.getMessage());
	        }
	        if (scopes.isEmpty()) {
	            //The client can access nothing on this RS
	            return null;
	        }
	        clientACL.add(scopes);
	    }
	          
        Set<String> scopes = null;
        for (Set<String> rs : clientACL) {
            if (scopes == null) {
                scopes = new HashSet<>();
                if (rs != null) {
                    scopes.addAll(rs);
                }
            } else {
                Set<String> remains = new HashSet<>(scopes);
                for (String foo : scopes) {
                    if (rs == null ) { 
                        //The client can access nothing on this RS
                        return null;
                    }
                    if (!rs.contains(foo)) {
                        remains.remove(foo);
                    }
                }
                scopes = remains;
            }
        }
           
        if (scopes == null || scopes.isEmpty()) {
            return null;
        }
        String scopeStr;
        String grantedScopesString = "";
        Object grantedScopes = null;
        
        // If the RS and the audience point at an OSCORE Group Manager,
        // the scope must be encoded as a CBOR Byte String
        boolean scopeMustBeBinary = false;
        boolean rsOSCOREGroupManager = false;
        for (String rs : rss) {
        	rsOSCOREGroupManager = isOSCOREGroupManager(rs, aud);
        	scopeMustBeBinary = rsOSCOREGroupManager;
        	if (scopeMustBeBinary) break;
        }
        
        // Handling of a Text String scope, just as in KissPDP
        if (scope instanceof String) {
        	if (scopeMustBeBinary)
        		throw new AceException("Scope for this audience must be a byte string");
        	
            scopeStr = (String)scope;
            String[] requestedScopes = scopeStr.split(" ");
            
            for (int i=0; i<requestedScopes.length; i++) {
                if (scopes.contains(requestedScopes[i])) {
                    if (!(grantedScopesString).isEmpty()) {
                    	grantedScopesString += " ";
                    }
                    grantedScopesString += requestedScopes[i];
                }
            }
            
            if (!grantedScopesString.isEmpty())
            	grantedScopes = grantedScopesString;
        }
        
        // Handling of a Byte String scope, formatted as per draft-ietf-ace-key-groupcomm , Section 3.1
        // This type of scope is expected to have this structure for each RS acting as OSCORE Group Manager
        else if (scope instanceof byte[] && rsOSCOREGroupManager) {
        	
        	// Allowed scope to be returned to the /token endpoint
        	CBORObject cborArrayScope = CBORObject.NewArray();
        	
        	// Retrieve the scope as CBOR Array
        	CBORObject scopeCBOR = CBORObject.DecodeFromBytes((byte[])scope);
        	
        	if (scopeCBOR.getType().equals(CBORType.Array)) {
        	
        	  // Inspect each scope entry, i.e. group name followed by role(s),
        	  // or a group name pattern followed by admin permissions.
        	  for (int entryIndex = 0; entryIndex < scopeCBOR.size(); entryIndex++) {
        		
        		  CBORObject scopeEntry = scopeCBOR.get(entryIndex);
        		  
        		  if (scopeEntry.getType().equals(CBORType.Array)) {
		        		
		        	  if (scopeEntry.size() != 2) {
		        		  throw new AceException("Scope must have two elements, i.e., group name and list of roles");
		        	  }

		        	  String groupName = "";
		        	  Set<String> permissions = new HashSet<>();
		        	  		        	  
		        	  // Retrieve the role or list of roles
		        	  CBORObject scopeElement = scopeEntry.get(1);
		        	  
		        	  int permissionSet = 0;
		        	  if (scopeElement.getType().equals(CBORType.Integer)) {
		        		  
		        		  permissionSet = scopeElement.AsInt32();
		        		  
		        		  if (permissionSet <= 0)
		        			  throw new AceException("The permission set must be encoded as a CBOR Unsigned Integer greater than 0");
		        		  
		        		  if ((permissionSet % 2) == 0) {
		        			  // This is a user scope entry, hence Tperm specifies roles to have as a group member
		        			  
			        		  Set<Integer> roleIdSet = Util.getGroupOSCORERoles(permissionSet);
			        		  short[] roleIdArray = new short[roleIdSet.size()];
			        		  int index = 0;
			        		  for (Integer elem : roleIdSet) {
			        			  roleIdArray[index++] = elem.shortValue();
			        		  }
			        		  for (int i = 0; i < roleIdArray.length; i++) {
			        			  short roleIdentifier = roleIdArray[i];
			        			  // Silently ignore unrecognized roles
			        			  if (roleIdentifier < GroupcommParameters.GROUP_OSCORE_ROLES.length) {
			        				  permissions.add(GroupcommParameters.GROUP_OSCORE_ROLES[roleIdentifier]);
			        			  }
			        		  }
		        		  }
		        		  else {
		        			  // This is an admin scope entry, hence Tperm specifies actions allowed to an Administrator
		        			  
		        			  Set<Integer> adminPermissionIdSet = Util.getGroupOSCOREAdminPermissions(permissionSet);
		        			  short[] adminPermissionIdArray = new short[adminPermissionIdSet.size()];
		        			  int index = 0;
		        			  for (Integer elem : adminPermissionIdSet) {
		        				  adminPermissionIdArray[index++] = elem.shortValue();
		        			  }
		        			  for (int i = 0; i < adminPermissionIdArray.length; i++) {
		        				  short adminPermissionIdentifier = adminPermissionIdArray[i];
		        				  // Silently ignore unrecognized admin permissions
		        				  if (adminPermissionIdentifier < GroupcommParameters.GROUP_OSCORE_ADMIN_PERMISSIONS.length) {
		        					  permissions.add(GroupcommParameters.GROUP_OSCORE_ADMIN_PERMISSIONS[adminPermissionIdentifier]);
		        				  }  
		        			  }
		        			  
		        		  }
		        		  
		        	  }
		        	  else {
		        		  throw new AceException("Invalid format of permissions for accessing an OSCORE Group Manager");
		        	  }
		        	  
		        	  
		        	  if ((permissionSet % 2) == 0) {
		        		  // This is a user scope entry, hence Toid specifies a group name as a literal string
		        		  
			        	  // Retrieve the group name of the OSCORE group
			        	  scopeElement = scopeEntry.get(0);
			        	  if (scopeElement.getType().equals(CBORType.TextString)) {
			        		  groupName = scopeElement.AsString();
			        	  }
			        	  else {throw new AceException("The group name must be a CBOR Text String");}
			        	  
			        	  // Check if the client can access the specified group on the RS with the specified roles.
			        	  // Note: this assumes that there is only one RS acting as Group Manager specified as audience
			        	  // Then, each element of 'scopes' refers to one OSCORE group under that Group Manager
			        	  
			        	  Set<String> allowedRoles = new HashSet<>();
			        	  
			        	  for (String myScope : scopes) {
			        		  
			        		  // The only valid format for a valid stored scope record to parse is:
			        		  //
			        		  // "oscgm1:LENGTH:NAME_ROLE1_ROLE2_...
			        		  //
			        		  // where LENGTH is the number of characters of the group name NAME
			        		  
			        		  int index = myScope.indexOf(":");
			        		  if (index == -1 || (index == (myScope.length() - 1))) {
			        			  continue;
			        		  }
			        		  String mySubstr = myScope.substring(0, index);
			        		  if (GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX.equals(mySubstr) == false) {
			        			  continue;
			        		  }
			        		  
			        		  parseOscoreGroupcommStoredScopeLiteralPattern(groupName, permissions, myScope, index, allowedRoles);
			        		  
			        	  }
			        	  
			        	  if (!allowedRoles.isEmpty()) {
			        		  
			        		  CBORObject cborArrayScopeEntry = CBORObject.NewArray();
			        	      
			        		  cborArrayScopeEntry.Add(groupName);
			        	      
			        		  int grantedRoles = 0;
		        	    	  for (String foo : allowedRoles) {
		        	    		  grantedRoles = Util.addGroupOSCORERole(grantedRoles, rolesToInt.get(foo));
		        	    	  }
		        	    	  cborArrayScopeEntry.Add(grantedRoles);
			        	      
			        	      cborArrayScope.Add(cborArrayScopeEntry);
			        	     
			        	  }
        		     }
		        	 else {
		        		 // This is an admin scope entry, hence Tperm specifies actions allowed to an Administrator
		        		 
		        		  boolean wildcardPattern = false;
		        		  boolean complexPattern = false;
		        		  boolean invalidGroupNamePattern = true;
		        		 
			        	  // Retrieve the group name pattern
			        	  scopeElement = scopeEntry.get(0);
			        	  if (scopeElement.equals(CBORObject.True)) {
			        		  // Wildcard pattern
			        		  wildcardPattern = true;
			        		  invalidGroupNamePattern = false;
			        	  }
			        	  else if (scopeElement.getType().equals(CBORType.TextString)) {

			        		  if (scopeElement.isTagged() == false) {
				        		  // Literal pattern
				        		  groupName = scopeElement.AsString();
				        		  invalidGroupNamePattern = false;
			        		  }
			        		  else if (scopeElement.HasTag(21065)) {
			        			  // Complex pattern (I-Regexp regular expression)
			        			  complexPattern = true;
			        			  groupName = scopeElement.AsString();
			        			  invalidGroupNamePattern = false;
			        		  }
			        		  
			        	  }
			        	  if (invalidGroupNamePattern) {
			        		  throw new AceException("The group name pattern must be the CBOR Simple Value true or a "
			        	  							 + "CBOR Text String, possibly as an I-Regexp regular expression");
			        	  }
		        		 
			        	  // Check if the client can be Administrator for the groups on the RS whose group name matches
			        	  // with the specified group name pattern, and according with the specified admin permissions.
			        	  // Note: this assumes that there is only one RS acting as Group Manager specified as audience
			        	  // Then, each element of 'scopes' refers to one OSCORE group under that Group Manager
			        	  
			        	  Set<String> allowedPermissions = new HashSet<>();
			        	  			        	  
			        	  for (String myScope : scopes) {
			        		  
			        		  // The format to parse for valid scope records depends on the type of
			        		  // group name pattern specified in the Toid of the present scope entry
			        		  
			        		  if (wildcardPattern == true) {
			        			  // Wildcard pattern
			        			  
				        		  // The only valid format for a valid stored scope record to parse is:
				        		  //
				        		  // "oscgm0:ROLE1_ROLE2_...
			        			  
			        			  int index = myScope.indexOf(":");
			        			  if (index == -1 || (index == (myScope.length() - 1))) {
				        			  continue;
				        		  }
			        			  
			        			  String mySubstr = myScope.substring(0, index);
			        			  
			        			  if (GroupcommParameters.GROUP_OSCORE_AS_SCOPE_WILDCARD_PREFIX.equals(mySubstr)) {
			        				  parseOscoreGroupcommStoredScopeWildcardPattern(permissions, myScope, index, allowedPermissions);
				        		  }

			        		  }
			        		  else {
			        			  if (complexPattern == true) {
			        				  // Complex pattern
			        				  
					        		  // Any of the two following formats of stored scope records are valid to parse:
				        			  //
				        			  // "oscgm0:ROLE1_ROLE2_...
			        				  //
			        				  //
					        		  // "oscgm2:SEMANTICS_ID:LENGTH:COMPLEXPATTERN_ROLE1_ROLE2_...
					        		  //
					        		  // where SEMANTICS_ID is the integer identifier of the semantics used for the
			        				  // group name pattern (only 21065 as I-Regexp regular expression is supported),
			        				  // and LENGTH is the number of characters of the group name pattern
			        			  			        				  
					        		  int index = myScope.indexOf(":");
					        		  if (index == -1 || (index == (myScope.length() - 1))) {
					        			  continue;
					        		  }

					        		  String mySubstr = myScope.substring(0, index);
					        		  
					        		  if (GroupcommParameters.GROUP_OSCORE_AS_SCOPE_WILDCARD_PREFIX.equals(mySubstr)) {
					        			  parseOscoreGroupcommStoredScopeWildcardPattern(permissions, myScope,
					        					  										 index, allowedPermissions);
					        		  }
					        		  if (GroupcommParameters.GROUP_OSCORE_AS_SCOPE_COMPLEX_PREFIX.equals(mySubstr)) {
					        			  parseOscoreGroupcommStoredScopeComplexPattern(true, groupName, permissions, myScope,
					        					  										index, allowedPermissions);
					        		  }
					        		  
			        			  }
				        		  else {
				        			  // Literal pattern
				        			  
					        		  // Any of the three formats of stored scope records are valid to parse:
				        			  //
				        			  // "oscgm0:ROLE1_ROLE2_...
					        		  //
				        			  //
					        		  // "oscgm1::LENGTH:COMPLEXPATTERN_ROLE1_ROLE2_...
					        		  //
					        		  // where SEMANTICS_ID is the integer identifier of the semantics used for the
			        				  // group name pattern (only 21065 as I-Regexp regular expression is supported),
			        				  // and LENGTH is the number of characters of the group name pattern
				        			  //
				        			  //
					        		  // "oscgm2:SEMANTICS_ID:LENGTH:COMPLEXPATTERN_ROLE1_ROLE2_...
					        		  //
					        		  // where SEMANTICS_ID is the integer identifier of the semantics used for the
			        				  // group name pattern (only 21065 as I-Regexp regular expression is supported),
			        				  // and LENGTH is the number of characters of the group name pattern

					        		  int index = myScope.indexOf(":");
					        		  if (index == -1 || (index == (myScope.length() - 1))) {
					        			  continue;
					        		  }
					        		  
					        		  String mySubstr = myScope.substring(0, index);
					        		  
					        		  if (GroupcommParameters.GROUP_OSCORE_AS_SCOPE_WILDCARD_PREFIX.equals(mySubstr)) {
					        			  parseOscoreGroupcommStoredScopeWildcardPattern(permissions, myScope,
					        					  										 index, allowedPermissions);
					        		  }
					        		  if (GroupcommParameters.GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX.equals(mySubstr)) {
					        			  parseOscoreGroupcommStoredScopeLiteralPattern(groupName, permissions, myScope,
					        					  										index, allowedPermissions);
					        		  }
					        		  if (GroupcommParameters.GROUP_OSCORE_AS_SCOPE_COMPLEX_PREFIX.equals(mySubstr)) {
					        			  parseOscoreGroupcommStoredScopeComplexPattern(false, groupName, permissions, myScope,
					        					  										index, allowedPermissions);
					        		  }
				        			  
				        		  }
			        		  }
			        		  
			        	  }
			        	  
			        	  if (!allowedPermissions.isEmpty()) {
			        		  
			        		  CBORObject cborArrayScopeEntry = CBORObject.NewArray();
			        		  CBORObject toid;
			        		  
			        		  if (wildcardPattern) {
			        			  toid = CBORObject.True;
			        		  }
			        		  else {
			        			  if (complexPattern) {
			        				  toid = CBORObject.FromObjectAndTag(groupName, 21065);
			        			  }
			        			  else {
			        				  toid = CBORObject.FromObject(groupName);
			        			  }
			        		  }
		        			  cborArrayScopeEntry.Add(toid);
			        		  
			        		  int grantedPermissions = 0;
		        	    	  for (String foo : allowedPermissions) {
		        	    		  grantedPermissions = Util.addGroupOSCOREAdminPermission(grantedPermissions, permissionsToInt.get(foo));
		        	    	  }
		        	    	  cborArrayScopeEntry.Add(grantedPermissions);
			        	      
			        	      cborArrayScope.Add(cborArrayScopeEntry);
			        	     
			        	  }
			        	  
		        	 }
		        	  
        		  } else {
        			  throw new AceException("Invalid scope entry format for accessing an OSCORE Group Manager");
          	      }
        		  
        	  } // End of scope entries inspection
        	  
        	  if (cborArrayScope.size() != 0) {
        		  grantedScopes = cborArrayScope.EncodeToBytes();
        	  }
        	  
  		    } else {
  		    	throw new AceException("Invalid scope format for accessing an OSCORE Group Manager");
  	        }
        	
        }
        
    	// This includes the case where the scope is encoded as a CBOR Byte String,
    	// but the audience is not registered as related to an OSCORE Group Manager.
    	// In fact, no processing for byte string scopes are defined, other than
    	// the one implemented above according to draft-ietf-ace-key-groupcomm-oscore
        else if (scope instanceof byte[]) {
        	throw new AceException("Unknown processing for this byte string scope");
        }
        
        else {
        	throw new AceException("Scopes must be Text Strings or Byte Strings");
        }
        
        return grantedScopes;
	}

    @Override
    public void close() throws Exception {
       this.db.close();
    }
    
    /**
     * Add access permission for the token endpoint
     * 
     * @param id  the identifier of the entity to be allowed access
     * 
     * @throws AceException
     */
    public void addTokenAccess(String id) throws AceException {
        if (id == null) {
            throw new AceException(
                    "addTokenAccess() requires non-null id");
        }
        try {
            this.addTokenAccess.setString(1, id);
            this.addTokenAccess.execute();
            this.addTokenAccess.clearParameters();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
    }

    /**
     * Add access permission for the introspect endpoint, defaulting to access to activeness and claims.
     *
     * @param id  the identifier of the entity to be allowed access
     *
     * @throws AceException
     */
    public void addIntrospectAccess(String id) throws AceException {
        addIntrospectAccess(id, IntrospectAccessLevel.ACTIVE_AND_CLAIMS);
    }

    /**
     * Add access permission for the introspect endpoint
     * 
     * @param id  the identifier of the entity to be allowed access
     * @param accessLevel the level of access to give when introspecting
     * 
     * @throws AceException
     */
    public void addIntrospectAccess(String id, IntrospectAccessLevel accessLevel) throws AceException {
        if (id == null) {
            throw new AceException(
                    "addIntrospectAccess() requires non-null id");
        }
        if (accessLevel.equals(IntrospectAccessLevel.NONE)) {
            throw new AceException(
                    "addIntrospectAccess() requires non-NONE access level");
        }
        try {
            boolean hasClaimsAccess = accessLevel.equals(IntrospectAccessLevel.ACTIVE_AND_CLAIMS);
            this.addIntrospectAccess.setString(1, id);
            this.addIntrospectAccess.setBoolean(2, hasClaimsAccess);
            this.addIntrospectAccess.execute();
            this.addIntrospectAccess.clearParameters();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
    } 
    
    /**
     * Add access permission for a client
     * 
     * @param cid  the identifier of the client to be allowed access
     * @param rid  the identifier of the RS to which access is allowed
     * @param scope  the identifier of the scope for which access is allowed
     * 
     * @throws AceException
     */
    public void addAccess(String cid, String rid, String scope) 
            throws AceException {
        if (cid == null) {
            throw new AceException(
                    "addAccess() requires non-null cid");
        }
        if (rid == null) {
            throw new AceException(
                    "addAccess() requires non-null rid");
        }
        
        if (scope == null) {
            throw new AceException(
                    "addAccess() requires non-null scope");
        }
        
        try {
            this.addAccess.setString(1, cid);
            this.addAccess.setString(2, rid);
            this.addAccess.setString(3, scope);
            this.addAccess.execute();
            this.addAccess.clearParameters();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
    }
    
    /**
     * Revoke an access right to the Token endpoint
     * 
     * @param id  the identifier if the entity for which access is revoked
     * 
     * @throws AceException
     */
    public void revokeTokenAccess(String id) throws AceException {
        if (id == null) {
            throw new AceException(
                    "revokeTokenAccess() requires non-null id");
        }
        try {
            this.deleteTokenAccess.setString(1, id);
            this.deleteTokenAccess.execute();
            this.deleteTokenAccess.clearParameters();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
    }
    
    /**
     * Revoke an access right to the Introspect endpoint.
     * 
     * @param id  the identifier of the entity for which access is revoked
     *
     * @throws AceException
     */
    public void revokeIntrospectAccess(String id) throws AceException {
        if (id == null) {
            throw new AceException(
                    "revokeIntrospectAccess() requires non-null id");
        }
        try {
            this.deleteIntrospectAccess.setString(1, id);
            this.deleteIntrospectAccess.execute();
            this.deleteIntrospectAccess.clearParameters();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
    }
    
    /**
     * Revoke a specific access right from a client.
     * 
     * @param cid  the client's identifier
     * @param rid  the RS's identifier
     * @param scope  the scope to be revoked
     * 
     * @throws AceException
     */
    public void revokeAccess(String cid, String rid, String scope) 
                throws AceException {
        if (cid == null) {
            throw new AceException(
                    "revokeAccess() requires non-null cid");
        }
        if (rid == null) {
            throw new AceException(
                    "revokeAccess() requires non-null rid");
        }
        
        if (scope == null) {
            throw new AceException(
                    "revokeAccess() requires non-null scope");
        }
        
        try {
            this.deleteAccess.setString(1, cid);
            this.deleteAccess.setString(2, rid);
            this.deleteAccess.setString(3, scope);
            this.deleteAccess.execute();
            this.deleteAccess.clearParameters();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
    }
    
    /**
     * Revoke all access for a given client.
     * 
     * @param id  the client's identifier
     * 
     * @throws AceException
     */
    public void revokeAllAccess(String id) throws AceException {
        if (id == null) {
            throw new AceException(
                    "revokeAllAccess() requires non-null id");
        }
        try {
            this.deleteAllAccess.setString(1, id);
            this.deleteAllAccess.execute();
            this.deleteAllAccess.clearParameters();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
    }
    
    /**
     * Revoke all access to a specific RS for a given client.
     * 
     * @param cid  the client's identifier
     * @param rid  the RS's identifier
     * 
     * @throws AceException
     */
    public void revokeAllRsAccess(String cid, String rid) 
            throws AceException {
        if (cid == null) {
            throw new AceException(
                    "revokeAllRsAccess() requires non-null cid");
        }
        
        if (rid == null) {
            throw new AceException(
                    "revokeAllRsAccess() requires non-null rid");
        }
        
        try {
            this.deleteAllRsAccess.setString(1, cid);
            this.deleteAllRsAccess.setString(2, rid);
            this.deleteAllRsAccess.execute();
            this.deleteAllRsAccess.clearParameters();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
    }

    /**
     * Gets a map of all access configured for a given client.
     *
     * @param id  the client's identifier
     *
     * @return A map of RS ids associated to sets of scopes, configured for the given client id.
     * @throws AceException
     */
    public Map<String, Set<String>> getAllAccess(String id) throws AceException {
        if (id == null) {
            throw new AceException(
                    "getAllAccess() requires non-null id");
        }
        try {
            this.getAllAccess.setString(1, id);
            ResultSet result = this.getAllAccess.executeQuery();
            this.getAllAccess.clearParameters();

            Map<String, Set<String>> accessMap = new HashMap<>();
            while(result.next()) {
                String rsId = result.getString(DBConnector.rsIdColumn);
                String scope = result.getString(DBConnector.scopeColumn);
                if(!accessMap.containsKey(rsId)) {
                    accessMap.put(rsId, new HashSet<>());
                }
                accessMap.get(rsId).add(scope);
            }
            result.close();
            return accessMap;
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
    }
    
    /**
     * Add a pre-registered audience as an OSCORE Group Manager
     * 
     * @param rsId  the identifier of the RS whose audiences are registered as OSCORE Group Manager
     * @param auds  the identifiers of the audiences the RS acting as OSCORE Group Manager identifies with
     * 
     * @throws AceException
     */
    public void addOSCOREGroupManagers(String rsId, Set<String> auds) throws AceException {
    	if (rsId == null || rsId.isEmpty()) {
            throw new AceException("RS must have non-null, non-empty identifier");
        }
        
        // Prevent adding an rs that has an identifier that is equal to an 
        // existing audience
        try {
        	this.selectOSCOREGroupManagers.setString(1, rsId);
        	ResultSet result = this.selectOSCOREGroupManagers.executeQuery();
        	this.selectOSCOREGroupManagers.clearParameters();
        	if (result.next()) {
        		result.close();
        		throw new AceException(
        				"RsId equal to existing audience id: " + rsId);
        	}
        	result.close();
        	
        	for (String aud : auds) {
                this.addOSCOREGroupManager.setString(1, rsId);
                this.addOSCOREGroupManager.setString(2, aud);
                this.addOSCOREGroupManager.execute();
            }
            this.addOSCOREGroupManager.clearParameters();
            
            //The RS always recognizes itself as a singleton audience
            this.addOSCOREGroupManager.setString(1, rsId);
            this.addOSCOREGroupManager.setString(2, rsId);
            this.addOSCOREGroupManager.execute();
            this.addOSCOREGroupManager.clearParameters();
            
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
    }

    /**
     * Remove all audiences an RS identifies with as an OSCORE Group Manager
     * 
     * @param rsId the identifier of the RS whose audiences are registered as OSCORE Group Manager
     * 
     * @throws AceException
     */
    public void deleteOSCOREGroupManagers(String rsId) throws AceException {
    	if (rsId == null || rsId.isEmpty()) {
            throw new AceException("RS must have non-null, non-empty identifier");
        }
        
        try {
            this.deleteOSCOREGroupManagers.setString(1, rsId);
            this.deleteOSCOREGroupManagers.execute();
            this.deleteOSCOREGroupManagers.clearParameters();
            
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
    }
    
    /**
     * Determine which permissions can be granted to a client that has requested an Access Token for accessing
     * an OSCORE Group Manager, based on a related stored scope that considers a wildcard pattern group name
     *
     * @param permissions  the set of permissions from Tperm of the considered scope entry
     * @param input  the stored scope to parse
     * @param index  the position of the character of the stored scope from which to start the parsing
     * @param allowedPermissions  the set where to add the actually granted permissions
     *
     * @throws AceException
     */
    private void parseOscoreGroupcommStoredScopeWildcardPattern(final Set<String> permissions, final String input,
    															final int index, Set<String> allowedPermissions) {
    
		String storedPermissionSequence = null;
		String[] storedPermissions = null;
		
		
		// Any type of group name pattern in the Toid of the scope entry of the Access Token Request
    	// matches with the wildcard group name pattern in the stored scope
		
		storedPermissionSequence = input.substring((index + 1));
		storedPermissions = storedPermissionSequence.split("_");
		  
		for (int i = 0; i < storedPermissions.length; i++) {
			if (permissions.contains(storedPermissions[i])) {
				// Concede only permissions that are both
				// possible to give and requested by the client
				allowedPermissions.add(storedPermissions[i]);
			}
		}
    	
    }
    
    /**
     * Determine which permissions can be granted to a client that has requested an Access Token for accessing
     * an OSCORE Group Manager, based on a related stored scope that considers a literal pattern group name
     *
     * @param groupNamePattern  the literal group name pattern from Toid of the considered scope entry
     * @param permissions  the set of permissions from Tperm of the considered scope entry
     * @param input  the stored scope to parse
     * @param index  the position of the character of the stored scope from which to start the parsing
     * @param allowedPermissions  the set where to add the actually granted permissions
     *
     * @throws AceException
     */
    private void parseOscoreGroupcommStoredScopeLiteralPattern(final String groupNamePattern, final Set<String> permissions,
    														   final String input, final int index,
    														   Set<String> allowedRolesOrPermissions) {
    	
    	int index2 = input.indexOf(":", (index + 1));
    	if (index2 == -1 || (index2 == (input.length() - 1))) {
    		return;
    	}
    	int length = 0;
    	String mySubstr = input.substring((index + 1), index2);
    	try {
    	    length = Integer.parseInt(mySubstr);
    	}
    	catch (NumberFormatException e) {
    	    return;
    	}
    	if ((length < 1)) {
    		return;
    	}
    	mySubstr = input.substring((index2 + 1));
    	if (mySubstr.length() < (length + 2) ) {
    	    return;
    	}

    	String storedGroupNamePattern = mySubstr.substring(0, length);

		// The literal group name pattern in the Toid of the scope entry of the Access Token Request
    	// has to be equal to the literal group name pattern in the stored scope
    	
    	if(groupNamePattern.equals(storedGroupNamePattern)) {
    	    String storedSequence = mySubstr.substring(length + 1);
    	    String[] storedElements = storedSequence.split("_");
    	    
    	    for (int i = 0; i < storedElements.length; i++) {
    	    	if (permissions.contains(storedElements[i])) {
    				// Concede only permissions that are both
    				// possible to give and requested by the client
    	    		allowedRolesOrPermissions.add(storedElements[i]);
    	    	}
    	    }
    	}

    }
    
    /**
     * Determine which permissions can be granted to a client that has requested an Access Token for accessing
     * an OSCORE Group Manager, based on a related stored scope that considers a complex pattern group name
     *
     * @param isComplexPattern  true if the group name pattern from the considered scope entry is complex, or false if it is literal 
     * @param groupNamePattern  the literal/complex group name pattern from Toid of the considered scope entry
     * @param permissions  the set of permissions from Tperm of the considered scope entry
     * @param input  the stored scope to parse
     * @param index  the position of the character of the stored scope from which to start the parsing
     * @param allowedPermissions  the set where to add the actually granted permissions
     *
     * @throws AceException
     */
    private void parseOscoreGroupcommStoredScopeComplexPattern(boolean isComplexPattern, final String groupNamePattern,
												    		   final Set<String> permissions, final String input,
												    		   final int index, Set<String> allowedPermissions) {
    	
		  String storedGroupNamePattern = null;
		  String storedPermissionSequence = null;
		  String[] storedPermissions = null;
		  
		  int index2 = input.indexOf(":", (index + 1));
		  if (index2 == -1 || (index2 == (input.length() - 1))) {
			  return;
		  }
		  int semanticsId = -1;
		  String mySubstr = input.substring((index + 1), index2);
		  try {
  		  semanticsId = Integer.parseInt(mySubstr);
		  }
		  catch (NumberFormatException e) {
			  return;
		  }
		  if ((semanticsId != 21065)) {
			  return;
		  }
		  
		  int index3 = input.indexOf(":", (index2 + 1));
		  if (index3 == -1 || (index3 == (input.length() - 1))) {
			  return;
		  }
		  int length = 0;
		  mySubstr = input.substring((index2 + 1), index3);
		  try {			        		  
  		  length = Integer.parseInt(mySubstr);
		  }
		  catch (NumberFormatException e) {
			  return;
		  }
		  if ((length < 1)) {
			  return;
		  }
		  mySubstr = input.substring((index3 + 1));
		  if (mySubstr.length() < (length + 2) ) {
			  return;
		  }
		  
		  storedGroupNamePattern = mySubstr.substring(0, length);
		  
		  boolean matching = false;		  
		  if (isComplexPattern) {
			  // In the Access Token Request, the Toid of this scope entry is a complex pattern.
			  // Therefore, it has to be equal to the regular expression in the stored scope.
			  matching = (groupNamePattern.equals(storedGroupNamePattern));
		  }
		  else {
			  // In the Access Token Request, the Toid of this scope entry is a literal pattern.
			  // Therefore, it has to match with the regular expression in the stored scope.
			  Pattern pat = Pattern.compile(storedGroupNamePattern);
			  Matcher myMatcher = pat.matcher(groupNamePattern);
			  matching = myMatcher.matches();
		  }
				  
		  if (matching) {
	  		  storedPermissionSequence = mySubstr.substring(length + 1);
	  		  storedPermissions = storedPermissionSequence.split("_");
				  
			  for (int i = 0; i < storedPermissions.length; i++) {
				  if (permissions.contains(storedPermissions[i])) {
					  // Concede only permissions that are both
					  // possible to give and requested by the client
					  allowedPermissions.add(storedPermissions[i]);
				  }
			  }
		  }
		  
    }
    
}
