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
package se.sics.ace.examples;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.*;

import se.sics.ace.AceException;
import se.sics.ace.as.DBConnector;
import se.sics.ace.as.PDP;

/**
 * A simple PDP implementation for test purposes. Uses static ACLs for everything.
 * This PDP backs up it's ACL's in the database.
 * 
 * NOTE: This PDP needs a SQL connector it won't work with other DBConnectors.
 * 
 * @author Ludwig Seitz
 *
 */
public class KissPDP implements PDP, AutoCloseable {

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

	/**
	 * Constructor, can supply an initial configuration.
	 * All configuration parameters that are null are expected
	 * to already be in the database.
	 * 
	 * @param connection  the database connector
	 * @throws AceException 
	 */
	public KissPDP(SQLConnector connection) throws AceException {
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

	    try (Connection conn = this.db.getAdapter().getDBConnection();
             Statement stmt = conn.createStatement()) {
	        stmt.execute(createToken);
	        stmt.execute(createIntrospect);
	        stmt.execute(createAccess);
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
        
        //Gets only the access of the client, the PDP sorts out the audiences
        //and scopes
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

        this.getAllAccess = this.db.prepareStatement(
                this.db.getAdapter().updateEngineSpecificSQL("SELECT * FROM "
                        + accessTable + " WHERE "
                        + DBConnector.idColumn + "=?;"));
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
	public String canAccess(String clientId, Set<String> aud, Object scope) 
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
        if (scope instanceof String) {
            scopeStr = (String)scope;
        } else {
            throw new AceException(
                    "KissPDP does not support non-String scopes");
        }
        String[] requestedScopes = scopeStr.split(" ");
        String grantedScopes = "";
        for (int i=0; i<requestedScopes.length; i++) {
            if (scopes.contains(requestedScopes[i])) {
                if (!grantedScopes.isEmpty()) {
                    grantedScopes += " ";
                }
                grantedScopes += requestedScopes[i];
            }
        }
        //all scopes found
        if (grantedScopes.isEmpty()) {
            return null;
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

}
