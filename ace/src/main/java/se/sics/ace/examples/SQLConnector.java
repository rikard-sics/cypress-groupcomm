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
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import com.upokecenter.cbor.CBORObject;

import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.OneKey;

import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.as.AccessTokenFactory;
import se.sics.ace.as.DBConnector;

/**
 * This class provides SQL database connectivity for the Attribute Authority.
 * 
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class SQLConnector implements DBConnector, AutoCloseable {

	/**
	 * The user configured for access.
	 */
	private String currentUser;

	/**
	 * The password configured for access.
	 */
	private String currentPassword;

	/**
	 * A prepared connection.
	 */
	private Connection conn = null;
	
	/**
	 * Records if the singleton connector is connected or disconnected
	 */
	private static boolean isConnected = false;

	/**
	 * A prepared INSERT statement to add a new Resource Server.
	 * 
	 * Parameters: rs id, cose encoding, default expiration time, psk, rpk
	 */
	protected PreparedStatement insertRS;

	/**
     * A prepared DELETE statement to remove a Resource Server
     * 
     * Parameter: rs id.
     */
	protected PreparedStatement deleteRS;
    
    /**
     * A prepared SELECT statement to get a set of RS for an audience
     * 
     * Parameter: audience name
     */
	protected PreparedStatement selectRS;

	/**
	 * A prepared SELECT statement to get all RSs
	 */
	protected PreparedStatement selectAllRS;

	/**
	 * A prepared INSERT statement to add a profile supported
	 * by a client or Resource Server
	 * 
	 * Parameters: id, profile name
	 */
	protected PreparedStatement insertProfile;
	
	/**
     * A prepared DELETE statement to remove the profiles supported
     * by a client or Resource Server
     * 
     * Parameter: id
     */
	protected PreparedStatement deleteProfiles;
	
    /**
     * A prepared SELECT statement to get all profiles for 
     * an audience and a client
     * 
     * Parameters: audience name, client id
     */
	protected PreparedStatement selectProfiles;
    
	/**
	 * A prepared SELECT statement to get the profiles
	 * for a single client or RS.	
	 */
	protected PreparedStatement selectProfile;
	
	/**
	 * A prepared INSERT statement to add the key types supported
     * by a client or Resource Server
     * 
     * Parameters: id, key type
	 */
	protected PreparedStatement insertKeyType;
	 
	/**
     * A prepared DELETE statement to remove the key types supported
     * by a client or Resource Server
     * 
     * Parameter: id
     */
	protected PreparedStatement deleteKeyTypes;
    
    /**
     * A prepared SELECT statement to get a set of key types
     * 
     * Parameters: audience name, client id
     */
	protected PreparedStatement selectKeyTypes;
	
	/**
     * A prepared INSERT statement to add the scopes supported
     * by a Resource Server
     * 
     * Parameters: rs id, scope name
     */
	protected PreparedStatement insertScope;
    
    /**
     * A prepared DELETE statement to remove the scopes supported
     * by a Resource Server
     * 
     * Parameter: rs id
     */
	protected PreparedStatement deleteScopes;
    
    /**
     * A prepared SELECT statement to get a set of Scopes for a specific audience
     * 
     * Parameter: audience id
     */
	protected PreparedStatement selectScopes;

	/**
	 * A prepared SELECT statement to get a set of Scopes for a specific RS
	 *
	 * Parameter: rs id
	 */
	protected PreparedStatement selectScopesForRS;

    /**
     * A prepared INSERT statement to add an audience a 
     * Resource Server identifies with
     * 
     * Parameter: rs id, audience name
     */
	protected PreparedStatement insertAudience;
	
    /**
     * A prepared DELETE statement to remove the audiences
     * a Resource Server identifies with
     * 
     * Parameter: rs id
     */
	protected PreparedStatement deleteAudiences;
	
	/**
     * A prepared SELECT statement to get a set of audiences for an RS
     * 
     * Parameter: rs id
     */
	protected PreparedStatement selectAudiences;
	
	/**
     * A prepared INSERT statement to add an audience a 
     * Resource Server acting as OSCORE Group Manager identifies with
     * 
     * Parameter: rs id, audience name
     */
	protected PreparedStatement insertOSCOREGroupManager;
	
    /**
     * A prepared DELETE statement to remove the audiences
     * a Resource Server acting as OSCORE Group Manager identifies with
     * 
     * Parameter: rs id
     */
	protected PreparedStatement deleteOSCOREGroupManagers;
	
    /**
     * A prepared SELECT statement to get a set of audiences
     * an RS acting as OSCORE Group Manager identifies with
     * 
     * Parameter: rs id
     */
	protected PreparedStatement selectOSCOREGroupManagers;
    
    /**
     * A prepared INSERT statement to add a token type a 
     * Resource Server supports
     * 
     * Parameters: rs id, token type
     */
	protected PreparedStatement insertTokenType;
    
    /**
     * A prepared DELETE statement to remove the token types a
     * a Resource Server supports
     * 
     * Parameter: rs id
     */
	protected PreparedStatement deleteTokenTypes;

    /**
     * A prepared SELECT statement to get a set of token types for an audience
     * 
     * Parameter: audience name
     */
	protected PreparedStatement selectTokenTypes;
    
	/**
	 * A prepared INSERT statement to add a new client
	 * 
	 * Parameters: client id, default audience, default scope, psk, rpk
	 */
	protected PreparedStatement insertClient;
	
	/**
	 * A prepared DELETE statement to remove a client
	 * 
	 * Parameter: client id
	 */
	protected PreparedStatement deleteClient;

	/**
	 * A prepared SELECT statement to get the default audience for a client.
	 * 
	 *  Parameter: client id
	 */
	protected PreparedStatement selectDefaultAudience;
	
	/**
     * A prepared SELECT statement to get the default scope for a client.
     * 
     *  Parameter: client id
     */
	protected PreparedStatement selectDefaultScope;

    
    /**
     * A prepared INSERT statement to add a new supported cose configuration
     * for protecting CWTs
     * 
     * Parameters: rs id, cose config
     */
	protected PreparedStatement insertCose;
    
    /**
     * A prepared DELETE statement to remove a cose configuration
     * 
     * Parameter: rs id
     */
	protected PreparedStatement deleteCose;
    
	/**
	 * A prepared SELECT statement to get the COSE configurations for
	 * an audience.
	 * 
	 * Parameter: audience name
	 */
	protected PreparedStatement selectCOSE;
	
	/**
     * A prepared SELECT statement to get the default expiration time for
     *     a RS
     *     
     * Parameter: audience name
     */
	protected PreparedStatement selectExpiration;
	
    /**
     * A prepared SELECT statement to get a pre-shared token-protection 
     * key for an audience
     *     
     * Parameter: audience name
     */
	protected PreparedStatement selectRsTokenPSK;
	
	/**
	 * A prepared SELECT statement to get the pre-shared authentication
	 * key for an RS
	 * 
	 * Parameter: RS name
	 * 
	 */
	protected PreparedStatement selectRsAuthPSK;
    
    /**
     * A prepared SELECT statement to get the public keys of an audience.
     * 
     * Parameter: audience name
     */
	protected PreparedStatement selectRsRPK;
    
    /**
     * A prepared SELECT statement to get a the pre-shared key for
     *     an client.
     * 
     * Parameter: client id
     */
	protected PreparedStatement selectCPSK;
    
    /**
     * A prepared SELECT statement to get the public key of a client.
     * 
     * Parameter: client id
     */
	protected PreparedStatement selectCRPK;
    
    /**
     * A prepared SELECT statement to fetch token ids and their
     * expiration time form the claims table.
     */
	protected PreparedStatement selectExpirationTime;
    
    /**
     * A prepared INSERT statement to add a claim of a token 
     * to the Claims table.
     * 
     * Parameters: token cti, claim name, claim value
     */
	protected PreparedStatement insertClaim;
    
    /**
     * A prepared DELETE statement to remove the claims of a token 
     * from the Claims table.
     * 
     * Parameters: token cti
     */
	protected PreparedStatement deleteClaims;
    
    /**
     * A prepared SELECT statement to select the claims of a token from
     * the Claims table.
     * 
     * Parameter: token cti
     */
	protected PreparedStatement selectClaims;
	
	/**
	 * A prepared INSERT statement to save a token's claims to the 
	 * InvalidTokens table.
	 */
	protected PreparedStatement logInvalidToken;	
    
    /**
     * A prepared SELECT statement to select the cti counter value from the 
     * cti counter table.
     */
	protected PreparedStatement selectCtiCtr;
    
    /**
     * A prepared UPDATE statement to update the saved cti counter value in the
     * cti counter table.
     */
	protected PreparedStatement updateCtiCtr;
    
    /**
     * A prepared SELECT statement to select the exi Sequence Number value
     * of a specific Resource Server from the RSs table.
     */
	protected PreparedStatement selectExiSn;
    
    /**
     * A prepared UPDATE statement to update the exi Sequence Number value
     * of a specific Resource Server in the RSs table.
     */
	protected PreparedStatement updateExiSn;
	
    /**
     * A prepared INSERT statement to insert a new token to client mapping.
     */
    protected PreparedStatement insertCti2Client;
    
    /**
     * A prepared SELECT statement to select the client identifier holding a
     * token identified by its cti.
     */
    protected PreparedStatement selectClientByCti;

	/**
	 * A prepared SELECT statement to select all registered clients.
	 */
	protected PreparedStatement selectAllClients;

    /**
     * A prepared SELECT statement to select the token identifiers (cti) 
     * held by a client
     */
    protected PreparedStatement selectCtisByClient;
    
    /**
     * A prepared SELECT statement to select the token identifier (cti) 
     * for an authorization grant
     */
    protected PreparedStatement selectCtisByGrant;
    
    /**
     * A prepared INSERT statement to add a new authorization grant to
     * access token cti mapping.
     */
    protected PreparedStatement insertGrant2Cti;
    
    /**
     * A prepared DELETE statement to remove the mapping of a grant
     * to an access token cti.
     */
    protected PreparedStatement deleteGrant2Cti;
    
    /**
     * A prepared UPDATE statement to mark an authorization grant
     * as used.
     */
    protected PreparedStatement updateGrant;

    /**
     * A prepared SELECT statement to select the RS information
     * for an authorization grant
     */
    protected PreparedStatement selectRsInfoByGrant;
    
    /**
     * A prepared INSERT statement to add the RS Information
     * for a given grant.
     */
    protected PreparedStatement insertGrant2RsInfo;
    
    /**
     * A prepared SELECT statement to check if a grant is marked invalid
     */
    protected PreparedStatement selectGrantValid;
    
    /**
     * The singleton instance of this connector
     */
    private static SQLConnector connector = null;
    
    /**
     * The DB adapter
     */
    private SQLDBAdapter adapter = null;

    /**
     * Gets the singleton instance of this connector.
     * 
     * @param dbAdapter an adapter already set up with the database information, specific for each engine.
     *
     * @return  the singleton instance
     * 
     * @throws SQLException
     */
    public static SQLConnector getInstance(SQLDBAdapter dbAdapter) throws SQLException {
        if (SQLConnector.connector == null) {
            SQLConnector.connector 
                = new SQLConnector(dbAdapter);
        }
        return SQLConnector.connector;
    }

	/**
	 * Create a new database connector either from given values or the 
	 * defaults.
	 *
     * @param dbAdapter handler for engine-db specific commands.
	 *
	 * @throws SQLException 
	 */
	protected SQLConnector(SQLDBAdapter dbAdapter) throws SQLException {
		this.adapter = dbAdapter;

		this.conn = dbAdapter.getDBConnection();
		SQLConnector.isConnected = true;
	        
		this.insertRS = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("INSERT INTO "
		                + DBConnector.rsTable + " VALUES (?,?,?,?,?,?);"));
		
		this.deleteRS = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("DELETE FROM "
		                + DBConnector.rsTable + " WHERE " 
		                + DBConnector.rsIdColumn + "=?;"));
		
		this.selectRS = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT "
		                + DBConnector.rsIdColumn
		                + " FROM "
		                + DBConnector.audiencesTable
		                + " WHERE " + DBConnector.audColumn + "=? ORDER BY "
		                + DBConnector.rsIdColumn + ";"));

		this.selectAllRS = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT "
		                + DBConnector.rsIdColumn
		                + " FROM "
		                + DBConnector.rsTable
		                + " ORDER BY "
		                + DBConnector.rsIdColumn + ";"));

		this.insertProfile = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("INSERT INTO "
		                + DBConnector.profilesTable
		                + " VALUES (?,?);"));
		
		this.deleteProfiles = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("DELETE FROM "
		                + DBConnector.profilesTable
		                + " WHERE " + DBConnector.idColumn + "=?;"));
		
		this.selectProfiles = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT * FROM "
		                + DBConnector.profilesTable
		                + " WHERE " + DBConnector.idColumn + " IN (SELECT " 
		                + DBConnector.rsIdColumn + " FROM " 
		                + DBConnector.audiencesTable
		                + " WHERE " + DBConnector.audColumn
		                + "=?) UNION SELECT * FROM " 
		                + DBConnector.profilesTable
		                + " WHERE " + DBConnector.idColumn + "=? ORDER BY "
		                + DBConnector.idColumn + ";"));
		
		this.selectProfile = this.conn.prepareStatement(
                dbAdapter.updateEngineSpecificSQL("SELECT * FROM "
                        + DBConnector.profilesTable
                        + " WHERE " + DBConnector.idColumn + "=?;"));

		this.insertKeyType = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("INSERT INTO "
		                + DBConnector.keyTypesTable
		                + " VALUES (?,?);"));

		this.deleteKeyTypes = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("DELETE FROM "
		                + DBConnector.keyTypesTable
		                + " WHERE " + DBConnector.idColumn + "=?;"));

		this.selectKeyTypes =  this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT * FROM "
		                + DBConnector.keyTypesTable
		                + " WHERE " + DBConnector.idColumn + " IN (SELECT " 
		                + DBConnector.rsIdColumn + " FROM " 
		                + DBConnector.audiencesTable
		                + " WHERE " + DBConnector.audColumn + "=?) ORDER BY "
		                + DBConnector.idColumn + ";"));

		this.insertScope = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("INSERT INTO "
		                + DBConnector.scopesTable
		                + " VALUES (?,?);"));

		this.deleteScopes = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("DELETE FROM "
		                + DBConnector.scopesTable
		                + " WHERE " + DBConnector.rsIdColumn + "=?;"));

		this.selectScopes = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT * FROM "
		                + DBConnector.scopesTable
		                + " WHERE " + DBConnector.rsIdColumn + " IN (SELECT " 
		                + DBConnector.rsIdColumn + " FROM " 
		                + DBConnector.audiencesTable
		                + " WHERE " + DBConnector.audColumn + "=?) ORDER BY "
		                + DBConnector.rsIdColumn + ";"));

		this.selectScopesForRS = this.conn.prepareStatement(
				dbAdapter.updateEngineSpecificSQL("SELECT * FROM "
						+ DBConnector.scopesTable
						+ " WHERE " + DBConnector.rsIdColumn + "=? ORDER BY "
						+ DBConnector.rsIdColumn + ";"));

		this.insertAudience = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("INSERT INTO "
		                + DBConnector.audiencesTable
		                + " VALUES (?,?);"));

		this.deleteAudiences = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("DELETE FROM "
		                + DBConnector.audiencesTable
		                + " WHERE " + DBConnector.rsIdColumn + "=?;"));
		
		this.selectAudiences = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT "
		                + DBConnector.audColumn + " FROM "
		                + DBConnector.audiencesTable
		                + " WHERE " + DBConnector.rsIdColumn + "=? ORDER BY "
		                + DBConnector.audColumn + ";"));

		this.insertOSCOREGroupManager = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("INSERT INTO "
		                + DBConnector.oscoreGroupManagersTable
		                + " VALUES (?,?);"));

		this.deleteOSCOREGroupManagers = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("DELETE FROM "
		                + DBConnector.oscoreGroupManagersTable
		                + " WHERE " + DBConnector.rsIdColumn + "=?;"));
		
		this.selectOSCOREGroupManagers = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT "
		                + DBConnector.audColumn + " FROM "
		                + DBConnector.oscoreGroupManagersTable
		                + " WHERE " + DBConnector.rsIdColumn + "=? ORDER BY "
		                + DBConnector.audColumn + ";"));		
		
		this.insertTokenType = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("INSERT INTO "
		                + DBConnector.tokenTypesTable
		                + " VALUES (?,?);"));

		this.deleteTokenTypes = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("DELETE FROM "
		                + DBConnector.tokenTypesTable
		                + " WHERE " + DBConnector.rsIdColumn + "=?;"));

		this.selectTokenTypes = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT * FROM "
		                + DBConnector.tokenTypesTable
		                + " WHERE " + DBConnector.rsIdColumn + " IN (SELECT " 
		                + DBConnector.rsIdColumn + " FROM " 
		                + DBConnector.audiencesTable
		                + " WHERE " + DBConnector.audColumn + "=?) ORDER BY "
		                + DBConnector.rsIdColumn + ";"));

		this.insertClient = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("INSERT INTO "
		                + DBConnector.cTable
		                + " VALUES (?,?,?,?,?);"));

		this.deleteClient = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("DELETE FROM "
		                + DBConnector.cTable
		                + " WHERE " + DBConnector.clientIdColumn + "=?;"));


		this.selectDefaultAudience = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT "
		                + DBConnector.defaultAud + " FROM " 
		                + DBConnector.cTable
		                + " WHERE " + DBConnector.clientIdColumn + "=?;"));

		this.selectDefaultScope = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT "
		                + DBConnector.defaultScope + " FROM " 
		                + DBConnector.cTable
		                + " WHERE " + DBConnector.clientIdColumn + "=?;"));

		this.insertCose = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("INSERT INTO "
		                + DBConnector.coseTable
		                + " VALUES (?,?);"));

		this.deleteCose = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("DELETE FROM "
		                + DBConnector.coseTable
		                + " WHERE " + DBConnector.rsIdColumn + "=?;"));

		this.selectCOSE = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT * "
		                + " FROM "  + DBConnector.coseTable
		                + " WHERE " + DBConnector.rsIdColumn + " IN (SELECT "
		                + DBConnector.rsIdColumn + " FROM " 
		                + DBConnector.audiencesTable
		                + " WHERE " + DBConnector.audColumn + "=?) ORDER BY "
		                + DBConnector.rsIdColumn + ";"));

		this.selectExpiration = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT "
		                + DBConnector.expColumn 
		                + " FROM "  + DBConnector.rsTable
		                + " WHERE " + DBConnector.rsIdColumn + "=?;"));

		this.selectRsTokenPSK = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT "
		                + DBConnector.tokenPskColumn
		                + " FROM "  + DBConnector.rsTable
		                + " WHERE " + DBConnector.rsIdColumn + " IN (SELECT "
		                + DBConnector.rsIdColumn + " FROM " 
		                + DBConnector.audiencesTable
		                + " WHERE " + DBConnector.audColumn + "=?);"));
		
		this.selectRsAuthPSK = this.conn.prepareStatement(
                dbAdapter.updateEngineSpecificSQL("SELECT "
                        + DBConnector.authPskColumn
                        + " FROM "  + DBConnector.rsTable
                        + " WHERE " + DBConnector.rsIdColumn + "=?;"));

		this.selectRsRPK = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT "
		                + DBConnector.rpkColumn
		                + " FROM "  + DBConnector.rsTable
		                + " WHERE " + DBConnector.rsIdColumn + " IN (SELECT "
		                + DBConnector.rsIdColumn + " FROM " 
		                + DBConnector.audiencesTable
		                + " WHERE " + DBConnector.audColumn + "=?);"));

		this.selectCPSK = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT "
		                + DBConnector.authPskColumn
		                + " FROM "  + DBConnector.cTable
		                + " WHERE " + DBConnector.clientIdColumn + "=?;"));

		this.selectCRPK = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT "
		                + DBConnector.rpkColumn
		                + " FROM "  + DBConnector.cTable
		                + " WHERE "  + DBConnector.clientIdColumn + "=?;"));

		this.selectExpirationTime = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT "
		                + DBConnector.ctiColumn + ","
		                + DBConnector.claimValueColumn
		                + " FROM "
		                + DBConnector.claimsTable
		                + " WHERE " + DBConnector.claimNameColumn + "=" 
		                + Constants.EXP + ";"));

		this.insertClaim = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("INSERT INTO "
		                + DBConnector.claimsTable
		                + " VALUES (?,?,?);"));

		this.deleteClaims = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("DELETE FROM "
		                + DBConnector.claimsTable
		                + " WHERE " + DBConnector.ctiColumn + "=?;"));

		this.selectClaims = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT "
		                + DBConnector.claimNameColumn + ","
		                + DBConnector.claimValueColumn + " FROM " 
		                + DBConnector.claimsTable
		                + " WHERE " + DBConnector.ctiColumn + "=?;"));

		this.logInvalidToken = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("INSERT INTO "
		                + DBConnector.oldTokensTable
		                + " SELECT * FROM " + DBConnector.claimsTable
		                + " WHERE " + DBConnector.ctiColumn + "=?;")); 

		this.selectCtiCtr = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT "
		                + DBConnector.ctiCounterColumn + " FROM "
		                + DBConnector.ctiCounterTable
		                + ";"));

		this.updateCtiCtr = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("UPDATE "
		                + DBConnector.ctiCounterTable
		                + " SET " + DBConnector.ctiCounterColumn + "=?;"));

		this.selectExiSn = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT "
		                + DBConnector.exiSeqNumColumn + " FROM " 
		                + DBConnector.rsTable
		                + " WHERE " + DBConnector.rsIdColumn + "=?;"));

		this.updateExiSn = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("UPDATE "
		                + DBConnector.rsTable
		                + " SET " + DBConnector.exiSeqNumColumn + "=?"
		                	    + " WHERE " + DBConnector.rsIdColumn
		                	    + "=?;"));
		
		this.insertCti2Client = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("INSERT INTO "
		                + DBConnector.cti2clientTable
		                + " VALUES (?,?);"));

		this.selectAllClients = this.conn.prepareStatement("SELECT "
		        + DBConnector.clientIdColumn + " FROM "
		        + DBConnector.cTable + ";");

		this.selectClientByCti = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT "
		                + DBConnector.clientIdColumn + " FROM "
		                + DBConnector.cti2clientTable
		                + " WHERE " + DBConnector.ctiColumn + "=?;"));   

		this.selectCtisByClient= this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("SELECT "
		                + DBConnector.ctiColumn + " FROM "
		                + DBConnector.cti2clientTable
		                + " WHERE " + DBConnector.clientIdColumn + "=?;"));  
		
		this.selectCtisByGrant = this.conn.prepareStatement(
                dbAdapter.updateEngineSpecificSQL("SELECT "
                        + DBConnector.ctiColumn + " FROM "
                        + DBConnector.grant2ctiTable
                        + " WHERE " + DBConnector.grantColumn + "=?;")); 

		this.insertGrant2Cti = this.conn.prepareStatement(
                dbAdapter.updateEngineSpecificSQL("INSERT INTO "
                        + DBConnector.grant2ctiTable
                        + " VALUES (?,?,?);"));
		
		this.deleteGrant2Cti = this.conn.prepareStatement(
                dbAdapter.updateEngineSpecificSQL("DELETE FROM "
                        + DBConnector.grant2ctiTable
                        + " WHERE " + DBConnector.grantColumn + "=?;"));
		
		this.updateGrant = this.conn.prepareStatement(
                dbAdapter.updateEngineSpecificSQL("UPDATE "
                        + DBConnector.grant2ctiTable
                        + " SET " + DBConnector.grantValidColumn + "=FALSE"
                                + " WHERE " + DBConnector.grantColumn 
                                + "=?;"));
		
		this.selectRsInfoByGrant = this.conn.prepareStatement(
                dbAdapter.updateEngineSpecificSQL("SELECT "
                        + DBConnector.claimNameColumn + ","
                        + DBConnector.claimValueColumn + " FROM " 
                        + DBConnector.grant2RSInfoTable
                        + " WHERE " + DBConnector.grantColumn + "=?;"));
		
		this.insertGrant2RsInfo = this.conn.prepareStatement(
		        dbAdapter.updateEngineSpecificSQL("INSERT INTO "
		                + DBConnector.grant2RSInfoTable
		                + " VALUES (?,?,?);"));
		
		this.selectGrantValid = this.conn.prepareStatement(
                dbAdapter.updateEngineSpecificSQL("SELECT "
                        + DBConnector.grantValidColumn + " FROM "
                        + DBConnector.grant2ctiTable
                        + " WHERE " + DBConnector.grantColumn + "=?;"));
                        
	}
	
	/**
	 * @return  the properties of the current database user
	 */
	public Properties getCurrentUserProperties() {
		Properties connectionProps = new Properties();
		connectionProps.put("user", this.currentUser);
		connectionProps.put("password", this.currentPassword);
		return connectionProps;
	}
	
	/**
	 * Set the current user properties
	 * @param user  the username of the new current user
	 * @param password  the password of the new current user
	 */
	public void setCurrentUser(String user, String password) {
	    this.currentUser = user;
	    this.currentPassword = password;
	}

	/**
	 * Create the necessary database and tables. Requires the
	 * admin user password.
	 * @param dbAdapter 
	 * 
	 * @param adminUser  the admin user name
	 * @param adminPwd  the admin user password
	 * @throws AceException
	 */
	public static void createDB(SQLDBAdapter dbAdapter, String adminUser, String adminPwd) throws AceException {
		if (adminPwd == null) {
			throw new AceException(
					"Cannot initialize the database without the password");
		}
        dbAdapter.createDBAndTables(adminUser, adminPwd);
	}

	/**
	 * Deletes the whole database.
	 * 
	 * CAUTION: This method really does what is says, without asking you again!
	 * It's main function is to clean the database during test runs.
	 * 
	 * @param dbAdapter handler for engine-db specific commands, containing DB name and owner data as well.
	 * @param adminUser  the admin user name
	 * @param adminPwd  the admin password
	 * @throws AceException
	 * @throws SQLException 
	 */
	public static void wipeDatabase(SQLDBAdapter dbAdapter, String adminUser, String adminPwd) throws AceException {
		if(SQLConnector.connector != null)
		{
			SQLConnector.connector.close();
		}
		dbAdapter.wipeDB(adminUser, adminPwd);
	}
	
	/**
	 * Close the connections. After this any other method calls to this
	 * object will lead to an exception.
	 * 
	 * @throws AceException
	 */
	@Override
	public synchronized void close() throws AceException {
	    if (SQLConnector.isConnected) {
			SQLConnector.isConnected = false;
	        try {
	            this.conn.close();
	            SQLConnector.connector = null;
	        } catch (SQLException e)
			{
				throw new AceException(e.getMessage());
			}
	    }
	}
	
	/**
	 * Returns a common value that the client supports (first param )
	 * and that every RS supports (every set in the map)
	 * 
	 * @param client  the set of values the client supports
	 * @param rss  the map of sets of values the rs support
	 * 
	 * @return  the common value or null if there isn't any
	 * @throws AceException 
	 */
	private static String getCommonValue(Set<String> client, 
	        Map<String,Set<String>> rss) throws AceException {
	    if (client == null || rss == null) {
	        throw new AceException(
	                "getCommonValue() requires non-null parameters");
	    }
	    for (String clientVal : client) {
            boolean isSupported = true;
            for (String rs : rss.keySet()) {
                if (!rss.get(rs).contains(clientVal)) {
                    isSupported = false;
                }
            }
            if (isSupported) {
                return clientVal;
            }
        }
        return null;
	}
	
    @Override
    public synchronized String getSupportedProfile(
            String clientId, Set<String> audience) throws AceException {
        if (clientId == null || audience == null) {
            throw new AceException(
                    "getSupportedProfile() requires non-null parameters");
        }
        Map<String, Set<String>> rsProfiles = new HashMap<>();
        Set<String> clientProfiles = new HashSet<>();
        for (String aud : audience) {
            try {
                this.selectProfiles.setString(1, aud);
                this.selectProfiles.setString(2, clientId);
                ResultSet result = this.selectProfiles.executeQuery();
                this.selectProfiles.clearParameters();

                while(result.next()) {
                    String id = result.getString(DBConnector.idColumn);
                    String profile = result.getString(
                            DBConnector.profileColumn);
                    if (id.equals(clientId)) {
                        clientProfiles.add(profile);
                    } else if (rsProfiles.containsKey(id)) {
                        Set<String> foo = rsProfiles.get(id);
                        foo.add(profile);
                        rsProfiles.put(id, foo);
                    } else {
                        Set<String> bar = new HashSet<>();
                        bar.add(profile);
                        rsProfiles.put(id, bar);
                    }
                }
                result.close();
            } catch (SQLException e) {
                throw new AceException(e.getMessage());
            }
        }
        return getCommonValue(clientProfiles, rsProfiles);
      
    }
    
    @Override
    public boolean hasDefaultProfile(String clientId) throws AceException {
        if (clientId == null ) {
            throw new AceException(
                    "hasDefaultProfile() requires non-null clientId");
        }
        try {
            this.selectProfile.setString(1, clientId);
            ResultSet result = this.selectProfile.executeQuery();
            this.selectProfile.clearParameters();
            int i = 0;
            while (result.next()) {
                i ++;
            }
            result.close();
            return (i==1 ? true:false);
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
    }
    
    @Override
    public synchronized Set<String> getSupportedPopKeyTypes(Set<String> aud) 
            throws AceException {
        if (aud == null) {
            throw new AceException(
                    "getSupportedPopKeyType() requires non-null parameter");
        }
        Map<String, Set<String>> rsKeyTypes = new HashMap<>();
    
        for (String audE : aud) {
            try {
                this.selectKeyTypes.setString(1, audE);
                ResultSet result = this.selectKeyTypes.executeQuery();
                this.selectKeyTypes.clearParameters();
                while(result.next()) {
                    String id = result.getString(DBConnector.idColumn);
                    String keyType = result.getString(
                            DBConnector.keyTypeColumn);
                    if (rsKeyTypes.containsKey(id)) {
                        Set<String> foo = rsKeyTypes.get(id);
                        foo.add(keyType);
                        rsKeyTypes.put(id, foo);
                    } else {
                        Set<String> bar = new HashSet<>();
                        bar.add(keyType);
                        rsKeyTypes.put(id, bar);
                    }
                }
                result.close();
            } catch (SQLException e) {
                throw new AceException(e.getMessage());
            }
        }
        Set<String> typeSet = null;
        for (Map.Entry<String, Set<String>> rs : rsKeyTypes.entrySet()) {
            if (typeSet == null) {
                typeSet = new HashSet<>();
                typeSet.addAll(rs.getValue());
            } else {
                Set<String> iterSet = new HashSet<>(typeSet);
                for (String keyType : iterSet) {
                    if (!rs.getValue().contains(keyType)) {
                        typeSet.remove(keyType);
                    }
                }
                if (typeSet.isEmpty()) {
                    return null;
                }
            }
        }
        return typeSet;
    }
    
    @Override
    public  synchronized Short getSupportedTokenType(Set<String> aud) 
            throws AceException {
        if (aud == null) {
            throw new AceException(
                    "getSupportedTokenType() requires non-null aud");
        }
        //Note: We store the token types as Strings in the DB
        Map<String, Set<String>> tokenTypes = new HashMap<>();
        for (String audE : aud) {
            try {
                this.selectTokenTypes.setString(1, audE);
                ResultSet result = this.selectTokenTypes.executeQuery();
                this.selectTokenTypes.clearParameters();
                while(result.next()) {
                    String id = result.getString(DBConnector.rsIdColumn);
                    String tokenType = result.getString(
                            DBConnector.tokenTypeColumn);
                    if (tokenTypes.containsKey(id)) {
                        Set<String> foo = tokenTypes.get(id);
                        foo.add(tokenType);
                        tokenTypes.put(id, foo);
                    } else {
                        Set<String> bar = new HashSet<>();
                        bar.add(tokenType);
                        tokenTypes.put(id, bar);
                    } 
                }
                result.close();
            } catch (SQLException e) {
                throw new AceException(e.getMessage());
            }
        }
        Set<String> refSet = null;
        for (Map.Entry<String, Set<String>> rs : tokenTypes.entrySet()) {
            if (refSet == null) {
                refSet = new HashSet<>();
                refSet.addAll(rs.getValue());
            } else {
                Set<String> iterSet = new HashSet<>(refSet);
                for (String tokenType : iterSet) {
                    if (!rs.getValue().contains(tokenType)) {
                        refSet.remove(tokenType);
                    }
                }
                if (refSet.isEmpty()) {
                    return null;
                }
            }
        }
        //Get the first remaining value
        if (refSet != null && !refSet.isEmpty()) {
            String tokenType = refSet.iterator().next();
            for (short i=0; i<AccessTokenFactory.ABBREV.length; i++) {
                if (tokenType.equals(AccessTokenFactory.ABBREV[i])) {
                    return i;
                }
            }
        } 
        //The audience was empty or didn't support any token types
        throw new AceException("No token types found for audience: " + aud);        
    }
    
    @Override
    public synchronized COSEparams getSupportedCoseParams(Set<String> aud) 
            throws AceException, CoseException {
        if (aud == null) {
            throw new AceException(
                    "getSupportedCoseParams() requires non-null aud");
        }
        Map<String, Set<String>> cose = new HashMap<>();
        for (String audE : aud) {
            try {
                this.selectCOSE.setString(1, audE);
                ResultSet result = this.selectCOSE.executeQuery();
                this.selectCOSE.clearParameters();
                while(result.next()) {
                    String id = result.getString(DBConnector.rsIdColumn);
                    String coseParam = result.getString(
                            DBConnector.coseColumn);
                    if (cose.containsKey(id)) {
                        Set<String> foo = cose.get(id);
                        foo.add(coseParam);
                        cose.put(id, foo);
                    } else {
                        Set<String> bar = new HashSet<>();
                        bar.add(coseParam);
                        cose.put(id, bar);
                    } 
                }
                result.close();
            } catch (SQLException e) {
                throw new AceException(e.getMessage());
            }
        }
        
        Set<String> refSet = null;
        for (Map.Entry<String, Set<String>> rs : cose.entrySet()) {
            if (refSet == null) {
                refSet = new HashSet<>();
                refSet.addAll(rs.getValue());
            } else {
                for (String tokenType : refSet) {
                    if (!rs.getValue().contains(tokenType)) {
                        refSet.remove(tokenType);
                    }
                }
                if (refSet.isEmpty()) {
                    return null;
                }
            }
        }
        
        //Get the first remaining value
        if (refSet != null && !refSet.isEmpty()) {
            String result = refSet.iterator().next();
            return COSEparams.parse(result);
        }
        
        //The audience was empty or didn't support any token types
        throw new AceException("No cose parameters found for audience: " + aud);                         
    }
    
    @Override
    public synchronized boolean isScopeSupported(String aud, String scope)
            throws AceException {
        if (scope == null || aud == null) {
            throw new AceException(
                    "isScopeSupported() requires non-null parameters");
        }
        Set<String> allRS = getRSS(aud);
        Set<String> supportingSope = new HashSet<>();
        try {
            this.selectScopes.setString(1, aud);
            ResultSet result = this.selectScopes.executeQuery();
            this.selectScopes.clearParameters();
            while (result.next()) {
                String scp = result.getString(DBConnector.scopeColumn);
                if (scp.equals(scope)) {
                    supportingSope.add(result.getString(DBConnector.rsIdColumn));
                }
            }
            result.close();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
        if (supportingSope.containsAll(allRS)) {
            return true;
        }
        return false;
    }
 
    @Override
    public synchronized String getDefaultScope(String clientId) 
            throws AceException {
        if (clientId == null) {
            throw new AceException(
                    "getDefaultScope() requires non-null clientId");
        }
        try {
            this.selectDefaultScope.setString(1, clientId);
            ResultSet result = this.selectDefaultScope.executeQuery();
            this.selectDefaultScope.clearParameters();
            if (result.next()) {
                String scope = result.getString(DBConnector.defaultScope);
                result.close();
                return scope;
            }
            result.close();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
        return null;
    }

    @Override
    public synchronized String getDefaultAudience(String clientId) 
            throws AceException {
        if (clientId == null) {
            throw new AceException(
                    "getDefaultAudience() requires non-null clientId");
        }
        try {
            this.selectDefaultAudience.setString(1, clientId);
            ResultSet result = this.selectDefaultAudience.executeQuery();
            this.selectDefaultAudience.clearParameters();
            if (result.next()) {
                String aud = result.getString(DBConnector.defaultAud);
                result.close();
                return aud;
            }
            result.close();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
        return null;
    }
    
    @Override
    public synchronized Set<String> getRSS(String aud) throws AceException {
        if (aud == null) {
            throw new AceException(
                    "getRSS() requires non-null aud");
        }
       Set<String> rss = new HashSet<>();
        try {
            this.selectRS.setString(1, aud);
            ResultSet result = this.selectRS.executeQuery();
            this.selectRS.clearParameters();
            while (result.next()) {
                rss.add(result.getString(DBConnector.rsIdColumn));
            }
            result.close();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
        if (rss.isEmpty()) {
            return Collections.emptySet();
        }
        return rss;
    }

	@Override
	public synchronized Set<String> getRSS() throws AceException {
		Set<String> rss = new HashSet<>();
		try {
			ResultSet result = this.selectAllRS.executeQuery();
			while (result.next()) {
				rss.add(result.getString(DBConnector.rsIdColumn));
			}
			result.close();
		} catch (SQLException e) {
			throw new AceException(e.getMessage());
		}
		if (rss.isEmpty()) {
			return null;
		}
		return rss;
	}
    
    @Override
    public synchronized long getExpTime(Set<String> aud) throws AceException {
        if (aud == null) {
            throw new AceException(
                    "getExpTime() requires non-null audience");
        }
        long smallest = Long.MAX_VALUE;
        
        for (String audE : aud) {
        	
        	Set<String> rsIds = getRSS(audE);
        	for (String myRS : rsIds) {
		            try {
		            	this.selectExpiration.setString(1, myRS);
		                ResultSet result = this.selectExpiration.executeQuery();
		                this.selectExpiration.clearParameters();
		                while (result.next()) {
		                    long val = result.getLong(DBConnector.expColumn);
		                    if (val < smallest) {
		                        smallest = val;
		                    }
		                }
		                result.close();
		            } catch (SQLException e) {
		                throw new AceException(e.getMessage());
		            }
        	}       
        }
        
        return smallest;
    }
    

    @Override
    public synchronized Set<String> getAudiences(String rsId) 
            throws AceException {
        if (rsId == null) {
            throw new AceException(
                    "getAudiences() requires non-null rsId");
        }
        Set<String> auds = new HashSet<>();
        try {
            this.selectAudiences.setString(1, rsId);
            ResultSet result = this.selectAudiences.executeQuery();
            this.selectAudiences.clearParameters();
            while (result.next()) {
                auds.add(result.getString(DBConnector.audColumn));      
            }
            result.close();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
        return auds;
    }

    @Override
    public synchronized Set<String> getOSCOREGroupManagers(String rsId) 
            throws AceException {
        if (rsId == null) {
            throw new AceException(
                    "getOSCOREGroupManagers() requires non-null rsId");
        }
        Set<String> auds = new HashSet<>();
        try {
            this.selectOSCOREGroupManagers.setString(1, rsId);
            ResultSet result = this.selectOSCOREGroupManagers.executeQuery();
            this.selectOSCOREGroupManagers.clearParameters();
            while (result.next()) {
                auds.add(result.getString(DBConnector.audColumn));      
            }
            result.close();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
        return auds;
    }
    
    @Override
    public synchronized Set<String> getScopes(String rsId) throws AceException
	{
		if (rsId == null) {
			throw new AceException(
					"getScopes() requires non-null rsId");
		}
		Set<String> scopes = new HashSet<>();
		try {
			this.selectScopesForRS.setString(1, rsId);
			ResultSet result = this.selectScopesForRS.executeQuery();
			this.selectScopesForRS.clearParameters();
			while (result.next()) {
				scopes.add(result.getString(DBConnector.scopeColumn));
			}
			result.close();
		} catch (SQLException e) {
			throw new AceException(e.getMessage());
		}
		return scopes;
	}

    @Override
    public synchronized OneKey getRsTokenPSK(String rsId) throws AceException {
        if (rsId == null) {
            throw new AceException(
                    "getRsPSK() requires non-null rsId");
        }
        try {
            this.selectRsTokenPSK.setString(1, rsId);
            ResultSet result = this.selectRsTokenPSK.executeQuery();
            this.selectRsTokenPSK.clearParameters();
            byte[] key = null;
            if (result.next()) {
                key = result.getBytes(DBConnector.tokenPskColumn);
            }
            result.close();
            if (key != null) {
                CBORObject cKey = CBORObject.DecodeFromBytes(key);
                return new OneKey(cKey);
            }
            return null;
        } catch (SQLException | CoseException e) {
            throw new AceException(e.getMessage());
        }
    }
    

    @Override
    public OneKey getRsAuthPSK(String rsId) throws AceException {
        if (rsId == null) {
            throw new AceException(
                    "getRsPSK() requires non-null rsId");
        }
        try {
            this.selectRsAuthPSK.setString(1, rsId);
            ResultSet result = this.selectRsAuthPSK.executeQuery();
            this.selectRsAuthPSK.clearParameters();
            byte[] key = null;
            if (result.next()) {
                key = result.getBytes(DBConnector.authPskColumn);
            }
            result.close();
            if (key != null) {
                CBORObject cKey = CBORObject.DecodeFromBytes(key);
                return new OneKey(cKey);
            }
            return null;
        } catch (SQLException | CoseException e) {
            throw new AceException(e.getMessage());
        }
    }

    @Override
    public synchronized OneKey getRsRPK(String rsId) throws AceException {
        if (rsId == null) {
            throw new AceException(
                    "getRsRPK() requires non-null rsId");
        }
        try {
            this.selectRsRPK.setString(1, rsId);
            ResultSet result = this.selectRsRPK.executeQuery();
            this.selectRsRPK.clearParameters();
            byte[] key = null;
            if (result.next()) {
                key = result.getBytes(DBConnector.rpkColumn);
            }
            result.close();
            if (key != null) {
                CBORObject cKey = CBORObject.DecodeFromBytes(key);
                return new OneKey(cKey);
            }
            return null;
        } catch (SQLException | CoseException e) {
            throw new AceException(e.getMessage());
        }
    }
    
    @Override
    public synchronized OneKey getCPSK(String clientId) throws AceException {
        if (clientId == null) {
            throw new AceException(
                    "getCPSK() requires non-null clientId");
        }
        try {
            this.selectCPSK.setString(1, clientId);
            ResultSet result = this.selectCPSK.executeQuery();
            this.selectCPSK.clearParameters();
            byte[] key = null;
            if (result.next()) {
                key = result.getBytes(DBConnector.authPskColumn);
            }
            result.close();
            if (key != null) {
                CBORObject cKey = CBORObject.DecodeFromBytes(key);
                return new OneKey(cKey);
            }
            return null;   
        } catch (SQLException | CoseException e) {
            throw new AceException(e.getMessage());
        }
    }

    @Override
    public synchronized OneKey getCRPK(String clientId) throws AceException {
        if (clientId == null) {
            throw new AceException(
                    "getCRPK() requires non-null clientId");
        }
        try {
            this.selectCRPK.setString(1, clientId);
            ResultSet result = this.selectCRPK.executeQuery();
            this.selectCRPK.clearParameters();
            byte[] key = null;
            if (result.next()) {
                key = result.getBytes(DBConnector.rpkColumn);
            }
            result.close();
            if (key != null) {
                CBORObject cKey = CBORObject.DecodeFromBytes(key);
                return new OneKey(cKey);
            }
            return null;
        } catch (SQLException | CoseException e) {
            throw new AceException(e.getMessage());
        }
    }

    @Override
    public synchronized void addRS(String rsId, Set<String> profiles, 
            Set<String> scopes, Set<String> auds, Set<String> keyTypes, 
            Set<Short> tokenTypes, Set<COSEparams> cose, long expiration, 
            OneKey authPsk, OneKey tokenPsk, OneKey publicKey)
                    throws AceException {
       
        if (rsId == null || rsId.isEmpty()) {
            throw new AceException("RS must have non-null, non-empty identifier");
        }
        
        if (tokenPsk == null && publicKey == null) {
            throw new AceException("Cannot register a RS without a key for"
                    +" protecting tokens");
        }
        
        if (profiles.isEmpty()) {
            throw new AceException("RS must support at least one profile");
        }
        
        if (tokenTypes.isEmpty()) {
            throw new AceException("RS must support at least one token type");
        }
        
        if (keyTypes.isEmpty()) {
            throw new AceException("RS must support at least one PoP key type");
        }
        
        if (expiration <= 0L) {
            throw new AceException("RS must have default expiration time > 0");
        }       
        
        // Prevent adding an rs that has an identifier that is equal to an 
        // existing audience
        try {
            this.selectRS.setString(1, rsId);
            ResultSet result = this.selectRS.executeQuery();
            this.selectRS.clearParameters();
            if (result.next()) {
                result.close();
                throw new AceException(
                        "RsId equal to existing audience id: " + rsId);
            }
            result.close();
           
            this.insertRS.setString(1, rsId);
            this.insertRS.setLong(2, expiration);
            if (tokenPsk != null) {
                this.insertRS.setBytes(3, tokenPsk.EncodeToBytes());
            } else {
                this.insertRS.setBytes(3, null);
            }
            
            if (authPsk != null) {
                this.insertRS.setBytes(4, authPsk.EncodeToBytes());
            } else {
                this.insertRS.setBytes(4, null);
            }

            if (publicKey != null) {
                this.insertRS.setBytes(5, publicKey.EncodeToBytes());
            } else {
                this.insertRS.setBytes(5, null);
            }
            
            // Initialize to 0 the sequence number to use when
            // issuing to this RS tokens with the 'exi' claim
            this.insertRS.setInt(6, 0);
            
            this.insertRS.execute();
            this.insertRS.clearParameters();
            
            for (String profile : profiles) {
                this.insertProfile.setString(1, rsId);
                this.insertProfile.setString(2, profile);
                this.insertProfile.execute();
            }
            this.insertProfile.clearParameters();
            
            for (String scope : scopes) {
                this.insertScope.setString(1, rsId);
                this.insertScope.setString(2, scope);
                this.insertScope.execute();
            }
            this.insertScope.clearParameters();
            
            for (String aud : auds) {
                this.insertAudience.setString(1, rsId);
                this.insertAudience.setString(2, aud);
                this.insertAudience.execute();
            }
            this.insertAudience.clearParameters();
            
            //The RS always recognizes itself as a singleton audience
            this.insertAudience.setString(1, rsId);
            this.insertAudience.setString(2, rsId);
            this.insertAudience.execute();
            this.insertAudience.clearParameters();
            
            for (String keyType : keyTypes) {
                this.insertKeyType.setString(1, rsId);
                this.insertKeyType.setString(2, keyType);
                this.insertKeyType.execute();
            }
            this.insertKeyType.clearParameters();
            
            for (short tokenType : tokenTypes) {
                this.insertTokenType.setString(1, rsId);
                this.insertTokenType.setString(2, 
                        AccessTokenFactory.ABBREV[tokenType]);
                this.insertTokenType.execute();
            }
            this.insertTokenType.clearParameters();
            
            for (COSEparams coseP : cose) {
                this.insertCose.setString(1, rsId);
                this.insertCose.setString(2, coseP.toString());
                this.insertCose.execute();
            }
            this.insertCose.clearParameters();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
    }
    
    @Override
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
                this.insertOSCOREGroupManager.setString(1, rsId);
                this.insertOSCOREGroupManager.setString(2, aud);
                this.insertOSCOREGroupManager.execute();
            }
            this.insertAudience.clearParameters();
            
            //The RS always recognizes itself as a singleton audience
            this.insertOSCOREGroupManager.setString(1, rsId);
            this.insertOSCOREGroupManager.setString(2, rsId);
            this.insertOSCOREGroupManager.execute();
            this.insertOSCOREGroupManager.clearParameters();
        	
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
    	
    }

    @Override
    public synchronized void deleteRS(String rsId) throws AceException {
        if (rsId == null) {
            throw new AceException("deleteRS() requires non-null rsId");
        }
        try {
            this.deleteRS.setString(1, rsId);
            this.deleteRS.execute();
            this.deleteRS.clearParameters();

            this.deleteProfiles.setString(1, rsId);
            this.deleteProfiles.execute();
            this.deleteProfiles.clearParameters();

            this.deleteScopes.setString(1, rsId);
            this.deleteScopes.execute();
            this.deleteScopes.clearParameters();

            this.deleteAudiences.setString(1, rsId);
            this.deleteAudiences.execute();
            this.deleteAudiences.clearParameters();

            this.deleteOSCOREGroupManagers.setString(1,  rsId);
            this.deleteOSCOREGroupManagers.execute();
            this.deleteOSCOREGroupManagers.clearParameters();
            
            this.deleteKeyTypes.setString(1, rsId);
            this.deleteKeyTypes.execute();
            this.deleteKeyTypes.clearParameters();

            this.deleteTokenTypes.setString(1, rsId);
            this.deleteTokenTypes.execute();
            this.deleteTokenTypes.clearParameters();    

            this.deleteCose.setString(1, rsId);
            this.deleteCose.execute();
            this.deleteCose.clearParameters();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
    }

    @Override
    public synchronized void addClient(String clientId, Set<String> profiles,
            String defaultScope, String defaultAud, Set<String> keyTypes,
            OneKey sharedKey, OneKey publicKey) 
                    throws AceException {   
        if (clientId == null || clientId.isEmpty()) {
            throw new AceException(
                    "Client must have non-null, non-empty identifier");
        }
        
        if (profiles == null || profiles.isEmpty()) {
            throw new AceException("Client must support at least one profile");
        }
        
        if (keyTypes.isEmpty()) {
            throw new AceException(
                    "Client must support at least one PoP key type");
        }
        
        if (sharedKey == null && publicKey == null) {
            throw new AceException("Cannot register a client without a key");
        }

        try {
            this.insertClient.setString(1, clientId);
            this.insertClient.setString(2, defaultAud);
            this.insertClient.setString(3, defaultScope);
            if (sharedKey != null) {
                this.insertClient.setBytes(4, sharedKey.EncodeToBytes());
            } else {
                this.insertClient.setBytes(4, null);
            }
            if (publicKey != null) {
                this.insertClient.setBytes(5, publicKey.EncodeToBytes());
            } else {
                this.insertClient.setBytes(5, null);
            }
            this.insertClient.execute();
            this.insertClient.clearParameters();

            for (String profile : profiles) {
                this.insertProfile.setString(1, clientId);
                this.insertProfile.setString(2, profile);
                this.insertProfile.execute();
            }
            this.insertProfile.clearParameters();

            for (String keyType : keyTypes) {
                this.insertKeyType.setString(1, clientId);
                this.insertKeyType.setString(2, keyType);
                this.insertKeyType.execute();
            }
            this.insertKeyType.clearParameters();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
    }

    @Override
    public synchronized void deleteClient(String clientId) throws AceException {
        if (clientId == null) {
            throw new AceException(
                    "deleteClient() requires non-null clientId");
        }
        try {
            this.deleteClient.setString(1, clientId);
            this.deleteClient.execute();
            this.deleteClient.clearParameters();

            this.deleteProfiles.setString(1, clientId);
            this.deleteProfiles.execute();
            this.deleteProfiles.clearParameters();

            this.deleteKeyTypes.setString(1, clientId);
            this.deleteKeyTypes.execute();
            this.deleteKeyTypes.clearParameters(); 
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }   
    }
    
    @Override
    public synchronized void addToken(String cti, 
            Map<Short, CBORObject> claims) throws AceException {
        if (cti == null || cti.isEmpty()) {
            throw new AceException(
                    "addToken() requires non-null, non-empty cti");
        }
        if (claims == null || claims.isEmpty()) {
            throw new AceException(
                    "addToken() requires at least one claim");
        }
        try {
            for (Map.Entry<Short, CBORObject> claim : claims.entrySet()) {
                this.insertClaim.setString(1, cti);
                this.insertClaim.setShort(2, claim.getKey());
                this.insertClaim.setBytes(3, claim.getValue().EncodeToBytes());
                this.insertClaim.execute();
            }
            this.insertClaim.clearParameters();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }       
    }

    @Override
    public synchronized void deleteToken(String cti) throws AceException {
        if (cti == null) {
            throw new AceException("deleteToken() requires non-null cti");
        }
        try {
            this.logInvalidToken.setString(1, cti);
            this.logInvalidToken.execute();
            this.logInvalidToken.clearParameters();
            this.deleteClaims.setString(1, cti);
            this.deleteClaims.execute();
            this.deleteClaims.clearParameters();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }   
    }

    @Override
    public synchronized void purgeExpiredTokens(long now) throws AceException {
        try {
            ResultSet result = this.selectExpirationTime.executeQuery();
            while (result.next()) {
                byte[] rawTime = result.getBytes(DBConnector.claimValueColumn);
                CBORObject cborTime = CBORObject.DecodeFromBytes(rawTime);
                long time = cborTime.AsNumber().ToInt64Checked();
                if (now > time) {
                    deleteToken(result.getString(DBConnector.ctiColumn));
                }
            }
            result.close();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        } 
    }

    @Override
    public synchronized Map<Short, CBORObject> getClaims(String cti) 
            throws AceException {
        if (cti == null) {
            throw new AceException("getClaims() requires non-null cti");
        }
        Map<Short, CBORObject> claims = new HashMap<>();
        try {
            this.selectClaims.setString(1, cti);
            ResultSet result = this.selectClaims.executeQuery();
            this.selectClaims.clearParameters();
            while (result.next()) {
                Short claimName 
                    = result.getShort(DBConnector.claimNameColumn);
                CBORObject cbor = CBORObject.DecodeFromBytes(
                        result.getBytes(DBConnector.claimValueColumn));
                claims.put(claimName, cbor);
            }
            result.close();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        } 
        return claims;
    }

    @Override
    public synchronized Long getCtiCounter() throws AceException {
        Long l = -1L;
        try {
            ResultSet result = this.selectCtiCtr.executeQuery();
            if (result.next()) {
                l = result.getLong(DBConnector.ctiCounterColumn);
            }
            result.close();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
        return l;
    }

    @Override
    public synchronized void saveCtiCounter(Long cti) throws AceException {
        try {
            this.updateCtiCtr.setLong(1, cti);
            this.updateCtiCtr.execute();
            this.updateCtiCtr.clearParameters();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }    
    }
    
    @Override
    public synchronized int getExiSequenceNumber(String rsId) throws AceException {
        int sn = -1;
        try {
        	this.selectExiSn.setString(1, rsId);
            ResultSet result = this.selectExiSn.executeQuery();
            if (result.next()) {
                sn = result.getInt(DBConnector.exiSeqNumColumn);
            }
            result.close();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
        return sn;
    }
    
    @Override
    public synchronized void saveExiSequenceNumber(int sn, String rsId) throws AceException {
        try {
            this.updateExiSn.setInt(1, sn);
            this.updateExiSn.setString(2, rsId);
            this.updateExiSn.execute();
            this.updateExiSn.clearParameters();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }    
    }
    
    /**
     * Creates the user that manages this database.
     *
	 * @param dbAdapter an adapter instance for the specific DB type being used.
     * @param adminUser  the database admin user name
     * @param adminPwd  the database admin password
     *
     * @throws AceException 
     */
    public synchronized static void createUser(SQLDBAdapter dbAdapter, String adminUser, String adminPwd) throws AceException {
		dbAdapter.createUser(adminUser, adminPwd);
    }
    
    @Override
    public synchronized void addCti2Client(String cti, String clientId) 
            throws AceException {
        if (cti == null || clientId == null) {
            throw new AceException(
                    "addCti2Client() requires non-null parameters");
        }
        try {
            this.insertCti2Client.setString(1, cti);
            this.insertCti2Client.setString(2, clientId);
            this.insertCti2Client.execute();
            this.insertCti2Client.clearParameters();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
    }

	@Override
	public synchronized Set<String> getClients() throws AceException {
		Set<String> clients = new HashSet<>();
		try {
			ResultSet result = this.selectAllClients.executeQuery();
			while (result.next()) {
				clients.add(result.getString(DBConnector.clientIdColumn));
			}
			result.close();
		} catch (SQLException e) {
			throw new AceException(e.getMessage());
		}
		return clients;
	}

    @Override
    public synchronized String getClient4Cti(String cti) throws AceException {
        if (cti == null) {
            throw new AceException("getClient4Cti() requires non-null cti");
        }
        try {
            this.selectClientByCti.setString(1, cti);
            ResultSet result = this.selectClientByCti.executeQuery();
            this.selectClientByCti.clearParameters();
            if (result.next()) {
                String clientId = result.getString(DBConnector.clientIdColumn);
                result.close();
                return clientId;
            }
            result.close();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
        return null;
    }


    @Override
    public synchronized Set<String> getCtis4Client(String clientId)
            throws AceException {
        if (clientId == null) {
            throw new AceException(
                    "getCtis4Client() requires non-null clientId");
        }
        Set<String> ctis = new HashSet<>();
        try {
            this.selectCtisByClient.setString(1, clientId);
            ResultSet result = this.selectCtisByClient.executeQuery();
            this.selectCtisByClient.clearParameters();
            while (result.next()) {
                ctis.add(result.getString(DBConnector.ctiColumn));      
            }
            result.close();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
        return ctis;
    }

    @Override
    public String getCti4Grant(String code) throws AceException {
        if (code == null) {
            throw new AceException(
                    "getCti4Grant() requires non-null code");
        }
        String cti = null;
        try {
            this.selectCtisByGrant.setString(1, code);
            ResultSet result = this.selectCtisByGrant.executeQuery();
            this.selectCtisByGrant.clearParameters();
            while (result.next()) {
                cti = (result.getString(DBConnector.ctiColumn));      
            }
            result.close();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
        return cti;
    }

    @Override
    public void addGrant(String code, String cti, Map<Short, CBORObject> claims,
            Map<Short, CBORObject> rsInfo) throws AceException {
        if (code == null) {
            throw new AceException(
                    "getaddGrant() requires non-null code");
        }
        if (cti == null) {
            throw new AceException(
                    "getaddGrant() requires non-null cti");
        }
        if (claims == null || claims.isEmpty()) {
            throw new AceException(
                    "getaddGrant() requires non-null and non-empty"
                    + " claims");
        }
        if (rsInfo == null || rsInfo.isEmpty()) {
            throw new AceException(
                    "getaddGrant() requires non-null and non-empty"
                    + " rsInfo");
        }
        
        addToken(cti, claims);
        
        try {
            this.insertGrant2Cti.setString(1, code);
            this.insertGrant2Cti.setString(2, cti);
            this.insertGrant2Cti.setBoolean(3, true);
            this.insertGrant2Cti.execute();
            this.insertGrant2Cti.clearParameters();
        } catch (SQLException e) {
            deleteToken(cti);
            throw new AceException(e.getMessage());
        }   

        try {
            this.insertGrant2RsInfo.setString(1, code);  
            for (Map.Entry<Short, CBORObject> rsEntry : rsInfo.entrySet()) {  
                this.insertGrant2RsInfo.setShort(2, rsEntry.getKey());
                this.insertGrant2RsInfo.setBytes(3, rsEntry.getValue().EncodeToBytes());
                this.insertGrant2RsInfo.execute();
            }
            this.insertGrant2RsInfo.clearParameters();        
        } catch (SQLException e) {
            deleteToken(cti);
            try {
                this.deleteGrant2Cti.setString(1, code);
                this.deleteGrant2Cti.execute();
                this.deleteGrant2Cti.clearParameters();
            } catch (SQLException e2) {
                throw new AceException("Error while tyring to roll-back an "
                        + "addGrant(): " + e2.getMessage());
            }
            throw new AceException(e.getMessage());
        }     
    }

    @Override
    public void useGrant(String code) throws AceException {
        if (code == null) {
            throw new AceException(
                    "useGrant() requires non-null code");
        }
        try {
            this.updateGrant.setString(1, code);
            this.updateGrant.execute();
            this.updateGrant.clearParameters();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
    }

    @Override
    public Map<Short, CBORObject> getRsInfo(String code) throws AceException {
        if (code == null) {
            throw new AceException(
                    "getRsInfo() requires non-null code");
        }
        Map<Short, CBORObject> rsInfo = new HashMap<>();
        try {
            this.selectRsInfoByGrant.setString(1, code);
            ResultSet result = this.selectRsInfoByGrant.executeQuery();
            this.selectRsInfoByGrant.clearParameters();
            while (result.next()) {
                    Short claimName 
                        = result.getShort(DBConnector.claimNameColumn);
                    CBORObject cbor = CBORObject.DecodeFromBytes(
                            result.getBytes(DBConnector.claimValueColumn));
                    rsInfo.put(claimName, cbor);
            }
            result.close(); 
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
        return rsInfo;
    }


    @Override
    public boolean isGrantValid(String code) throws AceException {
        if (code == null) {
            throw new AceException(
                    "getRsInfo() requires non-null code");
        }
        boolean valid = false;
        try {
            this.selectGrantValid.setString(1, code);
            ResultSet result = this.selectGrantValid.executeQuery();
            this.selectGrantValid.clearParameters();
            if (result.next()) {
                valid = result.getBoolean(DBConnector.grantValidColumn);
            } else {
                valid = false;
            }                  
            result.close();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
        return valid;
    }
    
    /**
     * Extensibility method to allow other modules to prepare statements.
     * 
     * @param statement  the statement string
     * 
     * @return the prepared statement
     * @throws AceException 
     * 
     */
    public PreparedStatement prepareStatement(String statement) throws AceException {
        PreparedStatement stmt = null;
        try {
            stmt = this.conn.prepareStatement(
                    this.adapter.updateEngineSpecificSQL(statement));
        } catch (SQLException e) {
           throw new AceException(e.getMessage());
        }
        return stmt;
        
    }
    
    /**
     * Get the SQL database adapter.  This method is for external modules 
     * that need access to the database.
     * 
     * @return  the SQL database adapter
     */
    public SQLDBAdapter getAdapter() {
        return this.adapter;
        
    }
}
