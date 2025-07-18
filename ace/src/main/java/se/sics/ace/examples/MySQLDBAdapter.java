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
package se.sics.ace.examples;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;

import se.sics.ace.AceException;
import se.sics.ace.as.DBConnector;

/**
 * This class handles proper MySQL Db SQL.
 *
 * @author Sebastian Echeverria and Marco Tiloca
 *
 */
public class MySQLDBAdapter implements SQLDBAdapter {
    
    /**
     * The default admin-user name
     */

    /**
     * The default connection URL for the database.
     */
    public static final String DEFAULT_DB_URL = "jdbc:mysql://localhost:3306";

    protected String user;
    protected String password;
    protected String dbUrl;
    protected String dbName;

    @Override
    public void setParams(String user, String pwd, String dbName, String dbUrl) {
        this.user = user;
        if(this.user == null)
        {
            this.user = DBConnector.DEFAULT_USER;
        }
        this.password = pwd;
        if(this.password == null)
        {
            this.password = DBConnector.DEFAULT_PASSWORD;
        }
        this.dbName = dbName;
        if(this.dbName == null)
        {
            this.dbName = DBConnector.DEFAULT_DB_NAME;
        }
        this.dbUrl = dbUrl;
        if(this.dbUrl == null)
        {
            this.dbUrl = DEFAULT_DB_URL;
        }
    }

    @Override
    public Connection getAdminConnection(String adminUser, String adminPwd) throws SQLException {
        Properties connectionProps = new Properties();
        connectionProps.put("user", adminUser);
        connectionProps.put("password", adminPwd);
        return DriverManager.getConnection(this.dbUrl + "/?useSSL=FALSE&allowPublicKeyRetrieval=true", connectionProps);
    }

    @Override
    public Connection getDBConnection() throws SQLException {
        Properties connectionProps = new Properties();
        connectionProps.put("user", this.user);
        connectionProps.put("password", this.password);
        return DriverManager.getConnection(this.dbUrl + "/" 
                + this.dbName + "?useSSL=FALSE&allowPublicKeyRetrieval=true", connectionProps);
    }

    @Override
    public synchronized void createUser(String adminUser, String adminPwd) throws AceException {
        String cUser = "CREATE USER IF NOT EXISTS'" + this.user
                + "'@'localhost' IDENTIFIED BY '" + this.password
                + "';";
        String authzUser = "GRANT DELETE, INSERT, SELECT, UPDATE, CREATE ON "
                + this.dbName + ".* TO '" + this.user + "'@'localhost';";

        try (Connection adminConn = getAdminConnection(adminUser, adminPwd);
             Statement stmt = adminConn.createStatement()) {
            stmt.execute(cUser);
            stmt.execute(authzUser);
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
    }

    @Override
    public synchronized void createDBAndTables(String adminUser, String adminPwd) throws AceException {

        String createDB = "CREATE DATABASE IF NOT EXISTS " + this.dbName
                + " CHARACTER SET utf8 COLLATE utf8_bin;";

        //rs id, cose encoding, default expiration time, psk, rpk
        String createRs = "CREATE TABLE IF NOT EXISTS " + this.dbName
                + "." + DBConnector.rsTable + "("
                + DBConnector.rsIdColumn + " varchar(255) NOT NULL, "
                + DBConnector.expColumn + " bigint NOT NULL, "
                + DBConnector.tokenPskColumn + " varbinary(64), "
                + DBConnector.authPskColumn + " varbinary(64), "
                + DBConnector.rpkColumn + " varbinary(255), "
                + DBConnector.exiSeqNumColumn + " int NOT NULL,"
                + " PRIMARY KEY (" + DBConnector.rsIdColumn + "));";

        String createC = "CREATE TABLE IF NOT EXISTS " + this.dbName
                + "." + DBConnector.cTable + " ("
                + DBConnector.clientIdColumn + " varchar(255) NOT NULL, "
                + DBConnector.defaultAud + " varchar(255), "
                + DBConnector.defaultScope + " varchar(255), "
                + DBConnector.authPskColumn + " varbinary(64), "
                + DBConnector.rpkColumn + " varbinary(255),"
                + " PRIMARY KEY (" + DBConnector.clientIdColumn + "));";

        String createProfiles = "CREATE TABLE IF NOT EXISTS "
                + this.dbName + "."
                + DBConnector.profilesTable + "("
                + DBConnector.idColumn + " varchar(255) NOT NULL, "
                + DBConnector.profileColumn + " varchar(255) NOT NULL);";

        String createKeyTypes = "CREATE TABLE IF NOT EXISTS "
                + this.dbName + "."
                + DBConnector.keyTypesTable + "("
                + DBConnector.idColumn + " varchar(255) NOT NULL, "
                + DBConnector.keyTypeColumn + " enum('PSK', 'RPK', 'TST'));";

        String createScopes = "CREATE TABLE IF NOT EXISTS "
                + this.dbName + "."
                + DBConnector.scopesTable + "("
                + DBConnector.rsIdColumn + " varchar(255) NOT NULL, "
                + DBConnector.scopeColumn + " varchar(255) NOT NULL);";

        String createTokenTypes = "CREATE TABLE IF NOT EXISTS "
                + this.dbName + "."
                + DBConnector.tokenTypesTable + "("
                + DBConnector.rsIdColumn + " varchar(255) NOT NULL, "
                + DBConnector.tokenTypeColumn + " enum('CWT', 'REF', 'TST'));";

        String createAudiences = "CREATE TABLE IF NOT EXISTS "
                + this.dbName + "."
                + DBConnector.audiencesTable + "("
                + DBConnector.rsIdColumn + " varchar(255) NOT NULL, "
                + DBConnector.audColumn + " varchar(255) NOT NULL);";

        String createOSCOREGroupManagers = "CREATE TABLE IF NOT EXISTS "
        		+ this.dbName + "."
        		+ DBConnector.oscoreGroupManagersTable + "("
        		+ DBConnector.rsIdColumn + " varchar(255) NOT NULL, "
                + DBConnector.audColumn + " varchar(255) NOT NULL);";
        
        String createCose =  "CREATE TABLE IF NOT EXISTS "
                + this.dbName + "."
                + DBConnector.coseTable + "("
                + DBConnector.rsIdColumn + " varchar(255) NOT NULL, "
                + DBConnector.coseColumn + " varchar(255) NOT NULL);";

        String createClaims = "CREATE TABLE IF NOT EXISTS "
                + this.dbName + "."
                + DBConnector.claimsTable + "("
                + DBConnector.ctiColumn + " varchar(255) NOT NULL, "
                + DBConnector.claimNameColumn + " SMALLINT NOT NULL,"
                + DBConnector.claimValueColumn + " varbinary(255));";

        String createOldTokens = "CREATE TABLE IF NOT EXISTS "
                + this.dbName + "."
                + DBConnector.oldTokensTable + "("
                + DBConnector.ctiColumn + " varchar(255) NOT NULL, "
                + DBConnector.claimNameColumn + " SMALLINT NOT NULL,"
                + DBConnector.claimValueColumn + " varbinary(255));";
        
        String createCtiCtr = "CREATE TABLE IF NOT EXISTS "
                + this.dbName + "."
                + DBConnector.ctiCounterTable + "("
                + DBConnector.ctiCounterColumn + " int unsigned);";

        String initCtiCtr = "INSERT INTO "
                + this.dbName + "." 
                + DBConnector.ctiCounterTable
                + " VALUES (0);";

        String createTokenLog = "CREATE TABLE IF NOT EXISTS "
                + this.dbName + "."
                + DBConnector.cti2clientTable + "("
                + DBConnector.ctiColumn + " varchar(255) NOT NULL, "
                + DBConnector.clientIdColumn + " varchar(255) NOT NULL,"
                + " PRIMARY KEY (" + DBConnector.ctiColumn + "));";
        
        String createGrant2Cti = "CREATE TABLE IF NOT EXISTS "
                + this.dbName + "."
                + DBConnector.grant2ctiTable + "("
                + DBConnector.grantColumn + " varchar(255) NOT NULL, "
                + DBConnector.ctiColumn + " varchar(255) NOT NULL, "
                + DBConnector.grantValidColumn + " BOOLEAN DEFAULT TRUE, "
                + " PRIMARY KEY (" + DBConnector.grantColumn + ","
                + DBConnector.ctiColumn + "));";
        
        String createGrant2RSInfo = "CREATE TABLE IF NOT EXISTS "
                + this.dbName + "."
                + DBConnector.grant2RSInfoTable + "("
                + DBConnector.grantColumn + " varchar(255) NOT NULL, "
                + DBConnector.claimNameColumn + " SMALLINT NOT NULL,"
                + DBConnector.claimValueColumn + " varbinary(255));";


        try (Connection adminConn = getAdminConnection(adminUser, adminPwd);
             Statement stmt = adminConn.createStatement()) {
            stmt.execute(createDB);
            stmt.execute(createRs);
            stmt.execute(createC);
            stmt.execute(createProfiles);
            stmt.execute(createKeyTypes);
            stmt.execute(createScopes);
            stmt.execute(createTokenTypes);
            stmt.execute(createAudiences);
            stmt.execute(createOSCOREGroupManagers);
            stmt.execute(createCose);
            stmt.execute(createClaims);
            stmt.execute(createOldTokens);
            stmt.execute(createCtiCtr);
            stmt.execute(initCtiCtr);
            stmt.execute(createTokenLog);
            stmt.execute(createGrant2Cti);
            stmt.execute(createGrant2RSInfo);
            adminConn.close();
            stmt.close();
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
    }

    @Override
    public String updateEngineSpecificSQL(String sqlQuery)
    {
        // Nothing to do here, as the default SQL statements in is compatible with MySQL.
        return sqlQuery;
    }

    @Override
    public void wipeDB(String adminUser, String adminPwd) throws AceException
    {
        try (Connection adminConn = getAdminConnection(adminUser, adminPwd);
             Statement stmt = adminConn.createStatement())
        {
            String dropDB = "DROP DATABASE IF EXISTS " + this.dbName + ";";
            String dropUser = "DROP USER IF EXISTS '" + this.user 
                    + "'@'localhost';";
            stmt.execute(dropDB);
            stmt.execute(dropUser);
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
    }
}