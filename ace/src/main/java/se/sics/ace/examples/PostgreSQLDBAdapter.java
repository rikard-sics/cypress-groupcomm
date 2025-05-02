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

import se.sics.ace.AceException;
import se.sics.ace.as.DBConnector;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.ResultSet;
import java.util.Properties;

/**
 * This class handles proper PostgreSQL Db SQL.
 *
 * @author Sebastian Echeverria
 *
 */
public class PostgreSQLDBAdapter implements SQLDBAdapter {

    /**
     * The default admin-user name
     */
    
    /**
     * The default database name
     */
    public static final String BASE_DB = "postgres";

    /**
     * The default connection URL for the database.
     */
    public static final String DEFAULT_DB_URL 
        = "jdbc:postgresql://localhost:5432";

    protected String user;
    protected String password;
    protected String baseDbUrl;
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
        this.baseDbUrl = dbUrl;
        if(this.baseDbUrl == null)
        {
            this.baseDbUrl = DEFAULT_DB_URL;
        }
    }

    @Override
    public Connection getAdminConnection(String adminUser, String adminPwd) throws SQLException {
        Properties connectionProps = new Properties();
        connectionProps.put("user", adminUser);
        connectionProps.put("password", adminPwd);
        return DriverManager.getConnection(this.baseDbUrl + "/" 
                + PostgreSQLDBAdapter.BASE_DB, connectionProps);
    }

    @Override
    public Connection getDBConnection() throws SQLException {
        Properties connectionProps = new Properties();
        connectionProps.put("user", this.user);
        connectionProps.put("password", this.password);
        return DriverManager.getConnection(this.baseDbUrl + "/" + this.dbName, connectionProps);
    }

    @Override
    public synchronized void createUser(String adminUser, String adminPwd) throws AceException {
        String createUser = "DO\n" +
                "$body$\n" +
                "BEGIN\n" +
                "   IF NOT EXISTS (\n" +
                "      SELECT *\n" +
                "      FROM   pg_catalog.pg_user\n" +
                "      WHERE  usename = '" +  this.user + "') THEN\n" +
                "\n" +
                "      CREATE ROLE " +  this.user + " LOGIN PASSWORD '" 
                    +  this.password + "';\n" +
                "   END IF;\n" +
                "END\n" +
                "$body$;";

        try (Connection adminConn = getAdminConnection(adminUser, adminPwd);
             Statement stmt = adminConn.createStatement())
        {
            stmt.execute(createUser);
        } catch (SQLException e) {
            e.printStackTrace();
            throw new AceException(e.getMessage());
        }
    }

    @Override
    public synchronized void createDBAndTables(String adminUser, String adminPwd) 
            throws AceException {
        // First check it DB exists.
        String checkDB = "SELECT datname FROM pg_catalog.pg_database "
                + "WHERE datname = '" + this.dbName + "';";
        try (Connection adminConn = getAdminConnection(adminUser, adminPwd);
             Statement stmt = adminConn.createStatement();
             ResultSet result = stmt.executeQuery(checkDB))
        {
            if (result.next())
            {
                // Treat this as a "create if not exist", so if it exists, end method without doing anything.
                return;
            }
        } catch (SQLException e) {
            e.printStackTrace();
            throw new AceException(e.getMessage());
        }

        // Create the database.
        String createDB = "CREATE DATABASE " + this.dbName
                + " WITH OWNER= " + this.user 
                + " ENCODING = 'UTF8' TEMPLATE = template0 " 
                + " CONNECTION LIMIT = -1;";
        try (Connection adminConn = getAdminConnection(adminUser, adminPwd);
             Statement stmt = adminConn.createStatement())
        {
            stmt.execute(createDB);
        } catch (SQLException e) {
            e.printStackTrace();
            throw new AceException(e.getMessage());
        }

        //rs id, cose encoding, default expiration time, psk, rpk
        String createRs = "CREATE TABLE " +  DBConnector.rsTable + "("
                + DBConnector.rsIdColumn + " varchar(255) NOT NULL, "
                + DBConnector.expColumn + " bigint NOT NULL, "
                + DBConnector.tokenPskColumn + " bytea, "
                + DBConnector.authPskColumn + " bytea, "        
                + DBConnector.rpkColumn + " bytea,"
                + "PRIMARY KEY (" + DBConnector.rsIdColumn + "));";

        String createC = "CREATE TABLE " +  DBConnector.cTable + " ("
                + DBConnector.clientIdColumn + " varchar(255) NOT NULL, "
                + DBConnector.defaultAud + " varchar(255), "
                + DBConnector.defaultScope + " varchar(255), "
                + DBConnector.authPskColumn + " bytea, "
                + DBConnector.rpkColumn + " bytea,"
                + "PRIMARY KEY (" + DBConnector.clientIdColumn + "));";

        String createProfiles = "CREATE TABLE "
                + DBConnector.profilesTable + "("
                + DBConnector.idColumn + " varchar(255) NOT NULL, "
                + DBConnector.profileColumn + " varchar(255) NOT NULL);";

        String keyType = "CREATE TYPE keytype AS ENUM ('PSK', 'RPK', 'TST');";

        String createKeyTypes = "CREATE TABLE "
                + DBConnector.keyTypesTable + "("
                + DBConnector.idColumn + " varchar(255) NOT NULL, "
                + DBConnector.keyTypeColumn + " keytype);";

        String createScopes = "CREATE TABLE "
                + DBConnector.scopesTable + "("
                + DBConnector.rsIdColumn + " varchar(255) NOT NULL, "
                + DBConnector.scopeColumn + " varchar(255) NOT NULL);";

        String tokenType 
            = "CREATE TYPE tokenType AS ENUM ('CWT', 'REF', 'TST');";

        String createTokenTypes = "CREATE TABLE "
                + DBConnector.tokenTypesTable + "("
                + DBConnector.rsIdColumn + " varchar(255) NOT NULL, "
                + DBConnector.tokenTypeColumn + " tokenType);";

        String createAudiences = "CREATE TABLE "
                + DBConnector.audiencesTable + "("
                + DBConnector.rsIdColumn + " varchar(255) NOT NULL, "
                + DBConnector.audColumn + " varchar(255) NOT NULL);";

        String createCose =  "CREATE TABLE "
                + DBConnector.coseTable + "("
                + DBConnector.rsIdColumn + " varchar(255) NOT NULL, "
                + DBConnector.coseColumn + " varchar(255) NOT NULL);";

        String createClaims = "CREATE TABLE "
                + DBConnector.claimsTable + "("
                + DBConnector.ctiColumn + " varchar(255) NOT NULL, "
                + DBConnector.claimNameColumn + " SMALLINT NOT NULL,"
                + DBConnector.claimValueColumn + " bytea);";
        
        String createOldTokens = "CREATE TABLE "
                + DBConnector.oldTokensTable + "("
                + DBConnector.ctiColumn + " varchar(255) NOT NULL, "
                + DBConnector.claimNameColumn + " SMALLINT NOT NULL,"
                + DBConnector.claimValueColumn + " bytea);";
        
        String createCtiCtr = "CREATE TABLE "
                + DBConnector.ctiCounterTable + "("
                + DBConnector.ctiCounterColumn + " bigint);";

        String initCtiCtr = "INSERT INTO "
                + DBConnector.ctiCounterTable
                + " VALUES (0);";

        String createTokenLog = "CREATE TABLE "
                + DBConnector.cti2clientTable + "("
                + DBConnector.ctiColumn + " varchar(255) NOT NULL, "
                + DBConnector.clientIdColumn + " varchar(255) NOT NULL,"
                + " PRIMARY KEY (" + DBConnector.ctiColumn + "));";
        
        String createGrant2Cti = "CREATE TABLE "
                + DBConnector.grant2ctiTable + "("
                + DBConnector.grantColumn + " varchar(255) NOT NULL, "
                + DBConnector.ctiColumn + " varchar(255) NOT NULL, "
                + DBConnector.grantValidColumn + " BOOLEAN DEFAULT TRUE, "
                + " PRIMARY KEY (" + DBConnector.grantColumn + ","
                + DBConnector.ctiColumn + "));";
            
        String createGrant2RSInfo = "CREATE TABLE "
                + DBConnector.grant2RSInfoTable + "("
                + DBConnector.grantColumn + " varchar(255) NOT NULL, "
                + DBConnector.claimNameColumn + " SMALLINT NOT NULL,"
                + DBConnector.claimValueColumn + " bytea);";

        // Table creation in PostgreSQL needs to be done with a connection 
        //using the local user and not the admin user, so that the local 
        //user will be automatically set as the owner of the tables.
        try (Connection adminConn = getDBConnection();
             Statement stmt = adminConn.createStatement())
        {
            stmt.execute(createRs);
            stmt.execute(createC);
            stmt.execute(createProfiles);
            stmt.execute(keyType);
            stmt.execute(createKeyTypes);
            stmt.execute(createScopes);
            stmt.execute(tokenType);
            stmt.execute(createTokenTypes);
            stmt.execute(createAudiences);
            stmt.execute(createCose);
            stmt.execute(createClaims);
            stmt.execute(createOldTokens);
            stmt.execute(createCtiCtr);
            stmt.execute(initCtiCtr);
            stmt.execute(createTokenLog);
            stmt.execute(createGrant2Cti);
            stmt.execute(createGrant2RSInfo);
        } catch (SQLException e) {
            e.printStackTrace();
            throw new AceException(e.getMessage());
        }
    }

    @Override
    public String updateEngineSpecificSQL(String sqlQuery)
    {
        // In PostgreSQL, enums need casting.
        if(sqlQuery.contains("INSERT") && sqlQuery.contains(
                DBConnector.keyTypesTable)) {
            return "INSERT INTO " + DBConnector.keyTypesTable 
                    + " VALUES (?,?::keytype)";
        }
        if(sqlQuery.contains("INSERT") && sqlQuery.contains(
                DBConnector.tokenTypesTable)) {
            return "INSERT INTO " + DBConnector.tokenTypesTable 
                    + " VALUES (?,?::tokentype)";
        }

        // Create table statements do not take the db name in PostgreSQL.
        if (sqlQuery.contains("CREATE TABLE")) {
           String ret = sqlQuery;
           if (sqlQuery.contains(this.dbName + ".")) {
               ret = sqlQuery.replace(this.dbName + ".", "");
           }
           return ret;
        }        
        return sqlQuery;
    }

    @Override
    public void wipeDB(String adminUser, String adminPwd) throws AceException
    {
        try (Connection adminConn = getAdminConnection(adminUser, adminPwd);
             Statement stmt = adminConn.createStatement())
        {
            String dropConnections = "SELECT pg_terminate_backend(pg_stat_activity.pid) " 
                    + "    FROM pg_stat_activity " 
                    + "    WHERE pg_stat_activity.datname = '" 
                    + this.dbName + "'" 
                    + "      AND pid <> pg_backend_pid();";
            String dropDB = "DROP DATABASE IF EXISTS " + this.dbName + ";";
            String dropUser = "DROP USER IF EXISTS " + this.user + ";";
            stmt.execute(dropConnections);
            stmt.execute(dropDB);
            stmt.execute(dropUser);
        } catch (SQLException e) {
            throw new AceException(e.getMessage());
        }
    }
}
