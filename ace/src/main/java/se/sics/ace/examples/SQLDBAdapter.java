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

import java.sql.Connection;
import java.sql.SQLException;

/**
 * Handles creating user, database and tables to store authorization data.
 *
 * @author Sebastian Echeverria
 */
public interface SQLDBAdapter {
    /**
     * Sets basic params for user and DB creation.
     *
     * @param user username for the DB.
     * @param pwd password for the user.
     * @param dbName the DB name.
     * @param dbUrl the URL to connect to this database type. Can be null, and default URL will be used.
     */
    void setParams (String user, String pwd, String dbName, String dbUrl);

    /**
     * Returns a connection to the DB engine with admin credentials.
     * @param adminUser the admin user name.
     * @param adminPwd the admin password.
     * @return an SQL Connection.
     * @throws SQLException
     */
    Connection getAdminConnection(String adminUser, String adminPwd) throws SQLException;

    /**
     * Returns a connection to the current DB.
     * @return an SQL Connection.
     * @throws SQLException
     */
    Connection getDBConnection() throws SQLException;

    /**
     * Creates a new user in the DB.
     *
     * @param adminUser  the admin user name.
     * @param adminPwd  the admin or base password to use.
     * @throws AceException
     */
    void createUser(String adminUser, String adminPwd) throws AceException;

    /**
     * Creates a new DB and the appropriate tables to handle authorization data.
     *
     * @param adminUser  the admin user name.
     * @param adminPwd  the admin or base password to use.
     * @throws AceException
     */
    void createDBAndTables(String adminUser, String adminPwd) throws AceException;


    /**
     * Totally deletes a DB as well as the user that owns it.
     *
     * @param adminUser  the admin user name.
     * @param adminPwd  the admin or base password to use.
     * @throws AceException
     */
    void wipeDB(String adminUser, String adminPwd) throws AceException;

    /**
     * Updates any SQL queries that need to be specific for each DB engine.
     * 
     * @param sqlQuery  the query that should be updated
     * 
     * @return  the updated query
     * 
     */
    String updateEngineSpecificSQL(String sqlQuery);
}
