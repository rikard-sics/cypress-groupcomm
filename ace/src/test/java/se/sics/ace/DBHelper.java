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
package se.sics.ace;

import se.sics.ace.coap.as.CoapDBConnector;
import se.sics.ace.examples.MySQLDBAdapter;
//import se.sics.ace.examples.PostgreSQLDBAdapter;
import se.sics.ace.examples.SQLConnector;
import se.sics.ace.examples.SQLDBAdapter;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.sql.SQLException;

/**
 * Helper class to set up databases for tests.
 *
 * @author Sebastian Echeverria and Marco Tiloca
 *
 */
public class DBHelper
{
    /**
     * Easy place to change which DB adapter wants to be used for all tests.
     */
    private static final SQLDBAdapter dbAdapter = new MySQLDBAdapter(); //PostgreSQLDBAdapter();

    private static final String testUsername = "testuser";
    private static final String testPassword = "testpwd";
    private static final String testDBName = "testdb";

    private static String dbAdminUser = null;
    private static String dbAdminPwd = null;

    /**
     * Sets up the DB using the current default adapter.
     * 
     * @throws AceException 
     * @throws IOException 
     */
    public static void setUpDB() throws AceException, IOException
    {
        // First load the DB admin username and password from an external file.
        loadAdminLoginInformation();
        
        // Set parameters for the DB.
        dbAdapter.setParams(testUsername, testPassword, testDBName, null);

        // In case database and/or user already existed.
        SQLConnector.wipeDatabase(dbAdapter, dbAdminUser, dbAdminPwd);

        // Create the DB and user for the tests.
        SQLConnector.createUser(dbAdapter, dbAdminUser, dbAdminPwd);
        SQLConnector.createDB(dbAdapter, dbAdminUser, dbAdminPwd);
    }

    /**
     * @return  the SQLConnector instance
     * @throws SQLException
     */
    public static SQLConnector getSQLConnector() throws SQLException
    {
        // Get a connection to the test DB.
        return SQLConnector.getInstance(dbAdapter);
    }

    /**
     * @return the CoapDBConnector instance
     * @throws SQLException
     */
    public static CoapDBConnector getCoapDBConnector() throws SQLException
    {
        // Get a connection to the test DB.
        return CoapDBConnector.getInstance(dbAdapter);
    }

    /**
     * Destroy the test DB with the default adapter.
     * @throws AceException
     */
    public static void tearDownDB() throws AceException
    {
        dbAdapter.setParams(testUsername, testPassword, testDBName, null);
        SQLConnector.wipeDatabase(dbAdapter, dbAdminUser, dbAdminPwd);
    }

    /**
     * Loads the admin username nad password form an external file.
     * @throws IOException
     */
    private static void loadAdminLoginInformation() throws IOException
    {
        BufferedReader br = new BufferedReader(new FileReader("db.pwd"));
        int readLines = 0;
        try
        {
            StringBuilder sb = new StringBuilder();
            String line = br.readLine();
            while (line != null && readLines < 2)
            {
            	sb.delete(0, sb.length());
                sb.append(line);
                sb.append(System.lineSeparator());
                
                if (readLines == 0) {
                	dbAdminUser = sb.toString().replace(System.getProperty("line.separator"), "");
                }
                if (readLines == 1) {
                	dbAdminPwd = sb.toString().replace(System.getProperty("line.separator"), "");
                }
                readLines++;
                line = br.readLine();
            }
        }
        finally
        {
            br.close();
        }
    }
}
