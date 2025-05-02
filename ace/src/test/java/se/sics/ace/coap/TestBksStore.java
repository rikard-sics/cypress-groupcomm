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
package se.sics.ace.coap;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

import javax.crypto.SecretKey;

import org.eclipse.californium.scandium.dtls.PskPublicInformation;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import se.sics.ace.TestConfig;

import org.junit.Assert;
/**
 * Tests for the Bouncy Castle Key Store backed implementation of 
 * Californium's PskStore Interface.
 * 
 * NOTE: You need to have the Java Cryptography Extension (JCE) Unlimited 
 * Strength Jurisdiction Policy Files installed for this test to work.
 * 
 * @author Ludwig Seitz
 *
 */
public class TestBksStore {

    /**
     * The keystore used in the tests
     */
    private static BksStore keystore;
    
    /**
     * Sets up the Keystore
     * @throws KeyStoreException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws FileNotFoundException
     * @throws IOException
     */
    @BeforeClass
    public static void setUp() throws KeyStoreException, 
            NoSuchProviderException, NoSuchAlgorithmException, 
            CertificateException, FileNotFoundException, IOException {
        BksStore.init(TestConfig.testFilePath + "testKeyStore.bks", "password",
                TestConfig.testFilePath + "add2id.cfg");
        keystore = new BksStore(TestConfig.testFilePath + "testKeyStore.bks",
                "password", TestConfig.testFilePath + "add2id.cfg");
    }
    
    /**
     * Delete the keystore and the mapping of addresses to ids.
     */
    @AfterClass
    public static void tearDown() {
        keystore = null;
        new File(TestConfig.testFilePath + "testKeyStore.bks").delete();
    }
    
    
    /**
     * Test successful call to addKey() and removeKey()
     * 
     * @throws Exception 
     */
    @Test
    public void testAddRemoveKeySuccess() throws Exception {
        byte[] key = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        assert(!keystore.hasKey("identity1"));
        keystore.addKey(key, "identity1");
        assert(keystore.hasKey("identity1"));
        keystore.removeKey("identity1");
        assert(!keystore.hasKey("identity1"));
    }
    
    /**
     * Test unsuccessful call to removeKey() with identity = null
     * 
     * @throws Exception 
     */
    @Test (expected=KeyStoreException.class)
    public void testRemoveKeyFail() throws Exception {
        keystore.removeKey(null);
        Assert.fail("No exception thrown");
    }
    
    /**
     * Test unsuccessful call to addKey() with key = null
     * 
     * @throws Exception 
     */
    @Test (expected=KeyStoreException.class)
    public void testAddKeyFail() throws Exception {
        keystore.addKey(null, "identity1");
        Assert.fail("No exception thrown");
    }
    
    
    /**
     * Test successful call to getKey()
     * 
     * @throws Exception 
     */
    @Test
    public void testGetKeySuccess() throws Exception {
        byte[] key = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        keystore.addKey(key, "identity1");
        byte[] key2 = keystore.getKey(
                new PskPublicInformation("identity1")).getEncoded();
        Assert.assertArrayEquals(key, key2);
        keystore.removeKey("identity1");
    }

    
    /**
     * Test unsuccessful call to getKey() wrong id
     * 
     * @throws Exception 
     */
    @Test
    public void testGetKeyFailId() throws Exception {
        byte[] key = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        keystore.addKey(key, "identity1");
        SecretKey key2 = keystore.getKey(
                new PskPublicInformation("wrongidentity"));
        Assert.assertNull(key2);
        keystore.removeKey("identity1");
    }
    
    
    /**
     * Test successful call to getIdentity()
     * 
     * @throws Exception 
     */
    @Test
    public void testGetIdentitySuccess() throws Exception {
        String id = keystore.getIdentity(
                InetSocketAddress.createUnresolved(
                        "example.com", 5684)).getPublicInfoAsString();
        assert(id.equals("id1"));
        id = keystore.getIdentity(
                InetSocketAddress.createUnresolved(
                        "blah.se", 5684)).getPublicInfoAsString();
        assert(id.equals("id2"));
        id = keystore.getIdentity(
                InetSocketAddress.createUnresolved(
                        "blubb.de", 5684)).getPublicInfoAsString();
        assert(id.equals("id3"));
    }
    
    /**
     * Test unsuccessful call to getIdentity()
     * 
     * @throws Exception 
     */
    @Test
    public void testGetIdentityFail() throws Exception {
     PskPublicInformation id = keystore.getIdentity(
                InetSocketAddress.createUnresolved("404.com", 5684));
        Assert.assertNull(id);
    }
}
