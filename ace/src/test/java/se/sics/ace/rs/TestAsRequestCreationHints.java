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
package se.sics.ace.rs;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.upokecenter.cbor.CBORObject;

import org.junit.Assert;
import se.sics.ace.AceException;
import se.sics.ace.Constants;

/**
 * Tests the AsRequestCreationHints  class.
 * 
 * @author Ludwig Seitz
 *
 */
public class TestAsRequestCreationHints {
    
    /**
     * Expected exception
     */
    @Rule
    public ExpectedException thrown = ExpectedException.none();
    
    /**
     * Test creating an AS info with null as AS uri.
     */
    @Test
    public void testNullUri() {
        this.thrown.expect(IllegalArgumentException.class);
        this.thrown.expectMessage("Cannot create an AsRequestCreationHints object with null or empty asUri field");
        @SuppressWarnings("unused")
        AsRequestCreationHints ai = new AsRequestCreationHints(null, null, false, false);
    }
    
    /**
     * Test creating an AS info with empty AS uri.
     */
    @Test
    public void testEmptyUri() {
        this.thrown.expect(IllegalArgumentException.class);
        this.thrown.expectMessage("Cannot create an AsRequestCreationHints object with null or empty asUri field");
        @SuppressWarnings("unused")
        AsRequestCreationHints ai = new AsRequestCreationHints("", null, false, false);
    }
    
    /**
     * Test creating a valid AS info
     * 
     * @throws AceException
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeyException 
     */
    @Test 
    public void testRoundTrip() throws AceException, InvalidKeyException, NoSuchAlgorithmException {
        AsRequestCreationHints ai = new AsRequestCreationHints("coaps://testAS/token", null, false, false);
        CBORObject cbor = ai.getHints(null, null);
        Map<Short, CBORObject> hints = AsRequestCreationHints.parseHints(cbor);
        Assert.assertTrue(hints.containsKey(Constants.AS));
        Assert.assertEquals("coaps://testAS/token", hints.get(Constants.AS).AsString());
 
    }

}
