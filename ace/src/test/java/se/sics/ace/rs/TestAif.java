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

import java.util.HashSet;
import java.util.Set;

import org.eclipse.californium.core.coap.CoAP;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

import se.sics.ace.AceException;
import se.sics.ace.examples.Aif;

/**
 * Tests for the RESTscope class.
 * 
 * Should be rewritten to test AIF when ready
 * 
 * @author Ludwig Seitz
 *
 */
public class TestAif {
   
    private static CBORObject scope;
    private static Aif s;
    
    /**
     * Set up tests.
     */
    @BeforeClass
    public static void setUp()  {
        Set<String> resources = new HashSet<>();
        resources.add("sensors/temp");
        resources.add("config/security");
        resources.add("sensors/co2");
        resources.add("");
        s = new Aif(resources);
        CBORObject authz1 = CBORObject.NewArray();
        CBORObject authz2 = CBORObject.NewArray();
        authz1.Add("sensors/temp");
        authz1.Add(1);  // == 2^GET(0) ==  2^0
        authz2.Add("config/security");
        authz2.Add(1|4); // == GET and PUT
        scope = CBORObject.NewArray();
        scope.Add(authz1);
        scope.Add(authz2);
    }
    
    
    /**
     * Test a scope against a resource URI that is not covered 
     * 
     * @throws AceException 
     */
    @Test
    public void testNoResource() throws AceException {
        Assert.assertFalse(s.scopeMatchResource(scope, "sensors/co2"));
        Assert.assertFalse(s.scopeMatch(scope, "blah", 
                (short)CoAP.Code.GET.value));
    }
    
    /**
     * Test a scope against different actions
     * 
     * @throws AceException 
     */
    @Test
    public void testNoPermission() throws AceException {
        // 1 = GET  5 = GET and PUT
        Assert.assertTrue(s.scopeMatchResource(scope, "sensors/temp"));
        Assert.assertFalse(s.scopeMatch(scope, "sensors/temp", Aif.DELETE));
        Assert.assertFalse(s.scopeMatch(scope, "sensors/temp", Aif.PUT));
        Assert.assertFalse(s.scopeMatch(scope, "sensors/temp", Aif.POST));
        Assert.assertTrue(s.scopeMatch(scope, "sensors/temp", Aif.GET));
        
        Assert.assertTrue(s.scopeMatchResource(scope, "config/security"));
        Assert.assertFalse(s.scopeMatch(scope, "config/security", Aif.DELETE));
        Assert.assertTrue(s.scopeMatch(scope, "config/security", Aif.PUT));
        Assert.assertFalse(s.scopeMatch(scope, "config/security", Aif.POST));
        Assert.assertTrue(s.scopeMatch(scope, "config/security", Aif.GET));
        
    }
    
    /**
     * Test a scope against with invalid action
     * 
     * @throws AceException 
     */
    @Test (expected = AceException.class)
    public void testInvalidAction() throws AceException {
         s.scopeMatch(scope, "sensors/temp", "BLAH");
        
    }
}
    
