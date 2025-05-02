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

import java.util.HashSet;
import java.util.Set;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import se.sics.ace.AceException;
import se.sics.ace.rs.ScopeValidator;

/**
 * This implements the scope format proposed in draft-bormann-core-ace-aif
 * 
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class Aif implements ScopeValidator {

    /**
     * Representation of GET in the AIF
     */
    public static short GET = 0;
    
    /**
     *  Representation of POST in the AIF
     */
    public static short POST = 1;
    
    /**
     *  Representation of PUT in the AIF
     */
    public static short PUT = 2;
    
    /**
     *  Representation of DELETE in the AIF
     */
    public static short DELETE = 3;
    
    /**
     * Representation of FETCH in the AIF
     */
    public static short FETCH = 4;
    
    /**
     * Representation of PATCH in the AIF
     */
    public static short PATCH = 5;
    
    /**
     * Representation of iPATCH in the AIF
     */
    public static short iPATCH = 6;
    
    
    /**
     * The powers of two starting with 0 up to 6
     */
    private static short[] powers = {1, 2, 4, 8, 16, 32, 64};
    
    /**
     * The resources served by this Aif
     */
    private Set<String> resources;
    
    /**
     * @param resources  the resources served by this Aif.
     */
    public Aif(Set<String> resources) {
        this.resources = new HashSet<>();
        this.resources.addAll(resources);
    }
    
    @Override
    public boolean scopeMatch(CBORObject scope, String resourceId, Object actionId)
            throws AceException {
                 
        if (!(actionId instanceof Short)) {
            throw new AceException("actionId must be a short");
        }
        
        if (!scope.getType().equals(CBORType.Array)) {  
            throw new AceException("scope must be a CBOR array in Aif");
        }
        
        for (int i=0; i<scope.size();i++) {
            CBORObject scopeElement = scope.get(i);
            if (!scopeElement.getType().equals(CBORType.Array)) {
                throw new AceException("Invalid scope format");
            }
            String resource = scopeElement.get(0).AsString();
            short action = scopeElement.get(1).AsNumber().ToInt16Checked();
            if (resource.equals(resourceId)) {
                //Check action
                if ((action & powers[(short)actionId]) != 0) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public boolean scopeMatchResource(CBORObject scope, String resourceId)
            throws AceException {
        
        if (!scope.getType().equals(CBORType.Array)) {
            throw new AceException("scope must be a CBOR array in Aif");
        }

        for (int i=0; i<scope.size();i++) {
            CBORObject scopeElement = scope.get(i);
            if (!scopeElement.getType().equals(CBORType.Array)) {
                throw new AceException("Invalid scope format");
            }
            String resource = scopeElement.get(0).AsString();
            if (resource.equals(resourceId)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean isScopeMeaningful(CBORObject scope) throws AceException {
        if (!scope.getType().equals(CBORType.Array)) {
            throw new AceException("Scope must be a CBOR array in Aif");
        }
        
        //Find the resource
        for (int i=0; i<scope.size();i++) {
            CBORObject scopeElement = scope.get(i);
            if (!scopeElement.getType().equals(CBORType.Array)) {
                throw new AceException("Invalid scope format");
            }
            String resource = scopeElement.get(0).AsString();
            if (this.resources.contains(resource)) {
                return true;
            }
        }
        return false; //No resource found
    }

    @Override
    public CBORObject getScope(String resource, short action) {
        CBORObject scope = CBORObject.NewArray();
        CBORObject scopeElement = CBORObject.NewArray();
        scopeElement.Add(resource);
        scopeElement.Add(powers[action]);
        scope.Add(scopeElement);
        return scope;
    }
    
    // This method performs as isScopeMeaningful(CBORObject scope) for this Validator
    @Override
    public boolean isScopeMeaningful(CBORObject scope, String aud) throws AceException {
    	return isScopeMeaningful(scope);
    }
    
}
