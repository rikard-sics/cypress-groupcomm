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

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import se.sics.ace.AceException;
import se.sics.ace.rs.AudienceValidator;
import se.sics.ace.rs.ScopeValidator;

/**
 * Simple audience and scope validator for testing purposes.
 * This validator expects the scopes to be Strings as in OAuth 2.0.
 * 
 * The actions are expected to be integers corresponding to the 
 * values for RESTful actions in <code>Constants</code>.
 * 
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class KissValidator implements AudienceValidator, ScopeValidator {

    /**
     * The audiences we recognize
     */
	private Set<String> myAudiences;
	
	/**
	 * Maps the scopes to a map that maps the scope's resources to the actions 
	 * allowed on that resource
	 */
	private Map<String, Map<String, Set<Short>>> myScopes;  
	
	/**
	 * Constructor.
	 * 
	 * @param myAudiences  the audiences that this validator should accept
	 * @param myScopes  the scopes that this validator should accept
	 */
	public KissValidator(Set<String> myAudiences, 
	        Map<String, Map<String, Set<Short>>> myScopes) {
		this.myAudiences = new HashSet<>();
		this.myScopes = new HashMap<>();
		if (myAudiences != null) {
		    this.myAudiences.addAll(myAudiences);
		} else {
		    this.myAudiences = Collections.emptySet();
		}
		if (myScopes != null) {
		    this.myScopes.putAll(myScopes);
		} else {
		    this.myScopes = Collections.emptyMap();
		}
	}
	
	@Override
	public boolean match(String aud) {
		return this.myAudiences.contains(aud);
	}

    @Override
    public boolean scopeMatch(CBORObject scope, String resourceId, Object actionId)
            throws AceException {
        if (!scope.getType().equals(CBORType.TextString)) {
            throw new AceException("Scope must be a String in KissValidator");
        }
        String[] scopes = scope.AsString().split(" ");
        for (String subscope : scopes) {
            Map<String, Set<Short>> resources = this.myScopes.get(subscope);
            if (resources == null) {
                continue;
            }
            if (resources.containsKey(resourceId)) {
                if (resources.get(resourceId).contains(actionId)) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public boolean scopeMatchResource(CBORObject scope, String resourceId)
            throws AceException {
        if (!scope.getType().equals(CBORType.TextString)) {
            throw new AceException("Scope must be a String in KissValidator");
        }
        String[] scopes = scope.AsString().split(" ");
        for (String subscope : scopes) {
            Map<String, Set<Short>> resources = this.myScopes.get(subscope);
            if (resources.containsKey(resourceId)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean isScopeMeaningful(CBORObject scope) throws AceException {
        if (!scope.getType().equals(CBORType.TextString)) {
            throw new AceException("Scope must be a String in KissValidator");
        }
        String[] scopes = scope.AsString().split(" ");
        for (String subscope : scopes) {
            if (!this.myScopes.containsKey(subscope))
                    return false;
        }
        return true;
    }

    @Override
    public CBORObject getScope(String resource, short action) {
        Iterator<Entry<String, Map<String, Set<Short>>>> it = this.myScopes.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, Map<String, Set<Short>>> e = it.next();
            Iterator<Entry<String, Set<Short>>> it2 = e.getValue().entrySet().iterator();
            while (it2.hasNext()) {
                Map.Entry<String, Set<Short>> e2 = it2.next();
                if (e2.getKey().equals(resource)) {//Found resource
                //Check if action matches
                    if (e2.getValue().contains(action)) {
                        return CBORObject.FromObject(e.getKey());
                    }
                }   
            }
        }
        return null; //No scope found
    }
    
    // This method performs as isScopeMeaningful(CBORObject scope) for this Validator
    @Override
    public boolean isScopeMeaningful(CBORObject scope, String aud) throws AceException {
        return isScopeMeaningful(scope);
    }
}
