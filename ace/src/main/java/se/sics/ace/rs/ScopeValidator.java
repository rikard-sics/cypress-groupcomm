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

import com.upokecenter.cbor.CBORObject;

import se.sics.ace.AceException;

/**
 * The interface for scope validators.  These should be implemented for the specific applications.
 * 
 * @author Ludwig Seitz
 *
 */
public interface ScopeValidator {
	
	/**
	 * Does the given scope matches the given resource and action
	 * 
	 * @param scope  the scope, can be a CBOR String or CBOR array
	 * @param resourceId  the resource
	 * @param actionId  the action on the resource
	 * @return  true if the scope includes the resource and the action, false if not.
	 * @throws AceException 
	 */
	boolean scopeMatch(CBORObject scope, String resourceId, Object actionId)
	        throws AceException;
	
    /**
     * Does the given scope matches the given resource
     * 
     * @param scope  the scope, as a CBOR text string
     * @param resourceId  the resource
     * @return  true if the scope includes the resource, false if not.
     * @throws AceException 
     */
    boolean scopeMatchResource(CBORObject scope, String resourceId)
            throws AceException;
	
    /**
     * Is the given scope meaningful for this validator.
     * 
     * @param scope  the scope, can be a CBOR String or CBOR array
     * @return  true if the scope is meaningful, false if not
     * @throws AceException 
     */
    boolean isScopeMeaningful(CBORObject scope) throws AceException;

    /**
     * Return the minimal scope for the given action on the given resource.
     * 
     * @param resource  the resource
     * @param action  the action
     * @return  the scope
     */
    CBORObject getScope(String resource, short action);
    
    /**
     * Is the given scope meaningful for this validator.
     * 
     * @param scope  the scope, as a CBOR text string or a CBOR byte string
     * @param aud  the audience as an CBOR text string
     * @return  true if the scope is meaningful, false if not
     * @throws AceException 
     */
    boolean isScopeMeaningful(CBORObject scope, String aud) throws AceException;
}
