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
package se.sics.ace.client;

import com.upokecenter.cbor.CBORObject;

import se.sics.ace.AceException;
import se.sics.ace.Constants;

/**
 * This class is an utility that produces the CBOR payload for a GET 
 * request to the AS.  Profile specific implementations of the client
 * can use this to generate the payload. 
 * 
 * @author Ludwig Seitz
 *
 */
public class GetToken {
    
    /**
     * Get the payload for an Access Token Request using
     * the Authorization Code Grant.
     *  
     * @param code  the authorization code, must not be null
     * @param redirectUri  REQUIRED if present earlier
     * @param clientId   REQUIRED if client not authenticating
     * @param aud  Audience restriction. OPTIONAL
     * @param cnf  Proof-of-Possession key requested. OPTIONAL
     * @param scope  The requested scope. OPTIONAL
     * 
     * @return  the CBOR map representing the access token request
     *      payload
     * @throws AceException 
     */
    public static CBORObject getAuthzCodeRequest(CBORObject code, 
            CBORObject redirectUri, CBORObject clientId, CBORObject aud, 
            CBORObject scope, CBORObject cnf) throws AceException {
        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.GRANT_TYPE, Constants.GT_AUTHZ_CODE);
        if (code == null) {
            throw new AceException("authorization code must be non-null");
        }
        payload.Add(Constants.CODE, code);
        if (redirectUri != null) {
            payload.Add(Constants.REDIRECT_URI, redirectUri);
        }
        if (clientId != null) {
            payload.Add(Constants.CLIENT_ID, clientId);
        }
        if (aud != null) {
            payload.Add(Constants.AUDIENCE, aud);
        }
        if (scope != null) {
            payload.Add(Constants.SCOPE, scope);
        }
        if (cnf != null) {
            payload.Add(Constants.CNF, cnf);
        }
        return payload;
    }
    

    /**
     * Get the payload for an Authorization Request using
     * the Implicit Grant.  Note that this grant flow does not include a 
     * separate Access Token Request.
     *  
     * @param clientId  REQUIRED
     * @param redirectURI  OPTIONAL
     * @param scope  The requested scope. OPTIONAL
     * @param state  State between request and callback. RECOMMENDED
     * @param aud  Audience restriction. OPTIONAL
     * @param cnf  Proof-of-Possession key requested. OPTIONAL
     * @return  the CBOR map representing the authorization request
     *      payload
     * @throws AceException
     */
    public static CBORObject getImplicitRequest(CBORObject clientId, 
            CBORObject redirectURI, CBORObject scope, CBORObject state, 
            CBORObject aud, CBORObject cnf) throws AceException {
        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.RESPONSE_TYPE, "token");
        if (clientId == null) {
            throw new AceException("client-id must be non-null");
        }
        payload.Add(Constants.CLIENT_ID, clientId);
        if (redirectURI != null) {
            payload.Add(Constants.REDIRECT_URI, redirectURI);
        }
        if (aud != null) {
            payload.Add(Constants.AUDIENCE, aud);
        }
        if (scope != null) {
            payload.Add(Constants.SCOPE, scope);
        }
        if (cnf != null) {
            payload.Add(Constants.CNF, cnf);
        }
        if (state != null) {
            payload.Add(Constants.STATE, state);
        }
        return payload;
    }

    /**
     * Get the payload for a Resource Owner Password Credentials Grant.
     *
     * @param username  the resource owner username. REQUIRED.
     * @param password   the resource onwer's password. REQUIRED.
     * @param aud  Audience restriction. OPTIONAL
     * @param scope  The requested scope. OPTIONAL 
     * @param cnf  Proof-of-Possession key requested. OPTIONAL 
     *   
     * @return  the CBOR map representing the access token request
     *      payload.
     * @throws AceException 
     */
    public static CBORObject getROPasswordRequest(CBORObject username,
            CBORObject password, CBORObject aud, CBORObject scope,
            CBORObject cnf) throws AceException {
        CBORObject payload = CBORObject.NewMap();
        payload.Add(Constants.GRANT_TYPE, Constants.GT_PASSWORD);
        if (username == null) {
            throw new AceException("username must be non-null");
        }
        payload.Add(Constants.USERNAME, username);
        
        if (password == null) {
            throw new AceException("password must be non-null");
        }
        payload.Add(Constants.PASSWORD, password);
        
        if (aud != null) {
            payload.Add(Constants.AUDIENCE, aud);
        }
        if (scope != null) {
            payload.Add(Constants.SCOPE, scope);
        }
        if (cnf != null) {
            payload.Add(Constants.CNF, cnf);
        }
        return payload;
    }

    /**
     * Get the payload for a Client Credentials Grant.
     *   
     * @param aud  Audience restriction. OPTIONAL
     * @param scope  The requested scope. OPTIONAL 
     * @param req_cnf  Proof-of-Possession key requested. OPTIONAL 
     *   
     * @return  the CBOR map representing the access token request
     *      payload
     */
    public static CBORObject getClientCredentialsRequest(CBORObject aud, 
            CBORObject scope, CBORObject reqCnf) {
        CBORObject payload = CBORObject.NewMap();
        if (aud != null) {
            payload.Add(Constants.AUDIENCE, aud);
        }
        if (scope != null) {
            payload.Add(Constants.SCOPE, scope);
        }
        if (reqCnf != null) {
            payload.Add(Constants.REQ_CNF, reqCnf);
        }
        return payload;
    }
}
