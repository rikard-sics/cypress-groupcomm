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
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.californium.core.coap.Request;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import se.sics.ace.AceException;
import se.sics.ace.Constants;

/**
 * This class manages the creation of AS Request Creation Hints at the RS.
 * 
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class AsRequestCreationHints {

    /**
     * Flag signaling whether to include the scope
     */
    private boolean includeScope;
    
    /**
     * The URI of the AS in charge of this RS
     */
    private String asUri;
    
    /**
     * The audience this RS identifies with, can be null
     */
    private String aud;
    
    /**
     * Flag signaling whether to create a client nonce
     */
    private boolean createNonce;
    

    /**
     * Constructor. Specifies which parameters are to be included in a AsRequestCreationHints
     * 
     * @param asUri  the required URI of the AS responsible for this RS
     * @param aud  the audience this RS identifies with or null if this parameter is to be omitted
     * @param includeScope  true if the scope is to be included  
     * @param createNonce  true if a nonce is to be created  
     */
    public AsRequestCreationHints(String asUri, 
            String aud, boolean includeScope, boolean createNonce) {
        if (asUri == null || asUri.isEmpty()) {
            throw new IllegalArgumentException(
                    "Cannot create an AsRequestCreationHints object "
                            + "with null or empty asUri field");
        }
        this.includeScope = includeScope;
        this.createNonce = createNonce;
        this.asUri = asUri;
        this.aud = aud;       
    }
    
    /**
     * Create the AS Request Creation Hints based on the configuration
     * of this class. 
     * 
     * Note: The token repository must have been initialized 
     * before calling this.
     * 
     * @param req  the client's request
     * @param kid  the kid linked to a the key used in the secure connection
     *  with the client, null if we don't have a secure connection
     *  
     * @return  the AS Request Creation Hints
     * @throws AceException   if the TokenRepository is not initialized
     * @throws InvalidKeyException  if the nonce creation fails
     * @throws NoSuchAlgorithmException  if the nonce creation fails
     */
    public CBORObject getHints(Request req, String kid) 
            throws InvalidKeyException, NoSuchAlgorithmException, AceException {
        CBORObject cbor = CBORObject.NewMap();
        cbor.Add(Constants.AS, this.asUri);          
        if (kid != null) {
        	if (kid != null) {
	            byte[] kidB = Base64.getDecoder().decode(kid);
	            cbor.Add(Constants.KID, kidB);
        	}
        }
        if (this.includeScope) {
            if (req == null) {
                throw new IllegalArgumentException("Request"
                        + " must both be non-null for scope creation");
            }

            
            String resource = req.getOptions().getUriPathString();
            short action = (short) req.getCode().value;  
            
            if (TokenRepository.getInstance() == null) {
                throw new AceException("TokenRepository not initialized");
            }
            CBORObject scope = TokenRepository.getInstance().getScope(resource, action);
            
            cbor.Add(Constants.SCOPE, scope);   
        }  
        if (this.aud != null) {
            cbor.Add(Constants.AUDIENCE, this.aud);
        }        
       
        if (this.createNonce) {
            byte[] cnonce = CnonceHandler.getInstance().createNonce();
            cbor.Add(Constants.CNONCE, cnonce);
        }        
        return cbor;
    }

    /**
     * Parse a CBOR object containing AS Request Creation Hints to a Map.
     * 
     * @param hints  the CBOR object, must be a CBOR Map containing at least
     * the AS parameter.
     * 
     * @return  a Map of the hints
     */
    public static Map<Short, CBORObject> parseHints(CBORObject hints) {
        if (!hints.getType().equals(CBORType.Map)) {
            throw new IllegalArgumentException("AS Request Creation Hints must"
                    + "be a CBOR map");
        }
        Map<Short, CBORObject> h = new HashMap<>();
        if (!hints.ContainsKey(CBORObject.FromObject(Constants.AS))){
            throw new IllegalArgumentException("AS Request Creation Hints"
                    + "malformed, must contain AS parameter");
        }
        h.put(Constants.AS, hints.get(CBORObject.FromObject(Constants.AS)));
        if (hints.ContainsKey(CBORObject.FromObject(Constants.KID))) {
            h.put(Constants.KID, hints.get(
                    CBORObject.FromObject(Constants.KID)));
        }
        if (hints.ContainsKey(CBORObject.FromObject(Constants.SCOPE))) {
            h.put(Constants.SCOPE, hints.get(
                    CBORObject.FromObject(Constants.SCOPE)));
        }
        if (hints.ContainsKey(CBORObject.FromObject(Constants.AUDIENCE))) {
            h.put(Constants.AUDIENCE, hints.get(
                    CBORObject.FromObject(Constants.AUDIENCE)));
        }
        if (hints.ContainsKey(CBORObject.FromObject(Constants.CNONCE))) {
            h.put(Constants.CNONCE, hints.get(
                    CBORObject.FromObject(Constants.CNONCE)));
        }
        return h;
    }

}
