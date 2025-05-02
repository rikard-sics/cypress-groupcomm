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
package se.sics.ace.as;

import java.util.Map;

import com.upokecenter.cbor.CBORObject;

import se.sics.ace.AccessToken;
import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.ReferenceToken;
import se.sics.ace.cwt.CWT;

/**
 * Factory that creates different types of access tokens.
 * 
 * @author Ludwig Seitz
 *
 */
public class AccessTokenFactory {
	
	/**
	 * The type identifier for CWTs
	 */
	public static final short CWT_TYPE = 0;
	
	/**
	 * The type identifier for reference tokens
	 */
	public static final short REF_TYPE = 1;
	
	/**
     * The type identifier for test tokens
     */
    public static final short TEST_TYPE = 2;
    
	
	/**
     * Array of String values for the token type
     */
    public static final String[] ABBREV = {"CWT", "REF", "TST"};
	
	/**
	 * Generate an access token.
	 * 
	 * @param type  the type of token you want to generate
	 * @param claims  the claims associated with this token
	 * @return  the generated token
	 * @throws AceException
	 */
	public static AccessToken generateToken(
			int type, Map<Short, CBORObject> claims) throws AceException {
		switch (type) {
		case CWT_TYPE :
			return new CWT(claims);
		case REF_TYPE :
		    CBORObject cti = claims.get(Constants.CTI);
	        if (cti == null) {
	            throw new AceException("Token has no cti");
	        }
			return new ReferenceToken(cti.GetByteString());	
		default: 
			throw new AceException("Unsupported token type");
		}
	}

}
