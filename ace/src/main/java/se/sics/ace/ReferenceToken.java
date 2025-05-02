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
package se.sics.ace;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import se.sics.ace.rs.IntrospectionException;
import se.sics.ace.rs.IntrospectionHandler;

/**
 * This class implements a reference token.
 * 
 * @author Ludwig Seitz
 *
 */
public class ReferenceToken implements AccessToken {

	/**
	 * The reference 
	 */
	private byte[] ref;
	
	/**
	 * The reference as Base64 encoded string
	 */
	private String refS;
	
	/**
	 * A handler for introspecting this token.
	 */
	private IntrospectionHandler introspect;
	
	/**
	 * Constructor.
	 * 
	 * @param length  the length in bits of the reference.
	 */
	public ReferenceToken(int length) {		
		this.ref = new byte[length];
		new SecureRandom().nextBytes(this.ref);
		this.refS = Base64.getEncoder().encodeToString(this.ref);
	}
	
	/**
	 * Constructor. Uses the default
	 * length of 128 bits for the reference.
	 */
	public ReferenceToken() {
	    this.ref = new byte[128/8];
	    new SecureRandom().nextBytes(this.ref);
	    this.refS = Base64.getEncoder().encodeToString(this.ref);
	}
	
	/**
	 * Constructor. Uses a given cti as reference.
	 * 
	 * @param ref  the reference
	 */
	public ReferenceToken(byte[] ref) {
	    this.ref = ref;
        this.refS = Base64.getEncoder().encodeToString(this.ref); 
	}
	
	
	/**
	 * Add an introspection handler to this ReferenceToken in order to do 
	 * introspection.
	 * 
	 * @param intropsect
	 */
	public void addIntrospectionHandler(IntrospectionHandler intropsect) {
		this.introspect = intropsect;
	}
	
	@Override
	public boolean expired(long now) throws AceException {
		if (this.introspect == null) {
			throw new AceException("Need IntrospectionHandler");
		}
		Map<Short, CBORObject> params = null;
        try {
            params = this.introspect.getParams(this.ref);
        } catch (IntrospectionException e) {
            throw new AceException("Introspection failed: "
                    + e.getMessage());
        }
		if (params == null) {
		    throw new AceException("Token reference not found: " + this.refS);
		}
		CBORObject expO = params.get(Constants.EXP);
		if (expO != null && expO.AsNumber().ToInt64Checked() < now) {
			//Token has expired
			return true;
		}
		return false;		
	}

	@Override
	public boolean isValid(long now) throws AceException {
		if (this.introspect == null) {
			throw new AceException("Need IntrospectionHandler");
		}
		Map<Short, CBORObject> params = null;
        try {
            params = this.introspect.getParams(this.ref);
        } catch (IntrospectionException e) {
            throw new AceException("Introspection failed: "
                    + e.getMessage());
        }
		if (params == null) {
		    throw new AceException("Token reference not found: " + this.refS);
		}
		//Check nbf and exp for the found match
		CBORObject nbfO = params.get(Constants.NBF);
		if (nbfO != null &&  nbfO.AsNumber().ToInt64Checked()	> now) {
		    return false;
		}	
		CBORObject expO = params.get(Constants.EXP);
		if (expO != null && expO.AsNumber().ToInt64Checked() < now) {
		    //Token has expired
		    return false;
		}
		return false;
	}

	@Override
	public CBORObject encode() {
		return CBORObject.FromObject(this.ref);
	}

	/**
	 * Parse a reference token from a CBOR object (must be a ByteString).
	 * @param ob
	 * @return  the reference token or null of the object didn't contain
	 *          a valid String
	 */
	public static ReferenceToken parse(CBORObject ob) {
	   if (ob.getType().equals(CBORType.ByteString)) {
	       return new ReferenceToken(ob.GetByteString());
	   } 
	   return null;
	}

    @Override
    public String getCti() throws AceException {
        return this.refS;
    }
}
