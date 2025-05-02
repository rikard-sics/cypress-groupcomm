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
package se.sics.ace.oscore;

import java.util.HashMap;
import java.util.Map;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import se.sics.ace.AceException;

/**
 * Constants for use in the OSCORE Input Material Object
 *  
 * @author Marco Tiloca
 *
 */
 
 public class OSCOREInputMaterialObjectParameters {

		/**
		 *  'id' - OSCORE Input Material Identifier
		 */
		public static final short id = 0;  // Major type 2 (byte string)
	 
		/**
		 *  'version' - OSCORE Master Secret Value
		 */
		public static final short version = 1;  // Major type 0 (unsigned integer)
	 
		/**
		 *  'ms' - OSCORE Master Secret Value
		 */
		public static final short ms = 2;  // Major type 2 (byte string)
		
		/**
		 *  'hkdf' - OSCORE HKDF value
		 */
		public static final short hkdf = 3; // Major type 0 (unsigned integer) or 1 (negative integer) or 3 (text string)
		
		/**
		 *  'alg' - OSCORE AEAD Algorithm value
		 */
		public static final short alg = 4; // Major type 0 (unsigned integer) or 1 (negative integer) or 3 (text string)
		
		/**
		 *  'salt' - OSCORE Master Salt Value
		 */
		public static final short salt = 5; // Major type 2 (byte string)
		
		/**
		 *  'contextId' - OSCORE ID Context Value
		 */
		public static final short contextId = 6; // Major type 2 (byte string)		
		
		/**
	     * The string values for the OSCORE Security Context Object parameter abbreviations (use for debugging)
	     */
	    public static final String[] CONTEXT_PARAMETER = {"id", "version", "ms", "hkdf", "alg", "salt", "contextId"};
	    
	    /**
	     * Takes a CBORObject that is a map and transforms it
	     * into Map<Short, CBORObject>
	     * @param cbor  the CBOR map
	     * @return  the Map
	     * @throws AceException if the cbor parameter is not a CBOR map or
	     *  if a key is not a short
	     */
	    public static Map<Short, CBORObject> getParams(CBORObject cbor) 
	            throws AceException {
	        if (!cbor.getType().equals(CBORType.Map)) {
	            throw new AceException("CBOR object is not a Map"); 
	        }
	        Map<Short, CBORObject> ret = new HashMap<>();
	        for (CBORObject key : cbor.getKeys()) {
	            if (!key.getType().equals(CBORType.Integer)) {
	                throw new AceException("CBOR key was not a Short: "
	                        + key.toString());
	            }
	            ret.put(key.AsNumber().ToInt16Checked(), cbor.get(key));
	        }
	        return ret;
	    }
	    
	    /**
	     * Takes a  Map<Short, CBORObject> and transforms it into a CBOR map.
	     * 
	     * @param map  the map
	     * @return  the CBOR map
	     */
	    public static CBORObject getCBOR(Map<Short, CBORObject> map) {
	        CBORObject cbor = CBORObject.NewMap();
	        for (Map.Entry<Short, CBORObject> e : map.entrySet()) {
	            cbor.Add(e.getKey(), e.getValue());
	        }
	        return cbor;
	    }
	 
 }
