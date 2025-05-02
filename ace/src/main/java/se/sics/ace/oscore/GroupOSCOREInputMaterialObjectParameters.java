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

/**
 * Constants for use in the OSCORE Input Material Object
 *  
 * @author Marco Tiloca
 *
 */
 
 public class GroupOSCOREInputMaterialObjectParameters extends OSCOREInputMaterialObjectParameters {

		/**
		 * 'group_SenderID' - Group OSCORE Countersignature Algorithm value
		 */
	    // Assume that "group_SenderID" is registered with label 7 in the
	    // "OSCORE Security Context Parameters" Registry defined in RFC9203
		public static final short group_SenderID = 7; // Major type 2 (byte string)
	 
		/**
		 *  'cs_key_enc' - Group OSCORE Public Key Encoding Value
		 */
		// Assume that "cred_fmt" is registered with label 8 in the
		// "OSCORE Security Context Parameters" Registry defined in RFC9203
		public static final short cred_fmt = 8; // Major type 0 (unsigned integer) or 1 (negative integer)
		
		/**
		 *  'sign_enc_alg' - Group OSCORE Signature Encryption Algorithm value 
		 */
		public static final short sign_enc_alg = 9; // Major type 0 (unsigned integer) or 1 (negative integer) or 3 (text string)
		
		/**
		 * 'sign_alg' - Group OSCORE Signature Algorithm value
		 */
	    // Assume that "sign_alg" is registered with label 10 in the
		// "OSCORE Security Context Parameters" Registry defined in RFC9203
		public static final short sign_alg = 10; // Major type 0 (unsigned integer) or 1 (negative integer) or 3 (text string)
		
		/**
		 *  'sign_params' - Group OSCORE Signature Algorithm Parameters value
		 */
		// Assume that "sign_params" is registered with label 11 in the
		// "OSCORE Security Context Parameters" Registry defined in RFC9203
		public static final short sign_params = 11; // Major type 4 (array)
		
		/**
		 * 'ecdh_alg' - Group OSCORE Pairwise Key Agreement Algorithm value
		 */
	    // Assume that "ecdh_alg" is registered with label 12 in the
		// "OSCORE Security Context Parameters" Registry defined in RFC9203
		public static final short ecdh_alg = 12; // Major type 0 (unsigned integer) or 1 (negative integer) or 3 (text string)
		
		/**
		 *  'ecdh_params' - Group OSCORE Pairwise Key Agreement Algorithm Parameters value
		 */
		// Assume that "ecdh_params" is registered with label 13 in the
		// "OSCORE Security Context Parameters" Registry defined in RFC9203
		public static final short ecdh_params = 13; // Major type 4 (array)
		
		/**
	     * The string values for the OSCORE Security Context Object parameter abbreviations (use for debugging)
	     */
	    public static final String[] CONTEXT_PARAMETER = {"id", "version", "ms", "hkdf", "alg", "salt", "contextId",
	    		"group_senderId, cred_fmt", "sign_enc_alg", "sign_alg", "sign_params", "ecdh_alg", "ecdh_params"};
	 
 }
