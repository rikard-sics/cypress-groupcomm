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

import java.util.Map;

import com.upokecenter.cbor.CBORObject;

/**
 * A class implementing the Group OSCORE Input Material Object, as defined in draft-ace-key-groupcomm-oscore
 * This Object is encoded as a CBOR Map.
 *  
 * @author Marco Tiloca
 *
 */
public class GroupOSCOREInputMaterialObject extends OSCOREInputMaterialObject {
	    
	/**
	 * Creates a new Group OSCORE Security Input Material from one provided as argument.
	 * 
	 * @param myMap the map of parameters
	 */
    public GroupOSCOREInputMaterialObject(Map<Short, CBORObject> myMap) {
    	
    	super(myMap);
    	
    }
    
    /**
	 * Return the Group OSCORE Input Material Object as a CBOR Map.
	 * 
	 * @param the map representing the Group OSCORE Input Material Object.
	 */
    @Override
    public CBORObject getAsCbor() {
    	
    	return OSCOREInputMaterialObjectParameters.getCBOR(this.myMap);
    	
    }
	    
}
