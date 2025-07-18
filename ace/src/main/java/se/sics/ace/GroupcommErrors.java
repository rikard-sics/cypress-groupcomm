/*******************************************************************************
 * Copyright (c) 2025, RISE AB
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

import com.upokecenter.cbor.CBORObject;

/**
 * Values for the labels of the ACE Groupcomm Errors
 * 
 * @author Marco Tiloca
 *
 */

public class GroupcommErrors {

	// Operation permitted only to group members
	public static final int ONLY_FOR_GROUP_MEMBERS = 0;
	
	// Request inconsistent with the current roles
	public static final int INCONSISTENCY_WITH_ROLES = 1;
	
	// Authentication credential incompatible with the group configuration
	public static final int INCOMPATIBLE_CRED = 2;
	
	// Invalid proof-of-possession evidence
	public static final int INVALID_POP_EVIDENCE = 3;
	
	// No available individual keying material
	public static final int UNAVAILABLE_INDIVIDUAL_KEYING_MATERIAL = 4;
	
	// Group membership terminated
	public static final int MEMBERSHIP_TERMINATED = 5;
	
	// Group deleted
	public static final int GROUP_DELETED = 6;
	
	
	// Defined in draft-ietf-ace-key-groupcomm-oscore
	
	// Signatures not used in the group
	public static final int SIGNATURES_NOT_USED = 7; // provisional
	
	// Operation permitted only to signature verifiers
	public static final int ONLY_FOR_SIGNATURE_VERIFIERS = 8; // provisional
	
	// Group currently not active
	public static final int GROUP_NOT_ACTIVE = 9; // provisional
	
	
	// Defined in draft-ietf-ace-oscore-gm-admin
	
	// Group currently active
	public static final int GROUP_ACTIVE = 10; // provisional
	
	// Unable to determine a group name
	public static final int GROUP_NAME_NOT_DETERMINED = 11; // provisional
	
	// Unsupported group configuration
	public static final int UNSUPPORTED_GROUP_CONF = 12; // provisional
	
	
	/**
     * The string values for the ACE Groupcomm errors
     */
    public static final String[] DESCRIPTION = {
    	/* 0 */ "Operation permitted only to group members", 
    	/* 1 */ "Request inconsistent with the current roles",
    	/* 2 */ "Authentication credential incompatible with the group configuration",
    	/* 3 */ "Invalid proof-of-possession evidence",
    	/* 4 */ "No available individual keying material",
    	/* 5 */ "Group membership terminated",
    	/* 6 */ "Group deleted",
    	
    	/* 7 */ "Signatures not used in the group", // provisional
    	/* 8 */ "Operation permitted only to signature verifiers", // provisional
    	/* 9 */ "Group currently not active", // provisional
    	
    	/* 10 */ "Group currently active", // provisional
    	/* 11 */ "Unable to determine a group name", // provisional
    	/* 12 */ "Unsupported group configuration" // provisional
    };

}
