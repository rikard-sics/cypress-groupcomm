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

import java.util.HashSet;
import java.util.Set;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.KeyKeys;

/**
 * Constants for use with ACE Groupcomm
 * 
 * @author Marco Tiloca
 *
 */

public class GroupcommParameters {
	
    /**
	 * Group OSCORE abbreviations =================================
	 */

	/*
	 * The prefixes used at the AS to internally represent scopes as text strings
	 */
	// This is relevant only for an admin scope entry,
	// where Toid is the wildcard group name pattern
	public static final String GROUP_OSCORE_AS_SCOPE_WILDCARD_PREFIX = "oscgm0";

	// This is relevant for an admin or user scope entry,
	// where Toid is a literal group name pattern (i.e., a specific group name)
	public static final String GROUP_OSCORE_AS_SCOPE_LITERAL_PREFIX = "oscgm1";

	// This is relevant only for an admin scope entry,
	// where Toid is a complex group name pattern (e.g., a regular expression)
	public static final String GROUP_OSCORE_AS_SCOPE_COMPLEX_PREFIX = "oscgm2";
	
    /**
     * The OSCORE group uses only the group mode
     */
    public static final short GROUP_OSCORE_GROUP_MODE_ONLY = 1;
    
    /**
     * The OSCORE group uses both the group mode and the pairwise mode
     */
    public static final short GROUP_OSCORE_GROUP_PAIRWISE_MODE = 2;
    
    /**
     * The OSCORE group uses only the pairwise mode
     */
    public static final short GROUP_OSCORE_PAIRWISE_MODE_ONLY = 3;
    
    
    /**
     * Requester role
     */
    public static final short GROUP_OSCORE_REQUESTER = 1;
    
    /**
     * Responder role
     */
    public static final short GROUP_OSCORE_RESPONDER = 2;
    
    /**
     * Monitor role
     */
    public static final short GROUP_OSCORE_MONITOR = 3;
    
    /**
     * Verifier role
     */
    public static final short GROUP_OSCORE_VERIFIER = 4;
    
    /**
     * Roles as strings
     */
    public static final String[] GROUP_OSCORE_ROLES = {"reserved", "requester", "responder", "monitor", "verifier"};
    
    /**
     * Return a set of integers including the valid Group OSCORE role combinations
	 *
     * @return  the set of valid Group OSCORE combinations
     */
    public static Set<Integer> getValidGroupOSCORERoleCombinations() {

    	Set<Integer> validRoleCombinations = new HashSet<Integer>();
    	
        // Set the valid combinations of roles in a Joining Request
        // Combinations are expressed with the AIF specific data model AIF-OSCORE-GROUPCOMM
        validRoleCombinations.add(1 << GROUP_OSCORE_REQUESTER);   // Requester (2)
        validRoleCombinations.add(1 << GROUP_OSCORE_RESPONDER);   // Responder (4)
        validRoleCombinations.add((1 << GROUP_OSCORE_REQUESTER) +
        		                  (1 << GROUP_OSCORE_RESPONDER)); // Requester+Responder (6)
        validRoleCombinations.add(1 << GROUP_OSCORE_MONITOR);     // Monitor (8)
    	
    	return validRoleCombinations;
    }
	
    /**
     * Admin permission "List"
     */
    public static final short GROUP_OSCORE_ADMIN_LIST = 0;
    
    /**
     * Admin permission "Create"
     */
    public static final short GROUP_OSCORE_ADMIN_CREATE = 1;
    
    /**
     * Admin permission "Read"
     */
    public static final short GROUP_OSCORE_ADMIN_READ = 2;
    
    /**
     * Admin permission "Write"
     */
    public static final short GROUP_OSCORE_ADMIN_WRITE = 3;
    
    /**
     * Admin permission "Delete"
     */
    public static final short GROUP_OSCORE_ADMIN_DELETE = 4;
    
    /**
     * Admin permissions as strings
     */
    public static final String[] GROUP_OSCORE_ADMIN_PERMISSIONS = {"list", "create", "read", "write", "delete"};
    
    
    /**
     * Value for the application profile "coap_group_oscore_app"
     */
    public static final short COAP_GROUP_OSCORE_APP = 1; // provisional
    
    
    /**
     * Value for the group key type "Group_OSCORE_Input_Material object"
     */
    public static final short GROUP_OSCORE_INPUT_MATERIAL_OBJECT = 1; // provisional
        
    
    /**
	 * CBOR abbreviations for the CoAP Content-Format application/ace-groupcomm+cbor =================================
	 */
    public static final CBORObject GID = CBORObject.FromObject(0);
    
    public static final CBORObject GNAME = CBORObject.FromObject(1);
    
    public static final CBORObject GURI = CBORObject.FromObject(2);
    
    public static final CBORObject SCOPE = CBORObject.FromObject(3);
    
    public static final CBORObject GET_CREDS = CBORObject.FromObject(4);
    
    public static final CBORObject CLIENT_CRED = CBORObject.FromObject(5);
    
    public static final CBORObject CNONCE = CBORObject.FromObject(6);
    
    public static final CBORObject GKTY = CBORObject.FromObject(7);
    
    public static final CBORObject KEY = CBORObject.FromObject(8);
    
    public static final CBORObject NUM = CBORObject.FromObject(9);
    
    public static final CBORObject ACE_GROUPCOMM_PROFILE = CBORObject.FromObject(10);
    
    public static final CBORObject EXP = CBORObject.FromObject(11);
    
    public static final CBORObject EXI = CBORObject.FromObject(12);
    
    public static final CBORObject CREDS = CBORObject.FromObject(13);
    
    public static final CBORObject PEER_ROLES = CBORObject.FromObject(14);
    
    public static final CBORObject PEER_IDENTIFIERS = CBORObject.FromObject(15);
    
    public static final CBORObject GROUP_POLICIES = CBORObject.FromObject(16);
    
    public static final CBORObject KDC_CRED = CBORObject.FromObject(17);
    
    public static final CBORObject KDC_NONCE = CBORObject.FromObject(18);
    
    public static final CBORObject KDC_CRED_VERIFY = CBORObject.FromObject(19);
    
    public static final CBORObject REKEYING_SCHEME = CBORObject.FromObject(20);
    
    public static final CBORObject CLIENT_CRED_VERIFY = CBORObject.FromObject(24);
    
    public static final CBORObject CREDS_REPO = CBORObject.FromObject(25);
    
    public static final CBORObject CONTROL_URI = CBORObject.FromObject(26);
    
    public static final CBORObject MGT_KEY_MATERIAL = CBORObject.FromObject(27);
    
    public static final CBORObject CONTROL_GROUP_URI = CBORObject.FromObject(28);
    
    public static final CBORObject SIGN_INFO = CBORObject.FromObject(29);
    
    public static final CBORObject KDCCHALLENGE = CBORObject.FromObject(30);

    
    // Defined in draft-ietf-ace-key-groupcomm-oscore
    
    public static final CBORObject GROUP_SENDER_ID = CBORObject.FromObject(21); // provisional
    
    public static final CBORObject ECDH_INFO = CBORObject.FromObject(31); // provisional
    
    public static final CBORObject KDC_DH_CREDS = CBORObject.FromObject(32); // provisional
    
    public static final CBORObject SIGN_ENC_KEY = CBORObject.FromObject(33); // provisional
    
    public static final CBORObject STALE_NODE_IDS = CBORObject.FromObject(34); // provisional
    
   
    // Defined in draft-ietf-ace-oscore-gm-admin
    
    public static final CBORObject HKDF = CBORObject.FromObject(-1); // provisional
    
    public static final CBORObject CRED_FMT = CBORObject.FromObject(-2); // provisional
    
    public static final CBORObject GROUP_MODE = CBORObject.FromObject(-3); // provisional
    
    public static final CBORObject GP_ENC_ALG = CBORObject.FromObject(-4); // provisional
    
    public static final CBORObject SIGN_ALG = CBORObject.FromObject(-5); // provisional
    
    public static final CBORObject SIGN_PARAMS = CBORObject.FromObject(-6); // provisional
    
    public static final CBORObject PAIRWISE_MODE = CBORObject.FromObject(-7); // provisional
    
    public static final CBORObject ALG = CBORObject.FromObject(-8); // provisional
    
    public static final CBORObject ECDH_ALG = CBORObject.FromObject(-9); // provisional
    
    public static final CBORObject ECDH_PARAMS = CBORObject.FromObject(-10); // provisional
        
    public static final CBORObject RT = CBORObject.FromObject(-11); // provisional
    
    public static final CBORObject ACTIVE = CBORObject.FromObject(-12); // provisional
    
    public static final CBORObject GROUP_NAME = CBORObject.FromObject(-13); // provisional
    
    public static final CBORObject GROUP_DESCRIPTION = CBORObject.FromObject(-14); // provisional
    
    public static final CBORObject MAX_STALE_SETS = CBORObject.FromObject(-15); // provisional
    
    public static final CBORObject GID_REUSE = CBORObject.FromObject(-16); // provisional
    
    public static final CBORObject APP_GROUPS = CBORObject.FromObject(-17); // provisional
    
    public static final CBORObject JOINING_URI = CBORObject.FromObject(-18); // provisional
    
    public static final CBORObject AS_URI = CBORObject.FromObject(-19); // provisional
    
    public static final CBORObject DET_REQ = CBORObject.FromObject(-25); // provisional
    
    public static final CBORObject DET_HASH_ALG = CBORObject.FromObject(-26); // provisional
    
    public static final CBORObject CONF_FILTER = CBORObject.FromObject(-27); // provisional
    
    public static final CBORObject APP_GROUPS_DIFF = CBORObject.FromObject(-28); // provisional
    
	/**
     * Check whether the specified parameter is meaningful, i.e., it is of the expected CBOR type
     * and it has the right value if it is of CBOR type simple value.
     * 
     * @param name  the CBOR abbreviation of the parameter to be checked
     * @param value  the value of the parameter to be checked
     * @return  true if the parameter is meaningful, or false if not meaningful or not recognized
     */
    public static boolean isAdminRequestParameterMeaningful(CBORObject name, CBORObject value) {
    	
		CBORType type = value.getType();
    	
    	if (name.equals(HKDF)) {
    		CBORType expectedType1 = CBORType.TextString;
    		CBORType expectedType2 = CBORType.Integer;
    		if ((type == expectedType1) || (type == expectedType2)) return true;
    		else return false;
    	}
    	
    	if (name.equals(CRED_FMT)) {
    		CBORType expectedType = CBORType.Integer;
    		if (type == expectedType) return true;
    		else return false;
    	}
    	
    	if (name.equals(GROUP_MODE)) {
    		CBORObject expectedValue1 = CBORObject.True;
    		CBORObject expectedValue2 = CBORObject.False;
    		if (value.equals(expectedValue1) || value.equals(expectedValue2)) return true;
    		else return false;
    	}
    	
    	if (name.equals(GP_ENC_ALG)) {
    		CBORType expectedType1 = CBORType.TextString;
    		CBORType expectedType2 = CBORType.Integer;
    		CBORObject expectedValue = CBORObject.Null;
    		if ((type == expectedType1) || (type == expectedType2) || value.equals(expectedValue)) return true;
    		else return false;
    	}
    	
    	if (name.equals(SIGN_ALG)) {
    		CBORType expectedType1 = CBORType.TextString;
    		CBORType expectedType2 = CBORType.Integer;
    		CBORObject expectedValue = CBORObject.Null;
    		if ((type == expectedType1) || (type == expectedType2) || value.equals(expectedValue)) return true;
    		else return false;
    	}
    	
    	if (name.equals(SIGN_PARAMS)) {
    		CBORType expectedType = CBORType.Array;
    		CBORObject expectedValue = CBORObject.Null;
    		if ((type == expectedType) || value.equals(expectedValue)) return true;
    		else return false;
    	}
    	
    	if (name.equals(PAIRWISE_MODE)) {
    		CBORObject expectedValue1 = CBORObject.True;
    		CBORObject expectedValue2 = CBORObject.False;
    		if (value.equals(expectedValue1) || value.equals(expectedValue2)) return true;
    		else return false;
    	}
    	
    	if (name.equals(ALG)) {
    		CBORType expectedType1 = CBORType.TextString;
    		CBORType expectedType2 = CBORType.Integer;
    		CBORObject expectedValue = CBORObject.Null;
    		if ((type == expectedType1) || (type == expectedType2) || value.equals(expectedValue)) return true;
    		else return false;
    	}
    	
    	if (name.equals(ECDH_ALG)) {
    		CBORType expectedType1 = CBORType.TextString;
    		CBORType expectedType2 = CBORType.Integer;
    		CBORObject expectedValue = CBORObject.Null;
    		if ((type == expectedType1) || (type == expectedType2) || value.equals(expectedValue)) return true;
    		else return false;
    	}
    	
    	if (name.equals(ECDH_PARAMS)) {
    		CBORType expectedType = CBORType.Array;
    		CBORObject expectedValue = CBORObject.Null;
    		if ((type == expectedType) || value.equals(expectedValue)) return true;
    		else return false;
    	}
    	
    	if (name.equals(DET_REQ)) {
    		CBORObject expectedValue1 = CBORObject.True;
    		CBORObject expectedValue2 = CBORObject.False;
    		if (value.equals(expectedValue1) || value.equals(expectedValue2)) return true;
    		else return false;
    	}
    	
    	if (name.equals(DET_HASH_ALG)) {
    		CBORType expectedType1 = CBORType.TextString;
    		CBORType expectedType2 = CBORType.Integer;
    		if ((type == expectedType1) || (type == expectedType2)) return true;
    		else return false;
    	}
    	
    	if (name.equals(ACTIVE)) {
    		CBORObject expectedValue1 = CBORObject.True;
    		CBORObject expectedValue2 = CBORObject.False;
    		if (value.equals(expectedValue1) || value.equals(expectedValue2)) return true;
    		else return false;
    	}
    	
    	if (name.equals(GROUP_NAME)) {
    		CBORType expectedType = CBORType.TextString;
    		if (type == expectedType) return true;
    		else return false;
    	}
    	
    	if (name.equals(GROUP_DESCRIPTION)) {
    		CBORType expectedType = CBORType.TextString;
    		CBORObject expectedValue = CBORObject.Null;
    		if ((type == expectedType) || value.equals(expectedValue)) return true;
    		else return false;
    	}

    	if (name.equals(MAX_STALE_SETS)) {
    		CBORType expectedType = CBORType.Integer;
    		if ((type == expectedType) && (value.AsInt32() > 1)) return true;
    		else return false;
    	}
    	
    	if (name.equals(EXP)) {
    		CBORType expectedType = CBORType.Integer;
    		if ((type == expectedType) && (value.AsInt32() > 0) && (value.AsInt64Value() > (System.currentTimeMillis() / 1000L))) return true;
    		else return false;
    	}
    	
    	if (name.equals(GROUP_POLICIES)) {
    		CBORType expectedType = CBORType.Map;
    		if (type == expectedType) return true;
    		else return false;
    	}
    	
    	if (name.equals(GID_REUSE)) {
    		CBORObject expectedValue1 = CBORObject.True;
    		CBORObject expectedValue2 = CBORObject.False;
    		if (value.equals(expectedValue1) || value.equals(expectedValue2)) return true;
    		else return false;
    	}
    	
    	if (name.equals(APP_GROUPS)) {
    		CBORType expectedType = CBORType.Array;
    		if (type == expectedType) return true;
    		else return false;
    	}
    	    	
    	if (name.equals(AS_URI)) {
    		CBORType expectedType = CBORType.TextString;
    		if (type == expectedType) return true;
    		else return false;
    	}
    	
    	if (name.equals(CONF_FILTER)) {
    		CBORType expectedType = CBORType.Array;
    		if (type == expectedType) return true;
    		else return false;
    	}
    	
    	if (name.equals(APP_GROUPS_DIFF)) {
    		CBORType expectedType = CBORType.Array;
    		if (type == expectedType) return true;
    		else return false;
    	}
    	
    	// Unrecognized parameter
    	return false;
    }
    
	/**
     * Check whether the specified parameter value is meaningful.
     * 
     * This takes into account admitted values altogether (e.g,. per the relevant COSE registries),
     * as well as the local support for algorithms and other functionalities at the Group Manager.
     * 
     * Note that the parameters have been checked already for being of the correct CBOR type.
     * The parameters of type CBOR simple value has also already been checked as to their value.
     * 
     * @param name  the CBOR abbreviation of the parameter to be checked
     * @param name  the value of the parameter to be checked
     * @return  true if the parameter value is meaningful, or false if not meaningful or not recognized
     */
    public static boolean isAdminParameterValueMeaningful(CBORObject name, CBORObject value) {
    	
    	if (name.equals(HKDF)) {
    		if (value.getType().equals(CBORType.Integer)) {
    			if (value.equals(AlgorithmID.HMAC_SHA_256.AsCBOR()) ||
    				value.equals(AlgorithmID.HMAC_SHA_512.AsCBOR())) {
    				return true;
    			}
    		}
    		return false;
    	}

    	if (name.equals(CRED_FMT)) {
			if (value.equals(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_X5BAG)) ||
				value.equals(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_X5CHAIN)) ||
				value.equals(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_KCWT)) ||
				value.equals(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_KCCS)) ||
				value.equals(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_C5B)) ||
				value.equals(CBORObject.FromObject(Constants.COSE_HEADER_PARAM_C5C))) {
				return true;
			}
    		return false;
    	}
    	
    	if (name.equals(GP_ENC_ALG)) {
    		if (value.getType().equals(CBORType.Integer)) {
    			if (value.equals(AlgorithmID.AES_CCM_16_64_128.AsCBOR()) ||
    				value.equals(AlgorithmID.AES_CCM_16_64_256.AsCBOR()) ||
    				value.equals(AlgorithmID.AES_CCM_64_64_128.AsCBOR()) ||
    				value.equals(AlgorithmID.AES_CCM_64_64_256.AsCBOR()) ||
    				value.equals(AlgorithmID.AES_CCM_16_128_128.AsCBOR()) ||
    				value.equals(AlgorithmID.AES_CCM_16_128_256.AsCBOR()) ||
    				value.equals(AlgorithmID.AES_CCM_64_128_128.AsCBOR()) ||
    				value.equals(AlgorithmID.AES_CCM_64_128_256.AsCBOR())) {
    				return true;
    			}
    		}
    		return false;
    	}
    	
    	if (name.equals(SIGN_ALG)) {
    		if (value.getType().equals(CBORType.Integer)) {
    			if (value.equals(AlgorithmID.EDDSA.AsCBOR()) ||
    				value.equals(AlgorithmID.ECDSA_256.AsCBOR()) ||
    				value.equals(AlgorithmID.ECDSA_384.AsCBOR()) ||
    				value.equals(AlgorithmID.ECDSA_512.AsCBOR())) {
    				return true;
    			}
    			// This Group Manager does not support RSA as signature algorithm
    		}
    		return false;
    	}
    	
    	if (name.equals(SIGN_PARAMS)) {
    		if (value.size() != 2)
    			return false;
    		if ((value.get(0).getType() != CBORType.Array) || (value.get(1).getType() != CBORType.Array))
    			return false;
    		if ((value.get(0).size() != 1) || (value.get(1).size() != 2))
    			return false;
    		
			CBORObject keyType = value.get(0).get(0);
			if (value.get(1).get(0).equals(keyType) == false)
				return false;
			
			CBORObject curve = value.get(1).get(1);
			if (keyType.equals(KeyKeys.KeyType_OKP)) {
				if (curve.equals(KeyKeys.OKP_Ed25519) || curve.equals(KeyKeys.OKP_Ed448)) {
					return true;
				}
			}
			if (keyType.equals(KeyKeys.KeyType_EC2)) {
				if (curve.equals(KeyKeys.EC2_P256) || curve.equals(KeyKeys.EC2_P384) || curve.equals(KeyKeys.EC2_P521)) {
					return true;
				}
			}
			// This Group Manager does not support RSA as signature algorithm
			
    		return false;
    	}
    	
    	if (name.equals(ALG)) {
    		if (value.getType().equals(CBORType.Integer)) {
    			if (value.equals(AlgorithmID.AES_CCM_16_64_128.AsCBOR()) ||
    				value.equals(AlgorithmID.AES_CCM_16_64_256.AsCBOR()) ||
    				value.equals(AlgorithmID.AES_CCM_64_64_128.AsCBOR()) ||
    				value.equals(AlgorithmID.AES_CCM_64_64_256.AsCBOR()) ||
    				value.equals(AlgorithmID.AES_CCM_16_128_128.AsCBOR()) ||
    				value.equals(AlgorithmID.AES_CCM_16_128_256.AsCBOR()) ||
    				value.equals(AlgorithmID.AES_CCM_64_128_128.AsCBOR()) ||
    				value.equals(AlgorithmID.AES_CCM_64_128_256.AsCBOR())) {
    				return true;
    			}
    		}
    		return false;
    	}
    	
    	if (name.equals(ECDH_ALG)) {
    		if (value.getType().equals(CBORType.Integer)) {
    			if (value.equals(AlgorithmID.ECDH_SS_HKDF_256.AsCBOR()) ||
    				value.equals(AlgorithmID.ECDH_SS_HKDF_512.AsCBOR())) {
    				return true;
    			}
    		}
    		return false;
    	}
    	
    	if (name.equals(ECDH_PARAMS)) {
    		if (value.size() != 2)
    			return false;
    		if ((value.get(0).getType() != CBORType.Array) || (value.get(1).getType() != CBORType.Array))
    			return false;
    		if ((value.get(0).size() != 1) || (value.get(1).size() != 2))
    			return false;
    		
			CBORObject keyType = value.get(0).get(0);
			if (value.get(1).get(0).equals(keyType) == false)
				return false;
			
			CBORObject curve = value.get(1).get(1);
			if (keyType.equals(KeyKeys.KeyType_OKP)) {
				if (curve.equals(KeyKeys.OKP_X25519) || curve.equals(KeyKeys.OKP_X448)) {
					return true;
				}
			}
			if (keyType.equals(KeyKeys.KeyType_EC2)) {
				if (curve.equals(KeyKeys.EC2_P256) || curve.equals(KeyKeys.EC2_P384) || curve.equals(KeyKeys.EC2_P521)) {
					return true;
				}
			}
			// This Group Manager does not support RSA as signature algorithm
			
    		return false;
    	}

    	if (name.equals(DET_HASH_ALG)) {
    		if (value.getType().equals(CBORType.Integer)) {
    			int hashAlg = value.AsInt32(); 
    			if (hashAlg == -16 || hashAlg == -43 || hashAlg ==  -44) { // SHA-256, SHA-384, SHA-512
    				return true;
    			}
    		}
    		return false;
    	}
    	
    	if (name.equals(GROUP_POLICIES)) {
    		Set<Integer> admittedPolicies = new HashSet<>();
    		admittedPolicies.add(GroupcommPolicies.KEY_CHECK_INTERVAL.AsInt32());
    		admittedPolicies.add(GroupcommPolicies.EXP_DELTA.AsInt32());
    		
    		for (CBORObject policyName : value.getKeys()) {
    			if (!admittedPolicies.contains(policyName.AsInt32()))
    				return false;
    			if (policyName.equals(GroupcommPolicies.KEY_CHECK_INTERVAL)) {
    				if (value.get(policyName).getType() != CBORType.Integer ||
    					value.get(policyName).AsInt32() < 0)
    					return false;
    			}
    			if (policyName.equals(GroupcommPolicies.EXP_DELTA)) {
    				if (value.get(policyName).getType() != CBORType.Integer ||
    					value.get(policyName).AsInt32() < 0)
    					return false;
    			}
    		}
    		
    		return true;
    	}
    	
    	if (name.equals(APP_GROUPS)) {

    		for (int i = 0; i < value.size(); i++) {
    			if (value.get(i).getType() != CBORType.TextString)
    				return false;
    		}
    		
    		return true;
    	}
    	
    	return true;
    	
    }
    
}
