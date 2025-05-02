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

import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import org.eclipse.californium.cose.AlgorithmID;

/**
 * Constants for use with the ACE framework.
 * 
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class Constants {
	
    /**
     * Charset for this library
     */
    public static final Charset charset = Charset.forName("UTF-8");
    
    
    /**
     * AS Request Creation Hints  ========================================================
     */
    
    /**
     * The authorization server address
     */
    public static final short AS = 1; // Major type 3 (text string)
   
    /**
     * The key identifier
     */
    public static final short KID = 2;
    
    //AUDIENCE = 5 as defined for the token endpoint parameters
    
    //SCOPE = 9 as defined for the token endpoint parameters
    
    //CNONCE = 39 as defined for the token endpoint parameters
    
    /**
     * Abbreviations for OAuth error codes ====================================
     */
    
    /**
     * The request is missing a required parameter, includes an
     * unsupported parameter value (other than grant type),
     * repeats a parameter, includes multiple credentials,
     * utilizes more than one mechanism for authenticating the
     * client, or is otherwise malformed.
     */
    public static final short INVALID_REQUEST = 1;
    
    /**
     * Client authentication failed
     */
    public static final short INVALID_CLIENT = 2;
    
    /**
     * The provided authorization grant or refresh token is
     * invalid, expired, revoked, does not match the redirection
     * URI used in the authorization request, or was issued to
     * another client.
     */ 
    public static final short INVALID_GRANT = 3;
    
    /**
     * The authenticated client is not authorized to use this
     * authorization grant type.
     */
    public static final short UNAUTHORIZED_CLIENT = 4;
    
    /**
     *  The authorization grant type is not supported by the
     *  authorization server.
     */
    public static final short UNSUPPORTED_GRANT_TYPE = 5;
    
    /**
     * The requested scope is invalid, unknown, malformed, or
     * exceeds the scope granted by the resource owner.
     */
    public static final short INVALID_SCOPE = 6;
    
    /**
     * The RS does not support the requestest pop key type
     */
    public static final short UNSUPPORTED_POP_KEY = 7;
    
    /**
     * The client and the RS do not share a common profile
     */
    public static final short INCOMPATIBLE_PROFILES = 8;
    
    /**
     * The string values for these abbreviations
     */
    public static final String[] ERROR_CODES 
        = {"", "invalid_request", "invalid_client", "invalid_grant", 
                "unauthorized_client", "unsupported_grant_type", 
                "invalid_scope", "unsupported_pop_key", 
                "incompatible_profiles"};
    
    
    
    /**
     * Abbreviations for OAuth grant types ====================================
     */
    
    /**
     * grant type password  
     */
    public static final short GT_PASSWORD = 0;
    
    /**
     * grant type authorization code
     */
    public static final short GT_AUTHZ_CODE = 1;
    
    /**
     * grant type client credentials
     */
    public static final short GT_CLI_CRED = 2;
    
    /**
     * grant type refresh token
     */
    public static final short GT_REF_TOK = 3;
    
    
    
    
    
	/** 
	 * OAuth token endpoint abbreviations =====================================
	 */
    
    /**
     * The access token
     */
    public static final short ACCESS_TOKEN = 1; // 3
    
    /**
     * The time when this token expires (in Epoch time)
     */
    public static final short EXPIRES_IN = 2; // 0
    
    /**
     * The requested public key for proof-of-possession
     */
    public static final short REQ_CNF = 4;
        
    /**
     * The requested audience of an access token
     */
    public static final short AUDIENCE = 5;
        
    /**
     * The proof-of-possession key selected by the AS
     */
    public static final short CNF = 8; //Major type 5 (map)
      
    /**
     * The scope of an access token
     */
    public static final short SCOPE = 9; //3
    
 
    /**
     * The client identifier in a token request
     */
    public static final short CLIENT_ID = 24; //3
    
    /**
     * The client password in a token request for certain grant types
     */
    public static final short CLIENT_SECRET = 25; //2
   
    /**
     * The response type (see 
     * https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#endpoint)
     */
    public static final short RESPONSE_TYPE = 26; //3
    
    /**
     * The redirect URI
     */
    public static final short REDIRECT_URI = 27; //3  
    
    /**
     * An opaque value used by the client to maintain
     *    state between the request and callback. 
     */
    public static final short STATE = 28; //3
    
    /**
     * The authorization code generated by the
     *   authorization server.
     */
    public static final short CODE = 29; //2
    
    /**
     * The error code
     */
    public static final short ERROR = 30; //0
    
    /**
     * Human-readable ASCII text providing
     *    additional information on an error
     */
    public static final short ERROR_DESCRIPTION = 31; //3
    
    /**
     * A URI identifying a human-readable web page with
     * information about the error,
     */
    public static final short ERROR_URI = 32; //3
    
    /**
     * The grant type (e.g. "client_credentials")
     */
    public static final short GRANT_TYPE = 33;// Major type 0 (uint)
       
    /**
     * The type of the access token, e.g. "pop" or "bearer"
     */
    public static final short TOKEN_TYPE = 34; // 0
    
    /**
     * The username, for a username/password grant
     */
    public static final short USERNAME = 35; //3
    
    /**
     * The password, for a username/password grant
     */
    public static final short PASSWORD = 36; //3
    
    /**
     * The refresh token
     */
    public static final short REFRESH_TOKEN = 37; //3
        
    /**
     * The profile to be used between client and RS
     */
    public static final short PROFILE = 38; //0
            
    /**
     * The client nonce obtained from the AS Request Creation Hints
     */
    public static final short CNONCE = 39;
    
    /**
     * The public key of the RS
     */
    public static final short RS_CNF = 41;
    
    
    /** 
     * OAuth introspection endpoint abbreviations =============================
     */
    
    /**
     * The issuer of an access token
     */
	public static final short ISS = 1; // Major type 3 (text string)
	
	/**
	 * The subject of an access token
	 */
	public static final short SUB = 2; //3
	
	/**
	 * The audience of an access token
	 */
	public static final short AUD = 3; //3
	
	/**
	 * The expiration time of an access token
	 * (in Epoch time)
	 */
	public static final short EXP = 4; // MT 6 tag 1 (Epoch-based date/time)
	
	/**
	 * The "not before" time of an access token (in Epoch time)
	 */
	public static final short NBF = 5; // 6t1
	
	/**
	 * The time an access token was issues (in Epoch time)
	 */
	public static final short IAT = 6; // 6t1
	
	/**
	 * The access token identifier
	 */
	public static final short CTI = 7; // Major type 2 (byte string)
	
	//cnf = 8  	
    //scope = 9
	
    /**
     * A boolean indicating if a token is active in an introspection response
     */
    public static final short ACTIVE = 10; // boolean
    
    /**
     * The token in an introspection request
     */
    public static final short TOKEN = 11; // 3
  	
    //client_id = 24
	//error = 30
	//error_description = 31
	//error_uri = 32

	/**
	 * A hint for the AS about the type of token in an introspection request
	 */
	public static final short TOKEN_TYPE_HINT = 33; //3
	
	//token_type = 34
	//username = 35
		
	//profile = 38  
	//cnonce = 39
	//rs_cnf = 40

    /**
     * The expiration of the token in seconds from when it first was seen by the RS.
     */
    public static final short EXI = 40; //0
	
	/**
	 * CWT claims abbreviations ===============================================
	 */
    
    /**
     * Abbreviation for the sentinel claim used only for token storage at the AS.
     * That is, this claim is not included in the access token sent on the wire.
     * 
     * In case of introspection, this claim signals that the EXP claim has been
     * added after the actual creation of the access token, if this was initially
     * created with the EXI claim but without the EXP claim.
     * 
     * The "sentinel claim" has CBOR abbreviation 0, which is reserved.
     * A value smaller than -65536 ("private use") would be more appropriate,
     * but it would not be representable through the short integer type already
     * used for the keys in the maps encoding claim sets.
     */
	public static final short LATE_ADDED_EXP = 0;
    
	//iss = 1
	//sub = 2
	//aud = 3
	//exp = 4
	//nbf = 5
	//iat = 6
	//cti = 7
	//cnf = 8
	//scope = 9
	//profile = 38
    //cnonce = 39
	//rs_cnf = 40
    //exi = 40

   /**
    * Token type abbreviations ================================================
    */
	
	/**
	 * Abbreviation identifying a bearer token
	 */
	public static final short BEARER = 1;
	
	/**
	 * Abbreviation identifying a proof-of-possession token
	 */	
	public static final short POP = 2;


	/**
	 * Authz-Info error abbreviations ========================================
	 */
	//invalid request = 1

	/**
	 * The access token provided is expired, revoked, malformed, or
	 *  invalid for other reasons. 
	 */
	public static final short INVALID_TOKEN = 9; 

	/**
	 * The request requires higher privileges than provided by 
	 * the access token.
	 */
	public static final short INSUFFICIENT_SCOPE = 10;


	/**
	 * OSCORE_Input_Material abbreviations =================================
	 */  

	/**
	 * The outer map key of a OSCORE_Input_Material object
	 * Specified in RFC9203
	 */
	public static final CBORObject OSCORE_Input_Material
	    = CBORObject.FromObject(4);

    /**
     * The input material identifier
     */
    public static final CBORObject OS_ID = CBORObject.FromObject(0);
	
	/**
	 * The version
	 */
	public static final CBORObject OS_VERSION = CBORObject.FromObject(1);
	
	/**
	 * The master secret
	 */
	public static final CBORObject OS_MS = CBORObject.FromObject(2);
	
    /**
     * The HKDF algorithm
     */
    public static final CBORObject OS_HKDF = CBORObject.FromObject(3);

    /**
     * The AEAD algorithm
     */
    public static final CBORObject OS_ALG = CBORObject.FromObject(4);

    /**
     * The Master Salt
     */
    public static final CBORObject OS_SALT = CBORObject.FromObject(5);
    
    /**
     * The Id Context
     */
    public static final CBORObject OS_CONTEXTID = CBORObject.FromObject(6);
    
	/**
	 * The client Id
	 */
	public static final CBORObject OS_CLIENTID = CBORObject.FromObject(-65537);

	/**
	 * The server Id
	 */
	public static final CBORObject OS_SERVERID = CBORObject.FromObject(-65538);


    /**
     * Default value for alg
     */
    public static final short OS_DEFAULT_ALG 
        = AlgorithmID.AES_CCM_16_64_128.AsCBOR().AsNumber().ToInt16Checked();

    
    /**
     * Default value for hkdf
     */
    public static final short OS_DEFAULT_HKDF 
        = AlgorithmID.HMAC_SHA_256.AsCBOR().AsNumber().ToInt16Checked();
    
	/**
	 * RESTful action names ===================================================
	 */
	public static final String[] RESTACTIONS 
	= {"GET", "POST", "PUT", "DELETE"};


	/**
	 * Abbreviations for the cnf parameter/claim ==============================
	 */

	/**
	 * A cnf containing a COSE_Key
	 */
	public static final short COSE_KEY = 1;

    /**
     * ... same as above as CBORObject
     */
    public static final CBORObject COSE_KEY_CBOR 
        = CBORObject.FromObject(COSE_KEY);	
	
	/**
	 * A cnf containing a COSE_Encrypted wrapping a COSE_Key
	 */
	public static final short COSE_ENCRYPTED = 2;
	
	/**
     * ... same as above as CBORObject
     */
    public static final CBORObject COSE_ENCRYPTED_CBOR 
        = CBORObject.FromObject(COSE_ENCRYPTED);
	
	/**
	 * A cnf containing just a key identifier
	 */
	public static final short COSE_KID = 3;
	
    /**
     * ... same as above as CBORObject
     */
    public static final CBORObject COSE_KID_CBOR 
        = CBORObject.FromObject(COSE_KID);
    

    /**
     * Searches an array of strings for the index of the given string.
     * @param array  an array of Strings
     * @param val  a String value
     * @return  the index of val in array
     */
    public static short getIdx(String[] array, String val) {
        if (val == null || array == null) {
            return -1;
        }
        for (short i=0; i<array.length; i++) {
            if (val.equals(array[i])) {
                return i;
            }
        }
        return -1;
    }
    
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
    
    /**
     * The string values for the grant type abbreviations (use for debugging)
     */
    public static final String[] GRANT_TYPES = {"password", 
            "authorization_code", "client_credentials", "refresh_token"};

    
    /**
     * The abbreviation code for the DTLS profile
     */
    public static final short COAP_DTLS = 1;
    
    /**
     * The abbreviation code for the OSCORE profile
     */
    public static final short COAP_OSCORE = 2;
    
    /**
     * Value for the label "nonce1" in the Token POST request for the OSCORE profile
     */
    public static final short NONCE1 = 40;
    
    /**
     * Value for the label "nonce2" in the Token POST request for the OSCORE profile
     */
    public static final short NONCE2 = 42;
    
    /**
     * Value for the label "ace_client_recipientid" in the Token POST request for the OSCORE profile
     */
    public static final short ACE_CLIENT_RECIPIENTID = 43;
    
    /**
     * Value for the label "ace_server_recipientid" in the Token POST request for the OSCORE profile
     */
    public static final short ACE_SERVER_RECIPIENTID = 44;
    
    /**
     * Return the abbreviated profile id for the full profile name.
     * 
     * @param profileStr  profile name
     * @return  the abbreviation
     */
    public static short getProfileAbbrev(String profileStr) {
        if (profileStr.equals("coap_dtls")) {
            return COAP_DTLS;
        } else if (profileStr.equals("coap_oscore")) {
            return COAP_OSCORE;
        } else {
            return -1;
        }
    }
    
    /**
     * Array of the human readable names for AS Request Creation Hints 
     * parameters.
     */
    public static String[] ABBREV_HINTS = new String[42];
    static {
        ABBREV_HINTS[1] = "AS";
        ABBREV_HINTS[2] = "kid";
        ABBREV_HINTS[5] = "audience";
        ABBREV_HINTS[9] = "scope";
        ABBREV_HINTS[39] = "cnonce";
    }
    
    /**
     * Array of the human readable names for the token parameters.
     */
    public static String[] ABBREV_TOKEN = new String[42];
    static {
        ABBREV_TOKEN[1] = "access_token"; 
        ABBREV_TOKEN[2] = "expires_in"; 
        ABBREV_TOKEN[4] = "req_cnf"; 
        ABBREV_TOKEN[5] = "audience"; 
        ABBREV_TOKEN[8] = "cnf"; 
        ABBREV_TOKEN[9] = "scope"; 
        ABBREV_TOKEN[24] = "client_id"; 
        ABBREV_TOKEN[25] = "client_secret"; 
        ABBREV_TOKEN[26] = "response_type"; 
        ABBREV_TOKEN[27] = "redirect_uri"; 
        ABBREV_TOKEN[28] = "state"; 
        ABBREV_TOKEN[29] = "code";
        ABBREV_TOKEN[30] = "error"; 
        ABBREV_TOKEN[31] = "error_description"; 
        ABBREV_TOKEN[32] = "error_uri"; 
        ABBREV_TOKEN[33] = "grant_type"; 
        ABBREV_TOKEN[34] = "token_type"; 
        ABBREV_TOKEN[35] = "username"; 
        ABBREV_TOKEN[36] = "password"; 
        ABBREV_TOKEN[37] = "refresh_token"; 
        ABBREV_TOKEN[38] = "profile"; 
        ABBREV_TOKEN[39] = "cnonce"; 
        ABBREV_TOKEN[41] = "rs_cnf";
    }
    
    /**
     * Array of the human readable names for the introspect parameters.
     */
    public static String[] ABBREV_INTROSPECT = new String[42];
    static {
        ABBREV_INTROSPECT[1] = "iss"; 
        ABBREV_INTROSPECT[2] = "sub"; 
        ABBREV_INTROSPECT[3] = "aud";
        ABBREV_INTROSPECT[4] = "exp"; 
        ABBREV_INTROSPECT[5] = "nbf"; 
        ABBREV_INTROSPECT[6] = "iat";
        ABBREV_INTROSPECT[7] = "cti"; 
        ABBREV_INTROSPECT[8] = "cnf"; 
        ABBREV_INTROSPECT[9] = "scope";
        ABBREV_INTROSPECT[10] = "active"; 
        ABBREV_INTROSPECT[11] = "token"; 
        ABBREV_INTROSPECT[24] = "client_id"; 
        ABBREV_INTROSPECT[30] = "error"; 
        ABBREV_INTROSPECT[31] = "error_description"; 
        ABBREV_INTROSPECT[32] = "error_uri"; 
        ABBREV_INTROSPECT[33] = "token_type_hint"; 
        ABBREV_INTROSPECT[34] = "token_type"; 
        ABBREV_INTROSPECT[35] = "username"; 
        ABBREV_INTROSPECT[38] = "profile"; 
        ABBREV_INTROSPECT[39] = "cnonce";
        ABBREV_INTROSPECT[40] = "exi";
        ABBREV_INTROSPECT[41] = "rs_cnf";
    }
    
    /**
     * Array of the human readable names for the CWT claims
     */
    public static String[] ABBREV_CWT = new String[42];
    static {
        ABBREV_CWT[1] = "iss"; 
        ABBREV_CWT[2] = "sub"; 
        ABBREV_CWT[3] = "aud";
        ABBREV_CWT[4] = "exp"; 
        ABBREV_CWT[5] = "nbf"; 
        ABBREV_CWT[6] = "iat";
        ABBREV_CWT[7] = "cti"; 
        ABBREV_CWT[8] = "cnf"; 
        ABBREV_CWT[9] = "scope";
        ABBREV_CWT[38] = "profile"; 
        ABBREV_CWT[39] = "cnonce";
        ABBREV_CWT[40] = "exi";
        ABBREV_CWT[41] = "rs_cnf";
    }
    
    /**
     * Type identifier for AS Request Creation Hints abbreviations
     */
    public static final short ABBREV_TYPE_HINTS = 0;
    
    /**
     * Type identifier for Token endpoint parameter abbreviations
     */
    public static final short ABBREV_TYPE_TOKEN = 1;
    
    /**
     * Type identifier for Introspection endpoint parameter abbreviations
     */
    public static final short ABBREV_TYPE_INTROSPECT = 2;
    
    /**
     * Type identifier for CWT claims abbreviations
     */
    public static final short ABBREV_TYPE_CWT = 3;
    
    /**
     * Maps a parameter/claims map to the unabbreviated version.
     * 
     * @param map  the parameter/claims map to decode
     * @param type  the type of parameter/claim map to decode 
     *   (see constants ABBREV_TYPE_*) 
     * 
      * @return  the unabbreviated version of the map
      * @throws AceException  if map is not a CBOR map
     */
    public static Map<String, CBORObject> unabbreviate(
            CBORObject map, short type) throws AceException {                
        if (!map.getType().equals(CBORType.Map)) {
            throw new AceException("Parameter is not a CBOR map");
        }
        Map<String, CBORObject> ret = new HashMap<>();

        String[] abbrev;
        switch (type) {
        case ABBREV_TYPE_HINTS:
            abbrev = ABBREV_HINTS;
            break;
        case ABBREV_TYPE_TOKEN:
            abbrev = ABBREV_TOKEN;
            break;
        case ABBREV_TYPE_INTROSPECT:
            abbrev = ABBREV_INTROSPECT;
            break;
        case ABBREV_TYPE_CWT:
        default: 
            abbrev = ABBREV_CWT;
        }

        for (CBORObject key : map.getKeys()) {
            String keyStr = null;
            CBORObject obj = map.get(key);
            if (key.isNumber() && key.AsNumber().IsInteger()) {
                short keyInt = key.AsNumber().ToInt16Checked();
                if (keyInt > 0 && keyInt < abbrev.length) {
                   keyStr = abbrev[keyInt];
                    if (keyInt == GRANT_TYPE
                            && map.get(key).getType().equals(CBORType.Integer)) {
                        obj = CBORObject.FromObject(GRANT_TYPES[obj.AsInt32()]);
                    } else if (keyInt == ERROR
                            && map.get(key).getType().equals(CBORType.Integer)) {
                        obj = CBORObject.FromObject(ERROR_CODES[obj.AsInt32()]);
                    }                   
                } else {
                    throw new AceException("Malformed parameter map");
                }
            } else if (key.getType().equals(CBORType.TextString)) {
                keyStr = key.AsString();
            } else {
                throw new AceException("Malformed parameter map");
            }
            ret.put(keyStr, obj);
        }
       return ret;
    }
    
    /**
     * Representation of GET
     */
    public static final short GET = 1;
    
    /**
     *  Representation of POST
     */
    public static final short POST = 2;
    
    /**
     *  Representation of PUT
     */
    public static final short PUT = 3;
    
    /**
     *  Representation of DELETE
     */
    public static final short DELETE = 4;
    
    /**
     * Representation of FETCH
     */
    public static final short FETCH = 5;
    
    /**
     * Representation of PATCH
     */
    public static final short PATCH = 6;
    
    /**
     * Representation of iPATCH
     */
    public static final short iPATCH = 7;
    
    

    /**
     * Content-Format ace+cbor
     */
    public static final int APPLICATION_ACE_CBOR = 19;
    
    /**
     * Content-Format ace-groupcomm+cbor
     */
    public static final int APPLICATION_ACE_GROUPCOMM_CBOR = 65001;
    
    
    /**
	 * Group OSCORE abbreviations =================================
	 */

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
      * Value for the label "get_creds" in the Join Request message
      */
     public static final short GET_CREDS = 101;
     
     /**
      * Value for the label "client_cred" in the Join Request message
      */
     public static final short CLIENT_CRED = 102;
     
     /**
      * Value for the label "client_cred_verify" in the Join Request message
      */
     public static final short CLIENT_CRED_VERIFY = 103;
     
     /**
      * Value for the label "gkty" in the Join Response message
      */
     public static final short GKTY = 1;
     
     /**
      * Value for the label "key" in the Join Response message
      */
     public static final short KEY = 2;
     
     /**
      * Value for the label "creds" in the Join Response message
      */
     public static final short CREDS = 3;
     
     /**
      * Value for the label "ace-groupcomm-profile" in the Join Response message
      */
     public static final short ACE_GROUPCOMM_PROFILE = 38;
     
     /**
      * Value for the label "sign_info" in the Token POST request/response and in the error response to the Join Request
      */
     public static final short SIGN_INFO = 203;
     
     /**
      * Value for the label "ecdh_info" in the Token POST request/response and in the error response to the Join Request
      */
     public static final short ECDH_INFO = 204;
     
     /**
      * Value for the label "kdc_dh_creds" in the Token POST request/response and in the error response to the Join Request
      */
     public static final short KDC_DH_CREDS = 205;
     
     /**
      * Value for the label "kdcchallenge" in the Token POST response
      */
     public static final short KDCCHALLENGE = 206;
     
     /**
      * Value for the label "num" in the Join Response message
      */
     public static final short NUM = 207;
     
     /**
      * Value for the label "group_policies" in the Join Response message
      */
     public static final short GROUP_POLICIES = 208;
     
     /**
      * Value for the label "peer_roles" in the Join Response message
      */
     public static final short PEER_ROLES = 209;
     
     /**
      * Value for the label "peer_identifiers" in the Join Response message
      */
     public static final short PEER_IDENTIFIERS = 210;
     
     /**
      * Value for the label "kdc_nonce" in the Join Response message
      */
     public static final short KDC_NONCE = 211;
     
     /**
      * Value for the label "kdc_cred" in the Join Response message
      */
     public static final short KDC_CRED = 212;
     
     /**
      * Value for the label "kdc_cred_verify" in the Join Response message
      */
     public static final short KDC_CRED_VERIFY = 213;
     
     /**
      * Value for the label "group_senderId" in the Key Renewal Response message
      */
     public static final short GROUP_SENDER_ID = 214;
     
     /**
      * Value for the label "gid" in the Group Name and URI Retrieval Request/Response message
      */
     public static final short GID = 215;
     
     /**
      * Value for the label "gname" in the Group Name and URI Retrieval Response message
      */
     public static final short GNAME = 216;
     
     /**
      * Value for the label "guri" in the Group Name and URI Retrieval Response message
      */
     public static final short GURI = 217;
     
     /**
      * Value for the label "group_key_enc" in the Signature Verification Data Response message
      */
     public static final short GROUP_KEY_ENC = 218;
     
     
     /**
      * Value for the group key type "Group_OSCORE_Input_Material object"
      */
     public static final short GROUP_OSCORE_INPUT_MATERIAL_OBJECT = 1;
     
     /**
      * Value for the application profile "coap_group_oscore_app"
      */
     public static final short COAP_GROUP_OSCORE_APP = 1;
     
     
     /* Values for labels of group policies */
     /**
      * Value for the label of "Sequence Number Synchronization Method"
      * 
      * This policy is not used by this application profile
      */
     public static final short POLICY_SN_SYNCH = 1;
     
     /**
      * Value for the label of "Key Update Check Interval"
      * 
      * Default: 3600 s
      */
     public static final short POLICY_KEY_CHECK_INTERVAL = 2;
     
     /**
      * Value for the label of "Expiration delta"
      * 
      * Default: 0 s
      */
     public static final short POLICY_EXP_DELTA = 3;
     
     
     /**
      * COSE Header Parameters
      * https://www.iana.org/assignments/cose/cose.xhtml
      */
     public static final int COSE_HEADER_PARAM_X5CHAIN = 33;
     public static final int COSE_HEADER_PARAM_CWT = 36;
     public static final int COSE_HEADER_PARAM_CCS = 37;
     
}
