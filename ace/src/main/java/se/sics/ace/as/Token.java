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
package se.sics.ace.as;

import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.Encrypt0Message;
import org.eclipse.californium.cose.HeaderKeys;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;

import se.sics.ace.AccessToken;
import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.Endpoint;
import se.sics.ace.Message;
import se.sics.ace.TimeProvider;
import se.sics.ace.Util;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;

/**
 * Implements the /token endpoint on the authorization server.
 * 
 * Note: If a client requests a scope that is not supported by (parts) of the 
 * audience this endpoint will just ignore that, assuming that the client will
 * be denied by the PDP anyway. This requires a default deny policy in the PDP.
 * 
 * Note: This endpoint assigns a cti to each issued token based on a counter. 
 * The same value is also used as kid for the proof-of-possession key
 * associated to the token by means of the 'cnf' claim.
 * 
 * Note: This endpoint assumes that the sender Id (the one you get from 
 * Message.getSenderId()) for a secure session created with a raw public key
 * is generated with 
 * org.eclipse.californium.scandium.auth.RawPublicKeyIdentity.getName()
 * 
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class Token implements Endpoint, AutoCloseable {
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(Token.class.getName());

    /**
     * Boolean for not verify
     */
    private static boolean sign = false;
    
	/**
	 * The PDP this endpoint uses to make access control decisions.
	 */
	private PDP pdp;
	
	/**
	 * The database connector for storing and retrieving stuff.
	 */
	private DBConnector db;
	
	/**
	 * The identifier of this AS for the iss claim.
	 */
	private String asId;
	
	/**
	 * The time provider for this AS.
	 */
	private TimeProvider time;
	
	/**
	 * The default expiration time of an access token
	 */
	private static long expiration = 1000 * 60 * 10; //10 minutes
	
	/**
	 * The counter for generating the cti
	 */
	private Long cti = 0L;

	/**
	 * The private key of the AS or null if there isn't any
	 */
	private OneKey privateKey;
    
    /**
     * The client credentials grant type as CBOR-integer
     */
	public static CBORObject clientCredentials 
	    = CBORObject.FromObject(Constants.GT_CLI_CRED);

	/**
	 * The authorizaton_code grant type as CBOR-integer
	 */
	public static CBORObject authzCode 
	    = CBORObject.FromObject(Constants.GT_AUTHZ_CODE);
	
	/**
	 * Converter to create the byte array from the cti number
	 */
	 private static ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
	 
	 /**
	  * The claim types included in tokens generated by this Token instance
	  */
	 private Set<Short> claims;
	 	 
	 private static Set<Short> defaultClaims = new HashSet<>();
	 
	 static {
	     defaultClaims.add(Constants.CTI);
	     defaultClaims.add(Constants.ISS);
	     defaultClaims.add(Constants.EXI);
	     defaultClaims.add(Constants.AUD);
	     defaultClaims.add(Constants.SCOPE);
	     defaultClaims.add(Constants.CNF);
	 }
	 
	 /**
	  * If true the AUD claim is inserted in the COSE header
      * of a CWT generated by this AS in order to be able to retrieve the right
      * keys when the CWT is presented by the client instead of the RS for 
      * introspection
	  */
	 private boolean setAudHeader = false;
	 
	 /**
	 * Incremented after having released an Access Token including OSCORE input material
	 * The current value is used for the 'id' parameter in the OSCORE Security Context object in 'cnf'
	 */
	 private int OSCORE_material_counter = 0;
	 
	 /**
	 * Store the association between the cti of an issued Access Token
	 * and the target audience intended to consume it.
	 */
	 private Map<String, String> cti2aud = new HashMap<>();

	 /**
	 * Store the association between the name of the Resource Server and the next value to use
	 * as Sequence Number to build the 'cti' claim when the 'exi' claim is included in the Access Token
	 * 
	 * The entry for a Resource Server is created when the first Access Token including 'exi' is issues,
	 * since the AS process has started. The initial value of the Sequence Number is retrieved from the database.
	 */
	 private Map<String, Integer> exiSequenceNumbers = new HashMap<>();
	 
	 /**
	 * Relevant only when the DTLS profile is used with symmetric PoP key
	 * 
	 * Store the association between the cti of an issued Acced Token and
	 * the 'kid' of the associated symmetric PoP key generated by the AS
	 */
	 private Map<String, CBORObject> cti2kid = new HashMap<>();
	 
	 /**
	 * Relevant only when the OSCORE profile is used
	 * 
	 * Store the association between the cti of an issued Acced Token
	 * and the ID identifying the OSCORE Input Material. Such an ID
	 * is stored as a CBOR byte string.
	 */
	 private Map<String, CBORObject> cti2oscId = new HashMap<>();
	 
	 /**
	  * Relevant only when the OSCORE profile is used
	  * 
	  * The size in bytes of the OSCORE Master Salt to provide to the Client
	  * and to include in the Token. It can be 0, to not provide a Master Salt.
	  */
	 private short masterSaltSize;
	 
	 /**
	  * Relevant only when the OSCORE profile is used
	  * 
	  * True if the OSCORE Id Context has to be provided, false otherwise
	  */
	 private boolean provideIdContext;
	 
	 /**
	  * Relevant only when the OSCORE profile is used
	  * 
	  * It specifies information on the next Id Context to assign for each Resource Server
	  */
	 private Map<String, IdContextInfo> idContextInfoMap = new HashMap<>(); 
	 
	 /**
	  * Mapping between security identities of the peers and their names; it can be null
	  * 
	  * This is relevant especially for the OSCORE profile, since all peers are registered in the
	  * AS database by nicknames. Instead, their OSCORE identities as retrieved from incoming OSCORE
	  * messages are structured base64 strings encoding the Context ID and Sender ID for that peer 
	 */ 
	private Map<String, String> peerIdentitiesToNames = null;
	 
	 
	/**
	 * Constructor using default set of claims.
	 * 
	 * @param asId  the identifier of this AS
	 * @param pdp   the PDP for deciding access
	 * @param db  the database connector
	 * @param time  the time provider
	 * @param privateKey  the private key of the AS or null if there isn't any
	 * @param peerIdentitiesToNames  mapping between security identities of the peers and their names; it can be null
	 * 
	 * @throws AceException  if fetching the cti from the database fails
	 */	
	public Token(String asId, PDP pdp, DBConnector db, 
	        TimeProvider time, OneKey privateKey,
	        Map<String, String> peerIdentitiesToNames) throws AceException {
	    this(asId, pdp, db, time, privateKey, defaultClaims, false, (short)0, false, peerIdentitiesToNames);
	}
	
	/**   
     * Constructor that allows configuration of the claims included in the token.
     *  
     * @param asId  the identifier of this AS
     * @param pdp   the PDP for deciding access
     * @param db  the database connector
     * @param time  the time provider
     * @param privateKey  the private key of the AS or null if there isn't any
     * @param claims  the claim types to include in tokens issued by this 
     *                Token instance
     * @param setAudInCwtHeader  if true the AUD claim is inserted in the COSE 
     * header of a CWT generated by this AS in order to be able to retrieve the
     * right keys when the CWT is presented by the client instead of the RS for
     * introspection
     * @param peerIdentitiesToNames  mapping between security identities of the peers and their names; it can be null
     * 
     * @throws AceException  if fetching the cti from the database fails
     */
    public Token(String asId, PDP pdp, DBConnector db, 
            TimeProvider time, OneKey privateKey,
            Set<Short> claims, boolean setAudInCwtHeader,
            Map<String, String> peerIdentitiesToNames) throws AceException {
        this(asId, pdp, db, time, privateKey, claims, setAudInCwtHeader, (short)0, false, peerIdentitiesToNames);
    }
	
	
	/**   
	 * Constructor that allows configuration of everything.
	 * 
     * @param asId  the identifier of this AS
     * @param pdp   the PDP for deciding access
     * @param db  the database connector
     * @param time  the time provider
     * @param privateKey  the private key of the AS or null if there isn't any
     * @param claims  the claim types to include in tokens issued by this 
     *                Token instance
     * @param setAudInCwtHeader  if true the AUD claim is inserted in the COSE 
     * header of a CWT generated by this AS in order to be able to retrieve the
     * right keys when the CWT is presented by the client instead of the RS for
     * introspection
     * @param masterSaltSize  the size in bytes of the OSCORE Master Salt
     * @param provideIdContext  true if the OSCORE Id Context has to be provided, false otherwise
     * @param peerIdentitiesToNames  mapping between security identities of the peers and their names; it can be null
     * 
     * @throws AceException  if fetching the cti from the database fails
	 */
	public Token(String asId, PDP pdp, DBConnector db, 
            TimeProvider time, OneKey privateKey, Set<Short> claims, 
            boolean setAudInCwtHeader, short masterSaltSize, boolean provideIdContext,
            Map<String, String> peerIdentitiesToNames) throws AceException {
		
		Set<Short> localClaims = claims;
        
		if(localClaims == null) {
			localClaims = defaultClaims;
		}

	    //Time for checks
        if (asId == null || asId.isEmpty()) {
            LOGGER.severe("Token endpoint's AS identifier was null or empty");
            throw new AceException(
                    "AS identifier must be non-null and non-empty");
        }
        if (pdp == null) {
            LOGGER.severe("Token endpoint's PDP was null");
            throw new AceException(
                    "Token endpoint's PDP must be non-null");
        }
        if (db == null) {
            LOGGER.severe("Token endpoint's DBConnector was null");
            throw new AceException(
                    "Token endpoint's DBConnector must be non-null");
        }
        if (time == null) {
            LOGGER.severe("Token endpoint's TimeProvider was null");
            throw new AceException("Token endpoint's TimeProvider "
                    + "must be non-null");
        }
        //All checks passed
        this.asId = asId;
        this.pdp = pdp;
        this.db = db;
        this.time = time;
        this.privateKey = privateKey;
        this.cti = db.getCtiCounter();
        this.claims = new HashSet<>();
        this.claims.addAll(localClaims);
        this.setAudHeader = setAudInCwtHeader;
        this.masterSaltSize = masterSaltSize;
        this.provideIdContext = provideIdContext;
        this.peerIdentitiesToNames = peerIdentitiesToNames;
        
	}

	@Override
	public Message processMessage(Message msg) {
		// Purge expired tokens from the database
		try {
			this.db.purgeExpiredTokens(this.time.getCurrentTime());
		} catch (AceException e) {
			LOGGER.severe("Database error: " + e.getMessage());
			return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}
		
	    if (msg == null) {//This should not happen
	        LOGGER.severe("Token.processMessage() received null message");
	        return null;
	    }
	    LOGGER.log(Level.INFO, "Token received message: " 
	            + msg.getParameters());
	    
	    //1. Check if this client can request tokens
		String id = msg.getSenderId();  
		if (id == null) {
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "unauthorized client: " + id);
            return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
		}
		
		if (peerIdentitiesToNames != null) {
		    id = peerIdentitiesToNames.get(id);
		    if (id == null) {
	            CBORObject map = CBORObject.NewMap();
	            map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
	            LOGGER.log(Level.INFO, "Message processing aborted: "
	                    + "unauthorized client: " + id);
	            return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
		    }
		}
		
		try {
            if (!this.pdp.canAccessToken(id)) {
                CBORObject map = CBORObject.NewMap();
                map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
                LOGGER.log(Level.INFO, "Message processing aborted: "
                        + "unauthorized client: " + id);
            	return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
            }
        } catch (AceException e) {
            LOGGER.severe("Database error: "
                    + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }
   
	    //2. Check that this is a supported grant type
	    if (msg.getParameter(Constants.GRANT_TYPE) == null
            //grant type == client credentials implied
	        || msg.getParameter(
	                Constants.GRANT_TYPE).equals(clientCredentials)) {
	        return processCC(msg);
	    } else if (msg.getParameter(Constants.GRANT_TYPE).equals(authzCode)) {
	        return processAC(msg);
	    }
	    CBORObject map = CBORObject.NewMap();
	    map.Add(Constants.ERROR, Constants.UNSUPPORTED_GRANT_TYPE);
	    LOGGER.log(Level.INFO, "Message processing aborted: "
	            + "unsupported_grant_type");
	    return msg.failReply(Message.FAIL_BAD_REQUEST, map); 	    
	}
	
	/**
	 * Process a Client Credentials grant.
	 * 
	 * @param msg  the message
	 * @param id  the identifier of the requester
	 * 
	 * @return  the reply
	 */
	private Message processCC(Message msg) {
	    String id = msg.getSenderId();
	    
		if (peerIdentitiesToNames != null) {
		    id = peerIdentitiesToNames.get(id);
		    if (id == null) {
	            CBORObject map = CBORObject.NewMap();
	            map.Add(Constants.ERROR, Constants.UNAUTHORIZED_CLIENT);
	            LOGGER.log(Level.INFO, "Message processing aborted: "
	                    + "unauthorized client: " + id);
	            return msg.failReply(Message.FAIL_UNAUTHORIZED, map);
		    }
		}
	    
		//3. Check if the request has a scope
		CBORObject cbor = msg.getParameter(Constants.SCOPE);
		Object scope = null;
		if (cbor == null) {
			try {
                scope = this.db.getDefaultScope(id);
            } catch (AceException e) {
                LOGGER.severe("Message processing aborted (checking scope): "
                        + e.getMessage());
                return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
            }
		} else {
		    if (cbor.getType().equals(CBORType.TextString)) {
		        scope = cbor.AsString();
		    } else if (cbor.getType().equals(CBORType.ByteString)) {
		        scope = cbor.GetByteString();		        
		    } else {
		        CBORObject map = CBORObject.NewMap();
		        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
	            map.Add(Constants.ERROR_DESCRIPTION, 
	                    "Invalid datatype for scope");
	            LOGGER.log(Level.INFO, "Message processing aborted: "
	                    + "Invalid datatype for scope in message");
	            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		    }
		}
		if (scope == null) {
		    CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, "No scope found for message");
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "No scope found for message");
		    return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		}
		
		//4. Check if the request has an audience or if there is a default audience
		cbor = msg.getParameter(Constants.AUDIENCE);
		
		// The audience has to be a text string. A set is built for compatibility with other methods
		Set<String> aud = new HashSet<>();
		
		String audStr = ""; // used to save the audience for later, for possible update of access rights
		String oldCti = ""; // used to track the cti of a Token to supersede, in case of update of access rights
		
		if (cbor == null) {
		    try {
		        String dAud = this.db.getDefaultAudience(id);
		        if (dAud != null) {
		            aud.add(dAud);
		            audStr = new String(dAud);
		        }
            } catch (AceException e) {
                LOGGER.severe("Message processing aborted (checking aud): "
                        + e.getMessage());
                return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
            }
		} else {
			  if (cbor.getType().equals(CBORType.TextString)) {
				  aud.add(cbor.AsString());
				  audStr = new String(cbor.AsString());
		    } else {//error
		        CBORObject map = CBORObject.NewMap();
	            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
	            map.Add(Constants.ERROR_DESCRIPTION, 
	                    "Audience malformed");
	            LOGGER.log(Level.INFO, "Message processing aborted: "
	                    + "Audience malformed");
	            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		    }
		}
		if (aud.isEmpty()) {
		    CBORObject map = CBORObject.NewMap();
		    map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
		    map.Add(Constants.ERROR_DESCRIPTION, 
		            "No audience found for message");
		    LOGGER.log(Level.INFO, "Message processing aborted: "
		            + "No audience found for message");
		    return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		}
		

		//5. Check if the scope is allowed
		Object allowedScopes = null;
        try {
            allowedScopes = this.pdp.canAccess(id, aud, scope);
        } catch (AceException e) {
            LOGGER.severe("Message processing aborted (checking permissions): "
                    + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }
		if (allowedScopes == null) {	
		    CBORObject map = CBORObject.NewMap();
		    map.Add(Constants.ERROR, Constants.INVALID_SCOPE);
		    LOGGER.log(Level.INFO, "Message processing aborted: "
		            + "invalid_scope");
		    return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		}
		
		//6. Create token
		//Find supported token type
		Short tokenType = null;
        try {
            tokenType = this.db.getSupportedTokenType(aud);
        } catch (AceException e) {
            LOGGER.severe("Message processing aborted (creating token): "
                    + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }
		if (tokenType == null) {
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, "Audience incompatible on token type");
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "Audience incompatible on token type");
		    return msg.failReply(Message.FAIL_BAD_REQUEST, 
		           map);
		}
		
		boolean includeExi = this.claims.contains(Constants.EXI);
		// If the 'exi' claim is included, ensure that the 'cti' claim is also included 
		if (includeExi) {
			this.claims.add(Constants.CTI);
		}
		
		// The construction of 'cti' depends on the presence/absence of the 'exi' claim.
		//
		// If the 'exi' claim is not present, 'cti' is the serialization of a global counter.
		//
		// If the 'exi' claim is present, 'cti' is the serialization of two concatenated strings,
		// i.e., the name of the Resource Server and the current value of the Exi Sequence Number
		byte[] ctiB = null;
		String ctiStr = null;
		String rsName = null;
		int exiSeqNum = -1;
		if (!includeExi) {
			// The 'exi' claim is not included in the Access Token.
			// Thus, 'cti' can be easily built by using the related single counter
			ctiB = buffer.putLong(0, this.cti).array();
	        ctiStr = Base64.getEncoder().encodeToString(ctiB);
	        this.cti++;
		}
		else {
			// The 'exi' claim is included in the Access Token.
			// Thus, 'cti' has to be built according to a particular semantics, as the
			// serialization of the text string S1 = (S2 | S3), where S2 is the name of
			// the Resource Server and S3 is the text encoding of the Exi Sequence Number
			// to use for that Resource Server.
			
			// Determine the name of the Resource Server associated to the specified Audience
			Set<String> rsSet = new HashSet<>();
			try {
				rsSet = db.getRSS(audStr);
			} catch (AceException e) {
                LOGGER.severe("Message processing aborted: Error when retrieving the name"
                		+ " of the Resource Server with Audience " + audStr + " from the database.\n" + e.getMessage());
			    return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
			}
			// Check the the specified Audience is associated to exactly one Resource Server
			if (rsSet.size() != 1) {
	            CBORObject map = CBORObject.NewMap();
	            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
	            map.Add(Constants.ERROR_DESCRIPTION, "The 'exi' claim has to be included, thus Audience must contain"
	            		+ " exactly one Resource Server");
	            LOGGER.log(Level.INFO, "Message processing aborted: The 'exi' claim has to be included,"
	            		+ "thus Audience must contain exactly one Resource Server");
			    return msg.failReply(Message.FAIL_BAD_REQUEST, 
			           map);
			}
			for (String rs : rsSet)
				rsName = new String(rs);
			
			// Retrieve the value of the Exi Sequence Number to use for this Resource Server
			if (exiSequenceNumbers.containsKey(rsName)) {
				exiSeqNum = exiSequenceNumbers.get(rsName).intValue();
			}
			else {
				// This is going to be the first Access Token including the 'exi' claim issued to
				// this Resource Server since the AS process started. Then, retrieve the current
				// Exi Sequence Number value for this Resource Server from the database.
				try {
					exiSeqNum = db.getExiSequenceNumber(rsName);
				} catch (AceException e) {
	                LOGGER.severe("Message processing aborted: Error when retrieving the Exi Sequence Number"
	                		+ " for the Resource Server with Audience " + audStr + " from the database.\n" + e.getMessage());
				    return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
				}
			}

			// Update the local collection of Exi Sequence Numbers
			Integer newSeqNum = Integer.valueOf(exiSeqNum + 1);
			exiSequenceNumbers.put(rsName, newSeqNum);
			
			String rawCti = new String(rsName + String.valueOf(exiSeqNum));
			ctiB = rawCti.getBytes(Constants.charset);
	        ctiStr = Base64.getEncoder().encodeToString(ctiB);
			
		}
        

        //Find supported profile

        String profileStr = null;
        try {
            profileStr = this.db.getSupportedProfile(id, aud);
        } catch (AceException e) {
        	if (!includeExi) {
        		this.cti--; //roll-back
        	}
        	else {
        		//roll-back
        		exiSequenceNumbers.put(rsName, exiSeqNum);
        	}
            LOGGER.severe("Message processing aborted (finding profile): "
                    + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }
        if (profileStr == null) {
        	if (!includeExi) {
        		this.cti--; //roll-back
        	}
        	else {
        		//roll-back
        		exiSequenceNumbers.put(rsName, exiSeqNum);
        	}
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INCOMPATIBLE_PROFILES);
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "No compatible profile found");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        }
        short profile = Constants.getProfileAbbrev(profileStr);
                
        if (tokenType != AccessTokenFactory.CWT_TYPE && tokenType != AccessTokenFactory.REF_TYPE) {
        	if (!includeExi) {
        		this.cti--; //roll-back
        	}
        	else {
        		//roll-back
        		exiSequenceNumbers.put(rsName, exiSeqNum);
        	}
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, "Unsupported token type");
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "Unsupported token type");
            return msg.failReply(Message.FAIL_NOT_IMPLEMENTED, map);
        }
       
        // This flag will be set to true if the Token is intended to update access rights
        boolean updateAccessRights = false;
        
        String keyType = null; //Save the key type for later
		Map<Short, CBORObject> claims = new HashMap<>();
		
		//ISS SUB AUD EXP NBF IAT CTI SCOPE CNF RS_CNF PROFILE EXI
        for (Short c : this.claims) {
		    switch (c) {
		    case Constants.ISS:
		        claims.put(Constants.ISS, CBORObject.FromObject(this.asId));        
		        break;
            case Constants.SUB:
                claims.put(Constants.SUB, CBORObject.FromObject(id));
                break;
		    case Constants.AUD:
		        //Check if AUDIENCE is a singleton
		        if (aud.size() == 1) {
		            claims.put(Constants.AUD, CBORObject.FromObject(
		                    aud.iterator().next()));
		        } else {
		            claims.put(Constants.AUD, CBORObject.FromObject(aud));
		        }
		        break;
		    case Constants.EXP:
		        long now = this.time.getCurrentTime();
		        long exp = Long.MAX_VALUE;
		        try {
		            exp = this.db.getExpTime(aud);
		        } catch (AceException e) {
		            LOGGER.severe("Message processing aborted (setting exp): "
		                    + e.getMessage());
		            return msg.failReply(
		                    Message.FAIL_INTERNAL_SERVER_ERROR, null);
		        }
		        if (exp == Long.MAX_VALUE) { // == No expiration time found
		            //using default
		            exp = now + expiration;
		        } else {
		            exp = now + exp;
		        }
		        claims.put(Constants.EXP, CBORObject.FromObject(exp));
		        break;
		    case Constants.EXI:
		        long exi = Long.MAX_VALUE;
		        try {
                    exi = this.db.getExpTime(aud);
                } catch (AceException e) {
                    LOGGER.severe("Message processing aborted (setting exp): "
                            + e.getMessage());
                    return msg.failReply(
                            Message.FAIL_INTERNAL_SERVER_ERROR, null);
                }
		        if (exi == Long.MAX_VALUE) { // == No expiration time found
		            //using default
		            exi = expiration;
		        }
		        claims.put(Constants.EXI, CBORObject.FromObject(exi)); 
		        break;
		    case Constants.NBF:
		        //XXX: NBF is not configurable in this version
		        now = this.time.getCurrentTime();
		        claims.put(Constants.NBF, CBORObject.FromObject(now));
		        break;
		    case Constants.IAT:
		        now = this.time.getCurrentTime();
		        claims.put(Constants.IAT, CBORObject.FromObject(now));
		        break;
		    case Constants.CTI:
		        claims.put(Constants.CTI, CBORObject.FromObject(ctiB));
		        break;
		    case Constants.SCOPE:
		        claims.put(Constants.SCOPE, 
		                CBORObject.FromObject(allowedScopes));
		        break;
		    case Constants.CNF:
		    	CBORObject cnf = msg.getParameter(Constants.REQ_CNF);
		    	
		        if (cnf == null) { //The client wants to use PSK
		            keyType = "PSK"; //save for later
		            
		            //check if PSK is supported for proof-of-possession
		            try {
		                if (!isSupported(keyType, aud)) {
		                	if (!includeExi) {
		                		this.cti--; //roll-back
		                	}
		                	else {
		                		//roll-back
		                		exiSequenceNumbers.put(rsName, exiSeqNum);
		                	}
	                        CBORObject map = CBORObject.NewMap();
	                        map.Add(Constants.ERROR, 
	                                Constants.UNSUPPORTED_POP_KEY);
	                        LOGGER.log(Level.INFO, 
	                                "Message processing aborted: "
	                                + "Unsupported pop key type PSK");
	                        return msg.failReply(
	                                Message.FAIL_BAD_REQUEST, map);
		                }
		            } catch (AceException e) {
		            	if (!includeExi) {
		            		this.cti--; //roll-back
		            	}
		               	else {
		            		//roll-back
		            		exiSequenceNumbers.put(rsName, exiSeqNum);
		            	}
                        LOGGER.severe("Message processing aborted "
                                + "(finding key type): "
                                + e.getMessage());
                        return msg.failReply(
                                Message.FAIL_INTERNAL_SERVER_ERROR, null);
                    }   
 
		            // Audience supports PSK, make a new PSK
                    try {
                        KeyGenerator kg = KeyGenerator.getInstance("AES");

                        // OSCORE profile
                        if (profile == Constants.COAP_OSCORE) {
                            //Generate OSCORE cnf
                        	SecretKey key = kg.generateKey();
                            byte[] masterSecret = key.getEncoded();
                            CBORObject osc = makeOscoreCnf(masterSecret, audStr);
                            claims.put(Constants.CNF, osc);
                        }
                        // DTLS profile
                        else {
                        	// Make a DTLS style psk
                        	CBORObject keyData = CBORObject.NewMap();
                            CBORObject coseKey = CBORObject.NewMap();

                            keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
                            
                            //Note: kid is the same as cti 
                            byte[] kid = ctiB;
                        	keyData.Add(KeyKeys.KeyId.AsCBOR(), kid);
                            
                        	SecretKey key = kg.generateKey();
                        	keyData.Add(KeyKeys.Octet_K.AsCBOR(), 
                                	CBORObject.FromObject(key.getEncoded()));
                            
                        	OneKey psk = new OneKey(keyData);
                            coseKey.Add(Constants.COSE_KEY, psk.AsCBOR());
                            claims.put(Constants.CNF, coseKey);
                        }
                    } catch (NoSuchAlgorithmException | CoseException e) {
                    	if (!includeExi) {
                    		this.cti--; //roll-back
                    	}
                       	else {
                    		//roll-back
                    		exiSequenceNumbers.put(rsName, exiSeqNum);
                    	}
                        LOGGER.severe("Message processing aborted "
                                + "(making PSK): " + e.getMessage());
                        return msg.failReply(
                                Message.FAIL_INTERNAL_SERVER_ERROR, null);
                    }
		            
		        } else if (cnf.ContainsKey(Constants.COSE_KID_CBOR)) {
		            // The client requested a specific kid
		            
		            //Check that the kid is well-formed
		            CBORObject kidC = cnf.get(Constants.COSE_KID_CBOR);
		            if (!kidC.getType().equals(CBORType.ByteString)) {
		            	if (!includeExi) {
		            		this.cti--; //roll-back
		            	}
		               	else {
		            		//roll-back
		            		exiSequenceNumbers.put(rsName, exiSeqNum);
		            	}
		                LOGGER.info("Message processing aborted: "
		                        + " Malformed kid in request parameter 'cnf'");
		                CBORObject map = CBORObject.NewMap();
		                map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
		                map.Add(Constants.ERROR_DESCRIPTION, 
		                        "Malformed kid in 'cnf' parameter");
		                return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		            }
		            keyType = "KID";

                	// Check if the new Token is intended to update the access rights for this client
                    Set<String> ctiSet = new HashSet<>();
                	try {
                        ctiSet = this.db.getCtis4Client(id);
                        
					} catch (AceException e) {
						if (!includeExi) {
							this.cti--; //roll-back
						}
				       	else {
			        		//roll-back
			        		exiSequenceNumbers.put(rsName, exiSeqNum);
			        	}
                        LOGGER.severe("Message processing aborted "
                                + "(finding cti of issues tokens): "
                                + e.getMessage());
                        return msg.failReply(
                                Message.FAIL_INTERNAL_SERVER_ERROR, null);
					}
                	                	
                	if (ctiSet.size() != 0) {
                		// Some Tokens have been issued to this client.
                		
                		for (String myCti : ctiSet) {
                			
                			// Check that not only the Token was released at some point in time,
                			// but that it is also currently stored in the Database. If so, it
                			// is possible to retrieve a non empty set of claims through its cti. 
                			try {
								if (this.db.getClaims(myCti).size() == 0) {
									// A Token with this cti is not active anymore.
									// Continue with checking the next Token.
									
									// But first take the opportunity to clean up some other
									// data structures, which might not have happened already
							        this.cti2aud.remove(myCti);
							        this.cti2oscId.remove(myCti);
							        this.cti2kid.remove(myCti);
									
									continue;
								}
							} catch (AceException e) {
								if (!includeExi) {
									this.cti--; //roll-back
								}
						       	else {
					        		//roll-back
					        		exiSequenceNumbers.put(rsName, exiSeqNum);
					        	}
		                        LOGGER.severe("Message processing aborted "
		                                + "(finding previously released token): "
		                                + e.getMessage());
		                        return msg.failReply(
		                                Message.FAIL_INTERNAL_SERVER_ERROR, null);
							}
                			
                			String myAud = this.cti2aud.get(myCti);
                			
                    		// Check especially if the previously released Token was intended to
                    		// the same Resource Server intended to consume the just requested Token
                			if (myAud != null && audStr.equals(myAud)) {
                				
                				// Retrieve the claims of the previously released Token
                				Map<Short, CBORObject> myClaims = null;
                				try {
									myClaims = this.db.getClaims(myCti);
								} catch (AceException e) {
									if (!includeExi) {
										this.cti--; //roll-back
									}
							       	else {
						        		//roll-back
						        		exiSequenceNumbers.put(rsName, exiSeqNum);
						        	}
			                        LOGGER.severe("Message processing aborted "
			                                + "(finding previously released token): "
			                                + e.getMessage());
			                        return msg.failReply(
			                                Message.FAIL_INTERNAL_SERVER_ERROR, null);
								}
                				
            					CBORObject oldCnf = myClaims.get(Constants.CNF);
            					
            					if (oldCnf.get(Constants.COSE_KID) != null) {
            						if (Arrays.equals(kidC.GetByteString(), oldCnf.get(Constants.COSE_KID).GetByteString())) {
                                		// The new Token is intended to update access rights (not the first update in the series)
                                		updateAccessRights = true;
                                		oldCti = new String(myCti);
                                		break;
            						}
            						continue;
            					}
            					
                				// OSCORE profile
                				if (profile == Constants.COAP_OSCORE) {
            						if (Arrays.equals(kidC.GetByteString(),
            							oldCnf.get(Constants.OSCORE_Input_Material).get(Constants.OS_ID).GetByteString())) {
                                		// The new Token is intended to update access rights (first update in the series)
                                		updateAccessRights = true;
                                		oldCti = new String(myCti);
                                		break;
            						}
            						continue;
                				}
                				// DTLS profile
                				else {               					
            						if (Arrays.equals(kidC.GetByteString(),
            							oldCnf.get(Constants.COSE_KEY).get(KeyKeys.KeyId.AsCBOR()).GetByteString())) {
                                    		// The new Token is intended to update access rights (first update in the series)
                                    		updateAccessRights = true;
                                    		oldCti = new String(myCti);
                                    		break;
                						}
                						continue;
                				}                			
                			}
                		}
		            
	                	if (updateAccessRights == true) {
	                		// The new Token is intended to update access rights
	                	
	                		// OSCORE profile
	                		if (profile == Constants.COAP_OSCORE) {
			                	//Generate OSCORE cnf
				            	CBORObject oscId = this.cti2oscId.get(oldCti);
				            	if (oscId == null) {
			            			if (!includeExi) {
			            				this.cti--; //roll-back
			            			}
			            	       	else {
			                    		//roll-back
			                    		exiSequenceNumbers.put(rsName, exiSeqNum);
			                    	}
			                        LOGGER.severe("Message processing aborted "
			                                + "(finding OSCORE ID when updating access rights)");
			                        return msg.failReply(
			                                Message.FAIL_INTERNAL_SERVER_ERROR, null);
			            		}
			                    CBORObject osc = makeOscoreCnfUpdateAccessRights(oscId);
			                    claims.put(Constants.CNF, osc);
	                		}
	                		// DTLS profile
	                		else {
	                        	// Make a DTLS style psk
	                			CBORObject keyData = CBORObject.NewMap();
	                			CBORObject coseKey = CBORObject.NewMap();
	                			
	                		    keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
	
	                		    CBORObject kidCbor = this.cti2kid.get(oldCti);
	
	                		    keyData.Add(KeyKeys.KeyId.AsCBOR(), kidCbor);
	
	                		    coseKey.Add(Constants.COSE_KEY, keyData);
	                		    claims.put(Constants.CNF, coseKey);
	                		}
	                	}
	                	else {
	                        LOGGER.severe("Message processing aborted "
	                                + "(cannot find access token for which access right have to be updated)");
	                        CBORObject myMap = CBORObject.NewMap();
	                        myMap.Add(Constants.ERROR, Constants.UNSUPPORTED_POP_KEY);
	                        return msg.failReply(
	                                Message.FAIL_BAD_REQUEST, myMap);
	                    }	
                	}
		            
		        } else {//Client has provided a key 
		            //Check what key the client provided
		            OneKey key = null;
		            try {
		                key = getKey(cnf, id);
		            } catch (AceException | CoseException e) {
		            	if (!includeExi) {
		            		this.cti--; //roll-back
		            	}
		               	else {
		            		//roll-back
		            		exiSequenceNumbers.put(rsName, exiSeqNum);
		            	}
						LOGGER.severe("1Message processing aborted: "
		                        + e.getMessage());
		                if (e.getMessage().startsWith("Malformed")) {
		                    CBORObject map = CBORObject.NewMap();
		                    map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
		                    map.Add(Constants.ERROR_DESCRIPTION, 
		                            "Malformed 'cnf' parameter in request");
		                    return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		                } 
		                return msg.failReply(
		                        Message.FAIL_INTERNAL_SERVER_ERROR, null);
		            }
		            if (key == null) {
		            	if (!includeExi) {
		            		this.cti--; //roll-back
		            	}
		               	else {
		            		//roll-back
		            		exiSequenceNumbers.put(rsName, exiSeqNum);
		            	}
		                CBORObject map = CBORObject.NewMap();
		                map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
		                map.Add(Constants.ERROR_DESCRIPTION, 
		                        "Couldn't retrieve RPK");
		                LOGGER.log(Level.INFO, "Message processing aborted: "
		                        + "Couldn't retrieve RPK");
		                return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		            }
		            
		            if (key.get(KeyKeys.KeyType).equals(KeyKeys.KeyType_Octet)) {
		                //Client tried to submit a symmetric key => reject
		            	if (!includeExi) {
		            		this.cti--; //roll-back
		            	}
		               	else {
		            		//roll-back
		            		exiSequenceNumbers.put(rsName, exiSeqNum);
		            	}
		                CBORObject map = CBORObject.NewMap();
		                map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
		                map.Add(Constants.ERROR_DESCRIPTION, 
		                        "Client tried to provide cnf PSK");
		                LOGGER.log(Level.INFO, "Message processing aborted: "
		                        + "Client tried to provide cnf PSK");
		                return msg.failReply(Message.FAIL_BAD_REQUEST, map);
		            }
                    
		            //At this point we assume the client wants to use RPK
		            keyType = "RPK";
		            
		            //Check that the client used this RPK to create this session
		            try {
                        RawPublicKeyIdentity rpkId = new RawPublicKeyIdentity(
                                key.AsPublicKey());
                        if (!rpkId.getName().equals(id)) {
                        	if (!includeExi) {
                        		this.cti--; //roll-back
                        	}
                           	else {
                        		//roll-back
                        		exiSequenceNumbers.put(rsName, exiSeqNum);
                        	}
                            CBORObject map = CBORObject.NewMap();
                            map.Add(Constants.ERROR, 
                                Constants.UNSUPPORTED_POP_KEY);
                            LOGGER.log(Level.INFO, 
                                    "Message processing aborted: "
                                       + "Client used unauthenticated RPK");
                            return msg.failReply(
                                    Message.FAIL_BAD_REQUEST, map);
                        }
                        
                    } catch (CoseException e) {
                    	if (!includeExi) {
                    		this.cti--; //roll-back
                    	}
                       	else {
                    		//roll-back
                    		exiSequenceNumbers.put(rsName, exiSeqNum);
                    	}
                        CBORObject map = CBORObject.NewMap();
                        map.Add(Constants.ERROR, 
                            Constants.UNSUPPORTED_POP_KEY);
                        LOGGER.log(Level.INFO, 
                                "Message processing aborted: "
                                        + "Unsupported pop key type RPK");
                        LOGGER.log(Level.FINEST, e.getMessage());
                        return msg.failReply(
                                Message.FAIL_BAD_REQUEST, map);
                    }
                       
		            //Can the audience support this?
		            try {
		                if (!isSupported(keyType, aud)) {
		                	if (!includeExi) {
		                		this.cti--; //roll-back
		                	}
		                   	else {
		                		//roll-back
		                		exiSequenceNumbers.put(rsName, exiSeqNum);
		                	}
		                    CBORObject map = CBORObject.NewMap();
		                    map.Add(Constants.ERROR, 
                                Constants.UNSUPPORTED_POP_KEY);
		                    LOGGER.log(Level.INFO, 
		                            "Message processing aborted: "
		                                    + "Unsupported pop key type RPK");
		                    return msg.failReply(
		                            Message.FAIL_BAD_REQUEST, map);
		                }
		            } catch (AceException e) {
		            	if (!includeExi) {
		            		this.cti--; //roll-back
		            	}
		               	else {
		            		//roll-back
		            		exiSequenceNumbers.put(rsName, exiSeqNum);
		            	}
						LOGGER.severe("2Message processing aborted: "
		                        + e.getMessage());
		                return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		            }   
                    
		            //Audience support RPK, use provided RPK
		            CBORObject coseKey = CBORObject.NewMap();
		            coseKey.Add(Constants.COSE_KEY, key.AsCBOR());
		            claims.put(Constants.CNF, coseKey);
		        }
		        break;
		    case Constants.PROFILE:
		        claims.put(Constants.PROFILE, CBORObject.FromObject(profile));
		        break;
		    default :
		       LOGGER.severe("Unknown claim type in /token endpoint configuration: " + c);
		       return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);   
		    }
		}

		AccessToken token = null;
		try {
		    token = AccessTokenFactory.generateToken(tokenType, claims);
		} catch (AceException e) {
			if (!includeExi) {
				this.cti--; //roll-back
			}
	       	else {
        		//roll-back
        		exiSequenceNumbers.put(rsName, exiSeqNum);
        	}
		    
            // If the OSCORE profile is used, and this was a first-released Token
            // to this client for RS in question, roll-back the counter used for
            // the 'id' parameter in the OSCORE Security Context and the
	        // Id Context value assigned for this Resource Server
            if (profile == Constants.COAP_OSCORE && updateAccessRights == false) {
         	   this.OSCORE_material_counter--;
        	   if (this.idContextInfoMap.containsKey(audStr)) {
        		   this.idContextInfoMap.get(audStr).rollback();
        	   }
            }
		    
			LOGGER.severe("3Message processing aborted: "
		            + e.getMessage());
		    return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}
		
		CBORObject rsInfo = CBORObject.NewMap();
		try {
			
			boolean includeProfile = false;
			
		    if (!this.db.hasDefaultProfile(id)) {
		    	// This client supports multiple profiles; need to specify the exact one to use
		    	includeProfile = true;
		    }
		    else {
		    	CBORObject profileParameter = msg.getParameter(Constants.PROFILE);
		    	if (profileParameter != null && profileParameter.equals(CBORObject.Null)) {
			    	// The client has requested an explicit indication of the profile to use
		    		includeProfile = true;
		    	}
		    }

		    if (includeProfile == true) {
		    	rsInfo.Add(Constants.PROFILE, CBORObject.FromObject(profile));
		    }
		    // Otherwise, no need to explicitly indicate the used profile
		    
		} catch (AceException e) {
			if (!includeExi) {
				this.cti--; //roll-back
			}
	       	else {
        		//roll-back
        		exiSequenceNumbers.put(rsName, exiSeqNum);
        	}
		    
            // If the OSCORE profile is used, and this was a first-released Token
            // to this client for RS in question, roll-back the counter used for
            // the 'id' parameter in the OSCORE Security Context and the
	        // Id Context value assigned for this Resource Server
            if (profile == Constants.COAP_OSCORE && updateAccessRights == false) {
         	   this.OSCORE_material_counter--;
        	   if (this.idContextInfoMap.containsKey(audStr)) {
        		   this.idContextInfoMap.get(audStr).rollback();
        	   }
            }
		    
			LOGGER.severe("4Message processing aborted: "
		            + e.getMessage());
		    return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}

		if (keyType != null && keyType.equals("PSK")) {
			if (profile == Constants.COAP_OSCORE) {
				if (updateAccessRights == false) {
					rsInfo.Add(Constants.CNF, claims.get(Constants.CNF));
				}
				// Do not add 'cnf' if the OSCORE profile is used and
				// the Token is released for updating access rights
				
			}
			else {
				rsInfo.Add(Constants.CNF, claims.get(Constants.CNF));
			}
		}  else if (keyType != null && keyType.equals("RPK")) {
		    Set<CBORObject> rscnfs = new HashSet<>();
            try {
                rscnfs = makeRsCnf(aud);
            } catch (AceException e) {
            	if (!includeExi) {
            		this.cti--; //roll-back
            	}
               	else {
            		//roll-back
            		exiSequenceNumbers.put(rsName, exiSeqNum);
            	}
                
                // If the OSCORE profile is used, and this was a first-released Token
                // to this client for RS in question, roll-back the counter used for
                // the 'id' parameter in the OSCORE Security Context and the
		        // Id Context value assigned for this Resource Server
                if (profile == Constants.COAP_OSCORE && updateAccessRights == false) {
             	    this.OSCORE_material_counter--;
            	    if (this.idContextInfoMap.containsKey(audStr)) {
            	 	    this.idContextInfoMap.get(audStr).rollback();
            	    }
                }
                
				LOGGER.severe("5Message processing aborted: "
                        + e.getMessage());
                return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
            }
		    for (CBORObject rscnf : rscnfs) {
		        rsInfo.Add(Constants.RS_CNF, rscnf);
		    }
		} //Skip cnf if client requested specific KID.

		// Handle "scope" both as String and as Byte Array
		if (scope instanceof String && !allowedScopes.equals(scope)) {
		    rsInfo.Add(Constants.SCOPE, CBORObject.FromObject(allowedScopes));
		}
		if (scope instanceof byte[] && !(Arrays.equals((byte[])allowedScopes, (byte[])scope))) {
		    rsInfo.Add(Constants.SCOPE, CBORObject.FromObject(allowedScopes));
		}

		if (token instanceof CWT) {

		    CwtCryptoCtx ctx = null;
		    try {
		        ctx = EndpointUtils.makeCommonCtx(aud, this.db, 
		                this.privateKey, sign);
		    } catch (AceException | CoseException e) {
		    	if (!includeExi) {
		    		this.cti--; //roll-back
		    	}
		       	else {
	        		//roll-back
	        		exiSequenceNumbers.put(rsName, exiSeqNum);
	        	}
		        
                // If the OSCORE profile is used, and this was a first-released Token
                // to this client for RS in question, roll-back the counter used for
                // the 'id' parameter in the OSCORE Security Context and the
		        // Id Context value assigned for this Resource Server
                if (profile == Constants.COAP_OSCORE && updateAccessRights == false) {
            	    this.OSCORE_material_counter--;
            	    if (this.idContextInfoMap.containsKey(audStr)) {
            	 	    this.idContextInfoMap.get(audStr).rollback();
            	    }
                }
		        
				LOGGER.severe("6Message processing aborted: "
		                + e.getMessage());
		        return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		    }
		    if (ctx == null) {
		    	if (!includeExi) {
		    		this.cti--; //roll-back
		    	}
		       	else {
	        		//roll-back
	        		exiSequenceNumbers.put(rsName, exiSeqNum);
	        	}
		        
	            // If the OSCORE profile is used, and this was a first-released Token
	            // to this client for RS in question, roll-back the counter used for
	            // the 'id' parameter in the OSCORE Security Context and the
		        // Id Context value assigned for this Resource Server
	            if (profile == Constants.COAP_OSCORE && updateAccessRights == false) {
	            	this.OSCORE_material_counter--;
            	    if (this.idContextInfoMap.containsKey(audStr)) {
            	 	    this.idContextInfoMap.get(audStr).rollback();
            	    }
	            }
		        
		        CBORObject map = CBORObject.NewMap();
		        map.Add(Constants.ERROR, "No common security context found for audience");
		        LOGGER.log(Level.INFO, "Message processing aborted: No common security context found for audience");
		        return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, map);
		    }
		    CWT cwt = (CWT)token;
		    Map<HeaderKeys, CBORObject> uHeaders = null;
		    if (this.setAudHeader) {
		        // Add the audience as the KID in the header, so it can be referenced by introspection requests.
		        CBORObject requestedAud = CBORObject.NewArray();
		        for (String a : aud) {
		            requestedAud.Add(a);
		        }
		        uHeaders = new HashMap<>();
		        uHeaders.put(HeaderKeys.KID, requestedAud);
		    }
		    try {
		        rsInfo.Add(Constants.ACCESS_TOKEN, cwt.encode(ctx, null, uHeaders).EncodeToBytes());
		    } catch (IllegalStateException | InvalidCipherTextException | CoseException | AceException e) {
		    	if (!includeExi) {
		    		this.cti--; //roll-back
		    	}
		       	else {
	        		//roll-back		       		
	        		exiSequenceNumbers.put(rsName, exiSeqNum);
	        	}
		        
	            // If the OSCORE profile is used, and this was a first-released Token
	            // to this client for RS in question, roll-back the counter used for
	            // the 'id' parameter in the OSCORE Security Context and the
		        // Id Context value assigned for this Resource Server
	            if (profile == Constants.COAP_OSCORE && updateAccessRights == false) {
	            	this.OSCORE_material_counter--;
            	    if (this.idContextInfoMap.containsKey(audStr)) {
            	 	    this.idContextInfoMap.get(audStr).rollback();
            	    }
	            }
		        
				LOGGER.severe("7Message processing aborted: "
		                + e.getMessage());
		        return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		    }		    
		} else {
		    rsInfo.Add(Constants.ACCESS_TOKEN, token.encode().EncodeToBytes());
		}

		try {
			
			// If the claim set includes EXI but not EXP, then extend the claim set to be stored as follows:
			//
			// 1. Add an EXP claim, computed as current time plus the EXI value.
			//    This allows to purge the token if expired, even though it was created without the EXP claim.
			//
			// 2. Add an internal "sentinel claim" to signal the presence of the artificially added EXP claim.
			//    In case of introspection, this allows the Authorization Server to return the Access Token
			//    like it was originally issued, i.e., without the EXI claim if this was artificially added.
			if (claims.containsKey(Constants.EXI) && !claims.containsKey(Constants.EXP)) {
				
				Long now = this.time.getCurrentTime();
				Long exp = now + claims.get(Constants.EXI).AsNumber().ToInt64Checked();
				
				claims.put(Constants.EXP, CBORObject.FromObject(exp));
				
				// Add the "sentinel claim" 
				claims.put(Constants.LATE_ADDED_EXP, CBORObject.True);
			}
			
		    this.db.addToken(ctiStr, claims);
		    this.db.addCti2Client(ctiStr, id);
		    if (!includeExi) {
		    	this.db.saveCtiCounter(this.cti);
		    }
		    else {
		    	this.db.saveExiSequenceNumber(exiSeqNum+1, rsName);
		    }

		    // In case the client has asked to use a PSK, store further associations,
		    // to support the issuing of Access Tokens for updating access rights
		    if (keyType != null && keyType.equals("PSK")) {
		    
			    this.cti2aud.put(ctiStr, audStr);
			    
			    if (profile == Constants.COAP_OSCORE) {
			    	CBORObject oscId;
			    	if (updateAccessRights == false) {
			    		// The Token is not updating access rights, hence the identifier of the OSCORE
			    		// Input Material is the 'id' 'OSCORE_Input_Material' element of the 'cnf' claim			    		
			    		oscId = claims.get(Constants.CNF).get(Constants.OSCORE_Input_Material).get(Constants.OS_ID);
			    	}
			    	else {
			    		// The Token is updating access rights, hence the identifier of the
			    		// OSCORE Input Material is used as 'kid' in the 'cnf' claim of the Token
			    		oscId = claims.get(Constants.CNF).get(Constants.COSE_KID_CBOR);
			    	}
			    	
            		// A deep copy is needed
			    	byte[] oscIdCopy = Arrays.copyOf(oscId.GetByteString(), oscId.GetByteString().length);
			    	this.cti2oscId.put(ctiStr, CBORObject.FromObject(oscIdCopy));
			    	
	            }
			    else if (profile == Constants.COAP_DTLS) {
		    		// Regardless if the Token is updating access rights or not, the identifier of the
		    		// PoP key is the 'kid' parameter inside the 'COSE_Key' parameter of the 'cnf' claim	
			    	CBORObject kid = claims.get(Constants.CNF).get(Constants.COSE_KEY).get(KeyKeys.KeyId.AsCBOR());
			    	
            		// A deep copy is needed
            		byte[] kidCopy = Arrays.copyOf(kid.GetByteString(), kid.GetByteString().length);
            		this.cti2kid.put(ctiStr, CBORObject.FromObject(kidCopy));
            		
			    }
			    
			    // The just issued Token is updating access rights, hence delete the superseded Token
			    if (updateAccessRights == true) {
			    	removeToken(oldCti);
			    }
		    
			}
		    
		    
		} catch (AceException e) {
			if (!includeExi) {
				this.cti--; //roll-back
			}
	       	else {
        		//roll-back
        		exiSequenceNumbers.put(rsName, exiSeqNum);
        	}
		    
            this.cti2aud.remove(ctiStr);
            
            if (keyType != null && keyType.equals("PSK")) {
            	
            	if (profile == Constants.COAP_OSCORE) {
	            	if (updateAccessRights == false) {
	            		// Roll-back the counter used for the 'id' parameter in the OSCORE Security Context
	            		// and the Id Context value assigned for this Resource Server
	            		this.OSCORE_material_counter--;
	            	    if (this.idContextInfoMap.containsKey(audStr)) {
	            	 	    this.idContextInfoMap.get(audStr).rollback();
	            	    }
	            	}

	            	this.cti2oscId.remove(ctiStr);
            	}
            	else if (profile == Constants.COAP_DTLS) {
            		this.cti2kid.remove(ctiStr);
            	}
            	
            }
            
			LOGGER.severe("8Message processing aborted: " + e.getMessage());
		    return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
		}
		LOGGER.log(Level.INFO, "Returning token: " + ctiStr);
		
		// If the EXP claim was added after the actual creation of the Access Token,
		// then print all the claims except for EXP and the sentinel claim.
		if (claims.containsKey(Constants.LATE_ADDED_EXP)) {
			Map<Short, CBORObject> actualClaims = new HashMap<>();
			for (Short s : claims.keySet()) {
				actualClaims.put(s, claims.get(s));
			}
			LOGGER.log(Level.FINEST, "Claims: " + actualClaims.toString());
		}
		return msg.successReply(Message.CREATED, rsInfo);
	}
	
	/**
	 * Populate RS_CNF
	 * @throws AceException 
	 */
	private Set<CBORObject> makeRsCnf(Set<String> aud) throws AceException {
	    Set<String> rss = new HashSet<>();
	    Set<CBORObject> rscnfs = new HashSet<>();
	    for (String audE : aud) {           
	        rss.addAll(this.db.getRSS(audE));
	    }
	    for (String rs : rss) {
	        OneKey rsKey = this.db.getRsRPK(rs);
	        CBORObject rscnf = CBORObject.NewMap();
	        rscnf.Add(Constants.COSE_KEY_CBOR, rsKey.AsCBOR());
	        rscnfs.add(rscnf);

	    }
	    return rscnfs;
	}
	
	/**
	 * Create the value of a 'cnf' claim as an "OSCORE_Input_Material" CBOR object.
	 * 
	 * @param masterSecret  the OSCORE Master Secret
	 * @param rsName  the name of the Resource Server
	 * 
	 * @return the value of a 'cnf' claim as an "OSCORE_Input_Material" CBOR object
	 */
	synchronized private CBORObject makeOscoreCnf(byte[] masterSecret, String rsName) {
	    CBORObject osccnf = CBORObject.NewMap();
	    CBORObject osc = CBORObject.NewMap();
	    
	    osc.Add(Constants.OS_MS, masterSecret);
	    
	    osc.Add(Constants.OS_ID, Util.intToBytes(OSCORE_material_counter));
	    OSCORE_material_counter++;
	    
	    if (masterSaltSize != 0) {
	        byte[] masterSalt = new byte[masterSaltSize];
	        new SecureRandom().nextBytes(masterSalt);
	        osc.Add(Constants.OS_SALT, masterSalt);
	    }

	    if (this.provideIdContext == true) {
	    	
	    	IdContextInfo idContextInfo;
	    	if (this.idContextInfoMap.containsKey(rsName)) {
		    	idContextInfo = this.idContextInfoMap.get(rsName);
	    	}
	    	else {
			    // This is the first Access Token for this Resource Server
	    		idContextInfo = new IdContextInfo();
	    		this.idContextInfoMap.put(rsName, idContextInfo);
	    	}
	    	
	    	byte[] idContext = idContextInfo.getIdContext();
	    	osc.Add(Constants.OS_CONTEXTID, idContext);
	    	
	    }
	    
	    osccnf.Add(Constants.OSCORE_Input_Material, osc);
	    return osccnf;  
	}
	
	
	/**
	 * Create the value of a 'cnf' claim as a "kid" CBOR object.
	 * 
	 * @param oscId  the Identifier of the OSCORE Input Material object
	 * 
	 * @return the value of a 'cnf' claim as a "kid" CBOR object
	 */
	private CBORObject makeOscoreCnfUpdateAccessRights(CBORObject oscId) {
	    CBORObject osccnf = CBORObject.NewMap();
	    
	    osccnf.Add(Constants.COSE_KID_CBOR, oscId);
	    return osccnf;  
	}


	/**
	 * Process an authorization grant message
	 * 
	 * @param msg  the message
	 * 
	 * @return the reply
	 */
	private Message processAC(Message msg) {
	       //3. Check if the request has a grant
        CBORObject cbor = msg.getParameter(Constants.CODE);
        if (cbor == null ) {
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, "No code found for message");
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "No code found for message");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        }
        if (!cbor.getType().equals(CBORType.TextString)) {
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
            map.Add(Constants.ERROR_DESCRIPTION, "Invalid grant format");
            LOGGER.log(Level.INFO, "Message processing aborted: "
                    + "Invalid grant format");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);
        }
        String code = cbor.AsString();
        
	    //4. Check if grant valid and unused
        try {
            if (!this.db.isGrantValid(code)) {
                CBORObject map = CBORObject.NewMap();
                map.Add(Constants.ERROR, Constants.INVALID_GRANT);
                LOGGER.log(Level.INFO, "Message processing aborted: "
                        + "Invalid grant");
                return msg.failReply(Message.FAIL_BAD_REQUEST, map);
            }
        } catch (AceException e) {
            LOGGER.log(Level.SEVERE, "Message processing aborted "
                    + "(checking grant): " + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }
        
	    //5. Mark grant invalid
        try {
            this.db.useGrant(code);
        } catch (AceException e) {
            LOGGER.log(Level.SEVERE, "Message processing aborted "
                    + "(marking grant invalid): " + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }
        
	    //6. Return the RS Information
        CBORObject rsInfo = CBORObject.NewMap();
       
        try {
            Map<Short, CBORObject> rsInfoDB = this.db.getRsInfo(code);
            for (Map.Entry<Short, CBORObject> e : rsInfoDB.entrySet()) {
                rsInfo.Add(e.getKey(), e.getValue());
            }
        } catch (AceException e) {
            LOGGER.log(Level.SEVERE, "Message processing aborted "
                    + "(collecting RS Info" + e.getMessage());
            return msg.failReply(Message.FAIL_INTERNAL_SERVER_ERROR, null);
        }
       
        if (rsInfo == null || !rsInfo.getType().equals(CBORType.Map)) {
            LOGGER.log(Level.SEVERE, "Message processing aborted: "
                    + "no RS information found for grant: " + code);
            CBORObject map = CBORObject.NewMap();
            map.Add(Constants.ERROR, Constants.INVALID_GRANT);
            map.Add(Constants.ERROR_DESCRIPTION, 
                    "No token found for grant");
            return msg.failReply(Message.FAIL_BAD_REQUEST, map);  
        }
        return msg.successReply(Message.CREATED, rsInfo);
	}

	private boolean isSupported(String keyType, Set<String> aud) 
	        throws AceException {
	    Set<String> keyTypes = this.db.getSupportedPopKeyTypes(aud);
	    return keyTypes.contains(keyType);	    
	}

	/**
	 * Retrieves a key from a cnf structure.
	 * 
	 * @param cnf  the cnf structure
	 * 
	 * @return  the key
	 * 
	 * @throws AceException 
	 * @throws CoseException 
	 */
	private OneKey getKey(CBORObject cnf, String id) 
	        throws AceException, CoseException {
	    CBORObject crpk = null; 
	    if (cnf.ContainsKey(Constants.COSE_KEY_CBOR)) {
	        crpk = cnf.get(Constants.COSE_KEY_CBOR);
	        if (crpk == null) {
	            return null;
	        }
	        return new OneKey(crpk);
	    } else if (cnf.ContainsKey(Constants.COSE_ENCRYPTED_CBOR)) {
	        Encrypt0Message msg = new Encrypt0Message();
            CBORObject encC = cnf.get(Constants.COSE_ENCRYPTED_CBOR);
          try {
              msg.DecodeFromCBORObject(encC);
              OneKey psk = this.db.getCPSK(id);
              if (psk == null) {
                  LOGGER.severe("Couldn't find a key to decrypt cnf parameter");
                  throw new AceException(
                          "No key found to decrypt cnf parameter");
              }
              CBORObject key = psk.get(KeyKeys.Octet_K);
              if (key == null || !key.getType().equals(CBORType.ByteString)) {
                  LOGGER.severe("Corrupt key retrieved from database");
                  throw new AceException("Key error in the database");  
              }
              msg.decrypt(key.GetByteString());
              CBORObject keyData = CBORObject.DecodeFromBytes(msg.GetContent());
              return new OneKey(keyData);
          } catch (CoseException e) {
              LOGGER.severe("Error while decrypting a cnf claim: "
                      + e.getMessage());
              throw new AceException("Error while decrypting a cnf parameter");
          }
	    } //Note: We checked the COSE_KID_CBOR case before 
	    throw new AceException("Malformed cnf structure");
    }

	/**
	 * Removes a token from the registry
	 * 
	 * @param cti  the token identifier Base64 encoded
	 * @throws AceException 
	 */
	public void removeToken(String cti) throws AceException {
	    this.db.deleteToken(cti);
	    
        this.cti2aud.remove(cti);
        this.cti2oscId.remove(cti);
        this.cti2kid.remove(cti);
	    
	    //FIXME: Add the token to the TRL
	}

    @Override
    public void close() throws AceException {
        this.db.saveCtiCounter(this.cti);
        
        for (String rs : exiSequenceNumbers.keySet())
        	this.db.saveExiSequenceNumber(exiSequenceNumbers.get(rs).intValue(), rs);
        
        this.db.close();
    }
    
	 /**
	  * Relevant only when the OSCORE profile is used
	  * 
	  * An instance of this class tracks the status of 
	  * OSCORE Id Contexts assigned to a Resource Server
	  */
	 class IdContextInfo {
		 
		 short currentSize;
		 int currentValue;
		 
		 public IdContextInfo() {
			 currentSize = 1;
			 currentValue = 0;
		 }
		 
		 // Retrieve the next unassigned IdContext for this Resource Server,
		 // using the smallest possible size in bytes.
		 // That is, first consume all the Id Contexts of 1 byte in size, then
		 // all the Id Contexts of 2 bytes in size, and so on up to 4 bytes in size.
		 synchronized public byte[] getIdContext() {

			 // Check if the size has to be changed
			 switch (currentSize) {
			 
			 	case 1: // Max value: 2^8 - 1
			 	case 2: // Max value: 2^16 - 1
			 	case 3: // Max value: 2^24 - 1
			 		if (currentValue == ((1 << (currentSize * 8)) - 1)) {
			 			currentSize++;
			 			currentValue = 0;
			 		}
			 		break;
			 	case 4: // Max value: 2^31 - 1  --- The other half is for negative integers
			 		if (currentValue == ((1 << ((currentSize *8) - 1)) - 1)) {
			 			currentSize = 1;
			 			currentValue = 0;
			 		}
			 		break;
			 	default:
			 		return null;
			 }
		 	 
			 byte[] idContext = null;
			 switch (currentSize) {
			 	case 1:
			 		idContext = new byte[] { (byte) (currentValue) };
			 		break;
			 	case 2:
			 		idContext = new byte[] { (byte) (currentValue >>> 8),
			 				                 (byte) currentValue };
			 		break;
			 	case 3:
			 		idContext = new byte[] { (byte) (currentValue >>> 16),
			 				                 (byte) (currentValue >>> 8),
			 				                 (byte) currentValue };
			 		break;
			 	case 4:
			 		idContext = new byte[] { (byte) (currentValue >>> 24),
			 				                 (byte) (currentValue >>> 16),
			 				                 (byte) (currentValue >>> 8),
			 				                 (byte) currentValue };
			 		break;
			 }
			 
			 currentValue++;
			 return idContext;
				 
		 }
		 
		 // Free up the Id Context latest assigned for this Resource Server
		 synchronized public void rollback() {
			 
			 if (currentValue != 0) {
				 currentValue--; 
			 }
			 else { 
				 switch (currentSize) {
				 	case 1: // Restore the maximum value: 2^31 - 1  --- The other half is for negative integers
				 		currentSize = 4;
				 		currentValue = (1 << ((currentSize *8) - 1)) - 1;
				 		break;
				 	case 2: // Restore the maximum value: 2^8 - 1
				 	case 3: // Restore the maximum value: 2^16 - 1
				 	case 4: // Restore the maximum value: 2^24 - 1
				 		currentSize--;
				 		currentValue = (1 << (currentSize * 8)) - 1;
				 		break;
				 }
			 }
		 }
		 
	 }
    
}
