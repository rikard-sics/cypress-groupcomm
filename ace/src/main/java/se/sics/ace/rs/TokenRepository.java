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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;
import java.util.logging.Logger;

import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.oscore.CoapOSException;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.Encrypt0Message;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.Hkdf;
import se.sics.ace.TimeProvider;
import se.sics.ace.coap.rs.oscoreProfile.OscoreCtxDbSingleton;
import se.sics.ace.coap.rs.oscoreProfile.OscoreSecurityContext;
import se.sics.ace.cwt.CwtCryptoCtx;

/**
 * This class is used to store valid access tokens and 
 * provides methods to check them against an incoming request.  It is the 
 * responsibility of the request handler to call this class. 
 * 
 * Note that this class assumes that every token has a 'scope',
 * 'aud', and 'cnf'.  Tokens
 * that don't have these will lead to request failure.
 * 
 * If the token has no cti, this class will use the hashCode() of the claims
 * Map to generate a local cti.
 * 
 * This class is implemented as a singleton to ensure that all users see
 * the same repository (and yes I know that parameterized singletons are bad 
 * style, go ahead and suggest a better solution).
 *  
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class TokenRepository implements AutoCloseable {
	
    /**
     * Return codes of the canAccess() method
     */
    public static final int OK = 1;
    
    /**
     * Return codes of the canAccess() method. 4.01 Unauthorized
     */
    public static final int UNAUTHZ = 0;
    
    /**
     * Return codes of the canAccess() method. 4.03 Forbidden
     */ 
    public static final int FORBID = -1;
    
    /**
     * Return codes of the canAccess() method. 4.05 Method Not Allowed
     */
    public static final int METHODNA = -2;

    /**
     * Converter for generating byte arrays from int
     */
    private static ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(TokenRepository.class.getName());
     
    /**
     * Is this closed?
     */
    private boolean closed = true;
    
	/**
	 * Maps the base64 encoded cti to the claims of the corresponding token
	 */
	private Map<String, Map<Short, CBORObject>> cti2claims;
	
	
	/**
	 * Map key identifiers collected from the access tokens to keys
	 */
	protected Map<String, OneKey> kid2key;
	
	/**
	 * Map the base64 encoded cti of a token to the corresponding pop-key kid
	 */
	protected Map<String, String>cti2kid;
	
	/**
	 * Map a subject identity to the kid they use
	 */
	private Map<String, String>sid2kid;
	
	/**
	 * Map a subject identity to the base64 encoded cti of a token
	 */
	private Map<String, String>sid2cti;
	
	/**
	 * Map an OSCORE input material identifier to the base64 encoded cti of a token
	 */
	private Map<String, String>id2cti;
	
	/**
	 * Map a subject identity to an OSCORE input material identifier
	 */
	private Map<String, String>sid2id;
	
	/**
	 * Map a subject identity to the rsnonce possibly provided upon Token posting
	 * This is relevant when joining an OSCORE Group, with the RS acting as Group Manager
	 */
	private Map<String, String> sid2rsnonce;
	
	/**
	 * The scope validator
	 */
	private ScopeValidator scopeValidator;
	
	/**
     * The filename + path for the JSON file in which the tokens are stored
     */
    private String tokenFile;
	
	/**
	 * The time provider providing local time for this RS
	 */
	private TimeProvider time;

	/**
	 * The key derivation key to use with the AS
	 */
	private byte[] keyDerivationKey;
	
	/**
	 * The size in bytes for symmetric keys derived with the key derivation key
	 */
	private int derivedKeySize;
	
	/**
	 * The singleton instance
	 */
	private static TokenRepository singleton = null;
	
	/**
	 * The identifier of the Resource Server.
	 * 
	 * This is required to process Access Tokens that include the 'exi' claim,
	 * where the format of the 'cti' claim also encodes the identifier of the
	 * Resource Server together with a Sequence Number value used for such Access Tokens. 
	 */
	private String rsId;
	
	/**
	 * Related to Access Tokens including the 'exi' claim, this has as value the highest
	 * Sequence Number received in any of such Tokens, as encoded in the 'cti' claim 
	 */
	private int topExiSequenceNumber;	

	/**
	 * The singleton getter.
	 * Note: The caller is expected to check if the singleton was initialized
	 * with TokenRepository.create().
	 * 
	 * @return  the singleton repository
	 */
	public static TokenRepository getInstance() {
	    return singleton;
	}
	
	/**
	 * Creates the one and only instance of the token repo and loads the 
	 * existing tokens from a JSON file is there is one.
     * 
     * The JSON file stores the tokens as a JSON array of JSON maps,
     * where each map represents the claims of a token, String mapped to
     * the Base64 encoded byte representation of the CBORObject.
     * 
	 * @param scopeValidator  the validator for scopes
	 * @param tokenFile  the file where to save tokens
	 * @param ctx  the crypto context
	 * @param keyDerivationKey  the key derivation key, it can be null
	 * @param derivedKeySize  the size in bytes of symmetric keys derived with the key derivation key
	 * @param time  the time provider for this RS
	 * @param rsId  the identifier of this RS
	 * @throws AceException
	 * @throws IOException
	 */
	public static void create(ScopeValidator scopeValidator, 
            String tokenFile, CwtCryptoCtx ctx, byte[] keyDerivationKey, int derivedKeySize, TimeProvider time, String rsId)
                    throws AceException, IOException {
	    if (singleton != null) {
	        throw new AceException("Token repository already exists");
	    }
	    singleton = new TokenRepository(scopeValidator, tokenFile, ctx, keyDerivationKey, derivedKeySize, time, rsId);
	}
	
	/**
	 * Creates a new token repository and loads the existing tokens
	 * from a JSON file is there is one.
	 * 
	 * The JSON file stores the tokens as a JSON array of JSON maps,
	 * where each map represents the claims of a token, String mapped to
	 * the Base64 encoded byte representation of the CBORObject.
	 * 
	 * @param scopeValidator  the application specific scope validator
	 * @param tokenFile  the file storing the existing tokens, if the file does not exist it is created
	 * @param ctx  the crypto context for reading encrypted tokens
	 * @param keyDerivationKey  the key derivation key to use to derive PoP keys, it can be null
	 * @param time  the time provider for this RS
	 * @param rsId  the identifier of this RS
     *
	 * @throws IOException 
	 * @throws AceException 
	 */
	protected TokenRepository(ScopeValidator scopeValidator, 
	        String tokenFile, CwtCryptoCtx ctx, byte[] keyDerivationKey, int derivedKeySize, TimeProvider time, String rsId) 
			        throws IOException, AceException {
	    this.closed = false;
	    this.cti2claims = new HashMap<>();
	    this.kid2key = new HashMap<>();
	    this.cti2kid = new HashMap<>();
	    this.sid2kid = new HashMap<>();
	    this.sid2cti = new HashMap<>();
	    this.id2cti = new HashMap<>();
	    this.sid2id = new HashMap<>();
	    this.sid2rsnonce = new HashMap<>();
	    this.scopeValidator = scopeValidator;
	    this.time = time;
	    this.keyDerivationKey = keyDerivationKey;
	    this.derivedKeySize = derivedKeySize;
		this.topExiSequenceNumber = -1;
		this.rsId = rsId;

	    if (tokenFile == null) {
	        throw new IllegalArgumentException("Must provide a token file path");
	    }
	    this.tokenFile = tokenFile;
	    File f = new File(this.tokenFile);
	    if (!f.exists()) {
	        return; //File will be created if tokens are added
	    }
	    FileInputStream fis = new FileInputStream(f);
        Scanner scanner = new Scanner(fis, "UTF-8");
        Scanner s = scanner.useDelimiter("\\A");
        String configStr = s.hasNext() ? s.next() : "";
        s.close();
        scanner.close();
        fis.close();
        JSONArray config = null;
        if (!configStr.isEmpty()) {
            config = new JSONArray(configStr);
            Iterator<Object> iter = config.iterator();
            while (iter.hasNext()) {
                Object foo = iter.next();
                if (!(foo instanceof JSONObject)) {
                    throw new AceException("Token file is malformed");
                }
                JSONObject token =  (JSONObject)foo;
                Iterator<String> iterToken = token.keys();
                Map<Short, CBORObject> params = new HashMap<>();
                while (iterToken.hasNext()) {
                    String key = iterToken.next();  
                    params.put(Short.parseShort(key), 
                            CBORObject.DecodeFromBytes(
                                    Base64.getDecoder().decode(
                                            token.getString((key)))));
                }
                this.addToken(null, params, ctx, null, -1);
            }
        }
	}

	/**
	 * Add a new Access Token to the repo.  Note that this method DOES NOT 
	 * check the validity of the token.
	 * 
	 * @param token  the token
	 * @param claims  the claims of the token
	 * @param ctx  the crypto context of this RS  
	 * @param sid  the subject identity of the user of this token, or null if not needed
	 * 
	 * @param exiSeqNum  the Sequence Number for an Access Token including the 'exi claim.
	 *                   - If its value is -1 and the Access Token includes an 'exi' claim, then the
	 *                   Access Token has been retrieved from a file, and the actual Sequence Number
	 *                   has to be retrieved again from the 'cti' claim.
	 *     				 - If its value is a positive integer and the Access Token includes an 'exi' claim,
	 *     				 this is the actual Sequence Number already retrieved from the 'cti' claim by
	 *     				 the Access Token processing at the /authz-info endpoint
	 *     				 - Any further negative integer value is not relevant
	 *     
	 * @return  the cti or the local id given to this token
	 * 
	 * @throws AceException 
	 */
	public synchronized CBORObject addToken(CBORObject token, Map<Short, CBORObject> claims, 
	        CwtCryptoCtx ctx, String sid, int exiSeqNum) throws AceException {
	    
		CBORObject so = claims.get(Constants.SCOPE);
		if (so == null) {
			throw new AceException("Token has no scope");
		}

		CBORObject cticb = claims.get(Constants.CTI);
		String cti = null;
		if (cticb == null) {
		    cticb = CBORObject.FromObject(
		            buffer.putInt(0, claims.hashCode()).array());
			cti = Base64.getEncoder().encodeToString(cticb.GetByteString());
			claims.put(Constants.CTI, cticb);
		} else if (!cticb.getType().equals(CBORType.ByteString)) {
		    LOGGER.info("Token's cti in not a ByteString");
            throw new AceException("Cti has invalid format");
        } else {		
		    cti = Base64.getEncoder().encodeToString(cticb.GetByteString());
		}

		//Store the pop-key
		boolean storeKey = true;
		CBORObject cnf = claims.get(Constants.CNF);
        if (cnf == null) {
            LOGGER.severe("Token has not cnf");
            throw new AceException("Token has no cnf");
        }
        if (!cnf.getType().equals(CBORType.Map)) {
            LOGGER.severe("Malformed cnf in token");
            throw new AceException("cnf claim malformed in token");
        }
        
		//Check for duplicate cti
        boolean repostedOscoreToken = false;
        byte[] oldOscoreRecipientId = null;
        byte[] oldOscoreContextId = null;
		if (this.cti2claims.containsKey(cti)) {
			
			if (cnf.getKeys().contains(Constants.OSCORE_Input_Material) && sid == null) {
				
				// This is a re-POST of the same Token through an insecure request under the OSCORE profile.
				//
				// This is admitted and results in a new exchange of nonces N1 and N2, together with the
				// establishment of a new OSCORE Security Context, which /authz-info already takes care of. 
				
				// The already stored token must also have been related to OSCORE
				CBORObject storedCnf = this.cti2claims.get(cti).get(Constants.CNF);
				if (storedCnf.getKeys().contains(Constants.OSCORE_Input_Material) == false) {
					throw new AceException("Duplicate cti");
				}
				
				// This same Token remains. Later on, it has to be associated with the new
				// client identity and the old OSCORE Security Context has to be deleted.
				repostedOscoreToken = true;
				oldOscoreRecipientId = storedCnf.get(Constants.OSCORE_Input_Material).
									   get(Constants.OS_CLIENTID).GetByteString();
				oldOscoreContextId = storedCnf.get(Constants.OSCORE_Input_Material).
						   			   get(Constants.OS_CONTEXTID).GetByteString();
				
			}
			else {
				throw new AceException("Duplicate cti");
			}
			
		}
        
        if (cnf.getKeys().contains(Constants.COSE_KEY_CBOR)) {
            CBORObject ckey = cnf.get(Constants.COSE_KEY_CBOR);
            
            try {            	
              
              // The PoP key is symmetric but only its 'kid' is specified (e.g., as in the DTLS profile).
    		  
              if (ckey.getKeys().contains(KeyKeys.KeyType.AsCBOR()) &&
            	  ckey.get(KeyKeys.KeyType.AsCBOR()).equals(KeyKeys.KeyType_Octet) &&
                  ckey.getKeys().contains(KeyKeys.Octet_K.AsCBOR()) == false) {
        		  
            	  if (sid == null) {
            		  
                      // The Token has been posted to /authz-info through an unprotected message.
                      // The actual PoP key has to be derived using the key derivation key shared with the AS
            		  
	            	  if (ckey.getKeys().contains(KeyKeys.KeyId.AsCBOR()) == false) {
	                      LOGGER.severe("Error while parsing cnf element: expected 'kid' in 'COSE_Key was not found");
	                      throw new AceException("Invalid cnf element: expected 'kid' in 'COSE_Key was not found");
	            	  }
	            	  
	            	  // Check also that a PoP key with the same received 'kid' is not already stored.
	            	  //
	            	  // That would be fine for a Token posted to update access rights,
	            	  // which must however happen through a secure POST to /authz-info
		      	      CBORObject kidC = ckey.get(KeyKeys.KeyId.AsCBOR());
		    	      if (kidC == null) {
		    	    	  LOGGER.severe("kid not found in COSE_Key");
		    	          throw new AceException("COSE_Key is missing kid");
		    	      } else if (kidC.getType().equals(CBORType.ByteString)) {
		    	    	  String kid = Base64.getEncoder().encodeToString(kidC.GetByteString());
		    	    	  
		    	          if (kid2key.containsKey(kid) == true) {
			    	    	  LOGGER.severe("A symmetric PoP key with the specified 'kid' is already stored");
			    	          throw new AceException("A symmetric PoP key with the specified 'kid' is already stored");
		    	          }
		    	      } else {
		    	          LOGGER.severe("kid is not a byte string");
		    	          throw new AceException("COSE_Key contains invalid kid");
		    	      }
	            	  
	                  // The salt as empty byte string has to be an array of bytes with all its
	                  // elements set to 0x00 and with the same size of the hash output in bytes
	                  byte[] salt = new byte[Hkdf.getHashLen()];
	                  Arrays.fill(salt, (byte) 0);
	            	  
	            	  // The 'info' structure
	            	  byte[] derivedKey = null;
	            	  CBORObject info = CBORObject.NewArray();
	            	  info.Add("ACE-CoAP-DTLS-key-derivation");
	            	  info.Add(derivedKeySize);
	            	  info.Add(token.EncodeToBytes()); // The content of the "access_token" field, as transferred
	            	                                   // from the authorization server to the resource server.
	
	            	  try {
						derivedKey = Hkdf.extractExpand(salt, keyDerivationKey, info.EncodeToBytes(), derivedKeySize);
					  } catch (InvalidKeyException e) {
			              LOGGER.severe("Error while deriving a symmetric PoP key: " 
			                      + e.getMessage());
			              throw new AceException("Error while deriving a symmetric PoP key: " 
			                      + e.getMessage());
					  } catch (NoSuchAlgorithmException e) {
			              LOGGER.severe("Error while deriving a symmetric PoP key: " 
			                      + e.getMessage());
			              throw new AceException("Error while deriving a symmetric PoP key: " 
			                      + e.getMessage());
					  }
	            	  ckey.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(derivedKey));

              	  }
            	  else {
            		  // Since there is a non-null identity, either:
            		  //  i) the Token has been posted through a protected message to /authz-info , to update access rights; or
            		  // ii) the Token has been specified in the DTLS handshake message, as "psk_identity"
            		  
            		  // Case (i), i.e. the current Token for this security association must be superseded
            		  if (sid2kid.containsKey(sid) && sid2cti.containsKey(sid)) {
            			  
    	            	  if (ckey.getKeys().contains(KeyKeys.KeyId.AsCBOR()) == false) {
    	                      LOGGER.severe("Error while parsing cnf element: expected 'kid' in 'COSE_Key was not found");
    	                      throw new AceException("Invalid cnf element: expected 'kid' in 'COSE_Key was not found");
    	            	  }
    	            	  
	    	              	// Check if there is a stored Token associated to this subject ID 
	    	              	String storedCti = sid2cti.get(sid);
	    	              	
	    	              	// A Token was found - This implies that the corresponding security association
	    	              	// is the same one used to protect the received Token POST request
	    	              	if (storedCti != null) {
	
	    	                      // Now check that the stored Token is actually bound to a key with that 'kid'
	      	              		  String retrievedKid = cti2kid.get(storedCti);
	      	              		  byte[] receivedKidBytes = ckey.get(KeyKeys.KeyId.AsCBOR()).GetByteString();
	      	              		  
	      	              		  String receivedKid = Base64.getEncoder().encodeToString(receivedKidBytes);
	      	              		  
	    	                      if (!retrievedKid.equals(sid2kid.get(sid)) || !retrievedKid.equals(receivedKid)) {	    	                    	  	
	      	                            LOGGER.severe("Impossible to retrieve a Token to supersede");
	      	                            throw new AceException("Impossible to retrieve a Token to supersede");
	    	              		  }
	    	                    	
			                      // Everything has matched - This Token is intended to update access rights, while
			                      // preserving the same security association used to protect this Token POST and
			                      // associated to the Token to supersede
			                      
	      	              		  Map<Short, CBORObject> storedClaims = cti2claims.get(storedCti);
	      	              		  CBORObject storedCnf = storedClaims.get(Constants.CNF);
	      	              		
	      	              		  // The following should never happen, being this an already stored Token
	      	                      if (storedCnf == null) {
	      	                          LOGGER.severe("The retrieved stored token has not cnf");
	      	                          throw new AceException("The retrieved stored token has no cnf");
	      	                      }
	      	                      if (!storedCnf.getType().equals(CBORType.Map)) {
	      	                          LOGGER.severe("Malformed cnf in the retrieved stored token");
	      	                          throw new AceException("cnf claim malformed in the retrieved stored token");
	      	                      }
	    	                      
			                      // Copy the "full" 'cnf' claim of the Token to replace into the new Token to store.
			                      // This will overwrite the orginal 'cnf' considered above in the new Token to store.
			                      claims.put(Constants.CNF, storedCnf);
			                      	
			                      // Store the association between the CTI of the new Token and the same current kid
			                      this.cti2kid.put(cti, receivedKid);
			                      
			                      // Store the association between the same current subjectId and the CTI of the new Token
			                      this.sid2cti.put(sid, cti);
			                      
			                      // The same PoP key remains in use
			                      storeKey = false;
			                      
			                      // Delete the Token to be replaced
			                      removeToken(storedCti);
	    	                      	
	    	              	}
	    	              	else {
	    	                      LOGGER.severe("Impossible to retrieve the stored Token to supersede");
	    	                      throw new AceException("Impossible to retrieve the stored Token to supersede");
	    	              	}
            			  
                  	  }
            		  // Else it's Case (ii), which will be handled later in processKey()
            		  
            	  }
            	  
              }
              if (storeKey) {
	              OneKey key = new OneKey(ckey);
	              processKey(key, sid, cti);
              }
            }
            catch (CoseException e) {
                LOGGER.severe("Error while parsing cnf element: " + e.getMessage());
                throw new AceException("Invalid cnf element: " + e.getMessage());
            }
        }
        
        else if (cnf.getKeys().contains(Constants.COSE_ENCRYPTED_CBOR)) {
            Encrypt0Message msg = new Encrypt0Message();
            CBORObject encC = cnf.get(Constants.COSE_ENCRYPTED_CBOR);
          try {
              msg.DecodeFromCBORObject(encC);
              msg.decrypt(ctx.getKey());
              CBORObject keyData = CBORObject.DecodeFromBytes(msg.GetContent());
              OneKey key = new OneKey(keyData);
              processKey(key, sid, cti);
          } catch (CoseException e) {
              LOGGER.severe("Error while decrypting a cnf claim: "
                      + e.getMessage());
              throw new AceException("Error while decrypting a cnf claim");
          }
        }
        
        else if (cnf.getKeys().contains(Constants.COSE_KID_CBOR)) {
            String kid = null;
            CBORObject kidC = cnf.get(Constants.COSE_KID_CBOR);
            
            if (kidC.getType().equals(CBORType.ByteString)) {            	
            	kid = Base64.getEncoder().encodeToString(kidC.GetByteString());
            } else {
                LOGGER.severe("kid is not a byte string");
                throw new AceException("cnf contains invalid kid");
            }
            
            // The Token POST is protected
            if (sid != null) {
                
            	// The Token POST can be protected with OSCORE, for
            	// updating access rights as per the OSCORE profile
            	
            	// Check if there is a stored Token associated to this subject ID 
            	String storedCti = sid2cti.get(sid);
            	
            	// A Token was found - This implies that the corresponding security association
            	// is the same one used to protect the received Token POST request
            	if (storedCti != null) {
            		// Now check that the stored Token is actually
            		// associated to an OSCORE Security Context 
            		
            		Map<Short, CBORObject> storedClaims = cti2claims.get(storedCti);
            		CBORObject storedCnf = storedClaims.get(Constants.CNF);
            		
            		// The following should never happen, being this an already stored Token
                    if (storedCnf == null) {
                        LOGGER.severe("The retrieved stored token has not cnf");
                        throw new AceException("The retrieved stored token has no cnf");
                    }
                    if (!storedCnf.getType().equals(CBORType.Map)) {
                        LOGGER.severe("Malformed cnf in the retrieved stored token");
                        throw new AceException("cnf claim malformed in the retrieved stored token");
                    }
            		
                    if (storedCnf.getKeys().contains(Constants.OSCORE_Input_Material)) {
                    	
                    	byte[] storedIdBytes = storedCnf.get(Constants.OSCORE_Input_Material).
                    					                     get(Constants.OS_ID).GetByteString();
                    	
                    	String storedId = Base64.getEncoder().encodeToString(storedIdBytes);
                    	String recoveredCti = id2cti.get(storedId);
                    	
                    	if (!storedCti.equals(recoveredCti) || !storedId.equals(kid) ) {
                            LOGGER.severe("Impossible to retrieve an OSCORE-related Token to supersede");
                            throw new AceException("Impossible to retrieve an OSCORE-related Token to supersede");
                    	}
                    	
                    	// Everything has matched - This Token is intended to update access rights, while
                    	// preserving the same OSCORE Security Context used to protect this Token POST
                    	// and associated to the Token to supersede
                    	
                    	// Copy the "full" 'cnf' claim of the Token to replace into the new Token to store.
                    	// This will overwrite the original 'cnf' considered above in the new Token to store.
                    	claims.put(Constants.CNF, storedCnf);
                    	
                    	// Store the association between the same current subjectId and the CTI of the new Token
                    	this.sid2cti.put(sid, cti);
                    	
                    	// Store the association between the CTI of the new Token and kid, with kid equal to the subjectId 
                        this.cti2kid.put(cti, sid);

                    	// Store the association between the immutable identifier of the OSCORE input material
                    	// and the base64 encoded cti of this Access Token; this will be updated in case a new
                    	// Access Token with updated access rights (and a new cti) is posted as still associated
                    	// to this OSCORE input material identifier and hence to the same kid
                    	this.id2cti.put(kid, cti);
                    	
                    	// Delete the old Token that has been replaced
                    	removeToken(storedCti);
                    	
                    }
                    else {
                		// The only admitted situation for 'cnf' of 'kid' type for a protected Token POST
                		// is the one described in the OSCORE profile for the update of access rights.
                		// Any other case should be treated as an error at the moment.
                        LOGGER.severe("A Token to supersede through 'cnf' of type 'kid' must be"
                        			   + "related to an OSCORE Security Context");
                        throw new AceException("A Token to supersede through 'cnf' of type 'kid' must be"
                        		                + "related to an OSCORE Security Context");
                    }
                    
            	}
            	else {
                    LOGGER.severe("Impossible to retrieve the stored Token to supersede");
                    throw new AceException("Impossible to retrieve the stored Token to supersede");
            	}
            	
            }
            
            // The Token POST is not protected
            else {	            
	            if (!this.kid2key.containsKey(kid)) {
	                LOGGER.info("Token refers to unknown kid");
	                throw new AceException("Token refers to unknown kid");
	            }
	            //Store the association between token and known key
	            this.cti2kid.put(cti, kid);
	            
	            // Since the Token POST is not protected, there is no Subject ID available
	            // at all for the moment, to store the associations sid2kid and sid2cti
	            // NOTE: Current profiles do not support this case
            }
        }
        
        else if (cnf.getKeys().contains(Constants.OSCORE_Input_Material)) {
        	// Coming from the /authz-info endpoint, it is ensured that
        	// this Token has been posted through an unprotected request
        	
            OscoreSecurityContext osc = new OscoreSecurityContext(cnf);
            String kid = Base64.getEncoder().encodeToString(osc.getClientId());

            // The subject ID stored in the Token Repository has format: i) IdContext:SenderID;
            // or ii) SenderID, if the IdContext is not in the OSCORE Security Context Object
        	String subjectId = "";
        	String kidContext = null;
        	byte[] kidContextBytes = osc.getContextId();
        	
        	if (kidContextBytes != null && kidContextBytes.length != 0) {
        		kidContext = Base64.getEncoder().encodeToString(kidContextBytes);        		
        		subjectId = kidContext + ":";
        	}
        	subjectId += kid;
        	
        	// Store the association between subjectId and kid, with kid equal to the subjectId
        	this.sid2kid.put(subjectId, subjectId);
        	
        	// Store the association between subjectId and the Token CTI
        	this.sid2cti.put(subjectId, cti);
        	
        	// Store the association between CTI and kid, with kid equal to the subjectId
            this.cti2kid.put(cti, subjectId);
            
            if (repostedOscoreToken == true) {
            	// The same Token has been reposted through an unprotected request
            	
            	// Delete the old OSCORE Security Context
            	OSCoreCtxDB db = OscoreCtxDbSingleton.getInstance();
            	OSCoreCtx oscCtx = null;
            	if (oldOscoreContextId == null) {
            		oscCtx = db.getContext(oldOscoreRecipientId);
            	}
            	else {
            		try {
						oscCtx = db.getContext(oldOscoreRecipientId, oldOscoreContextId);
					} catch (CoapOSException e) {
						e.printStackTrace();
			            LOGGER.severe("Unable to retrieve the OSCORE Security Context to delete");
			            throw new AceException("Unable to retrieve the OSCORE Security Context to delete");
					}
            	}
            	if (oscCtx != null) {
            		db.removeContext(oscCtx);
            	}
            	else {
		            LOGGER.severe("Unable to retrieve the OSCORE Security Context to delete");
		            throw new AceException("Unable to retrieve the OSCORE Security Context to delete");
            	}
            	
            }
            else {
                // Store the association between the immutable identifier of the OSCORE input material
                // and the base64 encoded cti of this Access Token; this will be updated in case a new
                // Access Token with updated access rights (and a new cti) is posted as still associated
                // to this OSCORE input material identifier and hence to the same kid
            	String id = Base64.getEncoder().encodeToString(osc.getId());
	            this.id2cti.put(id, cti);
	            
                // Store the association between the subjectId and
	            // the immutable identifier of the OSCORE input material
	            this.sid2id.put(subjectId, id);
	            
            }
            
        }
        
        else {
            LOGGER.severe("Malformed cnf claim in token");
            throw new AceException("Malformed cnf claim in token");
        }

        // If the Access Token includes the 'exi' claim, update the stored
        // highest Sequence Number values used to track the Access Tokens
        // with the 'exi' claim issues to this Resource Server
	    if (claims.containsKey(Constants.EXI)) {
	    	
	    	if (exiSeqNum >= 0) {
	    		// The Access Token has been just posted to authz-info
	    		TokenRepository.getInstance().setTopExiSequenceNumber(exiSeqNum);
	    	}
	    	else if (exiSeqNum == -1) {
	    		// The Access Token has been retrieved from a local file
	    		
	    		exiSeqNum = getExiSeqNumFromCti(cticb.GetByteString());
	    		
	    		if (exiSeqNum < 0) {
	    			// This should never happen, since the Access Token retrieved from the local file
	    			// should have been issued by the AS as including a 'cti' claim with the intended format
	                LOGGER.severe("Malformed cti claim in token including an exi claim and restored from a local file");
	                throw new AceException("Malformed cti claim in token including an exi claim and restored from a local file");
	    		}
	    		
	    		TokenRepository.getInstance().setTopExiSequenceNumber(exiSeqNum);
	    	}
	    		
	    } 
        
        //Now store the claims. Need deep copy here
        Map<Short, CBORObject> foo = new HashMap<>();
        foo.putAll(claims);
        this.cti2claims.put(cti, foo);
	    
        persist();
        
        return cticb;
	}
	
    /**
	 * Add the mappings for the cnf-key.
	 * 
	 * @param key  the key
	 * @param sid  the subject identifier
	 * @param cti  the token's identifier
	 * 
	 * @throws AceException
	 * @throws CoseException
	 */
	private void processKey(OneKey key, String sid, String cti) 
	        throws AceException, CoseException {
	    
	    String kid = null;
	    CBORObject kidC = null;
	    
	    if (key.get(KeyKeys.KeyType).equals(KeyKeys.KeyType_Octet)) {
	        kidC = key.get(KeyKeys.KeyId);
	        
	        if (kidC == null) {
	            LOGGER.severe("kid not found in COSE_Key");
	            throw new AceException("COSE_Key is missing kid");
	        } else if (kidC.getType().equals(CBORType.ByteString)) {	            
	        	kid = Base64.getEncoder().encodeToString(kidC.GetByteString());
	        } else {
	            LOGGER.severe("kid is not a byte string");
	            throw new AceException("COSE_Key contains invalid kid");
	        }
	    }
	    
	    else { //Key type is EC2
	        RawPublicKeyIdentity rpk = new RawPublicKeyIdentity(key.AsPublicKey());
	        kid = Base64.getEncoder().encodeToString(rpk.getName().getBytes());
	    }
	    
        if (sid != null) {
        	// Receiving a new PoP key through an already identifiable peer should
        	// happen only in the DTLS profile, and only when the whole Token conveying
        	// a symmetric PoP key is transported within the DTLS handshake message.
        	
        	// Add the new subject ID only if it is actually new, i.e. this is
        	// not an attempt to update access rights of an already stored Token
        	if (!sid2kid.containsKey(sid) && !sid2cti.containsKey(sid)) {
	            this.sid2kid.put(sid, kid);
	        	this.sid2cti.put(sid, cti);
        	}
        	else {
	            LOGGER.severe("A new PoP key must be provided through an unprotected Token POST");
	            throw new AceException("A new PoP key must be provided through an unprotected Token POST");
        	}
        }
        
        else if (key.get(KeyKeys.KeyType).equals(KeyKeys.KeyType_EC2) ||
        		 key.get(KeyKeys.KeyType).equals(KeyKeys.KeyType_OKP)) {
            //Scandium needs a special mapping for raw public keys
            RawPublicKeyIdentity rpk  = new RawPublicKeyIdentity(key.AsPublicKey());
            
            this.sid2kid.put(rpk.getName(), kid);
        	this.sid2cti.put(rpk.getName(), cti);
        }
        
        else { //Take the kid as sid
            this.sid2kid.put(kid, kid);
        	this.sid2cti.put(kid, cti);
        }  
        
        this.cti2kid.put(cti, kid);
        this.kid2key.put(kid, key);
    }

    /**
	 * Remove an existing token from the repository.
	 * 
	 * @param cti  the cti of the token to be removed Base64 encoded.
	 * @throws AceException 
	 */
	public synchronized void removeToken(String cti) throws AceException {
	    if (cti == null) {
            throw new AceException("Cti is null");
        } 
	    
        // Remove the claims
        this.cti2claims.remove(cti);
 
		// Remove the mapping to the pop key
		this.cti2kid.remove(cti);
		
		// Remove unused keys
		Set<String> remove = new HashSet<>();
		for (String kid : this.kid2key.keySet()) {
		    if (!this.cti2kid.containsValue(kid)) {
		        remove.add(kid);
		    }
		}
		for (String kid : remove) {
		    this.kid2key.remove(kid);
		}
		
		// Remove the mapping from the subject ID to cti
		remove = new HashSet<>();
		for (String sid : this.sid2cti.keySet()) {
			if (this.sid2cti.get(sid).equals(cti)) {
				remove.add(sid);
		    }
		}
		for (String sid : remove) {
			this.sid2cti.remove(sid);
		}
				
		// Remove unused kids
		remove = new HashSet<>();
		for (String sid : this.sid2kid.keySet()) {
		    if (!this.sid2cti.containsKey(sid)) {
		        remove.add(sid);
		    }
		}
		for (String sid : remove) {
		    this.sid2kid.remove(sid);
		}
		
		// Remove unused rs nonces
		// Relevant when joining an OSCORE Group, with the RS acting as Group Manager
		remove = new HashSet<>();
		for (String sid : this.sid2rsnonce.keySet()) {
		    if (!this.sid2cti.containsKey(sid)) {
		        remove.add(sid);
		    }
		}
		for (String sid : remove) {
		    this.sid2rsnonce.remove(sid);
		}
		
		// Remove the mapping from an OSCORE ID to cti,
		// if the Token was established with the OSCORE profile
		remove = new HashSet<>();
		for (String id : this.id2cti.keySet()) {
			if (this.id2cti.get(id).equals(cti)) {
				remove.add(id);
		    }
		}
		for (String id : remove) {
	    	this.id2cti.remove(id);
	    	
	    	// Remove the mapping from the subject ID to the OSCORE Input Material ID
	    	Set<String> sidsToRemove = new HashSet<>();
	    	for (String sid: sid2id.keySet()) {
	    	      if (sid2id.get(sid).equals(id)) {
	    	         sidsToRemove.add(sid);
	    	      }
	    	}	    	
	    	for (String sid: sidsToRemove) {
				sid2id.remove(sid);

				// Remove the OSCORE Security Context
				int index = sid.indexOf(":");
				byte[] idContext = null;
				if (index >= 0) {
					// Extract the OSCORE ID Context
					String idContextString = sid.substring(0, index);
					idContext = Base64.getDecoder().decode(idContextString);
				}
				String recipientIdString = sid.substring(index+1, sid.length());
				byte[] recipientId = Base64.getDecoder().decode(recipientIdString);

				OSCoreCtxDB db = OscoreCtxDbSingleton.getInstance();
				try {
					OSCoreCtx ctx = db.getContext(recipientId, idContext);
					db.removeContext(ctx);
				} catch (CoapOSException e) {
					e.printStackTrace();
					LOGGER.severe("Unable to retrieve the OSCORE Security Context to delete");
					throw new AceException("Unable to retrieve the OSCORE Security Context to delete");
				}
	    	}
	    	
		}
		
		persist();
	}
	
	/**
	 * Poll the stored tokens and expunge those that have expired.
	 * 
	 * Note that non-expired tokens might also be expunged, if including the 'exi' claim
     *
	 * @throws AceException 
	 */
	public synchronized void purgeTokens() throws AceException {
		
		// Set of Access Tokens to remove, due to the possible following reasons:
		// - The Access Token is expired
		// - The Access Token is not expired, but: it includes the 'exi' claim; and
		//   its associated Sequence Number is smaller than the highest Sequence Number
		//   among the expired Access Tokens to remove that include the 'exi' claim 
	    HashSet<String> tokenToRemove = new HashSet<>();
	    
	    // Set of non-expired Access Tokens that include the 'exi' claim
	    HashSet<String> tokenWithExiNotExpired = new HashSet<>();
	    
	    // Highest Sequence Number among the expired
	    // Access Tokens to remove that include the 'exi' claim 
	    int highestExiSeqNum = -1;
	    
	    
	    // Phase 1: identify and delete the expired Access Tokens
	    
		for (Map.Entry<String, Map<Short, CBORObject>> foo : this.cti2claims.entrySet()) {
		    if (foo.getValue() != null) {
		    	
		    	CBORObject exi = foo.getValue().get(Constants.EXI);
		        CBORObject exp = foo.getValue().get(Constants.EXP);
		        
		        if (exp == null) {
		            continue; //This token never expires
		        }
		        if (!(exp.isNumber() && exp.AsNumber().IsInteger())) {
		            throw new AceException("Expiration time is in wrong format");
		        }
		        
		        if (this.time.getCurrentTime() > exp.AsNumber().ToInt64Checked()) {
		        	// This Access Token is expired and has to be removed
		            tokenToRemove.add(foo.getKey());
		            
		            if (exi != null) {
		            	// This expired Access Token has an 'exi' claim 
		            	
		            	CBORObject cticb = foo.getValue().get(Constants.CTI);
			    		int exiSeqNum = getExiSeqNumFromCti(cticb.GetByteString());
			    		if (exiSeqNum < 0) {
			    			// This should never happen, since an accepted and stored Access Token
			    			// should have been validated as including a 'cti' claim with the intended format
			                LOGGER.severe("Malformed cti claim in stored token including an exi claim");
			                throw new AceException("Malformed cti claim in stored token including an exi claim");
			    		}
			    		// Track the highest Sequence Number among the expired Access Tokens with the 'exi' claim 
			    		if (exiSeqNum > highestExiSeqNum) {
			    			highestExiSeqNum = exiSeqNum;
			    		}
		            }

				}
		        else if (exi != null) {
	            	// The Access Token is not expired, but it includes the 'exi' claim
		        	// and thus will require further inspection for possible deletion
		        	tokenWithExiNotExpired.add(foo.getKey());
	            }
		        
			}
		}
		
		// Delete the expired Access Tokens
		for (String cti : tokenToRemove) {
		    removeToken(cti);
		}
		
		
	    // Phase 2: identify and delete the non-expired Access Tokens that include the 'exi' claim and that
		//          have their Sequence Number smaller than the highest Sequence Number previously identified. 
		
		// This can be skipped altogether if any of the two following conditions holds:
		// - There are no non-expired Access Tokens that include the 'exi' claim; OR
		// - No expired Access Tokens including the 'exi' claim were found and deleted
		if (!tokenWithExiNotExpired.isEmpty() || highestExiSeqNum != -1) {
			tokenToRemove = new HashSet<>();	
			
			for (Map.Entry<String, Map<Short, CBORObject>> foo : this.cti2claims.entrySet()) {
			    if (foo.getValue() != null) {
			    	
			    	if (tokenWithExiNotExpired.contains(foo.getKey())) {
				    	int exiSeqNum = -1;
		            	CBORObject cticb = foo.getValue().get(Constants.CTI);
			    		exiSeqNum = getExiSeqNumFromCti(cticb.GetByteString());
			    		
			    		if (exiSeqNum < 0) {
			    			// This should never happen, since an accepted and stored Access Token
			    			// should have been validated as including a 'cti' claim with the intended format
			                LOGGER.severe("Malformed cti claim in stored token including an exi claim");
			                throw new AceException("Malformed cti claim in stored token including an exi claim");
			    		}
			    		if (exiSeqNum <= highestExiSeqNum) {
			    			// This non-expired Access Tokens includes the 'exi' claim and
			    			// its Sequence Number is smaller than the highest Sequence Number
			    			// previously identified. Hence, it must also be removed.
			    			tokenToRemove.add(foo.getKey());
			    		}
			    	}
			    }
			}
			
			// Delete the non-expired Access Tokens including the 'exi' claim
			for (String cti : tokenToRemove) {
			    removeToken(cti);
			}
			
		}
				
	}
	
	/**
	 * Check if there is a token allowing access.
     *
	 * @param kid  the key identifier used for proof-of-possession.
	 * @param subject  the authenticated subject if there is any, can be null
	 * @param resource  the resource that is accessed
	 * @param action  the RESTful action code.
	 * @param intro  the introspection handler, can be null
	 * @return  1 if there is a token giving access, 0 if there is no token 
	 * for this resource and user,-1 if the existing token(s) do not authorize 
	 * the action requested.
	 * @throws AceException 
	 * @throws IntrospectionException 
	 */
	public int canAccess(String kid, String subject, String resource, 
	        short action, IntrospectionHandler intro) 
			        throws AceException, IntrospectionException {
	    //Expunge expired tokens
	    purgeTokens();
	    
	    //Check if we have tokens for this pop-key
	    if (!this.cti2kid.containsValue(kid)) {
	        return UNAUTHZ; //No tokens for this pop-key
	    }
	    
	    //Collect the token id's of matching tokens
	    Set<String> ctis = new HashSet<>();
	    for (String cti : this.cti2kid.keySet()) {
	        if (this.cti2kid.get(cti).equals(kid)) {
	            ctis.add(cti);   
	        }
	    }
	 
	    boolean methodNA = false;   
	    for (String cti : ctis) { //All tokens linked to that pop key
	        //Check if we have the claims for that cti
	        //Get the claims
            Map<Short, CBORObject> claims = this.cti2claims.get(cti);
            if (claims == null || claims.isEmpty()) {
                //No claims found
                continue;
            }
            
          //Check if the subject matches
            CBORObject subO = claims.get(Constants.SUB);
            if (subO != null) {
                if (subject == null) {
                    //Token requires subject, but none provided
                    continue;
                }
                if (!subO.AsString().equals(subject)) {
                    //Token doesn't match subject
                    continue;
                }
            }
            
            //Check if the token is expired
            CBORObject exp = claims.get(Constants.EXP); 
             if (exp != null && !(exp.isNumber() && exp.AsNumber().IsInteger())) {
                    throw new AceException(
                            "Expiration time is in wrong format");
             }
             if (exp != null && exp.AsNumber().ToInt64Checked() < this.time.getCurrentTime()) {
                 //Token is expired
                 continue;
             }
            
             //Check nbf
             CBORObject nbf = claims.get(Constants.NBF);
             if (nbf != null &&  !(nbf.isNumber() && nbf.AsNumber().IsInteger())) {
                 throw new AceException("NotBefore time is in wrong format");
             }
             if (nbf != null && nbf.AsNumber().ToInt64Checked() > this.time.getCurrentTime()) {
                 //Token not valid yet
                 continue;
             }
             
	        //Check the scope
             CBORObject scope = claims.get(Constants.SCOPE);
             if (scope == null) {
                 LOGGER.severe("Token: " + cti + " has no scope");
                 throw new AceException("Token: " + cti + " has no scope");
                 
             }
             
             if (this.scopeValidator.scopeMatchResource(scope, resource)) {
            	 
                 if (this.scopeValidator.scopeMatch(scope, resource, action)) {
                	 
                     //Check if we should introspect this token
                     if (intro != null) {
                         byte[] ctiB = Base64.getDecoder().decode(cti);
                         Map<Short,CBORObject> introspect = intro.getParams(ctiB);
                         if (introspect != null 
                                 && introspect.get(Constants.ACTIVE) == null) {
                             throw new AceException("Token introspection didn't "
                                     + "return an 'active' parameter");
                         }
                         if (introspect != null && introspect.get(
                                 Constants.ACTIVE).isTrue()) {
                             return OK; // Token is active and passed all other tests
                         }
                     } else {
                       //We didn't introspect, but the token is ok otherwise
                         return OK;
                     }
                     
                 }
                 methodNA = true; //scope did match resource but not action
                 
             }
	    }

	    return ((methodNA) ? METHODNA : FORBID); 
	}

	/**
	 * Save the current tokens in a JSON file
	 * @throws AceException 
	 */
	private void persist() throws AceException {
	    JSONArray config = new JSONArray();
	    for (String cti : this.cti2claims.keySet()) {
	        Map<Short, CBORObject> claims = this.cti2claims.get(cti);
	        JSONObject token = new JSONObject();
	        for (Map.Entry<Short,CBORObject> entry : claims.entrySet()) {
	            token.put(entry.getKey().toString(), 
	                    Base64.getEncoder().encodeToString(
	                            entry.getValue().EncodeToBytes()));
	        }
	        config.put(token);
	    }

        try (FileOutputStream fos 
                = new FileOutputStream(this.tokenFile, false)) {
            fos.write(config.toString(4).getBytes(Constants.charset));
            fos.close();
        } catch (JSONException | IOException e) {
            throw new AceException(e.getMessage());
        }
        
	}
	
	/**
	 * Get the proof-of-possession key of a token identified by its 'cti'.
	 * 
	 * @param cti  the cti of the token Base64 encoded
	 * 
	 * @return  the pop-key the token or null if this cti is unknown
	 * @throws AceException 
	 */
	public OneKey getPoP(String cti) throws AceException {
	    if (cti != null) {
	        purgeTokens();
	        String kid = this.cti2kid.get(cti);
	        OneKey key = this.kid2key.get(kid);
	        if (key == null) {
	            LOGGER.finest("Token with cti: " + cti 
	                    + " not found in getPoP()");
	            return null;
	        }
	        return key;
	    }
        LOGGER.severe("getCnf() called with null cti");
        throw new AceException("Must supply non-null cti to get cnf");
	}

	/**
	 * Get a key identified by it's 'kid'.
     * 
     * @param kid  the kid of the key
     * 
     * @return  the key identified by this kid of null if we don't have it
     * 
     * @throws AceException 
     */
	public OneKey getKey(String kid) throws AceException {
        if (kid != null) {
            OneKey key = this.kid2key.get(kid);
            if (key == null) {
                LOGGER.finest("Key with kid: " + kid 
                        + " not found in getKey()");
                return null;
            }
            return key;
        }
        LOGGER.severe("getKey() called with null kid");
        throw new AceException("Must supply non-null kid to get key");     
    }
	
	
	/**
	 * Get the kid by the subject id.
	 * 
	 * @param sid  the subject id
	 * 
	 * @return  the kid this subject uses
	 */
	public String getKid(String sid) {
	    if (sid != null) {
	        return this.sid2kid.get(sid);
	    }
	    LOGGER.finest("Key-Id for Subject-Id: " + sid + " not found");
	    return null;
	}
	
	
	/**
	 * Get the kid by the CTI.
	 * 
	 * @param sid  the CTI
	 * 
	 * @return  the kid associated to this CTI
	 */
	public String getKidByCti(String cti) {
	    if (cti != null) {
	        return this.cti2kid.get(cti);
	    }
	    LOGGER.finest("Key-Id for CTI: " + cti + " not found");
	    return null;
	}
	

	/**
	 * Get the subject id by the kid.
	 * 
	 * @param kid  the kid this subject uses
	 * 
	 * @return  the subject id
	 */
	public String getSid(String kid) {
	    if (kid != null) {
	    	for (String foo : this.sid2kid.keySet()) {
    			if (this.sid2kid.get(foo).equals(kid)) {
    				return foo;
    			}
    		}
	    }
	    return null;
	}
	
	
	/**
	 * Get the CTI by the subject id.
	 * 
	 * @param sid  the subject id
	 * 
	 * @return  the CTI associated to the subject id
	 */
	public String getCti(String sid) {
	    if (sid != null) {
	    		return sid2cti.get(sid);
	    }
	    return null;
	}
	
	
	/**
	 * Get the OSCORE Input Material ID by the subject id.
	 * 
	 * @param sid  the subject id
	 * 
	 * @return  the OSCORE Input Material ID
	 */
	public String getOscoreId(String sid) {
	    if (sid != null) {
	    		return sid2id.get(sid);
	    }
	    return null;
	}
	
	
	/**
	 * FIXME 
	 * @param sid  FIXME
	 * @param rsNonce  FIXME
	 */
	public synchronized void setRsnonce(String sid, String rsNonce) {
		if (sid != null && rsNonce != null) {
	        this.sid2rsnonce.put(sid, rsNonce);
	    }
	}
	
	/**
	 * FIXME
	 * @param sid  FIXME
	 * @return  FIXME
	 */
	public synchronized String getRsnonce(String sid) {
		if (sid != null) {
	        return this.sid2rsnonce.get(sid);
	    }
	    LOGGER.finest("rsnonce for Subject-Id: " + sid + " not found");
	    return null;
	}
	
    @Override
    public synchronized void close() throws AceException {
        if (!this.closed) {
            this.closed = true;   
            persist();
            singleton = null;
        }
    }
    
    /**
     * @return  a set of all token ids (cti) stored in this repository
     */
    public Set<String> getCtis() {
        return new HashSet<>(this.cti2claims.keySet());
    }

    /**
	 * @param   kid  the key identifier associated to the token ids (cti) of interest
     * @return  a set of all token ids (cti) stored in this repository and associated to 'kid'
     */
    public Set<String> getCtis(String kid) {
    	
	    //Check if we have tokens for this pop-key
	    if (!this.cti2kid.containsValue(kid)) {
	        return null; //No tokens for this pop-key
	    }
	    
	    //Collect the token id's of matching tokens
	    Set<String> ctis = new HashSet<>();
	    for (String cti : this.cti2kid.keySet()) {
	        if (this.cti2kid.get(cti).equals(kid)) {
	            ctis.add(cti);
	        }
	    }
	    return ctis;
    }
	    
    /**
     * Checks if a given scope is meaningful for this repository.
     * 
     * @param scope  the Scope, as a CBOR text string or a CBOR byte string
     * @return true if the scope is meaningful, false otherwise 
     * @throws AceException 
     */
    public boolean checkScope(CBORObject scope) throws AceException {
        return this.scopeValidator.isScopeMeaningful(scope);
    }
    
    /**
     * Returns the necessary scope to perform the given action on the given
     * resource.
     * 
     * @param resource  the resource
     * @param action  the action
     * @return  the scope necessary to perform the action on the resource
     */
    public CBORObject getScope(String resource, short action) {
        return this.scopeValidator.getScope(resource, action);
    }

    /**
     * Checks if a given scope is meaningful for this repository.
     * 
     * @param scope  the Scope, as a CBOR text string or a CBOR byte string
     * @param aud  the Audience as a CBOR text string
     * @return true if the scope is meaningful, false otherwise 
     * @throws AceException 
     */
    public boolean checkScope(CBORObject scope, String aud) throws AceException {
        return this.scopeValidator.isScopeMeaningful(scope, aud);
    }
    
	/**
	 * Get the claims of a token identified by its 'cti'.
	 * 
	 * @param cti  the cti of the token Base64 encoded
	 * 
	 * @return  the claims of the token
	 */
    public Map<Short, CBORObject> getClaims(String cti) {
    	return this.cti2claims.get(cti);
    }
    
    /**
     * Retrieve the Exi Sequence Number value, encoded in the 'cti'
     * claim of an Access Token that includes the 'exi' claim
     * 
     * @param  the 'cti' claim included in the Access Token
     * @return  It returns a positive integer if the Sequence Number is successfully extracted from the 'cti' claim
     *          It returns -1 in case of error while parsing the 'cti' claim
     * 
     */
    public int getExiSeqNumFromCti(byte[] cti) {
    	
        // Retrieve the raw CTI value, as a text string that concatenates:
        //  - the identifier of the Resource Server
        //  - the text-encoded Sequence Number used for this Access Token,
        //    as issued to this Resource Server and including the 'exi' claim 
        String rawCti = new String(cti);
        
        // Check that the retrieved 'cti' value has a minimum length
        int rawCtiLen = rawCti.length();
        int rsIdLen = this.rsId.length();
        if (rawCtiLen < (rsIdLen + 1)) {
        	// The 'cti' claim is malformed - It is too short in size
        	return -1;
        }
        
        // Check that the first part of the retrieved 'cti' coincides with the identifier of the Resource Server
        String receivedRsId = rawCti.substring(0, rsIdLen);
        if (receivedRsId.compareTo(this.rsId) != 0) {
        	// The 'cti' claim is malformed - The Resource Server Identifier does not match with the expected one
        	return -1;
        }
        
        // Check that the text-encoded Sequence Number is not greater than the stored highest Sequence Number
        int seqNum;
        String seqNumStr = rawCti.substring(rsIdLen, rawCtiLen);
        try {
        	seqNum = Integer.parseInt(seqNumStr);
        }
        catch (NumberFormatException e) {
        	// The 'cti' claim is malformed - The Sequence Number is not encoded as a parsable integer
        	return -1;
	    }
        
        return seqNum;
    	
    }
    
    /**
     * Retrieve the highest Exi Sequence Number value, related
     * to received Access Tokens that include the 'exi' claim
     * 
     */
    public synchronized int getTopExiSequenceNumber() {
    	return this.topExiSequenceNumber;
    }
    
    /**
     * Set the value of the highest Exi Sequence Number value, related
     * to received Access Tokens that include the 'exi' claim
     * 
     * @param seqNum   The new highest Exi Sequence Number value
     */
    private synchronized void setTopExiSequenceNumber(int seqNum) {
    	if (seqNum > this.topExiSequenceNumber) {
    		this.topExiSequenceNumber = seqNum;
    	}
    }
        
}

