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
package se.sics.ace.coap.as;

import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.scandium.dtls.PskPublicInformation;

import org.eclipse.californium.cose.OneKey;

import se.sics.ace.AceException;
import se.sics.ace.TimeProvider;
import se.sics.ace.as.Introspect;
import se.sics.ace.as.PDP;
import se.sics.ace.as.Token;
import se.sics.ace.coap.rs.oscoreProfile.OscoreCtxDbSingleton;

/**
 * An Authorization Server that offers secure connections and authentication via OSCORE.
 * 
 * This server uses the following conventions:
 * 
 * alg = AES_CCM_16_64_128
 * salt = null
 * kdf = HMAC_SHA_256
 * recipient_replay_window_size = 32
 * id_context = null
 * sender_id = asId
 * recipient_id = rs/client id
 * 
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class OscoreAS extends CoapServer implements AutoCloseable {

    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(OscoreAS.class.getName());
    
    /**
     * The token endpoint
     */
    Token t = null;
    
    /**
     * The introspect endpoint
     */
    Introspect i = null;

    private OscoreAceEndpoint token;

    private OscoreAceEndpoint introspect;
    
    private final static int MAX_UNFRAGMENTED_SIZE = 4096;
    
    /**
     * Constructor.
     * 
     * @param asId  identifier of the AS
     * @param db    database connector of the AS
     * @param pdp   PDP for deciding who gets which token
     * @param time  time provider, must not be null
     * @param asymmetricKey  asymmetric key pair of the AS or 
     *      null if it hasn't any
     * @param port  the port number to run the server on
     * 
     * @throws AceException 
     * @throws OSException 
     * 
     */
    public OscoreAS(String asId, CoapDBConnector db, 
            PDP pdp, TimeProvider time, 
            OneKey asymmetricKey, int port,
            Map<String, String> peerNamesToIdentities,
            Map<String, String> peerIdentitiesToNames,
            Map<String, String> myIdentities) 
                    throws AceException, OSException {
        this(asId, db, pdp, time, asymmetricKey, "token", "introspect", port,
                null, false, (short)0, false, peerNamesToIdentities,
                peerIdentitiesToNames, myIdentities);
    }
    
    
    /**
     * Constructor.
     * 
     * @param asId  identifier of the AS
     * @param db    database connector of the AS
     * @param pdp   PDP for deciding who gets which token
     * @param time  time provider, must not be null
     * @param asymmetricKey  asymmetric key pair of the AS or 
     *      null if it hasn't any
     * @throws AceException 
     * @throws OSException 
     * 
     */
    public OscoreAS(String asId, CoapDBConnector db, PDP pdp, TimeProvider time, 
            OneKey asymmetricKey, Map<String, String> peerNamesToIdentities,
            Map<String, String> peerIdentitiesToNames,
            Map<String, String> myIdentities) throws AceException, OSException {
        this(asId, db, pdp, time, asymmetricKey, "token", "introspect",
                CoAP.DEFAULT_COAP_PORT, null, false, (short)0, false,
                peerNamesToIdentities, peerIdentitiesToNames, myIdentities);
    }
    
    
    /**
     * Constructor.
     * 
     * @param asId  identifier of the AS
     * @param db    database connector of the AS
     * @param pdp   PDP for deciding who gets which token
     * @param time  time provider, must not be null
     * @param asymmetricKey  asymmetric key pair of the AS or 
     *      null if it hasn't any
     * @param tokenName the name of the token endpoint 
     *      (will be converted into the address as well)
     * @param introspectName  the name of the introspect endpoint 
     *      (will be converted into the address as well), if this is null,
     *      no introspection endpoint will be offered
     * @param port  the port number to run the server on
     * @param claims  the claim types to include in tokens issued by this 
     *                AS, can be null to use default set
     * @param setAudHeader  insert the AUD as header in the CWT.
     * @param masterSaltSize  the size in bytes of the Master Salt to provide. It can be 0 to not provide a Master Salt
     * @param provideIdContext  true if the Id Context has to provided, or false otherwise
     * @param peerNamesToIdentities  mapping between the names of the peers and their OSCORE identities
     * @param myIdentities  mapping between the names of the peers and the OSCORE identities that the AS uses with them
     * 
     * @throws AceException 
     * @throws OSException 
     * 
     */
    public OscoreAS(String asId, CoapDBConnector db,
            PDP pdp, TimeProvider time, OneKey asymmetricKey, String tokenName,
            String introspectName, int port, Set<Short> claims, 
            boolean setAudHeader, short masterSaltSize, boolean provideIdContext,
            Map<String, String> peerNamesToIdentities,
            Map<String, String> peerIdentitiesToNames,
            Map<String, String> myIdentities) throws AceException, OSException {
        this.t = new Token(asId, pdp, db, time, asymmetricKey, claims, setAudHeader,
        				   masterSaltSize, provideIdContext, peerIdentitiesToNames);
        this.token = new OscoreAceEndpoint(tokenName, this.t);
        add(this.token);
                
        if (introspectName != null) {
            if (asymmetricKey == null) {
                this.i = new Introspect(pdp, db, time, null, peerIdentitiesToNames);
            } else {
                this.i = new Introspect(pdp, db, time, asymmetricKey.PublicKey(), peerIdentitiesToNames);
            }
            this.introspect = new OscoreAceEndpoint(introspectName, this.i);
            add(this.introspect);    
        }
        this.addEndpoint(new CoapEndpoint.Builder()
                .setCoapStackFactory(new OSCoreCoapStackFactory())
                .setPort(port)
                .setCustomCoapStackArgument(OscoreCtxDbSingleton.getInstance())
                .build());  
        loadOscoreCtx(db, peerNamesToIdentities, myIdentities);

    }

    /**
     * Load the OSCORE contexts from the database
     * 
     * @param db  the database connector
     * @param asId  the AS identifier
     * @param peerNamesToIdentities  mapping between the names of the peers and their OSCORE identities
     * @param myIdentities  mapping between the names of the peers and the OSCORE identities that the AS uses with them
     * 
     * @throws AceException
     * @throws OSException
     */
    private static void loadOscoreCtx(CoapDBConnector db,
    								  Map<String, String> peerNamesToIdentities,
    								  Map<String, String> myIdentities) throws AceException, OSException {
        Set<String> ids = db.getRSS();
        ids.addAll(db.getClients());
        
        for (String id : ids) {
            byte[] key = db.getKey(new PskPublicInformation(id)).getEncoded();
                        
            // The identity that this AS uses with this peer
            String identity = myIdentities.get(id);
            IdPair idPair = new IdPair(identity);
            if (idPair.getSenderId() == null) {
            	// This identity is malformed; proceed to the next one
            }
            byte[] senderId = idPair.getSenderId();
            byte[] contextId = idPair.getContextId();
            
            // The identity that this peer uses with this AS
            identity = peerNamesToIdentities.get(id);
            idPair = new IdPair(identity);
            if (idPair.getSenderId() == null) {
            	// This identity is malformed; proceed to the next one
            }
            byte[] recipientId = idPair.getSenderId();
            byte[] contextIdBis = idPair.getContextId();
            
            // This are all error conditions; skipped this peer and proceed to the next one
            if (!Arrays.equals(contextId, contextIdBis)) {
            	continue;
            }
            
            OSCoreCtx ctx = new OSCoreCtx(key, false, null, senderId, 
            		recipientId, null, null, null, contextId, MAX_UNFRAGMENTED_SIZE);
            OscoreCtxDbSingleton.getInstance().addContext(ctx);
            
        }
        LOGGER.finest("Loaded OSCORE contexts");
    }

    @Override
    public void close() throws Exception {
        LOGGER.info("Closing down OscoreAS ...");
        this.token.close();
        this.introspect.close();       
    }
    
    public static class IdPair {
    	
    	private byte[] senderId;
    	private byte[] contextId;
    	
    	public IdPair(String identity) {
    		
    		senderId = null;
    		contextId = null;
    		
    		int index = identity.indexOf(":");
    		
    		if (index != -1) {
    			// The Context ID is present
    			contextId = Base64.getDecoder().decode(identity.substring(0, index));
    		}
    		index++; // This becomes 0 if the Context ID was not present
    		senderId = Base64.getDecoder().decode(identity.substring(index, identity.length()));
    		
    	}
    	
    	public byte[] getSenderId() {
    		return senderId;
    	}
    	
    	public byte[] getContextId() {
    		return contextId;
    	}
    	
    }

}
