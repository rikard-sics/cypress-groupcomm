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
package se.sics.ace.coap.rs.oscoreProfile;

import java.util.logging.Logger;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import se.sics.ace.AceException;
import se.sics.ace.Constants;

/**
 * Utility class to parse, verify and access  OSCORE_Input_Material in a cnf element
 * 
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class OscoreSecurityContext {
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(OscoreSecurityContext.class.getName());
    
    /**
     * The Master Secret
     */
    private byte[] ms;
    
    /**
     * The OSCORE Input Material Identifier
     */
    private byte[] id;
    
    /**
     * The server identifier
     */
    private byte[] serverId;
    
    /**
     * The client identifier
     */
    private byte[] clientId;
    
    /**
     * The context id, can be null
     */
    private byte[] contextId;
    
    /**
     * The key derivation function, can be null for default: HMAC_SHA_256
     */
    private AlgorithmID hkdf;
    
    /**
     * The encryption algorithm, can be null for default: AES_CCM_16_64_128
     */
    private AlgorithmID alg;
    
    /**
     * The Master Salt, can be null
     */
    private byte[] salt;

    /**
     * The replay window size
     */
    private Integer replaySize;
    
    /**
     * Max unfragmented size parameter for OSCORE
     */
    private final static int MAX_UNFRAGMENTED_SIZE = 4096;
    
    /**
     * Constructor.
     * 
     * @param cnf  the confirmation CBORObject containing 
     *      the OSCORE Security Context.
     * 
     * @throws AceException 
     */
    public OscoreSecurityContext(CBORObject cnf) throws AceException {
        CBORObject osc = cnf.get(Constants.OSCORE_Input_Material);
        if (osc == null || !osc.getType().equals(CBORType.Map)) {
            LOGGER.info("Missing or invalid parameter type for "
                    + "'OSCORE_Input_Material', must be CBOR-map");
            throw new AceException("invalid/missing OSCORE_Input_Material");
        }
        
        CBORObject algC = osc.get(Constants.OS_ALG);
        this.alg = null;
        if (algC != null) {
            try {
                this.alg = AlgorithmID.FromCBOR(algC);
            } catch (CoseException e) {
                LOGGER.info("Invalid algorithmId: " + e.getMessage());
                throw new AceException(
                        "Malformed algorithm Id in OSCORE security context");
            }
        }
        
        CBORObject clientIdC = osc.get(Constants.OS_CLIENTID);
        if (clientIdC != null) {
            if (!clientIdC.getType().equals(CBORType.ByteString)) {
                LOGGER.info("Invalid parameter: 'clientId',"
                        + " must be byte-array");
                throw new AceException(
                        "Malformed client Id in OSCORE security context");
            }
            this.clientId = clientIdC.GetByteString();
        }
               
        CBORObject ctxIdC = osc.get(Constants.OS_CONTEXTID);
        if (ctxIdC != null) {
            if (!ctxIdC.getType().equals(CBORType.ByteString)) {
                LOGGER.info("Invalid parameter: 'contextID',"
                        + "must be byte-array");
                throw new AceException( 
                        "Malformed context Id in OSCORE security context");
            }
            this.contextId = ctxIdC.GetByteString();
        }
        else {
        	this.contextId = null;
        }

        CBORObject kdfC = osc.get(Constants.OS_HKDF);
        if (kdfC != null) {
            try {
                this.hkdf = AlgorithmID.FromCBOR(kdfC);
            } catch (CoseException e) {
                LOGGER.info("Invalid kdf: " + e.getMessage());
                throw new AceException(
                        "Malformed KDF in OSCORE security context");
            }
        }

        CBORObject msC = osc.get(Constants.OS_MS);
        if (msC == null || !msC.getType().equals(CBORType.ByteString)) {
            LOGGER.info("Missing or invalid parameter: 'master secret',"
                    + " must be byte-array");
            throw new AceException("malformed or missing master secret"
                    + " in OSCORE security context");
        }
        this.ms = msC.GetByteString();

        CBORObject idC = osc.get(Constants.OS_ID);
        if (idC == null || !idC.getType().equals(CBORType.ByteString)) {
            LOGGER.info("Missing or invalid parameter: 'id',"
                    + " must be byte-array");
            throw new AceException("malformed or missing input material identifier"
                    + " in OSCORE security context");
        }
        this.id = idC.GetByteString();
        
        CBORObject saltC = osc.get(Constants.OS_SALT);
        if (saltC != null) {
            if (!saltC.getType().equals(CBORType.ByteString)) {
                LOGGER.info("Invalid parameter: 'master salt',"
                        + " must be byte-array");
                throw new AceException("malformed master salt"
                        + " in OSCORE security context");
            }
            this.salt = saltC.GetByteString();
        }        
        
        CBORObject serverIdC = osc.get(Constants.OS_SERVERID);
        if (serverIdC == null 
                || !serverIdC.getType().equals(CBORType.ByteString)) {
            LOGGER.info("Missing or invalid parameter: 'serverId',"
                    + " must be byte-array");
            throw new AceException("malformed or missing server id"
                    + " in OSCORE security context");
        }
        this.serverId = serverIdC.GetByteString();
        
    }
    
    /**
     * @param isClient
     * @param n1  the client's nonce
     * @param n2  the server's nonce
     * @return  an OSCORE context based on this object 
     * @throws OSException 
     */
    public OSCoreCtx getContext(boolean isClient, byte[] n1, byte[] n2) 
            throws OSException {
        byte[] senderId;
        byte[] recipientId;

        byte[] finalSalt;
        
        // The final Master Salt is the concatenation of whole CBOR byte strings
        byte[] saltEncoded = null;
        byte[] n1Encoded = null;
        byte[] n2Encoded = null;
        if (this.salt != null) {
            CBORObject saltCBOR = CBORObject.FromObject(this.salt);
        	saltEncoded  = saltCBOR.EncodeToBytes();
        }
        CBORObject n1CBOR = CBORObject.FromObject(n1);
        CBORObject n2CBOR = CBORObject.FromObject(n2);
        n1Encoded = n1CBOR.EncodeToBytes();
        n2Encoded = n2CBOR.EncodeToBytes();
        if (saltEncoded != null) {
            finalSalt = new byte[saltEncoded.length + n1Encoded.length + n2Encoded.length];
            System.arraycopy(saltEncoded, 0, finalSalt, 0, saltEncoded.length);
            System.arraycopy(n1Encoded, 0, finalSalt, saltEncoded.length, n1Encoded.length);
            System.arraycopy(n2Encoded, 0, finalSalt, saltEncoded.length + n1Encoded.length, n2Encoded.length);
        } else {
            finalSalt = new byte[n1Encoded.length + n2Encoded.length];
            System.arraycopy(n1Encoded, 0, finalSalt, 0, n1Encoded.length);
            System.arraycopy(n2Encoded, 0, finalSalt, n1Encoded.length, n2Encoded.length);
        }
                
        if (isClient) {
        	/*
            senderId = id2;
            recipientId = id1;
            */
            senderId = this.clientId;
            recipientId = this.serverId;
            
        } else {
        	/*
            senderId = id1;
            recipientId = id2;
            */
            senderId = this.serverId;
            recipientId = this.clientId;
        }
        
        org.eclipse.californium.cose.AlgorithmID algId = null;
        org.eclipse.californium.cose.AlgorithmID hkdfId = null;
        try {
            if(this.alg != null) {
                algId = org.eclipse.californium.cose.AlgorithmID.FromCBOR(this.alg.AsCBOR());
            }
            
            if(this.hkdf != null) {
                hkdfId = org.eclipse.californium.cose.AlgorithmID.FromCBOR(this.hkdf.AsCBOR());
            }
        } catch (org.eclipse.californium.cose.CoseException e) {
            System.err.println("Failed conversion of alg or hkdf to create OSCORE Context!");
            e.printStackTrace();
        }
        
        return new OSCoreCtx(this.ms, isClient, algId, senderId, 
                recipientId, hkdfId, this.replaySize, finalSalt, 
                this.contextId, MAX_UNFRAGMENTED_SIZE);
    }
    
    /**
     * @return  the client identifier
     */
    public byte[] getClientId() {
        return this.clientId;
    }
    
    /**
     * @return  the server identifier
     */
    public byte[] getServerId() {
        return this.serverId;
    }
    
    /**
     * @return  the input material identifier
     */
    public byte[] getId() {
        return this.id;
    }
    
    /**
     * @return  the context id
     */
    public byte[] getContextId() {
        return this.contextId;
    }

}
