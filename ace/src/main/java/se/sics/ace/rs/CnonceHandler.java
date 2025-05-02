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

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import java.util.logging.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import se.sics.ace.AceException;
import se.sics.ace.Constants;

/**
 * This class handles the freshness verification using client-nonces
 * (see Section 5.3.1 of RFC 9200).
 * 
 * @author Ludwig Seitz
 *
 */
public class CnonceHandler {

    /**
     * The singleton instance
     */
    private static CnonceHandler singleton = null;
    
    /**
     * The default window size
     */
    private static int defaultWindowSize = 30;
    
    /**
     * The counter used to generate the cnonces.
     * -1 means we don't use cnonces.
     */
    private Integer cnonceCounter = -1;
    
    /**
     * The last seen nonce
     */
    private int cnonceSeen;
    
    /**
     * The size of the replay window
     */
    private int cnonceWindowSize;

    /**
     * Cnonce replay window, 
     */
    private int cnonceWindow; 
    
    /**
     * Cnonce HMAC key (32 bytes)
     */
    private byte[] cnonceKey;
   
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(CnonceHandler.class.getName());
    
    /**
     * Create the cnonce handler.
     * 
     * @param cnonceReplayWindowSize  the cnonce replay window size (or null to
     *     use the default)
     */
    protected CnonceHandler() {
        this.cnonceCounter = 1;
        this.cnonceSeen = 0;
        this.cnonceKey = new byte[32];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(this.cnonceKey);  
        this.cnonceWindow = 0;
        this.cnonceWindowSize = defaultWindowSize;
    }
    
    /**
     * The singleton getter
     * @return  the singleton repository
     * @throws AceException  if the handler is not initialized
     */
    public static CnonceHandler getInstance() {
        if (singleton == null) {
            singleton = new CnonceHandler();
        }
        return singleton;
    }
    
    /**
     * Set the default window size for the replay window.
     * Will only have effect before the singleton is created.
     * 
     * @param size  the size of the replay window
     */
    public static void setDefaultWindowSize(int size) {
        if (singleton != null) {
            throw new RuntimeException(
                    "Cannot window size after singleton was created");
        }
        if (size < 0 || size > 32) {
            throw new IllegalArgumentException(
                    "cnonceWindow size must be between 0 and 32");
        }
        defaultWindowSize = size;
    }
    
    /**
     * Implements the nonce checking for a token received at authz-info.
     * 
     * @param claims  the claims of the token to check
     * @throws AceException 
     */
    public void checkNonce(Map<Short, CBORObject> claims) throws AceException {
        if (this.cnonceCounter == -1) {//Means we are not using the client nonces
            return;
        }
        CBORObject cnonce = claims.get(Constants.CNONCE);
        if (cnonce == null) {
            LOGGER.info("Expected a cnonce but found none");
            throw new AceException("cnonce expected but not found");
        }

        if (!cnonce.getType().equals(CBORType.ByteString)) {
            throw new AceException("Invalid cnonce type");
        }
        byte[] cnonceB = cnonce.GetByteString();
        if (cnonceB.length != 4+32) {//4 byte for the int counter, 16 bytes HMAC
            throw new AceException("Invalid cnonce length");
        }
        byte[] mac = new byte[32];
        byte[] counter = new byte[4];
        mac = Arrays.copyOfRange(cnonceB, 0, 32);
        counter = Arrays.copyOfRange(cnonceB, 32, 36);
        byte[] macExpected;
        //Verify MAC
        try {
            Mac sha256_HMAC = Mac.getInstance("HmacSHA256");

            SecretKeySpec secret_key = new SecretKeySpec(
                    this.cnonceKey, "HmacSHA256");
            sha256_HMAC.init(secret_key);

            macExpected = sha256_HMAC.doFinal(counter);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            LOGGER.severe("Error while verifying cnonce: " + e.getMessage());
            throw new AceException("Nonce verification failed");
        }

        if (!Arrays.equals(mac, macExpected)) {
            throw new AceException("cnonce invalid");
        }

        //Check if nonce is in the replay window
        ByteBuffer b = ByteBuffer.wrap(counter);
        int counterI = b.getInt();
        checkIncomingCounter(counterI);
    }

    /**
     * Check an incoming cnonce counter
     * @param counter
     * @throws AceException
     */
    private synchronized void checkIncomingCounter(int counter) throws AceException {
        if (counter > this.cnonceSeen) {
            // Update the replay window
            int shift = counter - this.cnonceSeen;
            this.cnonceWindow = this.cnonceWindow << shift;
            this.cnonceSeen = counter;
        } else if (counter == this.cnonceSeen) {
            throw new AceException("cnonce replayed");
        } else { // counter < this.cnonceSeen
            if (counter + this.cnonceWindowSize < this.cnonceSeen) {
                LOGGER.severe("cnonce too old");
                throw new AceException("cnonce expired");
            }
            // seq+replay_window_size > recipient_seq
            int shift = this.cnonceSeen - counter;
            int pattern = 1 << shift;
            int verifier = this.cnonceWindow & pattern;
            verifier = verifier >> shift;
            if (verifier == 1) {
                throw new AceException("cnonce replayed");
            }
            this.cnonceWindow = this.cnonceWindow | pattern;
        }
    }
    
    /**
     * Create a client-nonce to ensure freshness of access tokens, when the
     * RS has no synchronzied clock with the AS. 
     * 
     * @return  a nonce
     *
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeyException 
     */
    public byte[] createNonce() 
            throws NoSuchAlgorithmException, InvalidKeyException {
        if (this.cnonceCounter == -1) {
            LOGGER.info("cnonce requested but not configured to handle them");
            return null;
        }
        if (this.cnonceCounter == Integer.MAX_VALUE) {
            LOGGER.info("cnonce counter wrapped");
            this.cnonceCounter = 1;
            this.cnonceSeen = 0;
            this.cnonceWindow = 0;
            //Generate a new key to invalidate the old cnonces
            this.cnonceKey = new byte[32];
            new SecureRandom().nextBytes(this.cnonceKey);  
        } 

        byte[] mac = null;
        byte[] counter = ByteBuffer.allocate(4).putInt(
                this.cnonceCounter).array();
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(
                this.cnonceKey, "HmacSHA256");
        sha256_HMAC.init(secret_key);
        mac = sha256_HMAC.doFinal(counter);  
        byte[] nonce = new byte[mac.length + counter.length];
        System.arraycopy(mac,0, nonce, 0, mac.length);
        System.arraycopy(counter, 0, nonce , mac.length, counter.length);
        this.cnonceCounter++;       
        
        
        return nonce;
    }

}
