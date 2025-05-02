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
package se.sics.ace.as;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.upokecenter.cbor.CBORObject;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.Attribute;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.HeaderKeys;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.MessageTag;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.cose.Recipient;
import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.cwt.CwtCryptoCtx;

/**
 * Utility methods for the token and introspect endpoints.
 * 
 * @author Ludwig Seitz
 *
 */
public class EndpointUtils {

    
    /**
     * Create a common CWT crypto context for the given audience.
     * 
     * @param aud  the audiences
     * @param db  the database connector
     * @param asymKey  the asymmetric key of the AS if Sign1 is
     *      to be used, null otherwise 
     * @param verify  true if the context is needed for verifying, false if
     *  it is for signing.
     * 
     * @return  a common crypto context or null if there isn't any
     * 
     * @throws CoseException 
     * @throws AceException 
     */
    public static CwtCryptoCtx makeCommonCtx(Set<String> aud, DBConnector db, 
            OneKey asymKey, boolean verify) throws AceException, CoseException {
        COSEparams cose = db.getSupportedCoseParams(aud);
        if (cose == null) {
            return null;
        }
        MessageTag tag = cose.getTag();
        switch (tag) {
        case Encrypt:
            AlgorithmID ealg = cose.getAlg();
            return CwtCryptoCtx.encrypt(makeRecipients(aud, cose, db), 
                    ealg.AsCBOR());
        case Encrypt0:
            byte[] ekey = getCommonSecretKey(aud, db);
            if (ekey == null) {
                return null;
            }
            return CwtCryptoCtx.encrypt0(ekey, cose.getAlg().AsCBOR());
        case MAC:

            return CwtCryptoCtx.mac(makeRecipients(aud, cose, db), 
                    cose.getAlg().AsCBOR());
        case MAC0:
            byte[] mkey = getCommonSecretKey(aud, db);
            if (mkey == null) {
                return null;
            }
            return CwtCryptoCtx.mac0(mkey, cose.getAlg().AsCBOR());
        case Sign:
            // Access tokens with multiple signers not supported
            return null;
        case Sign1:
            if (verify) {
                return CwtCryptoCtx.sign1Verify(asymKey.PublicKey(), 
                        cose.getAlg().AsCBOR());
            }
            return CwtCryptoCtx.sign1Create(
                    asymKey, cose.getAlg().AsCBOR());
        default:
            throw new IllegalArgumentException("Unknown COSE message type");
        }
    }
    
    /**
     * Tries to find a common PSK for the given audience.
     * 
     * @param aud  the audience
     * @param db  the database connector
     * 
     * @return  a common PSK or null if there isn't any
     * @throws AceException 
     */
    private static byte[] getCommonSecretKey(Set<String> aud, DBConnector db) 
            throws AceException {
        Set<String> rss = new HashSet<>();
        for (String audE : aud) {
            rss.addAll(db.getRSS(audE));
        }
        byte[] key = null;
        for (String rs : rss) {
            OneKey cose = db.getRsTokenPSK(rs);
            if (cose == null) {
                return null;
            }
            byte[] secKey = cose.get(KeyKeys.Octet_K).GetByteString();
            if (key == null) {
                key = Arrays.copyOf(secKey, secKey.length);
            } else {
                if (!Arrays.equals(key, secKey)) {
                    return null;
                }
            }
        }
        return key;
    }
      
    /**
     * Create a recipient list for an audience.
     * 
     * @param aud  the audience
     * @param cose  the COSE parameters
     * @param db  the database connector
     * 
     * @return  the recipient list
     * @throws AceException 
     * @throws CoseException 
     */
    private static List<Recipient> makeRecipients(Set<String> aud, COSEparams cose,
            DBConnector db) throws AceException, CoseException {
        List<Recipient> rl = new ArrayList<>();
        for (String audE : aud) {
            for (String rs : db.getRSS(audE)) {
                Recipient r = new Recipient();
                r.addAttribute(HeaderKeys.Algorithm, 
                        cose.getKeyWrap().AsCBOR(), 
                        Attribute.UNPROTECTED);
                CBORObject key = CBORObject.NewMap();
                key.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
                key.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(
                        db.getRsTokenPSK(rs)));
                OneKey coseKey = new OneKey(key);
                r.SetKey(coseKey); 
                rl.add(r);
            }
        }
        return rl;
    }


   
}
