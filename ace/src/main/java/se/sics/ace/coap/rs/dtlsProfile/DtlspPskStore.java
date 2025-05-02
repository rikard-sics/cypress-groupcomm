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
package se.sics.ace.coap.rs.dtlsProfile;

import java.net.InetSocketAddress;
import java.util.Base64;
import java.util.logging.Logger;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.HandshakeResultHandler;
import org.eclipse.californium.scandium.dtls.PskPublicInformation;
import org.eclipse.californium.scandium.dtls.PskSecretResult;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedPskStore;
import org.eclipse.californium.scandium.util.ServerNames;

import com.upokecenter.cbor.CBORException;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.Message;
import se.sics.ace.examples.LocalMessage;
import se.sics.ace.rs.AuthzInfo;
import se.sics.ace.rs.TokenRepository;

/**
 * A store for Pre-Shared-Keys (PSK) at the RS.
 * 
 * Implements the retrieval of the access token as defined in section 3.3.2 of RFC 9202.
 * 
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class DtlspPskStore implements AdvancedPskStore {
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(DtlspPskStore.class.getName());
    
    
    /**
     * This component needs to access the authz-info endpoint.
     */
    private AuthzInfo authzInfo;
        
    
    /**
     * Constructor.
     * 
     * @param authzInfo  the authz-info used by this RS
     */
    public DtlspPskStore(AuthzInfo authzInfo) {
        this.authzInfo = authzInfo;
    }
    
    @Override
    public PskSecretResult requestPskSecretResult(ConnectionId cid, ServerNames serverName,
            PskPublicInformation identity, String hmacAlgorithm, SecretKey otherSecret, byte[] seed,
            boolean useExtendedMasterSecret) {
        return new PskSecretResult(cid, identity, getKey(identity));
    }

    public SecretKey getKey(PskPublicInformation identity) {

        // This profile expects opaque bytes as "psk_identity" on the wire.
        // If character strings were also used, an alternative method
        // would have to be invoked here to process it accordingly,
        // such as getKey(identity.getPublicInfoAsString())

        return getKey(identity.getBytes(), identity);

    }
   
    /**
     * Avoid having to refactor all my code since the CF people decided they needed to change public APIs
     * 
     * @param identity the identity of the key
     * @return the bytes of the key
     */
    private SecretKey getKey(byte[] rawIdentity, PskPublicInformation originalIdentity) {

        if (TokenRepository.getInstance() == null) {
            LOGGER.severe("TokenRepository not initialized");
            return null;
        }
        // First try if we have that key
        OneKey key = null;
        try {

            CBORObject identityStructure;

            try {
                identityStructure = CBORObject.DecodeFromBytes(rawIdentity);
            } catch (CBORException e) {
                LOGGER.severe("Error: " + e.getMessage());
                return null;
            }

            if (identityStructure != null && identityStructure.getType() == CBORType.Map
                    && identityStructure.size() == 1) {

                CBORObject cnfStructure = identityStructure.get(Constants.CNF);
                if (cnfStructure != null && cnfStructure.getType() == CBORType.Map && cnfStructure.size() == 1) {

                    CBORObject COSEKeyStructure = cnfStructure.get(Constants.COSE_KEY_CBOR);
                    if (COSEKeyStructure != null && COSEKeyStructure.getType() == CBORType.Map
                            && COSEKeyStructure.size() == 2) {

                        if (COSEKeyStructure
                                .get(CBORObject.FromObject(KeyKeys.KeyType.AsCBOR())) == KeyKeys.KeyType_Octet
                                && COSEKeyStructure.get(CBORObject.FromObject(KeyKeys.KeyId.AsCBOR())) != null) {

                            byte[] kid = COSEKeyStructure.get(CBORObject.FromObject(KeyKeys.KeyId)).GetByteString();

                            String kidString = Base64.getEncoder().encodeToString(kid);
                            key = TokenRepository.getInstance().getKey(kidString);

                            // For correct storage in the DTLS Key Store, change the originally received
                            // key identity from the "psk_identity" on the wire to only the "kid" included in it
                            originalIdentity.normalize(kidString);

                        }

                    }

                }

            }

            if (key != null) {
                return new SecretKeySpec(key.get(KeyKeys.Octet_K).GetByteString(), "PSK");
            }
        } catch (AceException e) {
            LOGGER.severe("Error: " + e.getMessage());
            return null;
        }

        //We don't have that key, try if the identity is an access token
        CBORObject payload = null;
        try {
            payload = CBORObject.DecodeFromBytes(rawIdentity);       	
        } catch (NullPointerException | CBORException e) {
            LOGGER.severe("Error decoding the psk_identity: " 
                    + e.getMessage());
            return null;
        }
        
        //We may have an access token, continue processing it

        // For correct storage in the Token Repository, use as subject identity
   	    // the base 64 serialization of what seen as "psk_identity" on the wire
        String identityStr = Base64.getEncoder().encodeToString(rawIdentity);
        LocalMessage message = new LocalMessage(0, identityStr, null, payload);
        
        
        LocalMessage res
            = (LocalMessage)this.authzInfo.processMessage(message);
        if (res.getMessageCode() == Message.CREATED) {
            CBORObject resPayl = CBORObject.DecodeFromBytes(res.getRawPayload());
            if (!resPayl.getType().equals(CBORType.Map)) {
                LOGGER.severe("Authz-Info returned non-CBOR-Map payload");
                return null;
            }
            //Note that this is either the token's cti or the internal
            //id that the AuthzInfo endpoint assigned to it 
            CBORObject cti = resPayl.get(CBORObject.FromObject(Constants.CTI));
            String ctiStr = Base64.getEncoder().encodeToString(
                    cti.GetByteString());
            try {
            	 
           	    // For correct storage in the DTLS Key Store, change the originally received
           	    // the base 64 serialization of what seen as "psk_identity" on the wire
            	originalIdentity.normalize(identityStr);
            	 
                 key = TokenRepository.getInstance().getPoP(ctiStr);
                 return new SecretKeySpec(
                         key.get(KeyKeys.Octet_K).GetByteString(), "PSK");
            } catch (AceException e) {
                LOGGER.severe("Error: " + e.getMessage());
                return null;
            }
        }
        LOGGER.severe("Error: Token in psk_identity not valid");  
        return null;
    }


    @Override
    public PskPublicInformation getIdentity(InetSocketAddress peerAddress,
            ServerNames virtualHost) {
        // XXX: No support for ServerNames extension yet
        return null;
    }

    @Override
    public boolean hasEcdhePskSupported() {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public void setResultHandler(HandshakeResultHandler resultHandler) {
        // TODO Auto-generated method stub

    }

}
