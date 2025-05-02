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

import java.net.InetSocketAddress;
import java.sql.SQLException;
import java.util.logging.Logger;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.HandshakeResultHandler;
import org.eclipse.californium.scandium.dtls.PskPublicInformation;
import org.eclipse.californium.scandium.dtls.PskSecretResult;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedPskStore;
import org.eclipse.californium.scandium.util.ServerNames;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import se.sics.ace.AceException;
import se.sics.ace.examples.SQLConnector;
import se.sics.ace.examples.SQLDBAdapter;

/**
 * A SQLConnector for CoAP, implementing the PskStore interface.
 * 
 * @author Ludwig Seitz
 *
 */
public class CoapDBConnector extends SQLConnector implements AdvancedPskStore {
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(CoapDBConnector.class.getName() );
    
    /**
     * The singleton instance
     */
    private static CoapDBConnector connector;

    /**
     * Constructor.
     *
     * @param dbAdapter handler for engine-db specific commands.
     *
     * @throws SQLException
     */
    protected CoapDBConnector(SQLDBAdapter dbAdapter)
            throws SQLException {
        super(dbAdapter);
    }

    @Override
    public PskSecretResult requestPskSecretResult(ConnectionId cid, ServerNames serverName,
            PskPublicInformation identity, String hmacAlgorithm, SecretKey otherSecret, byte[] seed,
            boolean useExtendedMasterSecret) {
        return new PskSecretResult(cid, identity, getKey(identity.getPublicInfoAsString()));
    }

    public SecretKey getKey(PskPublicInformation info) {
        return getKey(info.getPublicInfoAsString());
    }

    /**
     * Avoid having to refactor all my code because the CF people decided they needed to change APIs.
     * 
     * @param identity  the identity of the key
     * @return  the key
     */
    private SecretKey getKey(String identity) {
        OneKey key = null;
        try {
            key = super.getCPSK(identity);
        } catch (AceException e) {
            LOGGER.severe(e.getMessage());
            return null;
        }
        if (key == null) {
            try {
                key = super.getRsAuthPSK(identity);
            } catch (AceException e) {
                LOGGER.severe(e.getMessage());
                return null;
            }
        }
        if (key == null) { //Key not found
           return null;
        }
        CBORObject val = key.get(KeyKeys.KeyType);
        if (val.equals(KeyKeys.KeyType_Octet)) {
            val = key.get(KeyKeys.Octet_K);
            if ((val== null) || (val.getType() != CBORType.ByteString)) {
                return null; //Malformed key
            }
            return new SecretKeySpec(val.GetByteString(), "PSK");
        }
        return null; //Wrong KeyType
          
        
    }

   /**
    * Gets the singleton instance of this connector.
    * 
    * @param dbCreator a creator instance for the specific DB type being used.
    *
    * @return  the singleton instance
    * 
    * @throws SQLException
    */
   public static CoapDBConnector getInstance(SQLDBAdapter dbCreator) throws SQLException {
       if (CoapDBConnector.connector == null) {
           CoapDBConnector.connector 
               = new CoapDBConnector(dbCreator);
       }
       return CoapDBConnector.connector;
   }

    @Override
    public PskPublicInformation getIdentity(InetSocketAddress inetAddress, ServerNames virtualHost) {
        return null;
    }
    
    /**
     * Close the connections. After this any other method calls to this
     * object will lead to an exception.
     * 
     * @throws AceException
     */
    @Override
    public synchronized void close() throws AceException {
       super.close();
       CoapDBConnector.connector = null;
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
