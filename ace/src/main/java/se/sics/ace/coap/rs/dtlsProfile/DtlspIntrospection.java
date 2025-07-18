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
package se.sics.ace.coap.rs.dtlsProfile;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.x509.AsyncCertificateVerifier;
import org.eclipse.californium.scandium.dtls.x509.SingleCertificateProvider;

import com.upokecenter.cbor.CBORObject;

import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.Util;
import se.sics.ace.coap.BksStore;
import se.sics.ace.rs.IntrospectionException;
import se.sics.ace.rs.IntrospectionHandler;

/**
 * An introspection handler using CoAPS (i.e. CoAP over DTLS) to connect to an AS.
 *
 * @author Ludwig Seitz
 *
 */
public class DtlspIntrospection implements IntrospectionHandler {
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(DtlspIntrospection.class.getName());
    
     /**
     * The CoAP client
     */
    private CoapClient client = null;
    
    // Authentication asymmetric key pair of the Resource Server
    // ECDSA with P-256
    private static String rsX_ECDSA = "73B7D755827D5D59D73FD4015D47B445762F7CDB59799CD966714AB2727F1BA5";
    private static String rsY_ECDSA = "1A84F5C82797643D33F7E6E6AFCF016522238CE430E1BF21A218E6B4DEEAC37A";
    private static String rsD_ECDSA = "00EA086573C683477D74EB7A0C63A6D031D5DEB10F3CC2876FDA6D3400CAA4E507";
    private static OneKey rsRPK = null;
    
    /**
     * Constructor, builds a client that uses raw public keys.
     * 
     * @param rpk  the raw public key 
     * @param introspectAddress  the IP address of the introspect endpoint
     * 
     * 
     * @throws CoseException
     * @throws IOException 
     * 
     */
    public DtlspIntrospection(OneKey rpk, String introspectAddress) 
            throws CoseException, IOException {
    	
        Configuration dtlsConfig = Configuration.getStandard();
        dtlsConfig.set(DtlsConfig.DTLS_CIPHER_SUITES, Collections.singletonList(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8));
    	
        DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(dtlsConfig)
                .setAddress(new InetSocketAddress(0));
        builder.setCertificateIdentityProvider(
                new SingleCertificateProvider(rpk.AsPrivateKey(), rpk.AsPublicKey()));

        ArrayList<CertificateType> certTypes = new ArrayList<CertificateType>();
        certTypes.add(CertificateType.RAW_PUBLIC_KEY);
        certTypes.add(CertificateType.X_509);
        AsyncCertificateVerifier verifier = new AsyncCertificateVerifier(new X509Certificate[0],
                new RawPublicKeyIdentity[0], certTypes);
        builder.setCertificateVerifier(verifier);

        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
        CoapEndpoint e = new CoapEndpoint.Builder()
                .setConnector(dtlsConnector)
                .setConfiguration(Configuration.getStandard())
                .build();
        LOGGER.fine("Creating CoAPS client for introspection to: " 
                + introspectAddress + " with RPK");
        this.client = new CoapClient(introspectAddress);
        this.client.setEndpoint(e);
        dtlsConnector.start();
    }
    
    /**
     * Constructor, builds a client that uses pre-shared symmetric keys.
     * 
     * @param psk  the pre-shared key
     * @param pskIdentity  the identity associated to the pre-shared key
     * @param keystoreLocation 
     * @param keystorePwd 
     * @param addr2idFile 
     * @param introspectAddress  the IP address of the introspect endpoint
     * 
     * 
     * @throws CoseException
     * @throws IOException 
     * @throws NoSuchProviderException 
     * @throws KeyStoreException 
     * @throws CertificateException 
     * @throws NoSuchAlgorithmException 
     * 
     */
    public DtlspIntrospection(byte[] psk, String pskIdentity,
            String keystoreLocation, String keystorePwd, String addr2idFile,
            String introspectAddress) throws CoseException, IOException,
            NoSuchAlgorithmException, CertificateException, KeyStoreException,
            NoSuchProviderException {
    	
        Configuration dtlsConfig = Configuration.getStandard();
        dtlsConfig.set(DtlsConfig.DTLS_CIPHER_SUITES, Arrays.asList(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8));
        dtlsConfig.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION,  false);
    	
        DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(dtlsConfig)
                .setAddress(new InetSocketAddress(0));
        BksStore keystore = new BksStore(
                keystoreLocation, keystorePwd, addr2idFile);
        builder.setPskStore(keystore);

        
        CBORObject rpkData = CBORObject.NewMap();
        rpkData = Util.buildRpkData(KeyKeys.EC2_P256.AsInt32(), rsX_ECDSA, rsY_ECDSA, rsD_ECDSA);
        rsRPK = new OneKey(rpkData);
        String keyId = new RawPublicKeyIdentity(rsRPK.AsPublicKey()).getName();
        rsRPK.add(KeyKeys.KeyId, CBORObject.FromObject(keyId.getBytes(Constants.charset)));

        builder.setCertificateIdentityProvider(
                new SingleCertificateProvider(rsRPK.AsPrivateKey(), rsRPK.AsPublicKey()));

        ArrayList<CertificateType> certTypes = new ArrayList<CertificateType>();
        certTypes.add(CertificateType.RAW_PUBLIC_KEY);
        certTypes.add(CertificateType.X_509);
        AsyncCertificateVerifier verifier = new AsyncCertificateVerifier(
                                                            new X509Certificate[0],
                                                            new RawPublicKeyIdentity[0],
                                                            certTypes);
        builder.setCertificateVerifier(verifier);
        
        
        DTLSConnector dtlsConnector = new DTLSConnector(builder.build());
        
        CoapEndpoint e = new CoapEndpoint.Builder()
                .setConnector(dtlsConnector)
                .setConfiguration(Configuration.getStandard())
                .build();
        LOGGER.fine("Creating CoAPS client for introspection to: " 
                + introspectAddress + " with RPK");
        this.client = new CoapClient(introspectAddress);
        this.client.setEndpoint(e);
        dtlsConnector.start();
    }
    
    @Override
    public Map<Short, CBORObject> getParams(byte[] tokenReference) 
            throws AceException, IntrospectionException {
        LOGGER.info("Sending introspection request on " + tokenReference);
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.TOKEN, CBORObject.FromObject(CBORObject.FromObject(tokenReference).EncodeToBytes()));
        params.put(Constants.TOKEN_TYPE_HINT, CBORObject.FromObject(Constants.POP)); 
        CoapResponse response;
        try {
            response = this.client.post(
                    Constants.getCBOR(params).EncodeToBytes(), 
                    Constants.APPLICATION_ACE_CBOR);
        } catch (ConnectorException | IOException e) {
            throw new AceException("Connector/IO Error: " + e.getMessage());
        }    
        if (response == null) {
            throw new AceException("AS didn't respond");
        }
        if (!response.getCode().equals(ResponseCode.CREATED)) {
            //Some error happened
            if (response.getPayload() == null) {//This was a server error
                throw new IntrospectionException(response.getCode().value, "");
            }
            //Client error
            throw new IntrospectionException(response.getCode().value, 
                    CBORObject.DecodeFromBytes(
                            response.getPayload()).toString());
        }
        CBORObject res = CBORObject.DecodeFromBytes(response.getPayload());
        Map<Short, CBORObject> map = Constants.getParams(res);
        return map;
        
    }

}
