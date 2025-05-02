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
package se.sics.ace.coap;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.HandshakeResultHandler;
import org.eclipse.californium.scandium.dtls.PskPublicInformation;
import org.eclipse.californium.scandium.dtls.PskSecretResult;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedPskStore;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * A PskStore implementation based on BKS.
 * 
 * This will retrieve keys from a BKS keystore.
 * 
 * In order too keep this manageable all keys will 
 * have the same password as the keystore.
 * 
 * @author Ludwig Seitz
 *
 */
public class BksStore implements AdvancedPskStore {
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(BksStore.class.getName());

    /**
     * The underlying BKS keystore
     */
    private KeyStore keystore = null;
    
    /**
     * The in-memory map of addresses to identities
     */
    private Map<String, String> addr2id = new HashMap<>();
    
    /**
     * The file storing the keystore
     */
    private String keystoreFile;
    
    /**
     * The keystore password
     */
    private String keystorePwd;
    
    private String addr2IdFile;
    
    static {
        Security.addProvider(
                new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }
    
    /**
     * Constructor.
     * 
     * @param keystoreLocation  the location of the keystore file
     * @param keystorePwd the password to the keystore
     * @param addr2idFile  the location of the file mapping addresses to identities
     * 
     * @throws IOException 
     * @throws CertificateException 
     * @throws NoSuchAlgorithmException 
     * @throws KeyStoreException 
     * @throws NoSuchProviderException 
     */
    public BksStore(String keystoreLocation, String keystorePwd, String addr2idFile) 
            throws NoSuchAlgorithmException, CertificateException, 
            IOException, KeyStoreException, NoSuchProviderException {
        this.keystoreFile = keystoreLocation;
        this.keystorePwd = keystorePwd;
        InputStream keystoreStream = new FileInputStream(keystoreLocation);
        this.keystore = KeyStore.getInstance("BKS", "BC");
        this.keystore.load(keystoreStream, keystorePwd.toCharArray());
        keystoreStream.close();   
        this.addr2IdFile  = addr2idFile;
        BufferedReader in = new BufferedReader(new FileReader(addr2idFile));
        String line = "";
        while ((line = in.readLine()) != null) {
            String parts[] = line.split(":");
            this.addr2id.put((parts[0].trim() + ":" + parts[1].trim()),
                    parts[2].trim());
        }
        in.close();
    }
    
    /**
     * Create the initial keystore and address2identity mapping file.
     * 
     * @param keystoreLocation  the location of the keystore file
     * @param keystorePwd the password to the keystore
     * @param addr2idFile  the location of the file mapping addresses to identities
     * 
     * @throws NoSuchProviderException 
     * @throws KeyStoreException 
     * @throws IOException 
     * @throws FileNotFoundException 
     * @throws CertificateException 
     * @throws NoSuchAlgorithmException 
     */
    public static void init(String keystoreLocation, String keystorePwd,
            String addr2idFile) throws KeyStoreException, 
            NoSuchProviderException, NoSuchAlgorithmException, 
            CertificateException, FileNotFoundException, IOException {
        KeyStore keyStore = KeyStore.getInstance("BKS", "BC");
        keyStore.load(null, keystorePwd.toCharArray());
        FileOutputStream fo = new FileOutputStream(keystoreLocation);
        keyStore.store(fo, keystorePwd.toCharArray());
        fo.close();   
        File file = new File(addr2idFile);
        file.createNewFile();        
    }

    @Override
    public PskSecretResult requestPskSecretResult(ConnectionId cid, ServerNames serverName,
            PskPublicInformation identity, String hmacAlgorithm, SecretKey otherSecret, byte[] seed,
            boolean useExtendedMasterSecret) {

        String identityStr = identity.getPublicInfoAsString();
        try {
            if (!this.keystore.containsAlias(identityStr)) {
                return null;
            }
        } catch (KeyStoreException e) {
            LOGGER.severe("KeyStoreException: " + e.getMessage());
            return null;
        }

        Key key;
        try {
            // XXX: Note that we use the keystore password for all key passwords
            key = this.keystore.getKey(identityStr, this.keystorePwd.toCharArray());
        } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
            LOGGER.severe(e.getClass().getName() + ": " + e.getMessage());
            return null;
        }

        return new PskSecretResult(cid, identity, (SecretKey) key);
    }

    public SecretKey getKey(PskPublicInformation info) {
        PskSecretResult result = requestPskSecretResult(ConnectionId.EMPTY, null, info, null, null, null, false);

        if (result == null) {
            return null;
        } else {
            return result.getSecret();
        }

    }

    @Override
    public PskPublicInformation getIdentity(InetSocketAddress inetAddress, ServerNames virtualHost) {
        String id = inetAddress.getHostString() + ":" + inetAddress.getPort();
        String identity = this.addr2id.get(id);
        if (identity != null) {
            return new PskPublicInformation(identity);
        }
        return null;

    }

    public PskPublicInformation getIdentity(InetSocketAddress inetAddress) {
        return getIdentity(inetAddress, null);

    }

    /**
     * Add a new symmetric key to the keystore or overwrite the existing
     * one associated to this identity.
     * 
     * @param key  the bytes of java.security.Key.getEncoded()
     * @param identity  the key identity
     * @param address  the address to associate with this key (can be null)
     * @throws KeyStoreException 
     * @throws IOException 
     * @throws FileNotFoundException 
     * @throws CertificateException 
     * @throws NoSuchAlgorithmException 
     */
    public void addKey(byte[] key, String identity) 
            throws KeyStoreException, NoSuchAlgorithmException, 
            CertificateException, FileNotFoundException, IOException {
        if (identity == null || key == null) {
            throw new KeyStoreException("Key and identity must not be null");
        }
        if (this.keystore != null) {
            Key k = new SecretKeySpec(key, PskSecretResult.ALGORITHM_PSK);
            //XXX: Note that we use the keystore password for all key passwords
            this.keystore.setKeyEntry(identity, k, 
                    this.keystorePwd.toCharArray(), null);
            FileOutputStream fos = new FileOutputStream(this.keystoreFile);
            this.keystore.store(fos, this.keystorePwd.toCharArray());
            fos.close();
        }
    }
    
    /**
     * Add a new mapping of key identity to Internet address.
     * 
     * @param address the Internet address
     * @param identity  the key identity
     * @throws KeyStoreException 
     * @throws IOException 
     */
    public void addAddress(InetSocketAddress address, String identity) 
            throws KeyStoreException, IOException {
        if (hasKey(identity)) {
            this.addr2id.put(address.getHostString()+":"+address.getPort(),
                    identity);
        }
        PrintWriter writer = new PrintWriter(this.addr2IdFile, "UTF-8");
        for (Map.Entry<String, String> e 
                : this.addr2id.entrySet()) {        
            String line = e.getKey() + ":" + e.getValue();
            writer.println(line);  
        }
        writer.close();      
    }
    
    /**
     * Checks if a key for a certain identity is present.
     * 
     * @param identity  the key identity
     * 
     * @return  true if the identity is in the keystore, false otherwise
     * 
     * @throws KeyStoreException 
     */
    public boolean hasKey(String identity) throws KeyStoreException {
        if (identity != null) {
            if (this.keystore != null) {
                return this.keystore.isKeyEntry(identity);
            }
            throw new KeyStoreException("No keystore loaded");
        }
        throw new KeyStoreException("Key identity can not be null");
    }
    
    /**
     * Remove a symmetric key from the keystore, will do nothing if the
     * key doesn't exist.
     * 
     * @param identity  the key identity
     * @throws KeyStoreException 
     * @throws IOException 
     * @throws CertificateException 
     * @throws NoSuchAlgorithmException 
     */
    public void removeKey(String identity) throws KeyStoreException, 
           NoSuchAlgorithmException, CertificateException, IOException {
        if (identity != null) {
            if (this.keystore != null) {
                if (this.keystore.isKeyEntry(identity)) {
                    this.keystore.deleteEntry(identity);
                    FileOutputStream fos = new FileOutputStream(this.keystoreFile);
                    this.keystore.store(fos, this.keystorePwd.toCharArray());
                    fos.close();
                }
                return;
            }
            throw new KeyStoreException("No keystore loaded");
        }
        throw new KeyStoreException("Key identity can not be null");
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
