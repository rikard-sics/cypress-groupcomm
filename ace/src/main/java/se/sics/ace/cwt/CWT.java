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
package se.sics.ace.cwt;

import java.security.Security;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.crypto.InvalidCipherTextException;

import se.sics.ace.AccessToken;
import se.sics.ace.Constants;
import se.sics.ace.AceException;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.Attribute;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.Encrypt0Message;
import org.eclipse.californium.cose.EncryptMessage;
import org.eclipse.californium.cose.HeaderKeys;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.MAC0Message;
import org.eclipse.californium.cose.MACMessage;
import org.eclipse.californium.cose.Message;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.cose.Recipient;
import org.eclipse.californium.cose.Sign1Message;
import org.eclipse.californium.cose.SignMessage;
import org.eclipse.californium.cose.Signer;

import com.upokecenter.cbor.CBORObject;

/**
 * Implements CWTs.
 * 
 * @author Ludwig Seitz
 *
 */
public class CWT implements AccessToken {
    
    static {
        Security.addProvider(
                new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

	private Map<Short, CBORObject> claims;	
	
	/**
	 * Creates a new CWT without a COSE wrapper.
	 * 
	 * @param claims  the map of claims.
	 */
	public CWT(Map<Short, CBORObject> claims) {
		this.claims = new HashMap<> (claims);
	}
	
	/**
	 * Parse and validate the COSE wrapper of a CWT.
	 * 
	 * @param COSE_CWT  the raw bytes of the COSE object containing the CWT
	 * @param ctx  the crypto context
	 * @return  the CWT object wrapped by the COSE object
	 * @throws CoseException 
	 * @throws AceException 
 	 *
	 * @throws Exception 
	 */
	public static CWT processCOSE(byte[] COSE_CWT, CwtCryptoCtx ctx) 
			throws CoseException, AceException, Exception {
	    CBORObject cbor = CBORObject.DecodeFromBytes(COSE_CWT);
	    if (cbor.HasTag(61)) {
	        cbor = cbor.UntagOne();
	    }
		Message coseRaw = Message.DecodeFromBytes(cbor.EncodeToBytes());
		
		if (coseRaw instanceof SignMessage) {
			SignMessage signed = (SignMessage)coseRaw;
			//Check all signers, if kid is present compare that first
			CBORObject myKid = ctx.getPublicKey().get(
					CBORObject.FromObject(HeaderKeys.KID));
			for (Signer s : signed.getSignerList()) {
				CBORObject kid = s.findAttribute(HeaderKeys.KID);
				if (myKid == null || myKid.equals(kid)) {
					s.setKey(ctx.getPublicKey());
					if(signed.validate(s)) {
						return new CWT(Constants.getParams(
								CBORObject.DecodeFromBytes(
										signed.GetContent())));
					}
				}
			}
			throw new AceException("No valid signature found");	
			
		} else if (coseRaw instanceof Sign1Message) {
			Sign1Message signed = (Sign1Message)coseRaw;
			if (signed.validate(ctx.getPublicKey())) {
				return new CWT(Constants.getParams(
					CBORObject.DecodeFromBytes(signed.GetContent())));
			}
			
		} else if (coseRaw instanceof MACMessage) {
			MACMessage maced = (MACMessage)coseRaw;
			for (Recipient me : ctx.getRecipients()) {
				CBORObject myKid = me.findAttribute(HeaderKeys.KID);
				CBORObject myAlg = me.findAttribute(HeaderKeys.Algorithm);
				CBORObject key = CBORObject.NewMap();
				key.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
				key.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(
		        		me.getKey(AlgorithmID.FromCBOR(myAlg))));
				for (Recipient r : maced.getRecipientList()) {
					if (myKid == null || myKid.equals(
							r.findAttribute(HeaderKeys.KID)))	{
						if (myAlg.equals(r.findAttribute(HeaderKeys.Algorithm))) {
						    OneKey coseKey = new OneKey(key);
						    r.SetKey(coseKey);			    
						    if (maced.Validate(r)) {
						        return new CWT(Constants.getParams(
						                CBORObject.DecodeFromBytes(
						                        maced.GetContent())));
						    }
						}
					}
				}
			}
			throw new AceException("No valid MAC found");
			
		} else if (coseRaw instanceof MAC0Message) {
			MAC0Message maced = (MAC0Message)coseRaw;
			if (maced.Validate(ctx.getKey())) {
				return new CWT(Constants.getParams(
						CBORObject.DecodeFromBytes(maced.GetContent())));
			}
			
		} else if (coseRaw instanceof EncryptMessage) {
			EncryptMessage encrypted = (EncryptMessage)coseRaw;
			for (Recipient me : ctx.getRecipients()) {
				CBORObject myKid = me.findAttribute(HeaderKeys.KID);
				CBORObject myAlg = me.findAttribute(HeaderKeys.Algorithm);
				CBORObject key = CBORObject.NewMap();
				key.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
				key.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(
		        		me.getKey(AlgorithmID.FromCBOR(myAlg))));
				for (Recipient r : encrypted.getRecipientList()) {
					if (myKid == null || myKid.equals(
							r.findAttribute(HeaderKeys.KID)))	{
						if (myAlg.equals(r.findAttribute(HeaderKeys.Algorithm))) {
						    OneKey coseKey = new OneKey(key);
							r.SetKey(coseKey);
							byte[] plaintext = processDecrypt(encrypted, r);
							if (plaintext != null) {
								return new CWT(Constants.getParams(
										CBORObject.DecodeFromBytes(
												plaintext)));
							}
						}
					}
				}
			}
			throw new AceException("No valid key for ciphertext found");
			
		} else if (coseRaw instanceof Encrypt0Message) {
			Encrypt0Message encrypted = (Encrypt0Message)coseRaw;
			return new CWT(Constants.getParams(
					CBORObject.DecodeFromBytes(encrypted.decrypt(
							ctx.getKey()))));
		}
		throw new AceException("Unknown or invalid COSE crypto wrapper");
	}
	
	private static byte[] processDecrypt(EncryptMessage m, Recipient r) {
		try {
			return m.decrypt(r);
		} catch (CoseException e) {
		    e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * Encodes this CWT as CBOR Map without crypto wrapper.
	 * 
	 * @return  the claims as CBOR Map.
	 */
	@Override
	public CBORObject encode() {
	    return Constants.getCBOR(this.claims);
	}
	
	/**
	 * Encodes this CWT with a COSE crypto wrapper.
	 *
	 * @param ctx  the crypto context.
	 * @param pHeaders  additional protected COSE header parameters
	 * @param uHeaders additional unprotected COSE header parameters
	 * @return  the claims as CBOR Map.
	 * @throws CoseException 
	 * @throws InvalidCipherTextException 
	 * @throws IllegalStateException 
	 * @throws AceException 
	 */
	public CBORObject encode(CwtCryptoCtx ctx, 
	        Map<HeaderKeys, CBORObject> pHeaders,
	        Map<HeaderKeys, CBORObject> uHeaders) 
	        throws IllegalStateException, InvalidCipherTextException, 
	               CoseException, AceException {
		CBORObject map = encode();
		switch (ctx.getMessageType()) {
		
		case Encrypt0:
			Encrypt0Message coseE0 = new Encrypt0Message();
			coseE0.addAttribute(HeaderKeys.Algorithm, ctx.getAlg(), 
					Attribute.PROTECTED);
			addHeaders(coseE0, pHeaders, true);
			addHeaders(coseE0, uHeaders, false);
			coseE0.SetContent(map.EncodeToBytes());
			coseE0.encrypt(ctx.getKey());
			return coseE0.EncodeToCBORObject();		
			
		case Encrypt:
			EncryptMessage coseE = new EncryptMessage();
			coseE.addAttribute(HeaderKeys.Algorithm, ctx.getAlg(), 
					Attribute.PROTECTED);
			addHeaders(coseE, pHeaders, true);
            addHeaders(coseE, uHeaders, false);
			coseE.SetContent(map.EncodeToBytes());
			for (Recipient r : ctx.getRecipients()) {
				coseE.addRecipient(r);
			}
            try {
                coseE.encrypt();
            } catch (Exception e) {
                //Catching Jim's general "not implemented" exception
                //and casting it to something more useful
               throw new CoseException(e.getMessage());
            }
			return coseE.EncodeToCBORObject();
			
		case Sign1:
			Sign1Message coseS1 = new Sign1Message();
			coseS1.addAttribute(HeaderKeys.Algorithm, ctx.getAlg(), 
						Attribute.PROTECTED);
			addHeaders(coseS1, pHeaders, true);
            addHeaders(coseS1, uHeaders, false);
			coseS1.SetContent(map.EncodeToBytes());
			coseS1.sign(ctx.getPrivateKey());
			return coseS1.EncodeToCBORObject();	
			
		case Sign:
			SignMessage coseS = new SignMessage();
			coseS.addAttribute(HeaderKeys.Algorithm, ctx.getAlg(), 
					Attribute.PROTECTED);
			addHeaders(coseS, pHeaders, true);
            addHeaders(coseS, uHeaders, false);
			coseS.SetContent(map.EncodeToBytes());
			for (Signer s : ctx.getSigners()) {
				coseS.AddSigner(s);
			}
			coseS.sign();
			return coseS.EncodeToCBORObject();
			
		case MAC:
			MACMessage coseM = new MACMessage();
			coseM.addAttribute(HeaderKeys.Algorithm, ctx.getAlg(), 
					Attribute.PROTECTED);
			addHeaders(coseM, pHeaders, true);
            addHeaders(coseM, uHeaders, false);
			coseM.SetContent(map.EncodeToBytes());
			for (Recipient r : ctx.getRecipients()) {
				coseM.addRecipient(r);
			}
			try {
                coseM.Create();
            } catch (Exception e) {
                //Catching Jim's general "not implemented" exception
                //and casting it to something more useful 
                throw new CoseException(e.getMessage());
            }
			return coseM.EncodeToCBORObject();
			
		case MAC0:
			MAC0Message coseM0 = new MAC0Message();
			coseM0.addAttribute(HeaderKeys.Algorithm, ctx.getAlg(), 
					Attribute.PROTECTED);
			addHeaders(coseM0, pHeaders, true);
            addHeaders(coseM0, uHeaders, false);
			coseM0.SetContent(map.EncodeToBytes());
			coseM0.Create(ctx.getKey());
			return coseM0.EncodeToCBORObject();
			
		default:
			throw new AceException("Unknown COSE wrapper type");
			
		}	
	}

	/**
	 * Add additional header parameters to a COSE message
	 * 
	 * @param m  the message
	 * @param headers  the parameters
	 * @param protect  are these protected or unprotected parameters
	 * (we don't currently support Not_Included parameters)
	 * 
	 * @throws CoseException
	 */
	private static void addHeaders(Message m, Map<HeaderKeys, 
	        CBORObject> headers, boolean protect) throws CoseException {
	    if (headers == null) { 
	        return;
	    }
	    for (Map.Entry<HeaderKeys, CBORObject> h : headers.entrySet()) {
            m.addAttribute(h.getKey(), h.getValue().EncodeToBytes(), 
                    (protect ? Attribute.PROTECTED : Attribute.UNPROTECTED));
        }   
	}
	
	/**
     * Encodes this CWT with a COSE crypto wrapper.
     *
     * @param ctx  the crypto context.
     * @return  the claims as CBOR Map.
     * @throws CoseException 
     * @throws InvalidCipherTextException 
     * @throws IllegalStateException 
     * @throws AceException 
     */
    public CBORObject encode(CwtCryptoCtx ctx) 
            throws IllegalStateException, InvalidCipherTextException, 
                   CoseException, AceException {
        return encode(ctx, null, null);
    }
	
	
	/**
	 * Returns the value of a claim referenced by name or 
	 * null if this claim is not in the CWT.
	 * 
	 * @param name  the name of the claim
	 * @return  the value of the claim or null.
	 */
	public CBORObject getClaim(Short name) {
		return this.claims.get(name);
	}
	
	/**
	 * @return  a list of all claims in this CWT.
	 */
	public Set<Short> getClaimKeys() {
		return this.claims.keySet();
	}
	
	/**
	 * @return a copy of the claims in this CWT.
	 */
	public Map<Short, CBORObject> getClaims() {
	    return new HashMap<>(this.claims);
	}
	
	/**
	 * Checks if the token is valid according to the nbf and exp claims
	 * (if present).  Does not check the crypto wrapper.
	 * 
	 * @param now  the current time in ms since January 1, 1970, 00:00:00 GMT
	 * @return  true if the CWT is valid, false if not
	 */
	@Override
	public boolean isValid(long now) {
		//Check nbf and exp for the found match
		CBORObject nbfO = this.claims.get(Constants.NBF);
		if (nbfO != null &&  nbfO.AsNumber().ToInt64Checked()	> now) {
			return false;
		}	
		CBORObject expO = this.claims.get(Constants.EXP);
		if (expO != null && expO.AsNumber().ToInt64Checked() < now) {
			//Token has expired
			return false;
		}
		return true;
	}
	
	/**
	 * Checks if the token is not expired according to the exp claim
	 * (if present).  Does not check anything else.
	 *  
	 * @param now  the current time in ms since January 1, 1970, 00:00:00 GMT
	 * @return  true if the CWT is expired false if it is still valid or has no expiration date
	 */
	@Override
	public boolean expired(long now) {
		CBORObject expO = this.claims.get(Constants.EXP);
		if (expO != null && expO.AsNumber().ToInt64Checked() < now) {
			//Token has expired
			return true;
		}
		return false;		
	}
	
	@Override
	public String toString() {
	    return this.claims.toString();
	}

    @Override
    public String getCti() throws AceException {
        CBORObject cti = this.claims.get(Constants.CTI);
        if (cti == null) {
            throw new AceException("Token has no cti");
        }
        return Base64.getEncoder().encodeToString(cti.GetByteString());
    }
	
}
