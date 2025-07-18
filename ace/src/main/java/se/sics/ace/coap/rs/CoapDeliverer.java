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
package se.sics.ace.coap.rs;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.core.server.ServerMessageDeliverer;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.scandium.DTLSConnector;

import com.upokecenter.cbor.CBORException;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import org.eclipse.californium.cose.KeyKeys;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.coap.CoapReq;
import se.sics.ace.rs.AsRequestCreationHints;
import se.sics.ace.rs.IntrospectionException;
import se.sics.ace.rs.IntrospectionHandler;
import se.sics.ace.rs.TokenRepository;

/**
 * This deliverer processes incoming and outgoing messages at the RS 
 * according to the specifications of the ACE framework (RFC 9200)
 * 
 *  It can handle tokens passed through the DTLS handshake as specified in Section 3.3.2 of RFC 9202.
 * 
 * It's specific task is to match requests against existing access tokens
 * to see if the request is authorized.
 * 
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class CoapDeliverer implements MessageDeliverer {
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(CoapDeliverer.class.getName());
    
    /**
     * The introspection handler
     */
    private IntrospectionHandler i;
    
    /**
     * The class managing the AS Request Creation Hints
     */
    private AsRequestCreationHints asRCH;
    
	/**
	 * CoAP Endpoint used by the Resource Server for secure communication with the Clients.
	 * This is required in order to be able to terminate secure associations with a Client
	 * upon deleting the last access token bound to that association. This is the case, e.g.,
	 * for access tokens bound to a DTLS connection.
	 */
	private CoapEndpoint coapEndpoint;
    
    /** 
     * The ServerMessageDeliverer that processes the request
     * after access control has been done
     */
    private ServerMessageDeliverer d;
    

    /**
     * Constructor. 
     * 
     * Note: This expects that a TokenRepository has been created.
     * 
     * @param root  the root of the resources that this deliverer controls
     * @param i  the introspection handler or null if there isn't any.
     * @param asRCHM  the AS Request Creation Hints Manager.
     * @param cep  the CoAP endpoint used by the Resource Server for secure communication with the Clients
     * @throws AceException   if the token repository is not initialized
     */
    public CoapDeliverer(Resource root, IntrospectionHandler i, AsRequestCreationHints asRCHM, CoapEndpoint cep) throws AceException {
        if (TokenRepository.getInstance() == null) {
            throw new AceException("Must initialize TokenRepository");
        }
        this.d = new ServerMessageDeliverer(root, null);
        this.asRCH = asRCHM;
        
        if (cep == null) {
            throw new AceException("Null CoAP Endpoint when setting up the CoAPDeliverer");
        }
        this.coapEndpoint = cep;
    }
  
    // Really the TokenRepository _should not_ be closed here
    @SuppressWarnings("resource") 
    @Override
    public void deliverRequest(final Exchange ex) {
        Request request = ex.getCurrentRequest();
        Response r = null;
        
        // authz-info is not under access control
        try {
            URI uri = new URI(request.getURI());
            // Need to check with and without trailing / in case there are query options
            if (uri.getPath().endsWith("/authz-info") || uri.getPath().endsWith("/authz-info/") ) { 
                this.d.deliverRequest(ex);
                return;
            }
        } catch (URISyntaxException e) {
            LOGGER.warning("Request-uri " + request.getURI()
                    + " is invalid: " + e.getMessage());
            r = new Response(ResponseCode.BAD_REQUEST);
            ex.sendResponse(r);
            return;
        }      
       
       
        String subject = null;
        
        if (request.getSourceContext() == null 
                || request.getSourceContext().getPeerIdentity() == null) {
            
        	Request req = ex.getRequest();
            try {
				subject = CoapReq.getInstance(req, false).getSenderId();
				if (subject == null) {
				    LOGGER.warning("Unauthenticated client tried to get access");
				    failUnauthz(ex);
				    return;
				}
			} catch (AceException e) {
	            LOGGER.severe("Error while retrieving the client identity: " + e.getMessage());
			}
        } else  {
            subject = request.getSourceContext().getPeerIdentity().getName();
        }
        	    
        TokenRepository tr = TokenRepository.getInstance();
        if (tr == null) {
            LOGGER.finest("TokenRepository not initialized");
            ex.sendResponse(new Response(
                    ResponseCode.INTERNAL_SERVER_ERROR));
        }
        String kid = TokenRepository.getInstance().getKid(subject);
       
        if (kid == null) { // Check if this was the Base64 encoded kid map
            try {
                CBORObject cbor = CBORObject.DecodeFromBytes(
                        Base64.getDecoder().decode(subject));
                if (cbor.getType().equals(CBORType.Map)) {
                   CBORObject ckid = cbor.get(KeyKeys.KeyId.AsCBOR());
                   if (ckid != null && ckid.getType().equals(
                           CBORType.ByteString)) {
                      kid = new String(ckid.GetByteString(), 
                              Constants.charset);
                   } else { // No kid in that CBOR map or it isn't a bstr
                       failUnauthz(ex);
                       return;
                   }
                } else { // Some weird CBOR that is not a map here
                   failUnauthz(ex);
                   return;
                }                
            } catch (CBORException e) { // Really no kid found for that subject
                LOGGER.finest("Error while trying to parse some "
                        + "subject identity to CBOR: " + e.getMessage());
               failUnauthz(ex);
               return;
            } catch (IllegalArgumentException e) { // Text was not Base64 encoded
                LOGGER.finest("Error: " + e.getMessage() 
                + " while trying to Base64 decode this: " + subject);
                failUnauthz(ex);
                return;
            }
           
        }
               
        String resource = request.getOptions().getUriPathString();
        short action = (short) request.getCode().value;
      
        try {
            int res = TokenRepository.getInstance().canAccess(
                    kid, subject, resource, action, this.i);
            
            // In case an error response is returned, it will be a Request Creation Hints message.
            // 
            // The message will include 'kid' as the "key identifier of a key used in the
            // existing security association between the client and the RS". Note that:
            //
            // - For the DTLS profile, this is already what the RS stores as 'kid'
            //
            // - For the OSCORE profile, this has to actually be the identifier of
            //   the OSCORE Input Material, which has to be separately retrieved
            
            // Check if the security association was an OSCORE Security Context
            if (tr.getOscoreId(subject) != null) {
            	
            	// The 'kid' included in the Creation Hints message will
            	// will be the identifier of the OSCORE Input Material
            	kid = tr.getOscoreId(subject);
            }
            
            switch (res) {
            case TokenRepository.OK :
                this.d.deliverRequest(ex);
                return;
            case TokenRepository.UNAUTHZ :
               failUnauthz(ex);
               
               EndpointContext ctx = request.getSourceContext();
               if (ctx != null && ctx instanceof DtlsEndpointContext) {
            	   // The canAccess() method of the TokenRepository has returned Unauthorized, even though
            	   // the request from the Client was protected. That can happen only if the Resource Server
            	   // has deleted the previously stored access token associated with the Client.
            	   //
            	   // Consequently, the secure association with the Client must be terminated.
            	   // The handling below terminates a DTLS connection. In case of an OSCORE association,
            	   // the corresponding OSCORE Security Context has been already deleted in the removeToken()
            	   // method of the TokenRepository, following the deletion of the access token. 
            	   
            	   InetSocketAddress peerAddress = (InetSocketAddress) ex.getPeersIdentity();
            	   Connector connector = coapEndpoint.getConnector();
            	   if (connector instanceof DTLSConnector) {
            		   ((DTLSConnector) connector).close(peerAddress);
            	   }
               }
               
               return;
            case TokenRepository.FORBID :
                r = new Response(ResponseCode.FORBIDDEN);
                try {
                    r.setPayload(this.asRCH.getHints(ex.getCurrentRequest(), 
                            kid).EncodeToBytes());
                    r.getOptions().setContentFormat(Constants.APPLICATION_ACE_CBOR);
                } catch (InvalidKeyException | NoSuchAlgorithmException e) {
                    LOGGER.severe("cnonce creation failed: " + e.getMessage());
                    ex.sendResponse(r); //Send response without payload
                }
                ex.sendResponse(r);
                return;
            case TokenRepository.METHODNA :
                r = new Response(ResponseCode.METHOD_NOT_ALLOWED);
                try {
                    r.setPayload(this.asRCH.getHints(ex.getCurrentRequest(),
                            kid).EncodeToBytes());
                    r.getOptions().setContentFormat(Constants.APPLICATION_ACE_CBOR);
                } catch (InvalidKeyException | NoSuchAlgorithmException e) {
                    LOGGER.severe("cnonce creation failed: " + e.getMessage());
                    ex.sendResponse(r);
                }
                ex.sendResponse(r);
                return;
            default :
                LOGGER.severe("Error during scope evaluation,"
                        + " unknown result: " + res);
               ex.sendResponse(new Response(
                       ResponseCode.INTERNAL_SERVER_ERROR));
               return;
            }
        } catch (AceException e) {
            LOGGER.severe("Error in CoapDeliverer.deliverRequest(): "
                    + e.getMessage());    
        } catch (IntrospectionException e) {
            LOGGER.info("Introspection error, "
                    + "message processing aborted: " + e.getMessage());
           if (e.getMessage().isEmpty()) {
               ex.sendResponse(new Response(
                       ResponseCode.INTERNAL_SERVER_ERROR));
           }
           CBORObject map = CBORObject.NewMap();
           map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
           map.Add(Constants.ERROR_DESCRIPTION, e.getMessage());
           r = new Response(ResponseCode.BAD_REQUEST);
           r.setPayload(map.EncodeToBytes());
           ex.sendResponse(r);
        }
    }
    
    /**
     * Fail a request with 4.01 Unauthorized.
     * 
     */
    private void failUnauthz(Exchange ex) {
        Response r = new Response(ResponseCode.UNAUTHORIZED);
        try {
            r.setPayload(this.asRCH.getHints(
                    ex.getCurrentRequest(), null).EncodeToBytes());
            r.getOptions().setContentFormat(Constants.APPLICATION_ACE_CBOR);
            ex.sendResponse(r);
        } catch (InvalidKeyException | NoSuchAlgorithmException 
                | AceException e) {
            LOGGER.severe("cnonce creation failed: " + e.getMessage());
            ex.sendResponse(r); //Just send UNAUTHORIZED without a payload
        }
       
    }

    @Override
    public void deliverResponse(Exchange exchange, Response response) {
        this.d.deliverResponse(exchange, response);        
    }
    

    public byte[] GetBytes(String str)
    {
        char[] chars = str.toCharArray();
        byte[] bytes = new byte[chars.length * 2];
        for (int i = 0; i < chars.length; i++)
        {
            bytes[i * 2] = (byte) (chars[i] >> 8);
            bytes[i * 2 + 1] = (byte) chars[i];
        }

        return bytes;
    }

}
