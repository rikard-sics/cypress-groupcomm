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

import java.security.Principal;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.OSCoreEndpointContextInfo;

import com.upokecenter.cbor.CBORException;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.Message;

/**
 * A CoAP request implementing the Message interface for the ACE library.
 * 
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class CoapReq implements Message {

    /**
     * The parameters in the payload of this message as a Map for convenience,
     * if the payload is a CBOR Map.
     */
    private Map<Short, CBORObject> parameters;
    
    /**
     * The underlying Request from Californium
     */
    private Request request;
    
    
    /**
     * Create a request from an underlying Californium request.
     * 
     * @param req  the underlying Californium request
     * @param payloadMustBeCbor  if true, the payload (if any) MUST be in CBOR
     * @throws AceException 
     */
    protected CoapReq(Request req, boolean payloadMustBeCbor) throws AceException {
        this.request = req;
        CBORObject cborPayload = null;
        if (req.getPayload() != null && req.getPayload() != Bytes.EMPTY && payloadMustBeCbor) {
            try {
                cborPayload = CBORObject.DecodeFromBytes(req.getPayload());
            } catch (CBORException ex) {
                throw new AceException(ex.getMessage());
            }
            if (cborPayload != null 
                    && cborPayload.getType().equals(CBORType.Map)) {
                this.parameters = Constants.getParams(cborPayload);
            }
        }
    }
    

    @Override
    public byte[] getRawPayload() {
        return this.request.getPayload();
    }

    @Override
    public String getSenderId() {
        EndpointContext ctx = this.request.getSourceContext();
        if (ctx==null) {
            return null;
        }
        if (ctx instanceof DtlsEndpointContext) {
            Principal p = ctx.getPeerIdentity();
            if (p==null) {
                return null;
            }
            return p.getName();
        } 
        // If OSCORE is used, retrieve the OSCORE SenderID and ContextID that the client
        // used in the request, by using the information in the endpoint context.
        // The OSCORE Sender ID that the client used in the request is the local OSCORE Recipient ID.
        // The returned string has format ["ContextID:" +] "SenderID", depending on the presence of the OSCORE Context ID.
        else if (ctx instanceof MapBasedEndpointContext) {
            MapBasedEndpointContext mapCtx = (MapBasedEndpointContext) ctx;

            byte[] clientSenderId = StringUtil
                    .hex2ByteArray((String) mapCtx.get(OSCoreEndpointContextInfo.OSCORE_RECIPIENT_ID));
            byte[] idContext = StringUtil
                    .hex2ByteArray((String) mapCtx.get(OSCoreEndpointContextInfo.OSCORE_CONTEXT_ID));

            if (clientSenderId == null) {
                return null;
            }

            // The identity is a string with format ["A" + ":" +] "B", where A and B are
            // the base64 encoding of the ContextID (if present) and of the SenderID.
            String senderId = "";
            if (idContext != null && idContext.length != 0) {            	
            	senderId += Base64.getEncoder().encodeToString(idContext);
                senderId += ":";
            }
            senderId += Base64.getEncoder().encodeToString(clientSenderId);

            return senderId;
        }

        return null;
    }

    @Override
    public Set<Short> getParameterNames() {
        if (this.parameters != null) {
            return this.parameters.keySet();
        }
        return null;
    }

    @Override
    public CBORObject getParameter(Short name) {
        if (this.parameters != null) {
            return this.parameters.get(name);
        }
        return null;
    }

    @Override
    public Map<Short, CBORObject> getParameters() {
        if (this.parameters != null) {
            Map<Short, CBORObject> map = new HashMap<>();
            map.putAll(this.parameters);
            return map;
        }
        return null;
    }

    @Override
    public Message successReply(int code, CBORObject payload) {
        ResponseCode coapCode = ResponseCode.valueOf(code);
        CoapRes res = new CoapRes(coapCode, payload);
        return res;
    }

    @Override
    public Message failReply(int failureReason, CBORObject payload) {
        ResponseCode coapCode = ResponseCode.valueOf(failureReason);
        CoapRes res = new CoapRes(coapCode, payload);
        return res;
    }
    
    /**
     * Create a CoAPRequest from a Californium <code>Request</code>.
     * 
     * @param req  the Californium Request
     * @return  the ACE CoAP request
     * @throws AceException 
     */
    public static CoapReq getInstance(Request req) throws AceException {
        return new CoapReq(req, true);
    }
    
    /**
     * Create a CoAPRequest from a Californium <code>Request</code>.
     * 
     * @param req  the Californium Request
     * @param payloadMustBeCbor  if true, the payload (if any) MUST be in CBOR
     * @return  the ACE CoAP request
     * @throws AceException 
     */
    public static CoapReq getInstance(Request req, boolean payloadMustBeCbor) throws AceException {
        return new CoapReq(req, payloadMustBeCbor);
    }

    @Override
    public int getMessageCode() {
        return this.request.getCode().value;
    }
    
    /**
     * @return  the CoAP token associated with this message
     */
    public Token getToken() {
        return this.request.getToken();
    }
    
    /**
     * @return  the OptionSet associated with this message
     */
    public OptionSet getOptions() {
    	return this.request.getOptions();
    }
    
}
