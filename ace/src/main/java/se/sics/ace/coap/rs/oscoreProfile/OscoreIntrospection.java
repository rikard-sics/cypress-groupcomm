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
package se.sics.ace.coap.rs.oscoreProfile;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import org.eclipse.californium.oscore.OSException;

import com.upokecenter.cbor.CBORObject;

import org.eclipse.californium.cose.CoseException;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.rs.IntrospectionException;
import se.sics.ace.rs.IntrospectionHandler;

/**
 * An introspection handler using CoAPS (i.e. CoAP over DTLS) to connect to an AS.
 *
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class OscoreIntrospection implements IntrospectionHandler {
    
    /**
     * The logger
     */
    private static final Logger LOGGER 
        = Logger.getLogger(OscoreIntrospection.class.getName());
    
    /**
     * The CoAP client
     */
    private CoapClient client = null;
    
    
    
    /**
     * Constructor, builds a client that uses an OSCORE context.
     * 
     * @param ctx  the OSCORE context between the introspector (typically RS)
     *      and the AS
     * @param introspectAddress  the IP address of the introspect endpoint
     *
     * @throws CoseException
     * @throws IOException 
     * @throws OSException 
     * 
     */
    public OscoreIntrospection(OSCoreCtx ctx, String introspectAddress, OSCoreCtxDB db) 
            throws CoseException, IOException, OSException {
        
        db.addContext(ctx);
        db.addContext(introspectAddress, ctx);
        this.client = new CoapClient(introspectAddress);
        CoapEndpoint.Builder ceb = new CoapEndpoint.Builder();
        ceb.setCoapStackFactory(new OSCoreCoapStackFactory());
        ceb.setCustomCoapStackArgument(db);
        this.client.setEndpoint(ceb.build());
    }
      
    @Override
    public Map<Short, CBORObject> getParams(byte[] tokenReference) 
            throws AceException, IntrospectionException {
        LOGGER.info("Sending introspection request on " + tokenReference);
        Map<Short, CBORObject> params = new HashMap<>();
        params.put(Constants.TOKEN, CBORObject.FromObject(CBORObject.FromObject(tokenReference).EncodeToBytes()));
        params.put(Constants.TOKEN_TYPE_HINT, CBORObject.FromObject("pop")); 
        CoapResponse response;
        Request r = new Request(Code.POST);
        r.setPayload(Constants.getCBOR(params).EncodeToBytes());
        r.getOptions().setOscore(new byte[0]);
        try {
            response = this.client.advanced(r);
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
