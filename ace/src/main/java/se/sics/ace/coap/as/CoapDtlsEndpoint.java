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

import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.server.resources.CoapExchange;

import se.sics.ace.AceException;
import se.sics.ace.Constants;
import se.sics.ace.Endpoint;
import se.sics.ace.Message;
import se.sics.ace.as.Introspect;
import se.sics.ace.as.Token;
import se.sics.ace.coap.CoapReq;
import se.sics.ace.coap.CoapRes;

/**
 * This class implements the ACE endpoints/resources 
 * (OAuth lingo vs CoAP lingo) token and introspect for the DTLS profile.
 * 
 * @author Ludwig Seitz
 *
 */
public class CoapDtlsEndpoint extends CoapResource implements AutoCloseable {
    
    /**
     * The logger
     */
    private static final Logger LOGGER = Logger.getLogger(CoapDtlsEndpoint.class.getName() );
    
    /**
     * The token library
     */
    private Endpoint e;
    
    /**
     * Constructor.
     * 
     * @param name  the resource name (should be "introspect" or "token")
     * @param e  the endpoint library instance
     */
    public CoapDtlsEndpoint(String name, Endpoint e) {
        super(name);
        this.e = e;        
    }
    
    /**
     * Default constructor.
     * 
     * @param e  the endpoint library instance
     */
    public CoapDtlsEndpoint(Introspect e) {
        super("introspect");
        this.e = e;
    }
    
    /**
     * Default constructor.
     * 
     * @param e  the endpoint library instance
     */
    public CoapDtlsEndpoint(Token e) {
        super("token");
        this.e = e;
    }
     
    /**
     * Handles the POST request in the given CoAPExchange.
     *
     * @param exchange the CoapExchange for the simple API
     */
    @Override
    public void handlePOST(CoapExchange exchange) {
        CoapReq req = null;
        try {
            req = CoapReq.getInstance(exchange.advanced().getRequest());
        } catch (AceException e) {//Message didn't have CBOR payload
            LOGGER.info(e.getMessage());
            exchange.respond(ResponseCode.BAD_REQUEST);
        }
        LOGGER.log(Level.FINEST, "Received request: " 
                + ((req==null)?"null" : req.toString()));
        Message m = this.e.processMessage(req);
        
        if (m instanceof CoapRes) {
            CoapRes res = (CoapRes)m;
            LOGGER.log(Level.FINEST, "Produced response: " + res.toString());
            //XXX: Should the profile set the content format here?
            exchange.respond(res.getCode(), res.getRawPayload(), 
                    Constants.APPLICATION_ACE_CBOR);
            return;
        }
        if (m == null) {//Wasn't a CoAP message
            return;
        }
        LOGGER.severe(this.e.getClass().getName() 
                + " library produced wrong response type");
        exchange.respond(ResponseCode.INTERNAL_SERVER_ERROR);
    }

    @Override
    public void close() throws Exception {
        this.e.close();
    }

}
