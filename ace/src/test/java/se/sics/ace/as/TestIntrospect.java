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

import java.io.IOException;
import java.sql.SQLException;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.upokecenter.cbor.CBORObject;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.MessageTag;
import org.eclipse.californium.cose.OneKey;
import org.eclipse.californium.cose.HeaderKeys;

import se.sics.ace.AceException;
import se.sics.ace.COSEparams;
import se.sics.ace.Constants;
import se.sics.ace.DBHelper;
import se.sics.ace.Message;
import se.sics.ace.ReferenceToken;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;
import se.sics.ace.examples.KissPDP;
import se.sics.ace.examples.KissTime;
import se.sics.ace.examples.LocalMessage;
import se.sics.ace.examples.SQLConnector;

/**
 * Test the introspection endpoint library.
 * 
 * @author Ludwig Seitz and Marco Tiloca
 *
 */
public class TestIntrospect {
    
    private static OneKey publicKey;
    private static OneKey privateKey;
    private static byte[] key128 = {'a', 'b', 'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    static String aKey = "piJYICg7PY0o/6Wf5ctUBBKnUPqN+jT22mm82mhADWecE0foI1ghAKQ7qn7SL/Jpm6YspJmTWbFG8GWpXE5GAXzSXrialK0pAyYBAiFYIBLW6MTSj4MRClfSUzc8rVLwG8RH5Ak1QfZDs4XhecEQIAE=";
      
    private static SQLConnector db = null;
    private static KissPDP pdp = null;
    private static Introspect i = null;
    
    /**
     * Set up tests.
     * @throws AceException 
     * @throws SQLException 
     * @throws IOException 
     * @throws CoseException 
     */
    @BeforeClass
    public static void setUp() throws AceException, SQLException, IOException, CoseException {
        DBHelper.setUpDB();
        db = DBHelper.getSQLConnector();

        privateKey = new OneKey(CBORObject.DecodeFromBytes(Base64.getDecoder().decode(aKey)));
        publicKey = privateKey.PublicKey();

        CBORObject keyData = CBORObject.NewMap();
        keyData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_Octet);
        keyData.Add(KeyKeys.Octet_K.AsCBOR(), CBORObject.FromObject(key128));
        OneKey key = new OneKey(keyData);
        
        //Setup RS entries
        Set<String> profiles = new HashSet<>();
        profiles.add("coap_dtls");
        profiles.add("coap_oscore");
        
        Set<String> scopes = new HashSet<>();
        scopes.add("temp");
        scopes.add("co2");
        
        Set<String> auds = new HashSet<>();
        auds.add("aud1");
        auds.add("sensors");
        auds.add("failCWTpar");
        
        Set<String> keyTypes = new HashSet<>();
        keyTypes.add("PSK");
        keyTypes.add("RPK");
        
        Set<Short> tokenTypes = new HashSet<>();
        tokenTypes.add(AccessTokenFactory.CWT_TYPE);
        tokenTypes.add(AccessTokenFactory.REF_TYPE);
        
        Set<COSEparams> cose = new HashSet<>();
        COSEparams coseP = new COSEparams(MessageTag.Sign1, AlgorithmID.ECDSA_256, AlgorithmID.Direct);
        cose.add(coseP);
        
        long expiration = 1000000L;
       
        db.addRS("rs1", profiles, scopes, auds, keyTypes, tokenTypes, cose, expiration, key, key, publicKey);
        
        
        auds.clear();
        auds.add("actuators");
        db.addRS("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w",
        		 profiles, scopes, auds, keyTypes, tokenTypes, cose, expiration, key, key, publicKey);
        
        
        profiles.clear();
        profiles.add("coap_dtls");
        keyTypes.clear();
        keyTypes.add("PSK");
        db.addClient("client1", profiles, null, null, keyTypes, key, null);
                
        KissTime time = new KissTime();
        
        //Setup token entries
        byte[] cti = new byte[] {0x00};
        String ctiStr = Base64.getEncoder().encodeToString(cti);

        Map<Short, CBORObject> claims = new HashMap<>();
        claims.put(Constants.SCOPE, CBORObject.FromObject("co2"));
        claims.put(Constants.AUD,  CBORObject.FromObject("sensors"));
        claims.put(Constants.EXP, CBORObject.FromObject(time.getCurrentTime()-1L));   
        claims.put(Constants.AUD,  CBORObject.FromObject("actuators"));
        claims.put(Constants.CTI, CBORObject.FromObject(cti));
        CBORObject cnf = CBORObject.NewMap();
        cnf.Add(Constants.COSE_KEY_CBOR, publicKey.AsCBOR());
        claims.put(Constants.CNF, cnf);
        db.addToken(ctiStr, claims);
        db.addCti2Client(ctiStr, "client1");
        
        cti = new byte[]{0x01};
        ctiStr =  Base64.getEncoder().encodeToString(cti);
        claims.clear();
        claims.put(Constants.SCOPE, CBORObject.FromObject("temp"));
        claims.put(Constants.AUD,  CBORObject.FromObject("sensors"));
        claims.put(Constants.EXP, CBORObject.FromObject(time.getCurrentTime() + 2000000L));
        claims.put(Constants.CTI, CBORObject.FromObject(cti));
        claims.put(Constants.CNF, cnf);
        db.addToken(ctiStr, claims);
        db.addCti2Client(ctiStr, "client1");
        
        cti = new byte[]{0x02};
        String cti3Str =  Base64.getEncoder().encodeToString(cti);
        claims.clear();
        claims.put(Constants.SCOPE, CBORObject.FromObject("temp"));
        claims.put(Constants.AUD,  CBORObject.FromObject("actuators"));
        claims.put(Constants.EXP, CBORObject.FromObject(time.getCurrentTime() + 2000000L));
        claims.put(Constants.CTI, CBORObject.FromObject(cti));
        claims.put(Constants.CNF, cnf);
        db.addToken(cti3Str, claims);
        db.addCti2Client(cti3Str, "client1");
        
        
        pdp = new KissPDP(db);
        pdp.addIntrospectAccess("ni:///sha-256;xzLa24yOBeCkos3VFzD2gd83Urohr9TsXqY9nhdDN0w",
        						PDP.IntrospectAccessLevel.ACTIVE_AND_CLAIMS);
        pdp.addIntrospectAccess("rs1", PDP.IntrospectAccessLevel.ACTIVE_AND_CLAIMS);
        pdp.addIntrospectAccess("rs2", PDP.IntrospectAccessLevel.ACTIVE_AND_CLAIMS);
        pdp.addIntrospectAccess("rs3", PDP.IntrospectAccessLevel.ACTIVE_AND_CLAIMS);
        i = new Introspect(pdp, db, time, publicKey, null);
        
    }
    
    
    /**
     * Deletes the test DB after the tests
     * 
     * @throws Exception 
     */
    @AfterClass
    public static void tearDown() throws Exception {
        if(pdp != null)
            pdp.close();
        DBHelper.tearDownDB();
    }
    
    /**
     * Test the introspect endpoint. Request should fail since it is unauthorized.
     * 
     * @throws Exception
     */
    @Test
    public void testFailUnauthorized() throws Exception {
        Message response = i.processMessage(new LocalMessage(-1, "unauthorizedRS", "TestAS", CBORObject.Null));
        assert(response.getMessageCode() == Message.FAIL_FORBIDDEN);
        Assert.assertArrayEquals(null, response.getRawPayload());
    }
    
    /**
     * Test the introspect endpoint. Request should fail since it
     * got a null payload.
     * 
     * @throws Exception
     */
    @Test
    public void testFailNoTokenSent() throws Exception {
        CBORObject nullObj = null;
        Message response = i.processMessage(new LocalMessage(-1, "rs1", "TestAS", nullObj));
        assert(response.getMessageCode() == Message.FAIL_BAD_REQUEST);
        
        CBORObject map = CBORObject.NewMap();
        map.Add(Constants.ERROR, Constants.INVALID_REQUEST);
        map.Add(Constants.ERROR_DESCRIPTION, "Must provide 'token' parameter");
        Assert.assertArrayEquals(map.EncodeToBytes(), response.getRawPayload());
    }
    
    /**
     * Test the introspect endpoint. Expired token purged before introspected.
     * 
     * @throws Exception
     */
    @Test
    public void testSuccessPurgedInactive() throws Exception {
        ReferenceToken purged = new ReferenceToken(new byte[]{0x00});
        Map<Short, CBORObject> params = new HashMap<>();
        
        params.put(Constants.TOKEN, CBORObject.FromObject(purged.encode().EncodeToBytes()));
        Message response = i.processMessage(new LocalMessage(-1, "rs1", "TestAS", params));
        assert(response.getMessageCode() == Message.CREATED);
        
        CBORObject rparams = CBORObject.DecodeFromBytes(response.getRawPayload());
        params = Constants.getParams(rparams);
        System.out.println(params.toString());
        assert(params.get(Constants.ACTIVE).equals(CBORObject.False));
    }
    
    /**
     * Test the introspect endpoint. Token does not exist.
     * 
     * @throws Exception
     */
    @Test
    public void testSuccessNotExistInactive() throws Exception {
        CBORObject notExist = CBORObject.FromObject(new byte[] {0x03});
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.TOKEN, CBORObject.FromObject(notExist.EncodeToBytes()));
        Message response = i.processMessage(new LocalMessage(-1, "rs1", "TestAS", params));
        assert(response.getMessageCode() == Message.CREATED);
        
        CBORObject rparams = CBORObject.DecodeFromBytes(response.getRawPayload());
        params = Constants.getParams(rparams);
        assert(params.get(Constants.ACTIVE).equals(CBORObject.False));
    }
    
    /**
     * Test the introspect endpoint. CWT token which is still valid.
     * 
     * @throws Exception
     */
    @Test
    public void testSuccessCWT() throws Exception {
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.SCOPE, CBORObject.FromObject("rw_valve r_pressure foobar"));
        params.put(Constants.CTI, CBORObject.FromObject(new byte[]{0x01}));

        // Add the audience as the KID in the header, so it can be referenced by introspection requests.
        CBORObject requestedAud = CBORObject.NewArray();
        requestedAud.Add("rs1");
        Map<HeaderKeys, CBORObject> uHeaders = new HashMap<>();
        uHeaders.put(HeaderKeys.KID, requestedAud);

        CWT token = new CWT(params);
        COSEparams coseP = new COSEparams(MessageTag.Sign1, AlgorithmID.ECDSA_256, AlgorithmID.Direct);
        CwtCryptoCtx ctx = CwtCryptoCtx.sign1Create(privateKey, coseP.getAlg().AsCBOR());
        params.clear();
        params.put(Constants.TOKEN, CBORObject.FromObject(token.encode(ctx,null, uHeaders).EncodeToBytes()));

        Message response = i.processMessage(new LocalMessage(-1, "rs1", "TestAS", params));
        assert(response.getMessageCode() == Message.CREATED);
        
        CBORObject rparams = CBORObject.DecodeFromBytes(response.getRawPayload());
        params = Constants.getParams(rparams);
        assert(params.get(Constants.ACTIVE).equals(CBORObject.True)); 
    }
    
    /**
     * Test the introspect endpoint. Expired token purged before introspected.
     * 
     * @throws Exception
     */
    @Test
    public void testSuccessRef() throws Exception {
        ReferenceToken t = new ReferenceToken(new byte[]{0x02});
        Map<Short, CBORObject> params = new HashMap<>(); 
        params.put(Constants.TOKEN, CBORObject.FromObject(t.encode().EncodeToBytes()));
        String senderId = new RawPublicKeyIdentity(publicKey.AsPublicKey()).getName().trim();
        
        Message response = i.processMessage(new LocalMessage(-1, senderId, "TestAS", params));       
        assert(response.getMessageCode() == Message.CREATED);
        
        CBORObject rparams = CBORObject.DecodeFromBytes( response.getRawPayload());
        params = Constants.getParams(rparams);
        assert(params.get(Constants.ACTIVE).equals(CBORObject.True));
    }
}
