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
package se.sics.ace.examples;

import java.io.File;
import java.io.FilenameFilter;
import java.net.URI;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.wso2.balana.PDPConfig;
import org.wso2.balana.attr.StringAttribute;
import org.wso2.balana.ctx.AbstractResult;
import org.wso2.balana.ctx.Attribute;
import org.wso2.balana.ctx.ResponseCtx;
import org.wso2.balana.ctx.xacml3.RequestCtx;
import org.wso2.balana.ctx.xacml3.Result;
import org.wso2.balana.finder.PolicyFinder;
import org.wso2.balana.finder.impl.FileBasedPolicyFinderModule;
import org.wso2.balana.xacml3.Attributes;

import se.sics.ace.AceException;
import se.sics.ace.as.PDP;

/**
 * A PDP that uses XACML to provide access control decisions.
 * 
 * @author Ludwig Seitz
 *
 */
public class XacmlPDP implements PDP {

	private org.wso2.balana.PDP pdp;

	/**
	 * The standard URI for listing a subject's id
	 */
	private static URI SUBJECT_ID =
			URI.create("urn:oasis:names:tc:xacml:1.0:subject:subject-id");

	/**
	 * The standard URI for listing a resource's id
	 */
	private static final URI RESOURCE_ID =
			URI.create("urn:oasis:names:tc:xacml:1.0:resource:resource-id");

	/**
	 * The standard URI for the subject category
	 */
	private static URI SUBJECT_CAT =
			URI.create("urn:oasis:names:tc:xacml:1.0:subject-category:"
					+ "access-subject");

	/**
	 * The standard URI for the resource category
	 */
	private static final URI RESOURCE_CAT =
			URI.create("urn:oasis:names:tc:xacml:3.0:attribute-category:resource");

	/**
	 * The standard URI for the action category
	 */
	private static final URI ACTION_CAT =
			URI.create("urn:oasis:names:tc:xacml:3.0:attribute-category:action");

    /**
     * The resource identifier for the token endpoint
     */
    private static final StringAttribute tokenAV 
    	= new StringAttribute("token");
    
    /**
     * The resource identifier for the introspect endpoint
     */
    private static final StringAttribute introspectAV 
    	= new StringAttribute("introspect");
    
    /**
     * The attribute indicating the token endpoint
     */
	private static final Attribute token 
		= new Attribute(RESOURCE_ID, null, null, tokenAV, false, 0);
	
	/**
	 * The attribute indicating the introspect endpoint
	 */
	private static final Attribute introspect 
		= new Attribute(RESOURCE_ID, null, null, introspectAV, false, 0);
	

	private static final Attributes tokenResource 
		= new Attributes(RESOURCE_CAT, Collections.singleton(token));
	
	private static final Attributes introspectResource
		= new Attributes(RESOURCE_CAT, Collections.singleton(introspect));
	

	private String defaultAud;
	
	private String defaultScope;
	
	/**
	 * Constructor, load policy files from a directory.
	 * 
	 * @param defaultAud  The defaultAudience, can be null.
	 * @param defaultScope  The default Scope, can be null.
	 * @param policyDirectory 
	 */
	public XacmlPDP(String policyDirectory, String defaultAud, String defaultScope) {
		this.defaultAud = defaultAud == null ? "" : defaultAud;
		this.defaultScope = defaultScope == null ? "" : defaultScope;
		Set<String> fileNames 
			= getFilesInFolder(policyDirectory, ".xml");
		PolicyFinder pf = new PolicyFinder();
		FileBasedPolicyFinderModule  pfm 
			= new FileBasedPolicyFinderModule(fileNames);
		pf.setModules(Collections.singleton(pfm));
		pfm.init(pf);
		this.pdp = new org.wso2.balana.PDP(new PDPConfig(null, pf, null));
	}
	
	@Override
	public boolean canAccessToken(String clientId) {
		Set<Attributes> attributes = new HashSet<>();
		attributes.add(tokenResource);
		StringAttribute subjectAV = new StringAttribute(clientId);
		Attribute subject = new Attribute(SUBJECT_ID, null, null, subjectAV, 0);
		Attributes subjectCat = new Attributes(
				SUBJECT_CAT, Collections.singleton(subject));
		attributes.add(subjectCat);
		RequestCtx req = new RequestCtx(attributes, null);
		ResponseCtx res = this.pdp.evaluate(req);
		Iterator<AbstractResult> results = res.getResults().iterator();
        while (results.hasNext()) {
        	AbstractResult result = results.next();
        	if (result.getDecision() != AbstractResult.DECISION_PERMIT) {
        		return false;
        	}
        }
        return true;
	}

	@Override
	public IntrospectAccessLevel getIntrospectAccessLevel(String rsId) {
		Set<Attributes> attributes = new HashSet<>();
		attributes.add(introspectResource);
		StringAttribute subjectAV = new StringAttribute(rsId);
		Attribute subject = new Attribute(SUBJECT_ID, null, null, subjectAV, 0);
		Attributes subjectCat = new Attributes(
				SUBJECT_CAT, Collections.singleton(subject));
		attributes.add(subjectCat);
		RequestCtx req = new RequestCtx(attributes, null);
		ResponseCtx res = this.pdp.evaluate(req);
		Iterator<AbstractResult> results = res.getResults().iterator();
        while (results.hasNext()) {
        	AbstractResult result = results.next();
        	if (result.getDecision() != AbstractResult.DECISION_PERMIT) {
        		return IntrospectAccessLevel.NONE;
        	}
        }
        return IntrospectAccessLevel.ACTIVE_AND_CLAIMS;
	}

	@Override
	public String canAccess(String clientId, Set<String> aud, Object scopes) 
			throws AceException {
		Set<Attributes> attributes = new HashSet<>();
		StringAttribute subjectAV = new StringAttribute(clientId);
		Attribute subject 
			= new Attribute(SUBJECT_ID, null, null, subjectAV, false, 0);
		Attributes subjectCat = new Attributes(
				SUBJECT_CAT, Collections.singleton(subject));
		attributes.add(subjectCat);
		
		Set<String> audSet = new HashSet<>();
		if (aud == null || aud.isEmpty()) {
			if (this.defaultAud.isEmpty()) {
				return null;
			}
			audSet.add(this.defaultAud);
		}
		
		HashSet<Attribute> resources = new HashSet<>();
		for (String audE : audSet) {
		    StringAttribute audAV = new StringAttribute(audE);
		    Attribute audA = new Attribute(URI.create("oauth2:audience"), 
		            null, null, audAV, false, 0);
		    resources.add(audA);
		}
		Attributes resourceCat = new Attributes(
				RESOURCE_CAT, resources);
		attributes.add(resourceCat);
      
		String scopeStr;
        if (scopes instanceof String) {
            scopeStr = (String)scopes;
        } else {
            throw new AceException(
                    "KissPDP does not support non-String scopes");
        }
		if (scopeStr.isEmpty()) {
			if (this.defaultScope.isEmpty()) {
				return null;
			}
			scopeStr = this.defaultScope;
		}
		
		
		String[] scopeArray = scopeStr.split(" ");
		for (int i=0; i<scopeArray.length; i++) {
			String scope = scopeArray[i];			
			StringAttribute scopeAV = new StringAttribute(scope);
			Attribute scopeA = new Attribute(
					URI.create("oauth2:scope"), null, null, scopeAV, 
					true, 0);
			Attributes actionCat = new Attributes(
					ACTION_CAT, Collections.singleton(scopeA));
			attributes.add(actionCat);
		}
		
		RequestCtx req = new RequestCtx(attributes, null);
		ResponseCtx res = this.pdp.evaluate(req);
		Iterator<AbstractResult> results = res.getResults().iterator();
	
		String allowedScopes = "";
        while (results.hasNext()) {
        	AbstractResult aResult = results.next();
        	if (!(aResult instanceof Result)) {
        		throw new AceException(
        				"Received XAML 2 Result when expecting XACML 3");		
        	}
        	Result result = (Result)aResult;
        	
        	if (result.getDecision() != AbstractResult.DECISION_PERMIT) {
        		for (Attributes as : result.getAttributes()) {
        			//Only interested in the action category
        			if (as.getCategory().equals(ACTION_CAT)) {
        				for (Attribute a : as.getAttributes()) {
        					//Only interested in the scope
        					if (a.getId().equals(URI.create("oauth2:scope"))) {
        						if (!allowedScopes.isEmpty()) {
        							allowedScopes += " "; //Add delimiter
        						}
        						allowedScopes += a.getValue().encode();
        					}
        				}
        			}
        		}
        	}
        }
        if (allowedScopes.isEmpty()) {
        	return null;
        }
        return allowedScopes;
	}

	/**
	 * Get the files from a directory (optionally specifying the desired
	 * extension).
	 * 
	 * @param directory  the directory (full pathname)
	 * @param extension  the desired extension filter
	 * @return  the List of file names
	 */
	private static Set<String> getFilesInFolder(String directory, 
			final String extension) {
		File dir = new File(directory);
		String[] children = null;
		if (extension != null) {
			FilenameFilter filter = new FilenameFilter() {
				@Override
				public boolean accept(File f, String name) {
					return name.endsWith(extension);
				}
			};
			children = dir.list(filter);
		} else {
			children = dir.list();
		}
		HashSet<String> result = new HashSet<>();
		for (int i=0; i<children.length;i++) {
			result.add(directory + System.getProperty("file.separator") + children[i]);
		}
		return result;
	}
}
