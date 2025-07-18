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
package se.sics.ace.oscore;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.OneKey;
import net.i2p.crypto.eddsa.Utils;
import se.sics.ace.Util;
import se.sics.ace.GroupcommParameters;
import se.sics.ace.GroupcommPolicies;
import se.sics.ace.Hkdf;

/**
 * A class implementing the status of an OSCORE Group at its Group ManagerOSCORE
 *  
 * @author Marco Tiloca
 *
 */
public class GroupInfo {

	/**
	 * Information element for the OSCORE group
	 */
	
	private String groupName;
	
	private byte[] masterSecret;
	private byte[] masterSalt;
	private byte[] signatureEncryptionKey = null;
	private AlgorithmID hkdf = null;
	private int authCredFormat; // the format of authentication credentials used in the group
	
	// Each set of the list refers to a different size of Sender IDs.
	// The element with index 0 includes as elements Sender IDs with size 1 byte.
	private List<Set<Integer>> usedSenderIds = new ArrayList<Set<Integer>>();
	
	private int maxSenderIdSize; // Maximum size in bytes of the byte array representation of Sender IDs
	private int senderIdSize; // Current size in bytes of the byte array representation of Sender IDs 
	private int maxSenderIdValue;
	
	// Each set of the list refers to a different size of Sender IDs.
	// The element with index 0 has elements referring to Sender IDs with size 1 byte.
	// Each map has as values CBOR byte strings, with value the serialization of the
	// authentication credentials of the group members, according to the format used in the group.
	// The map key (label) is a CBOR byte string with value the Sender ID of the group member.
	private List<Map<CBORObject, CBORObject>> authCredRepo = new ArrayList<Map<CBORObject, CBORObject>>();
	
	// Each set of the list refers to a different size of Sender IDs.
	// The element with index 0 has elements referring to Sender IDs with size 1 byte.
	// Each map has as value the AIF-based role(s) of group members.
	// The map key (label) is the integer representation of the Sender ID of the group member.
	private List<Map<Integer, Integer>> nodeRoles = new ArrayList<Map<Integer, Integer>>();
	
	// The value of each map entry is the node name of a group member with a certain identity.
	// The map (key) label is the identity of each group member, as per its secure association with the Group Manager.
	private Map<String, String> identities2nodeNames = new HashMap<String, String>();

	// The value of each map entry is the current Sender ID (CBOR byte string) of a group member with a certain identity.
	// The map (key) label is the identity of each group member, as per its secure association with the Group Manager.
	private Map<String, CBORObject> identities2senderIDs = new HashMap<String, CBORObject>();
	
	// The value of each map entry is the "Birth GID" (CBOR byte string) of that group member.
	// The map (key) label is the node name of the group member.
	private Map<String, CBORObject> birthGIDs = new HashMap<String, CBORObject>();
	
	// The maximum number of sets of stale Sender IDs for the group
	// This value must be strictly greater than 1
	private int maxStaleIdsSets;
	
	// The value of each map entry is a set of stale Sender IDs.
	// The map (key) label is the version number of the symmetric keying material in use where the Sender ID was marked stale
	private Map<Integer, Set<CBORObject>> staleSenderIds = new HashMap<Integer, Set<CBORObject>>();	
	
	private final int groupIdPrefixSize; // Prefix size (bytes), same for every Group ID on the same Group Manager
	private byte[] groupIdPrefix;
	private boolean groupIdReuse; // true if the Group Manager can recycle the values used as Group Identifier for this group 
	
	private final String prefixMonitorNames; // Initial part of the node name for monitors, since they do not have a Sender ID
	
	private final String nodeNameSeparator; // For non-monitor members, separator between the two components of the node name
	
	// Each element of the set is an allocated variable part of the node name for monitors, since they do not have a Sender ID
	private Set<Integer> suffixMonitorNames = new HashSet<Integer>();
	
	private int groupIdEpochSize; // Epoch size (bytes) in the {Prefix ; Epoch} Group ID
	private int maxGroupIdEpochValue;
	private int groupIdEpoch;
	
	private int mode; // The mode(s) of operation used in the group (group only / group+pairwise / pairwise only)
	
	// Specific to the group mode
	private AlgorithmID gpEncAlg = null;
	private AlgorithmID signAlg = null;
	private CBORObject signParams = null;

	// Specific to the pairwise mode
	private AlgorithmID alg = null;
	private AlgorithmID ecdhAlg = null;
	private CBORObject ecdhParams = null;
	
	private CBORObject groupPolicies = null;
	
	private int version; // Version of the current symmetric keying material
	private boolean status; // True if the group is currently active, false otherwise
	private Long exp; // The expiration time of the group, as the number of seconds from 1970-01-01T00:00:00Z UTC
	
    // The map key is the cryptographic curve; the map value is the hex string of the key pair
    private Map<CBORObject, String> gmSigningKeyPairs;
    
    // For the outer map, the map key is the type of authentication credential
    // For the inner map, the map key is the cryptographic curve, while the map value is the hex string of the authentication credential
    private Map<Integer,  Map<CBORObject, String>> gmSigningPublicAuthCred;
    
    // The map key is the cryptographic curve; the map value is the hex string of the key pair
    private Map<CBORObject, String> gmKeyAgreementKeyPairs;
    
    // For the outer map, the map key is the type of authentication credential
    // For the inner map, the map key is the cryptographic curve, while the map value is the hex string of the authentication credential
    private Map<Integer,  Map<CBORObject, String>> gmKeyAgreementPublicAuthCred;
	
	private OneKey gmKeyPair;   // The asymmetric key pair of the Group Manager, as a OneKey object
	private byte[] gmAuthCred;  // The serialization of the authentication credential of the Group Manager, in the format used in the group
	
	private int detHashAlg = 0; // If Cacheable OSCORE is used in the group, this parameter has value different than 0 and indicating
	                            // the COSE Hash Algorithm used to compute the Request Hash when composing an OSCORE Deterministic Request
	private byte[] detClientSenderID = null; // Sender ID of the Deterministic Client, if Cacheable OSCORE is used
	
	/**
	 * Creates a new GroupInfo object tracking the current status of an OSCORE group.
	 * 
	 * @param groupName           the invariant name of the OSCORE group.
	 * @param masterSecret        the OSCORE Master Secret.
	 * @param masterSalt          the OSCORE Master Salt.
	 * @param groupIdPrefixSize   the size in bytes of the Prefix part of the OSCORE Group ID. Up to 4 bytes.
	 * @param groupIdPrefix       the Prefix part of the OSCORE Group ID.
	 * @param groupIdEpochSize    the size in bytes of the byte array representation of the Epoch part of the OSCORE Group ID. Up to 4 bytes.
	 * @param groupIdEpoch        the current value of the Epoch part of the OSCORE Group ID as a positive integer.
	 * @param groupIdReuse        true if the Group Manager recycles values of Group Identifiers, or false otherwise
	 * @param prefixMonitorNames  the prefix string used to build the name of a group member acting as monitor.
	 * @param nodeNameSeparator   the string separator used to build the name of a group member non acting as monitor.
	 * @param hkdf                the HKDF Algorithm.
	 * @param credFmt             the format of the authentication credentials used in the OSCORE group.
	 * @param mode			      the mode(s) of operation used in the group (group only / group+pairwise / pairwise only)
	 * @param gpEncAlg            the Group Encryption Algorithm if the group mode is used, or null otherwise
	 * @param signAlg             the Signature Algorithm if the group mode is used, or null otherwise
	 * @param signParams          the parameters of the Signature Algorithm if the group mode is used, or null otherwise
	 * @param alg                 the AEAD algorithm if the pairwise mode is used, or null otherwise
	 * @param ecdhAlg             the Pairwise Key Agreement Algorithm if the pairwise mode is used, or null otherwise
	 * @param ecdhParams          the parameters of the Pairwise Key Agreement Algorithm if the pairwise mode is used, or null otherwise
	 * @param groupPolicies		  the map of group policies, or Null for building one with default values
	 * @param gmKeyPair           the asymmetric key pair of the Group Manager
	 * @param gmAuthCred		  the serialization of the authentication credential of the Group Manager, in the format used in the group
     * @param gmSigningKeyPairs  the signing key pairs of the Group Manager
     * @param gmSigningPublicAuthCred  the signing public authentication credentials of the Group Manager
     * @param gmKeyAgreementKeyPairs  the key agreement key pairs of the Group Manager
     * @param gmKeyAgreementPublicAuthCred  the key agreement public authentication credentials of the Group Manager
	 * @param maxStaleIdsSets     the maximum number of sets of stale Sender IDs for the group
	 * @param detHashAlg          the hash algorithm to compute the Request Hash for OSCORE Deterministic Requests (or 0, if not supported)
	 */
    public GroupInfo(final String groupName,
    				 final byte[] masterSecret,
    				 final byte[] masterSalt,
    				 final int groupIdPrefixSize,
    		         final byte[] groupIdPrefix,
    		         final int groupIdEpochSize,
    		         final int groupIdEpoch,
    		         final boolean groupIdReuse,
    		         final String prefixMonitorNames,
    		         final String nodeNameSeparator,
    		         final AlgorithmID hkdf,
    		         final int authCredFormat,
    		         final int mode,
    		         final AlgorithmID gpEncAlg,
    		         final AlgorithmID signAlg,
    		         final CBORObject signParams,
    		         final AlgorithmID alg,
    		         final AlgorithmID ecdhAlg,
    		         final CBORObject ecdhParams,
    		         final CBORObject groupPolicies,
    		         final OneKey gmKeyPair,
    		         final byte[] gmAuthCred,
					  Map<CBORObject, String> gmSigningKeyPairs,
					  Map<Integer,  Map<CBORObject, String>> gmSigningPublicAuthCred,
					  Map<CBORObject, String> gmKeyAgreementKeyPairs,
					  Map<Integer,  Map<CBORObject, String>> gmKeyAgreementPublicAuthCred,
    		         final int maxStaleIdsSets,
    		         final int detHashAlg) {
    	
    	this.version = 0;
    	this.status = false;
    	this.exp = 2682374400L; // Hardcoded value to enable test units
    	
    	setGroupName(groupName);
    	
    	setHkdf(hkdf);
    	setMasterSecret(masterSecret);
    	setMasterSalt(masterSalt);
    	
    	this.groupIdPrefixSize = groupIdPrefixSize;
    	setGroupIdPrefix(groupIdPrefix);
    	setGroupIdEpoch(groupIdEpochSize, groupIdEpoch);
    	this.groupIdReuse = groupIdReuse;
    	
    	this.mode = mode;
    	this.authCredFormat = authCredFormat;
    	this.prefixMonitorNames = prefixMonitorNames;
    	this.nodeNameSeparator = nodeNameSeparator;
    	
    	// The group mode is used
    	if (mode != GroupcommParameters.GROUP_OSCORE_PAIRWISE_MODE_ONLY) {
    		setGpEncAlg(gpEncAlg);
	    	setSignAlg(signAlg);
	    	setSignParams(signParams);
	    	setSignatureEncryptionKey();
    	}
    	
    	// The pairwise mode is used
    	if (mode != GroupcommParameters.GROUP_OSCORE_GROUP_MODE_ONLY) {
    		setAlg(alg);
	    	setEcdhAlg(ecdhAlg);
	    	setEcdhParams(ecdhParams);
    	}
    	    	
    	setMaxSenderIdSize();
    	this.senderIdSize = 1; // Currently used size of Sender IDs, in bytes
    	this.maxSenderIdValue = 255; // Maximum value for the currently used size of Sender IDs
    	
    	this.maxStaleIdsSets = maxStaleIdsSets;
    	staleSenderIds.put(Integer.valueOf(version), new HashSet<CBORObject>());
    	
    	for (int i = 0; i < 4; i++) {
        	// Empty sets of assigned Sender IDs; one set for each possible Sender ID size in bytes.
        	// The set with index 0 refers to Sender IDs with size 1 byte
    		usedSenderIds.add(new HashSet<Integer>());
    		
        	// Empty sets of stored authentication credentials; one set for each possible Sender ID size in bytes.
        	// The set with index 0 refers to Sender IDs with size 1 byte
    		authCredRepo.add(new HashMap<CBORObject, CBORObject>());
    		
        	// Empty sets of roles; one set for each possible Sender ID size in bytes.
        	// The set with index 0 refers to Sender IDs with size 1 byte
    		nodeRoles.add(new HashMap<Integer, Integer>());
    		
    	}
    	
    	this.groupPolicies = groupPolicies;
    	
    	if (groupPolicies == null) {
    		// Set default policy values
        	CBORObject defaultGroupPolicies = CBORObject.NewMap();
        	defaultGroupPolicies.Add(GroupcommPolicies.KEY_CHECK_INTERVAL, CBORObject.FromObject(3600));
        	defaultGroupPolicies.Add(GroupcommPolicies.EXP_DELTA, CBORObject.FromObject(0));
        	this.groupPolicies = defaultGroupPolicies;
    	}
    	
    	this.gmKeyPair = gmKeyPair;
    	this.gmAuthCred = gmAuthCred;
    	
        this.gmSigningKeyPairs = gmSigningKeyPairs;
        this.gmSigningPublicAuthCred = gmSigningPublicAuthCred;
        this.gmKeyAgreementKeyPairs = gmKeyAgreementKeyPairs;
        this.gmKeyAgreementPublicAuthCred = gmKeyAgreementPublicAuthCred;
    	
    	setDetHashAlg(detHashAlg);
    	
    }
    
    /** Update the current information about this OSCORE Group, following
     *  an overwrite/update to the corresponding group-configuration resource
     *
     * @param updatedParameterValues   The parameters to be considered for updating the current information
     * 
     * @return  A CBOR map including the parameters that have actually been updated and their new value, or null in case of error
     */
    synchronized public CBORObject updateGroupInfo(final CBORObject updatedParameterValues) {
    	
    	CBORObject changedParameters = CBORObject.NewMap();
    	
    	for (CBORObject key : updatedParameterValues.getKeys()) {
    		
    		CBORObject value = updatedParameterValues.get(key);
    		
    		if (key.equals(GroupcommParameters.HKDF)) {
    			if (getHkdf().AsCBOR().equals(value) == false) {
    		    	try {
    		    		setHkdf(AlgorithmID.FromCBOR(value));
    				} catch (CoseException e) {
    					System.err.println("Error when setting the HKDF Algorithm "
    							         + "for the OSCORE group with name \"" + groupName + "\"");
    					e.printStackTrace();
    					return null;
    				}
    		    	changedParameters.Add(key, value);
    			}
    		}
    		if (key.equals(GroupcommParameters.CRED_FMT)) {
    			if (getAuthCredFormat() != value.AsInt32()) {
    				setAuthCredFormat(value.AsInt32());
    				changedParameters.Add(key, value);
    			}
    		}
    		if (key.equals(GroupcommParameters.GP_ENC_ALG)) {
    			if (getGpEncAlg().AsCBOR().equals(value) == false) {
    		    	try {
    		    		setGpEncAlg(AlgorithmID.FromCBOR(value));
    				} catch (CoseException e) {
    					System.err.println("Error when setting the Group Encryption Algorithm "
    							         + "for the OSCORE group with name \"" + groupName + "\"");
    					e.printStackTrace();
    					return null;
    				}
    		    	changedParameters.Add(key, value);
    			}
    		}
    		if (key.equals(GroupcommParameters.SIGN_ALG)) {
    			if (getSignAlg().AsCBOR().equals(value) == false) {
    		    	try {
    		    		setSignAlg(AlgorithmID.FromCBOR(value));
    				} catch (CoseException e) {
    					System.err.println("Error when setting the Signature Algorithm "
    							         + "for the OSCORE group with name \"" + groupName + "\"");
    					e.printStackTrace();
    					return null;
    				}
    		    	changedParameters.Add(key, value);
    			}
    		}
    		if (key.equals(GroupcommParameters.SIGN_PARAMS)) {
    			if (getSignParams().equals(value) == false) {
    				setSignParams(value);
    				changedParameters.Add(key, value);
    			}
    		}
    		if (key.equals(GroupcommParameters.ALG)) {
    			if (getAlg().AsCBOR().equals(value) == false) {
    		    	try {
    		    		setAlg(AlgorithmID.FromCBOR(value));
    				} catch (CoseException e) {
    					System.err.println("Error when setting the AEAD Algorithm "
    							         + "for the OSCORE group with name \"" + groupName + "\"");
    					e.printStackTrace();
    					return null;
    				}
    		    	changedParameters.Add(key, value);
    			}
    		}
    		if (key.equals(GroupcommParameters.ECDH_ALG)) {
    			if (getEcdhAlg().AsCBOR().equals(value) == false) {
    		    	try {
    		    		setEcdhAlg(AlgorithmID.FromCBOR(value));
    				} catch (CoseException e) {
    					System.err.println("Error when setting the Pairwise Key Agreement Algorithm "
    							         + "for the OSCORE group with name \"" + groupName + "\"");
    					e.printStackTrace();
    					return null;
    				}
    		    	changedParameters.Add(key, value);
    			}
    		}
    		if (key.equals(GroupcommParameters.ECDH_PARAMS)) {
    			if (getEcdhParams().equals(value) == false) {
    				setEcdhParams(value);
    				changedParameters.Add(key, value);
    			}
    		}
    		if (key.equals(GroupcommParameters.GROUP_POLICIES)) {
    			if (getGroupPolicies().equals(value) == false) {
    				setGroupPolicies(value);
    				changedParameters.Add(key, value);
    			}
    		}
    		if (key.equals(GroupcommParameters.MAX_STALE_SETS)) {
    			if (getMaxStaleIdsSets() != value.AsInt32()) {
    				setMaxStaleIdsSets(value.AsInt32());
    				changedParameters.Add(key, value);
    			}
    		}
    		if (key.equals(GroupcommParameters.ACTIVE)) {
    			if (getStatus() != value.AsBoolean()) {
    				setStatus(value.AsBoolean());
    				changedParameters.Add(key, value);
    			}
    		}
    		if (key.equals(GroupcommParameters.DET_HASH_ALG)) {
    			if (getDetHashAlg() != value.AsInt32()) {
    				setDetHashAlg(value.AsInt32());
    				changedParameters.Add(key, value);
    			}
    		}
    		
    	}
    	
    	if (updatedParameterValues.get(GroupcommParameters.DET_HASH_ALG) != null) {
    		setDetHashAlg(0);
    	}
    	
    	if (changedParameters.ContainsKey(GroupcommParameters.GP_ENC_ALG) || changedParameters.ContainsKey(GroupcommParameters.ALG)) {
    		
    		int oldMaxSenderIdSize = this.maxSenderIdSize;
        	setMaxSenderIdSize();
        	
        	if (this.maxSenderIdSize < oldMaxSenderIdSize) {
        		List<Set<Integer>> usedSenderIDs = this.getUsedSenderIds();
        		
        		for (Set<Integer> mySet : usedSenderIDs) {
        			
        			for (Integer sidInt : mySet) {
        				byte[] sidBytes = Util.intToBytes(sidInt);
        				
        				if (sidBytes.length < this.maxSenderIdSize) {
        					CBORObject sidCBOR = CBORObject.FromObject(sidBytes);
        					
        					for (String identity : this.identities2senderIDs.keySet()) {
        						
        						if (this.identities2senderIDs.get(identity).equals(sidCBOR) && isGroupMember(identity)) {
        							// TODO Remove this group member and its associated node resource.
        							//      Then, rekey the group accordingly
        						}
        					}
        				}
        			}
        		}
        	}
    	}
    	
    	if (changedParameters.ContainsKey(GroupcommParameters.SIGN_ALG) || changedParameters.ContainsKey(GroupcommParameters.SIGN_PARAMS) ||
    		changedParameters.ContainsKey(GroupcommParameters.ECDH_ALG) || changedParameters.ContainsKey(GroupcommParameters.ECDH_PARAMS) ||
    		changedParameters.ContainsKey(GroupcommParameters.CRED_FMT)) {
    		
    		// The algorithms, corresponding parameters, or format of authentication credential have changed in the OSCORE group.
    		// The Group Manager has to switch to an appropriate asymmetric key pair and corresponding public authentication credential.
    		
        	boolean useGroupMode;
        	if (this.getMode() != GroupcommParameters.GROUP_OSCORE_PAIRWISE_MODE_ONLY) {
        		useGroupMode = true;
        	}
        	else useGroupMode = false;
        	
        	CBORObject algParameters;
        	if (useGroupMode) {
        		algParameters = this.getSignParams();
        	}
        	else {
        		algParameters = this.getEcdhParams();
        	}
        	
        	setGmKeyPair(Util.retrieveGmKeyPair(this.gmSigningKeyPairs, this.gmKeyAgreementKeyPairs, useGroupMode, algParameters));
        	
        	setGmAuthCred(Util.retrieveGmAuthCred(getAuthCredFormat(), gmSigningPublicAuthCred,
        										  gmKeyAgreementPublicAuthCred, useGroupMode, algParameters));
    		
    	}
    	
    	return changedParameters;
    		
    }
    
    
    
    /** Retrieve the mode(s) of operation used in the group
     * 
     * @return  The mode(s) of operation used in the group (group only / group+pairwise / pairwise only)
     */
    synchronized public final int getMode() {
    	
    	return this.mode;
    	
    }
    
    /** Retrieve the current status of the group
     * 
     * @return  True if the group is currently active, false otherwise
     */
    synchronized public final boolean getStatus() {
    	
    	return this.status;
    	
    }
    
    /** 
     * Set the status of the group
     * @param The new status to set for the group, i.e. true for active, false for inactive
     */
    synchronized public void setStatus(final boolean status) {
    	
    	this.status = status;
    	
    }
    
    /** Retrieve the expiration time of the group
     * 
     * @return  The expiration time of the group
     */
    synchronized public final Long getExp() {
    	
    	return this.exp;
    	
    }
    
    /** 
     * Set the expiration time of the group
     * @param The new expiration time of the group
     */
    synchronized public void setExp(final Long exp) {
    	
    	this.exp = exp;
    	
    }
    
    /** Retrieve the asymmetric key pair of the Group Manager
     * 
     * @return  The asymmetric key pair of the Group Manager
     */
    synchronized public final OneKey getGmKeyPair() {
    	
    	return this.gmKeyPair;
    	
    }
    
    /** 
     * Set the asymmetric key pair of the Group Manager
     * @param The new asymmetric key pair of the Group Manager
     */
    synchronized public void setGmKeyPair(OneKey gmKeyPair) {
    	
    	this.gmKeyPair = gmKeyPair;
    	
    }
    
    /** Retrieve the authentication credential of the Group Manager, according to the format used in the group
     * 
     * @return  The authentication credential of the Group Manager
     */
    synchronized public final byte[] getGmAuthCred() {
    	
    	return this.gmAuthCred;
    	
    }
    
    /** 
     * Set the authentication credential of the Group Manager, according to the format used in the group
     * @param The new authentication credential of the Group Manager
     */
    synchronized public void setGmAuthCred(byte[] gmAuthCred) {
    	
    	this.gmAuthCred = gmAuthCred;
    	
    }
    
    /** Retrieve the OSCORE Master Secret value
     * 
     * @return  the master secret
     */
    synchronized public final byte[] getMasterSecret() {
    	
    	byte[] myArray = new byte[this.masterSecret.length];
    	System.arraycopy(this.masterSecret, 0, myArray, 0, this.masterSecret.length);
    	return myArray;
    	
    }
    
    /** 
     * Set the OSCORE Master Secret value
     * @param masterSecret
     */
    synchronized public void setMasterSecret(final byte[] masterSecret) {
    	
    	this.masterSecret = new byte[masterSecret.length];
    	System.arraycopy(masterSecret, 0, this.masterSecret, 0, masterSecret.length);
    	
    }
    
    /** Retrieve the name of the OSCORE group
     * @return  the name of the OSCORE group
     */
    synchronized public final String getGroupName() {
    	
    	return new String(this.groupName); 
    	
    }
    
    /** 
     * Set the name of the OSCORE group
     * @param groupName
     */
    synchronized public void setGroupName(final String groupName) {
    	
    	this.groupName = new String(groupName);
    	
    }
    
    /**
     *  Retrieve the OSCORE Master Salt value
     * @return  the master salt
     */
    synchronized public final byte[] getMasterSalt() {
    	
    	byte[] myArray = new byte[this.masterSalt.length];
    	System.arraycopy(this.masterSalt, 0, myArray, 0, this.masterSalt.length);
    	return myArray;
    	
    }
    
    /**
     * Set the OSCORE Master Salt value
     * @param masterSalt
     */
    synchronized public void setMasterSalt(final byte[] masterSalt) {
    	
    	if (masterSalt == null) {
			this.masterSalt = new byte[0];
    	}
    	else {
    		this.masterSalt = new byte[masterSalt.length];
    		System.arraycopy(masterSalt, 0, this.masterSalt, 0, masterSalt.length);
    	}
    	
    }
    
    /**
     *  Retrieve the OSCORE Signature Encryption Key
     * @return  the Signature Encryption Key, or null in case of error
     */
    synchronized public final byte[] getSignatureEncryptionKey() {
    	
    	if (this.signatureEncryptionKey == null || this.mode == GroupcommParameters.GROUP_OSCORE_PAIRWISE_MODE_ONLY)
    		return null;
    	
    	byte[] myArray = new byte[this.signatureEncryptionKey.length];
    	System.arraycopy(this.signatureEncryptionKey, 0, myArray, 0, this.signatureEncryptionKey.length);
    	return myArray;
    	
    }
    
    /**
     * Set the OSCORE Signature Encryption Key
     * 
     */
    synchronized public void setSignatureEncryptionKey() {
    	
    	CBORObject info = CBORObject.NewArray();
    	
    	 // 'id'
    	byte[] emptyArray = new byte[0];
    	info.Add(emptyArray);
    	
    	// 'id_context'
    	info.Add(getGroupId());
    	
    	// 'alg_aead'
    	if (this.getGpEncAlg().AsCBOR().getType() == CBORType.Integer)
        	info.Add(this.getGpEncAlg().AsCBOR().AsInt32());
    	if (this.getGpEncAlg().AsCBOR().getType() == CBORType.TextString)
        	info.Add(this.getGpEncAlg().AsCBOR().AsString());
    	
    	// 'type'
    	info.Add("SEKey");
    	
    	// 'L'
    	int L = getKeyLengthGroupEncryptionAlgorithm();
    	info.Add(L);
    	
    	try {
			this.signatureEncryptionKey = Hkdf.extractExpand(getMasterSalt(), getMasterSecret(), info.EncodeToBytes(), L);
		} catch (InvalidKeyException e) {
			System.err.println("Error when deriving the Signature Encryption Key: " + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Error when deriving the Signature Encryption Key: " + e.getMessage());
		}
    	
    }
    
    /**
     *  Get the Group ID Prefix as byte array
     * @return  the Group ID Prefix
     */
    synchronized public final byte[] getGroupIdPrefix() {
    	
    	byte[] myArray = new byte[this.groupIdPrefix.length];
    	System.arraycopy(this.groupIdPrefix, 0, myArray, 0, this.groupIdPrefix.length);
    	return myArray;
    	
    }
    
    /**
     *  Set the Group ID Prefix.
     * @param groupIdPrefix
     * @return false in case of error, or true otherwise.
     */
    synchronized public boolean setGroupIdPrefix(final byte[] groupIdPrefix) {
    	
    	if (groupIdPrefix.length != this.groupIdPrefixSize)
    		return false;
    	
    	this.groupIdPrefix = new byte[groupIdPrefix.length];
    	System.arraycopy(groupIdPrefix, 0, this.groupIdPrefix, 0, groupIdPrefix.length);
    	return true;
    	
    }
    
    /**
     *  Retrieve the Group ID Epoch value as an integer
     * @return  the Group ID Epoch
     */
    synchronized public final int getGroupIdEpoch() {
    	
    	return this.groupIdEpoch;
    	
    }
    
    // Set the size and initial value of the Group ID Epoch.
    // This method is only internally invoked by this class' constructor.
    //
    // Return false in case of invalid input parameters, or true otherwise.
    synchronized private boolean setGroupIdEpoch(final int groupIdEpochSize, final int groupIdEpoch) {
    	
    	if (groupIdEpochSize < 1)
    		return false;
    	else if (groupIdEpochSize > 4)
    		return false;

    	this.groupIdEpochSize = groupIdEpochSize;
    	this.groupIdEpoch = groupIdEpoch;
    	
    	if (groupIdEpochSize == 4)
    		this.maxGroupIdEpochValue = (1 << 31) - 1;
    	else
    		this.maxGroupIdEpochValue = (1 << (groupIdEpochSize * 8)) - 1;
    	
    	return true;
    }

    /**
     *  Set an arbitrary new value of the Group ID Epoch.
     * @param groupIdEpoch
     * @return  false in case of invalid input parameters, or true otherwise.
     */
    synchronized public boolean setGroupIdEpoch(final int groupIdEpoch) {

        // The Group ID Epoch can only grow
        if (groupIdEpoch <= this.groupIdEpoch)
            return false;

        if (groupIdEpoch > this.maxGroupIdEpochValue)
            return false;

        this.groupIdEpoch = groupIdEpoch;
        return true;

    }

    /**
     *  Increment the value of the Group ID Epoch.
     * @return  false if the maximum value is passed, or true otherwise.
     */
    synchronized public boolean incrementGroupIdEpoch() {

        boolean ret = false;

        // This should trigger a group rekeying
        if (this.groupIdEpoch == this.maxGroupIdEpochValue)
            this.groupIdEpoch = 0;

        else {
            this.groupIdEpoch++;
            ret = true;
        }
    	
    	return ret;
    	
    }
    
    /** Retrieve whether the Group Manager recycles Group ID values for this group
     * 
     * @return  True if the Group Manager recycles Group ID values for this group, or false otherwise
     */
    synchronized public final boolean getGroupIdReuse() {
    	
    	return this.groupIdReuse;
    	
    }
    
    /**
     * @return  the full {Prefix + Epoch} Group ID as a Byte Array
     */
    synchronized public final byte[] getGroupId() {
    	
    	byte[] myArray = new byte[this.groupIdPrefix.length + this.groupIdEpochSize];
    	for (int i = 0; i < myArray.length; i++)
    		myArray[i] = (byte) 0x00;
    	
    	System.arraycopy(this.groupIdPrefix, 0, myArray, 0, this.groupIdPrefix.length);
    	
    	byte[] groupIdEpochArray = Util.intToBytes(this.groupIdEpoch, this.groupIdEpochSize);
    	
    	if (groupIdEpochArray.length == 0 || groupIdEpochArray.length != this.groupIdEpochSize)
    		return null;
    	
    	System.arraycopy(groupIdEpochArray, 0, myArray, this.groupIdPrefix.length, groupIdEpochArray.length);
    	     
    	return myArray;
    	
    }
    
    /**
     * @return the KDF used in the group
     */
    synchronized public final AlgorithmID getHkdf() {
    	
    	return this.hkdf;
    	
    }
    
    /**
     *  Set the KDF used in the group
     * @param hkdf
     */
    synchronized public void setHkdf(final AlgorithmID hkdf) {
    	
    	if (hkdf == null)
    		this.hkdf = AlgorithmID.HMAC_SHA_256;
    	else
    		this.hkdf = hkdf;
    	
    }
    
    /**
     * @return the Group Encryption Algorithm used in the group for the group mode
     */
    synchronized public final AlgorithmID getGpEncAlg() {
    	
    	return this.gpEncAlg;
    	
    }
    
    /**
     *  Set the Group Encryption Algorithm used in the group for the group mode
     * @param gpEncAlg
     */
    synchronized public void setGpEncAlg(final AlgorithmID gpEncAlg) {
    	
    	if (gpEncAlg == null)
			this.gpEncAlg = AlgorithmID.AES_CCM_16_64_128;
    	else
    		this.gpEncAlg = gpEncAlg;
    	
    }
    
    /**
     * @return  the Signature Algorithm used in the group for the group mode
     */
    synchronized public final AlgorithmID getSignAlg() {
    	
    	return this.signAlg;
    	
    }
    
    /**
     *  Set the Signature Algorithm used in the group for the group mode
     * @param signAlg
     */
    synchronized public void setSignAlg(final AlgorithmID signAlg) {
    	
    	if (signAlg == null)
    		this.signAlg = AlgorithmID.EDDSA;
    	else
    		this.signAlg = signAlg;
    	
    }    
    
    /**
     * @return  the parameters of the Signature Algorithm used in the group for the group mode
     */
    synchronized public final CBORObject getSignParams() {
    	
    	return this.signParams;
    	
    }

    /**
     * Set the parameters of the Signature Algorithm used in the group for the group mode
     * @param signParams
     * 
     * @return true of the parameters were successfully set, false otherwise
     */
    synchronized public boolean setSignParams(final CBORObject signParams) {

    	if (signParams.getType() != CBORType.Array)
    		return false;
    	
    	this.signParams = signParams;
    	
    	return true;
    	
    }
    
    /**
     * @return the AEAD Algorithm used in the group for the pairwise mode
     */
    synchronized public final AlgorithmID getAlg() {
    	
    	return this.alg;
    	
    }
    
    /**
     *  Set the AEAD Algorithm used in the group for the pairwise mode
     * @param alg
     */
    synchronized public void setAlg(final AlgorithmID alg) {
    	
    	if (alg == null)
			this.alg = AlgorithmID.AES_CCM_16_64_128;
    	else
    		this.alg = alg;
    	
    }
    
    /**
     * @return the Pairwise Key Agreement Algorithm used in the group for the pairwise mode
     */
    synchronized public final AlgorithmID getEcdhAlg() {
    	
    	return this.ecdhAlg;
    	
    }
    
    /**
     *  Set the Pairwise Key Agreement Algorithm used in the group for the pairwise mode
     * @param ecdhAlg
     */
    synchronized public void setEcdhAlg(final AlgorithmID ecdhAlg) {
    	
    	if (ecdhAlg == null)
			this.ecdhAlg = AlgorithmID.ECDH_SS_HKDF_256;
    	else
    		this.ecdhAlg = ecdhAlg;
    	
    }
    
    /**
     * @return  the parameters of the Pairwise Key Agreement Algorithm used in the group for the pairwise mode
     */
    synchronized public final CBORObject getEcdhParams() {
    	
    	return this.ecdhParams;
    	
    }

    /**
     * Set the parameters of the Pairwise Key Agreement Algorithm used in the group for the pairwise mode
     * @param ecdhParams
     * 
     * @return true of the parameters were successfully set, false otherwise
     */
    synchronized public boolean setEcdhParams(final CBORObject ecdhParams) {

    	if (ecdhParams.getType() != CBORType.Array)
    		return false;
    	
    	this.ecdhParams = ecdhParams;
    	
    	return true;
    	
    }
    
    /**
     * Return the format of the authentication credentials used in the group
     * 
     * @return the format of the authentication credentials used in the group
     */
    synchronized public final int getAuthCredFormat() {
    	
    	return this.authCredFormat;
    	
    }
    
    /**
     * Set the format of the authentication credentials used in the group
     * 
     * @param authCredFormat   The format of authentication credentials used in the group
     */
    synchronized public final void setAuthCredFormat(final int authCredFormat) {
    	
    	this.authCredFormat = authCredFormat;
    	
    }

    /**
     *  Return the whole collection of Sender IDs assigned so far.
     *  Note that this includes also Sender IDs of members that have left the group.
     *  On top of uniqueness, there is not re-cycling of previously assigned Sender IDs.
     * @return   The whole collection of assigned Sender IDs.
     */
    synchronized public List<Set<Integer>> getUsedSenderIds() {
    	
    	return this.usedSenderIds;
    	
    }
    
    /**
     * Based on the set Group Encryption Algorithm and AEAD Algorithm,
     * set the maximum size of Sender IDs in bytes
     */
    synchronized private void setMaxSenderIdSize() {
    	
    	int L = 0;
    	
    	if (getGpEncAlg() == null && getAlg() != null) {
    		L = Util.getSizeOfAlgNonce(getAlg());
    	}
    	if (getGpEncAlg() != null && getAlg() == null) {
    		L = Util.getSizeOfAlgNonce(getGpEncAlg());
    	}
    	if (getGpEncAlg() != null && getAlg() != null) {
    		int size1 = Util.getSizeOfAlgNonce(getGpEncAlg());
    		int size2 = Util.getSizeOfAlgNonce(getAlg());
    		L = (size1 < size2) ? size1 : size2;
    	}
    	
    	this.maxSenderIdSize = L - 6;
    	
    }
    
    /**
     * Find the first available Sender ID value and allocate it.
     * @return  the allocated Sender ID value as a byte array, or null if all values are used.
     */
    synchronized public byte[] allocateSenderId() {
    	
    	// All the possible values for the Sender IDs with this size have been allocated.
    	// Switch to the next size, up to 4 bytes, and update the maximum Sender ID value.
    	if (this.usedSenderIds.get(this.senderIdSize - 1).size() == (this.maxSenderIdValue + 1)) {
	    	this.senderIdSize++;
	    	
	    	// The new intended size exceeds the maximum admitted one
	    	if (this.senderIdSize > this.maxSenderIdSize)
	    		return null;
	    
        	// All Sender IDs with all possible sizes have been assigned already
        	if (this.senderIdSize > 4)
        		return null;
        	
        	if (this.senderIdSize == 4)
        		this.maxSenderIdValue = (1 << 31) - 1;
        	else
        		this.maxSenderIdValue = (1 << (this.senderIdSize * 8)) - 1;
    	}
    	
    	byte[] senderIdByteArray = null;
    	for (int i = 0; i <= this.maxSenderIdValue; i++) {
    		if (!this.usedSenderIds.get(this.senderIdSize - 1).contains(i)) {
    			this.usedSenderIds.get(this.senderIdSize - 1).add(i);
    			
    			senderIdByteArray = new byte[this.senderIdSize];
    			senderIdByteArray = Util.intToBytes(i, this.senderIdSize);
    			break;
    		}
    	}
    	
    	return senderIdByteArray;
    	
    }
    
    /**
     *  If never assigned before, assign a particular Sender ID value provided as byte array.
     * @param id   The requested Sender ID to allocate
     * @return   True is the Sender ID could be allocated, false otherwise.
     */
    synchronized public boolean allocateSenderId(byte[] id) {
    	
    	if (id.length != this.senderIdSize)
    		return false;
    	
    	// All the possible values for the Sender IDs with this size have been assigned already
    	if (this.usedSenderIds.get(this.senderIdSize - 1).size() == (this.maxSenderIdValue + 1))
    		return false;
    	
    	// The specified Sender ID has been already assigned - And no recycling is admitted
    	if (this.usedSenderIds.get(this.senderIdSize - 1).contains(Util.bytesToInt(id)))
    		return false;
    	
    	// In case the input array is 4 bytes in size and encoding a negative integer, this will return false
    	return allocateSenderId(Util.bytesToInt(id));
    	
    }
    
    /**
     *  Check if a particular Sender ID value provided as an integer is available.
     * @param id
     * @return  if available allocate it and return true. Otherwise, return false.
     */
    synchronized private boolean allocateSenderId(final int id) {
    	
    	if (id < 0 || id > this.maxSenderIdValue)
    		return false;
    	
    	if (!this.usedSenderIds.get(senderIdSize - 1).contains(id)) {
    		this.usedSenderIds.get(senderIdSize - 1).add(id);
    		return true;
    	}
    	
    	return false;
    	
    }
    
    /**
     * Release a particular Sender ID value provided as a byte array.
     * 
     * This method is intended only to rollback from errors during the joining process.
     * 
     * @param idByteArray   The Sender ID as byte array
     * @return  false in case of failure, true otherwise.
     */
    synchronized public boolean deallocateSenderId(final byte[] idByteArray) {
    	
    	if (idByteArray.length != this.senderIdSize)
    		return false;
    	
    	int id = Util.bytesToInt(idByteArray);
    	
    	// In case the input array is 4 byte in size and encoding a negative integer, this will return false
    	return deallocateSenderId(id, idByteArray.length);
    	
    }
    
    /**
     * Release a particular Sender ID value provided as an integer.
     * 
     * This method is intended only to rollback from errors during the joining process.
     *  
     * @param id   the Sender ID converted to integer
     * @param size   the size in bytes of the original Sender ID as byte array
     * @return  false in case of failure, or true otherwise.
     */
    synchronized private boolean deallocateSenderId(final int id, final int size) {

    	if (size < 0 || size > 4)
    		return false;
    	
    	int maxValue;
    	
    	if (size == 4)
    		maxValue = (1 << 31) - 1;
    	else
    		maxValue = (1 << (senderIdSize * 8)) - 1;
    	
    	if (id < 0 || id > maxValue)
    		return false;
    	
    	if (this.usedSenderIds.get(size - 1).contains(id)) {
    		this.usedSenderIds.get(size - 1).remove(id);
			return true;
    	}
    	
    	return false;
    	
    }
    
    /**
     * Assign a node name to group member. If applicable, the group member must have already received a Sender ID.
     * 
     * @param id   The Sender ID already assigned to the node. It is Null if the node is a monitor.
     * @return   The name assigned to the group member, or Null if there was a problem.
     */
    synchronized public String allocateNodeName(byte[] id) {
    	
    	String nodeName = null;
    	
    	// The group member is a monitor and gets a node name following a monitor-name schema
    	if (id == null) {
        	int maxSuffixValue = (1 << 31) - 1;
    		for (int i = 0; i <= maxSuffixValue; i++) {
    			// This suffix value has been already assigned - No recycling is admitted
    			if (suffixMonitorNames.contains(Integer.valueOf(i))) {
    				continue;
    			}
    			else {
    				// Mark the suffix value as assigned
    				suffixMonitorNames.add(Integer.valueOf(i));
    				nodeName = new String(prefixMonitorNames + String.valueOf(i));
    				break;
    			}
    		}
    	}
    	// The group member is not a monitor and has already been assigned a Sender ID
    	else {
	    	// Double-check that the specified Sender ID has been in fact allocated
	    	if (this.usedSenderIds.get(this.senderIdSize - 1).contains(Util.bytesToInt(id)))
	    		nodeName = new String(Utils.bytesToHex(this.groupIdPrefix) +
	    				              Utils.bytesToHex(Util.intToBytes(this.groupIdEpoch, this.groupIdEpochSize)) +
	    				              this.nodeNameSeparator +
	    				              Utils.bytesToHex(id));
    	}
    	
    	return nodeName;
    	
    }
    
    /**
     * Release a particular node name previously assigned to a node joining the group as monitor.
     * 
     * This method is intended only to rollback from errors during the joining process,
     * and only for candidate members attempting to join the group as monitor.
     * 
     * @param nodeName   The node name as a string
     */
    synchronized public void deallocateNodeName(final String nodeName) {
    	
    	// Double-check that the node name is consistent with the naming schema for monitor group members
    
    	int prefixSize = prefixMonitorNames.length();
    	if (nodeName.length() < (prefixMonitorNames.length() + 1))
    		return;
    	if(!nodeName.substring(0, prefixSize).equals(prefixMonitorNames))
    		return;
    	for (int i = prefixSize; i < nodeName.length(); i++) {
    		if (!Character.isDigit(nodeName.charAt(i)))
    			return;
    	}
    	
    	String valueStr = nodeName.substring(prefixSize, nodeName.length());
    	int value = Integer.parseInt(valueStr);
    	
    	suffixMonitorNames.remove(Integer.valueOf(value));
    	
    }
    
    /**
     * Check if a certain node is a current group member
     * 
     * @param subject   The identity of the node, as per its secure association with the Group Manager
     * @return   True if the node is a current member of the group, false otherwise
     */
    synchronized public boolean isGroupMember(final String subject) {

    	return this.identities2nodeNames.containsKey(subject);
    		
    }
    
    /**
     * Add a new group member - Note that the authentication credential has to be added separately
     * 
     * @param sid   The Sender ID of the new node. It is Null if the node is a monitor.
     * @param name   The node name of the new node.
     * @param roles   The role(s) of the new node, encoded in the AIF data model
     * @param subject   The node's identity based on the secure association with the GM
     * @return   True if the node is successfully added to the group, false otherwise
     */
    synchronized public boolean addGroupMember(final byte[] sid, final String name, final int roles, final String subject) {

    	// The node is a monitor
    	if (sid == null) {
    		if (roles != (1 << GroupcommParameters.GROUP_OSCORE_MONITOR))
    			return false;
    	}
    	// The node is not a monitor
    	else {
    		if (roles == (1 << GroupcommParameters.GROUP_OSCORE_MONITOR))
    			return false;
    		setGroupMemberRoles(sid, roles);
	    	setSenderIdToIdentity(subject, sid);
	    	
    	}
    	
    	this.identities2nodeNames.put(subject, name);
    	
    	CBORObject gidCbor = CBORObject.FromObject(getGroupId());
    	this.birthGIDs.put(name, gidCbor);
    	
    	return true;
    	
    }
    
    /**
     * Return the node name of the group member identified by the specified identity
     * 
     * @param subject   The identity of the node, as per its secure association with the Group Manager
     * 
     * @return The node name of the group member, of null if no member is found with the specified identity
     */
    synchronized public String getGroupMemberName(final String subject) {
    	
    	if (!this.identities2nodeNames.containsKey(subject))
    		return null;
    	
    	return this.identities2nodeNames.get(subject);
    	
    }
    
    /**
     * Return the identity of the group member identified by the specified identity
     * 
     * @param subject   The identity of the node, as per its secure association with the Group Manager
     * 
     * @return The current Sender ID of the group member as a CBOR byte string, of null if no member is found with the specified identity
     */
    synchronized public CBORObject getGroupMemberSenderId(final String subject) {
    	
    	if (!this.identities2senderIDs.containsKey(subject))
    		return null;
    	
    	return this.identities2senderIDs.get(subject);
    	
    }
    
    /**
     * 
     * @param subject   Associate a Sender Id to the specified identity of a group member
     *                  It has to be a valid and previously, consistently assigned Sender ID
     * 
     */
    synchronized public void setSenderIdToIdentity(final String subject, final byte[] sid) {
    	    	
    	// This overwrites a possible existing entry, if the group member has received a new Sender ID value
    	this.identities2senderIDs.put(subject, CBORObject.FromObject(sid));
    	
    }    
    
    /**
     * Return the Birth GID of the group member identified by the specified node name
     * 
     * @param senderId   The node name of the group member
     * 
     * @return The Birth GID of the Group Member, or null in case of error
     */
    synchronized public byte[] getBirthGid(final String nodeName) {
    
    	byte[] birthGid = null;
    	CBORObject birthGidCbor;
    	
    	birthGidCbor = birthGIDs.get(nodeName);
    	
    	if (birthGidCbor != null)
    		birthGid = birthGidCbor.GetByteString();
    	
    	return birthGid;
    	
    }
    
    /**
     * Remove the Birth GID of the group member identified by the specified node name
     * 
     * @param nodeName   The node name of the group member
     * 
     */
    synchronized public void deleteBirthGid(final String nodeName) {
    	
    	birthGIDs.remove(nodeName);
    	
    }
    
    
    
    /**
     * Return the roles of the group member identified by the specified node name
     * 
     * @param nodeName   The node name of the group member
     * 
     * @return The roles of the group member encoded in the AIF data model
     */
    synchronized public short getGroupMemberRoles(final String nodeName) {
    	
    	// First, check if the node is a monitor, based on the naming-schema
    	int prefixSize = prefixMonitorNames.length();
    	if (nodeName.length() > (prefixMonitorNames.length()) &&
    		nodeName.substring(0, prefixSize).equals(prefixMonitorNames)) {
    		
    		return 1 << GroupcommParameters.GROUP_OSCORE_MONITOR;
    		
    	}

    	// The node is not a monitor and has a Sender ID
    	byte[] sid = Utils.hexToBytes(nodeName.substring(nodeName.indexOf(this.nodeNameSeparator) + 1));
    	
    	return getGroupMemberRoles(sid);
    	
    }
    
    /**
     * 
     * @param sid   The Sender Id of a group member. It has to be a valid and previously, consistently assigned Sender ID                       
     * @param roles   The role(s) of the new node, encoded in the AIF data model
     */
    synchronized public void setGroupMemberRoles(final byte[] sid, final int roles) {
    	    	
    	// This overwrites a possible existing entry, if the group member has received a new Sender ID value
    	// Consider the inner map related to the size in bytes of the Sender ID
    	this.nodeRoles.get(sid.length - 1).put(Util.bytesToInt(sid), roles);
    	
    }   
    
    /**
     * Return the roles of the group member identified by the specified Sender ID
     * 
     * @param sid   The Sender ID of the group member
     * 
     * @return The roles of the group member, encoded in the AIF data model
     */
    synchronized public short getGroupMemberRoles(final byte[] sid) {
    	
    	return this.nodeRoles.get(sid.length - 1).get(Util.bytesToInt(sid)).shortValue();
    	
    }
        
    /**
     * Remove the group member identified by the specified identity
     * 
     * Note that the Sender ID is not deallocated, to ensure non-reassignment to future group members under
     * the same Group ID value. The relinquished Sender ID can be separately stored to be made available again
     * when changing the Group ID value following a group rekeying.
     * 
     * Note that this method does not delete the sub-resource associated to the removed group member.
     * The Group Manager has to separately do that _before_ invoking this method. 
     * 
     * @param subject   The node's identity based on the secure association with the GM 
     * @return True if an entry for the group member was found and removed, false otherwise
     */
    synchronized public boolean removeGroupMemberBySubject(final String subject) {
    	
    	if (!this.identities2nodeNames.containsKey(subject))
        		return false;
    	
    	if (getGroupMemberRoles((getGroupMemberName(subject))) != (1 << GroupcommParameters.GROUP_OSCORE_MONITOR)) {
    	
	    	byte[] sid = getGroupMemberSenderId(subject).GetByteString();
	    	
	    	if (!this.nodeRoles.get(sid.length - 1).containsKey(Util.bytesToInt(sid)))
	    		return false;
	    	
	    	this.nodeRoles.get(sid.length - 1).remove(Util.bytesToInt(sid));
	    	
	    	deleteAuthCred(sid);
	    	
	    	addStaleSenderId(sid);
	    	
    	}
    	
    	String nodeName = getGroupMemberName(subject);
    	this.birthGIDs.remove(nodeName);
    	
    	this.identities2nodeNames.remove(subject);
    	this.identities2senderIDs.remove(subject);
    	
    	return true;
    	
    }
    
    /**
     * Return the authentication credentials of the current group members
     * 
     * @return  The set of authentication credentials of the current group members. The authentication credentials
     * 			are provided as CBOR byte strings, with value the serialization of the authentication credentials
     * 			according to the format used in the group
     */
    synchronized public Map<CBORObject, CBORObject> getAuthCreds() {
    	
    	Map<CBORObject, CBORObject> authCreds = new HashMap<CBORObject, CBORObject>();
    	
    	// Go through each size of Sender ID, i.e. from 1 (i=0) to 4 (i=3) bytes
    	for (int i = 0; i < this.authCredRepo.size(); i++) {
    		
    		// Retrieve each authentication credential
    		for (Map.Entry<CBORObject, CBORObject> pair : authCredRepo.get(i).entrySet()) {
    			authCreds.put(pair.getKey(), pair.getValue());
    		}
    		
    	}
    	
    	return authCreds;
    	
    }
    
    /**
     * Return the authentication credential of the group member indicated by the provided Sender ID
     * 
     * @param sid   Sender ID of the group member associated to the authentication credential.
     * @return  a CBOR byte string, with value the serialization of the authentication credential
     * 			of the group member, according to the format used in the group
     */
    synchronized public CBORObject getAuthCred(final byte[] sid) {
    	
    	if (sid.length < 1 || sid.length > 4)
    		return null;
    	
    	return this.authCredRepo.get(sid.length - 1).get(CBORObject.FromObject(sid));
    	
    }
    
    /**
     *  Add the authentication credential 'cred' of the group member with Sender ID 'sid' to the authentication credential repo.
     * @param sid   Sender ID of the group member associated to the authentication credential.
     * @param key   A CBOR byte string, with value the serialization of the authentication credential of the group member,
     *              according to the format used in the group
     * @return  true if it worked, false if it failed
     */
    synchronized public boolean storeAuthCred(final byte[] sid, final CBORObject cred) {
    	
    	if (sid.length < 1 || sid.length > 4)
    		return false;
    	
    	if (cred.getType() != CBORType.ByteString)
    		return false;
    	
    	this.authCredRepo.get(sid.length - 1).put(CBORObject.FromObject(sid), cred);
    	
    	return true;
    	
    }
    

    /**
     *  Remove the authentication credential of the group member indicated by the provided Sender ID
     *  
     * @param sid   Sender ID of the group member associated to the authentication credential.
     * @return  True if the authentication credential was found and removed, false otherwise
     */
    synchronized public boolean deleteAuthCred(final byte[] sid) {
    	
    	if (sid.length < 1 || sid.length > 4)
    		return false;
    	
    	if (!this.authCredRepo.get(sid.length - 1).containsKey(CBORObject.FromObject(sid)))
    		return false;
    	
    	this.authCredRepo.get(sid.length - 1).remove(CBORObject.FromObject(sid));
    	
    	return true;
    	
    }
    
    /**
     *  Return the maximum number of stale Sender ID sets
	 *
	 *  @return  the maximum number of stale Sender ID sets
     */
    synchronized public int getMaxStaleIdsSets() {
    	
    	return this.maxStaleIdsSets;
    	
    }
    
    /**
     *  Set the maximum number of stale Sender ID sets
	 *
	 *  @param maxStaleIdsSets   the maximum number of stale Sender ID sets
     */
    synchronized public void setMaxStaleIdsSets(int maxStaleIdsSets) {
    	
    	this.maxStaleIdsSets = maxStaleIdsSets;
    	
    }
    
    
    /**
     *  Return the current version of the symmetric keying material
	 *
	 *  @return  an integer indicating the current version of the symmetric keying material
     */
    synchronized public int getVersion() {
    	
    	return this.version;
    	
    }
    
    /**
     *  Increment the version of the symmetric keying material 
	 *
     */
    synchronized public void incrementVersion() {
    	
    	this.version++;
    	
    }
    
    /**
     *  Return the group policies
	 *
	 *  @return  a CBOR map including the group policies
     */
    synchronized public CBORObject getGroupPolicies() {
    	
    	return this.groupPolicies;
    	
    }

    /**
     *  Set the group policies
	 *
	 *  @param groupPolicies   a CBOR map including the group policies
     */
    synchronized public void setGroupPolicies(final CBORObject groupPolicies) {
    	
    	this.groupPolicies = groupPolicies;
    	
    }
    
    /**
     *  Return the Hash Algorithm used to compute the Request Hash for OSCORE Deterministic Requests (or 0, if not supported
	 *
	 *  @return  the Hash Algorithm used to compute the Request Hash for OSCORE Deterministic Requests (or 0, if not supported)
     */
    synchronized public int getDetHashAlg() {
    	
    	return this.detHashAlg;
    	
    }
    
    /**
     *  Set the Hash Algorithm used to compute the Request Hash for OSCORE Deterministic Requests (or 0, if not supported)
     *  
     *  @param detHashAlg  the new Hash Algorithm to use to compute the Request Hash for OSCORE Deterministic Requests
     *  
     */
    synchronized public void setDetHashAlg(final int detHashAlg) {
    	
    	if ((this.detHashAlg == 0) && (detHashAlg != 0) && (this.detClientSenderID == null)) {
    		// This update is enabling the use of Cacheable OSCORE for the first time.
    		// Hence, the Group Manager allocates the Sender ID of the Deterministic Client
    		this.detClientSenderID = allocateSenderId();
    	}
    	this.detHashAlg = detHashAlg;
    	
    }
    
    /**
     *  Return the Sender ID of the Deterministic Client used for Cacheable OSCORE
	 *
	 *  @return  the Sender ID of the Deterministic Client, or null if Cacheable OSCORE is not supported
     */
    synchronized public byte[] getDetClientSenderId() {
    	
    	return this.detClientSenderID;
    	
    }
    
    /**
     *  Return the current size of new Sender IDs to assign
	 *
	 *  @return  an integer with the current size of new Sender IDs to assign 
     */
    synchronized public int getSenderIdSize() {
    	
    	return this.senderIdSize;
    	
    }
    
    /**
     *  Return the separator used between the two components of a node name of a non-monitor member
	 *
	 *  @return  a string with the separator used between the two components of a node name of a non-monitor member
     */
    synchronized public String getNodeNameSeparator() {
    	
    	return this.nodeNameSeparator;
    	
    }

    /**
     *  Return the current amount of sets of stale Sender IDs
     *  
     *  @return  The current amount of sets of stale Sender IDs 
     */
    synchronized public int getNumberOfStaleSenderIdsSet() {
    	
    	return this.staleSenderIds.size();
    	
    }
    
    /**
     *  Return one aggregated set including the Sender IDs that have become stale starting from
     *  the version of the symmetric keying material specified as argument  
     *  
     *  @param   The version of the symmetric keying material starting from which stale Sender IDs have to be considered
     *  @return  The aggregated set of stale Sender IDs, or null in case of error
     */
    synchronized public Set<CBORObject> getStaleSenderIds(final int baselineVersion) {
    	
    	if (baselineVersion < 0 || baselineVersion > this.version)
    		return null;
    	
    	Set<CBORObject> ret = new HashSet<CBORObject>();
    	
    	for (Integer i : this.staleSenderIds.keySet()) {
    		
    		if (i.intValue() < baselineVersion) {
    			// Skip this set of stale Sender IDs
    			continue;
    		}
    		
    		for (CBORObject obj : this.staleSenderIds.get(i)) {
    			ret.add(obj);
    		}
    	}
    	
    	return ret;
    	
    }
    
        
    /**
     *  Add a Sender ID as stale to the set associated with the current version of the symmetric keying material
     *  
     *  @param senderId   The Sender ID to add to the set associated with the current version of the symmetric keying material
     *  @return  True if the addition was successful, or false otherwise
     */
    synchronized public boolean addStaleSenderId(byte[] senderId) {
    	
    	if (senderId == null) {
    		return false;
    	}
    	
    	if (!this.staleSenderIds.containsKey(Integer.valueOf(version))) {
    		// This should never happen
    		return false;
    	}
    	
    	this.staleSenderIds.get(Integer.valueOf(version)).add(CBORObject.FromObject(senderId));
    	return true;
    	
    }
    
    /**
     *  Add a new empty set of stale Senders IDs associated with the current version of the symmetric keying material
     *  
     *  @return  True if the addition was successful, or false otherwise
     */
    synchronized public boolean addStaleSenderIdSet() {
    	
    	if (this.staleSenderIds.size() == getMaxStaleIdsSets()) {
    		// This should never happen. In case the collection of set reaches its maximum size,
    		// the oldest set has to be deleted before rekeying the group, and a new empty set is added
    		return false;
    	}
    	
    	if (this.staleSenderIds.put(Integer.valueOf(version), new HashSet<CBORObject>()) == null)
    		return true;
    	
    	return false;

    }
    
    /**
     *  Remove the oldest set of stale Senders IDs, where the collection of set has reached its maximum size
     *  
     *  @return  True if the removal was successful, or false otherwise
     */
    synchronized public boolean removeStaleSenderIdOldestSet() {

    	if (this.staleSenderIds.size() != getMaxStaleIdsSets()) {
    		// This should never happen. This method should be called only when
    		// the current size of the collection of sets has reached its maximum size
    		return false;
    	}
    	
    	int index = this.version - getMaxStaleIdsSets() + 1;
    	if (this.staleSenderIds.remove(Integer.valueOf(index)) != null)
    		return true;
    	
    	return false;
    	
    }
    
    /**
     *  Get the key length (in bytes) for the Group Encryption Algorithm used in the group
     * @return  the key length (in bytes) for the Group Encryption Algorithm
     */
	private int getKeyLengthGroupEncryptionAlgorithm() {

		int keyLength = 0;
	    
		if (this.gpEncAlg != null && this.mode != GroupcommParameters.GROUP_OSCORE_PAIRWISE_MODE_ONLY) {
		
			if (this.gpEncAlg == AlgorithmID.AES_CCM_16_64_128 || this.gpEncAlg == AlgorithmID.AES_CCM_16_128_128 ||
				this.gpEncAlg == AlgorithmID.AES_CCM_64_64_128 || this.gpEncAlg == AlgorithmID.AES_CCM_64_128_128 )
				keyLength = 16;
			
			if (this.gpEncAlg == AlgorithmID.AES_CCM_16_64_256 || this.gpEncAlg == AlgorithmID.AES_CCM_16_128_256 ||
				this.gpEncAlg == AlgorithmID.AES_CCM_64_64_256 || this.gpEncAlg == AlgorithmID.AES_CCM_64_128_256 )
					keyLength = 32;
		
		}
	    
	    return keyLength;
		
	}
    
}
