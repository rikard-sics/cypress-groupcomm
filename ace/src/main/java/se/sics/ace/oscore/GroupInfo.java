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
import org.eclipse.californium.cose.OneKey;
import net.i2p.crypto.eddsa.Utils;
import se.sics.ace.Util;
import se.sics.ace.Constants;
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
	private byte[] groupEncryptionKey = null;
	private AlgorithmID hkdf = null;
	private int authCredFormat; // the format of authentication credentials used in the group
	
	// Each set of the list refers to a different size of Sender IDs.
	// The element with index 0 includes as elements Sender IDs with size 1 byte.
	private List<Set<Integer>> usedSenderIds = new ArrayList<Set<Integer>>();
	
	private int senderIdSize; // Size in bytes of the byte array representation of Sender IDs 
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
	
	private final int groupIdPrefixSize; // Prefix size (bytes), same for every Group ID on the same Group Manager
	private byte[] groupIdPrefix;
	
	private final String prefixMonitorNames; // Initial part of the node name for monitors, since they do not have a Sender ID
	
	private final String nodeNameSeparator; // For non-monitor members, separator between the two components of the node name
	
	// Each element of the set is an allocated variable part of the node name for monitors, since they do not have a Sender ID
	private Set<Integer> suffixMonitorNames = new HashSet<Integer>();
	
	private int groupIdEpochSize; // Epoch size (bytes) in the {Prefix ; Epoch} Group ID
	private int maxGroupIdEpochValue;
	private int groupIdEpoch;
	
	private int mode; // The mode(s) of operation used in the group (group only / group+pairwise / pairwise only)
	
	// Specific to the group mode
	private AlgorithmID signEncAlg = null;
	private AlgorithmID signAlg = null;
	private CBORObject signParams = null;

	// Specific to the pairwise mode
	private AlgorithmID alg = null;
	private AlgorithmID ecdhAlg = null;
	private CBORObject ecdhParams = null;
	
	private CBORObject groupPolicies = null;
	
	private int version; // Version of the current symmetric keying material
	private boolean status; // True if the group is currently active, false otherwise
	
	private OneKey gmKeyPair;   // The asymmetric key pair of the Group Manager, as a OneKey object
	private byte[] gmAuthCred;  // The serialization of the authentication credential of the Group Manager, in the format used in the group
	
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
	 * @param prefixMonitorNames  the prefix string used to build the name of a group member acting as monitor.
	 * @param nodeNameSeparator   the string separator used to build the name of a group member non acting as monitor.
	 * @param hkdf                the HKDF Algorithm.
	 * @param credFmt             the format of the authentication credentials used in the OSCORE group.
	 * @param mode			      the mode(s) of operation used in the group (group only / group+pairwise / pairwise only)
	 * @param signEncAlg          the Signature Encryption Algorithm if the group mode is used, or null otherwise
	 * @param signAlg             the Signature Algorithm if the group mode is used, or null otherwise
	 * @param signParams          the parameters of the Signature Algorithm if the group mode is used, or null otherwise
	 * @param alg                 the AEAD algorithm if the pairwise mode is used, or null otherwise
	 * @param ecdhAlg             the Pairwise Key Agreement Algorithm if the pairwise mode is used, or null otherwise
	 * @param ecdhParams          the parameters of the Pairwise Key Agreement Algorithm if the pairwise mode is used, or null otherwise
	 * @param groupPolicies		  the map of group policies, or Null for building one with default values
	 * @param gmKeyPair           the asymmetric key pair of the Group Manager
	 * @param gmAuthCred		  the serialization of the authentication credential of the Group Manager, in the format used in the group
	 */
    public GroupInfo(final String groupName,
    				 final byte[] masterSecret,
    				 final byte[] masterSalt,
    				 final int groupIdPrefixSize,
    		         final byte[] groupIdPrefix,
    		         final int groupIdEpochSize,
    		         final int groupIdEpoch,
    		         final String prefixMonitorNames,
    		         final String nodeNameSeparator,
    		         final AlgorithmID hkdf,
    		         final int authCredFormat,
    		         final int mode,
    		         final AlgorithmID signEncAlg,
    		         final AlgorithmID signAlg,
    		         final CBORObject signParams,
    		         final AlgorithmID alg,
    		         final AlgorithmID ecdhAlg,
    		         final CBORObject ecdhParams,
    		         final CBORObject groupPolicies,
    		         final OneKey gmKeyPair,
    		         final byte[] gmAuthCred) {
    	
    	this.version = 0;
    	this.status = false;
    	
    	setGroupName(groupName);
    	
    	setHkdf(hkdf);
    	setMasterSecret(masterSecret);
    	setMasterSalt(masterSalt);
    	
    	this.groupIdPrefixSize = groupIdPrefixSize;
    	setGroupIdPrefix(groupIdPrefix);
    	setGroupIdEpoch(groupIdEpochSize, groupIdEpoch);
    	
    	this.mode = mode;
    	this.authCredFormat = authCredFormat;
    	this.prefixMonitorNames = prefixMonitorNames;
    	this.nodeNameSeparator = nodeNameSeparator;
    	
    	// The group mode is used
    	if (mode != Constants.GROUP_OSCORE_PAIRWISE_MODE_ONLY) {
    		setSignEncAlg(signEncAlg);
	    	setSignAlg(signAlg);
	    	setSignParams(signParams);
	    	setGroupEncryptionKey();
    	}
    	
    	// The pairwise mode is used
    	if (mode != Constants.GROUP_OSCORE_GROUP_MODE_ONLY) {
    		setAlg(alg);
	    	setEcdhAlg(ecdhAlg);
	    	setEcdhParams(ecdhParams);
    	}
    	
    	this.senderIdSize = 1;
    	this.maxSenderIdValue = 255;
    	
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
        	defaultGroupPolicies.Add(Constants.POLICY_KEY_CHECK_INTERVAL, CBORObject.FromObject(3600));
        	defaultGroupPolicies.Add(Constants.POLICY_EXP_DELTA, CBORObject.FromObject(0));
        	this.groupPolicies = defaultGroupPolicies;
    	}
    	
    	this.gmKeyPair = gmKeyPair;
    	this.gmAuthCred = gmAuthCred;
    	
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
     *  Retrieve the OSCORE Group Encryption Key
     * @return  the Group Encryption Key, or null in case of error
     */
    synchronized public final byte[] getGroupEncryptionKey() {
    	
    	if (this.groupEncryptionKey == null || this.mode == Constants.GROUP_OSCORE_PAIRWISE_MODE_ONLY)
    		return null;
    	
    	byte[] myArray = new byte[this.groupEncryptionKey.length];
    	System.arraycopy(this.groupEncryptionKey, 0, myArray, 0, this.groupEncryptionKey.length);
    	return myArray;
    	
    }
    
    /**
     * Set the OSCORE Group Encryption Key
     * 
     */
    synchronized public void setGroupEncryptionKey() {
    	
    	CBORObject info = CBORObject.NewArray();
    	
    	 // 'id'
    	byte[] emptyArray = new byte[0];
    	info.Add(emptyArray);
    	
    	// 'id_context'
    	info.Add(getGroupId());
    	
    	// 'alg_aead'
    	if (this.getSignEncAlg().AsCBOR().getType() == CBORType.Integer)
        	info.Add(this.getSignEncAlg().AsCBOR().AsInt32());
    	if (this.getSignEncAlg().AsCBOR().getType() == CBORType.TextString)
        	info.Add(this.getSignEncAlg().AsCBOR().AsString());
    	
    	// 'type'
    	info.Add("Group Encryption Key");
    	
    	// 'L'
    	int L = getKeyLengthSignatureEncryptionAlgorithm();
    	info.Add(L);
    	
    	try {
			this.groupEncryptionKey = Hkdf.extractExpand(getMasterSalt(), getMasterSecret(), info.EncodeToBytes(), L);
		} catch (InvalidKeyException e) {
			System.err.println("Error when deriving the Group Encryption Key: " + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Error when deriving the Group Encryption Key: " + e.getMessage());
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
     * @return the Signature Encryption Algorithm used in the group for the group mode
     */
    synchronized public final AlgorithmID getSignEncAlg() {
    	
    	return this.signEncAlg;
    	
    }
    
    /**
     *  Set the Signature Encryption Algorithm used in the group for the group mode
     * @param signEncAlg
     */
    synchronized public void setSignEncAlg(final AlgorithmID signEncAlg) {
    	
    	if (signEncAlg == null)
			this.signEncAlg = AlgorithmID.AES_CCM_16_64_128;
    	else
    		this.signEncAlg = signEncAlg;
    	
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
     * @return format of the authentication credentials used in the group
     */
    synchronized public final int getAuthCredFormat() {
    	
    	return this.authCredFormat;
    	
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
     * Find the first available Sender ID value and allocate it.
     * @return  the allocated Sender ID value as a byte array, or null if all values are used.
     */
    synchronized public byte[] allocateSenderId() {
    	
    	// All the possible values for the Sender IDs with this size have been allocated.
    	// Switch to the next size, up to 4 bytes, and update the maximum Sender ID value.
    	if (this.usedSenderIds.get(this.senderIdSize - 1).size() == (this.maxSenderIdValue + 1)) {
	    		this.senderIdSize++;
	    
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
    		if (roles != (1 << Constants.GROUP_OSCORE_MONITOR))
    			return false;
    	}
    	// The node is not a monitor
    	else {
    		if (roles == (1 << Constants.GROUP_OSCORE_MONITOR))
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
    		
    		return 1 << Constants.GROUP_OSCORE_MONITOR;
    		
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
    	
    	if (getGroupMemberRoles((getGroupMemberName(subject))) != (1 << Constants.GROUP_OSCORE_MONITOR)) {
    	
	    	byte[] sid = getGroupMemberSenderId(subject).GetByteString();
	    	
	    	if (!this.nodeRoles.get(sid.length - 1).containsKey(Util.bytesToInt(sid)))
	    		return false;
	    	
	    	this.nodeRoles.get(sid.length - 1).remove(Util.bytesToInt(sid));
	    	
	    	deleteAuthCred(sid);
	    	
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
     *  Return the current size of new Sender IDs to assign
	 *
	 *  @return  an integer with the current size of new Sender IDs to assign 
     */
    synchronized public int getSenderIdSize() {
    	
    	return this.senderIdSize;
    	
    }

    /**
     *  Get the key length (in bytes) for the Signature Encryption Algorithm used in the group
     * @return  the key length (in bytes) for the Signature Encryption Algorithm
     */
	private int getKeyLengthSignatureEncryptionAlgorithm() {

		int keyLength = 0;
	    
		if (this.signEncAlg != null && this.mode != Constants.GROUP_OSCORE_PAIRWISE_MODE_ONLY) {
		
			if (this.signEncAlg == AlgorithmID.AES_CCM_16_64_128 || this.signEncAlg == AlgorithmID.AES_CCM_16_128_128 ||
				this.signEncAlg == AlgorithmID.AES_CCM_64_64_128 || this.signEncAlg == AlgorithmID.AES_CCM_64_128_128 )
				keyLength = 16;
			
			if (this.signEncAlg == AlgorithmID.AES_CCM_16_64_256 || this.signEncAlg == AlgorithmID.AES_CCM_16_128_256 ||
				this.signEncAlg == AlgorithmID.AES_CCM_64_64_256 || this.signEncAlg == AlgorithmID.AES_CCM_64_128_256 )
					keyLength = 32;
		
		}
	    
	    return keyLength;
		
	}
    
}
