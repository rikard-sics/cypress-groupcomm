package se.sics.ace;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.Response;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.cose.KeyKeys;
import org.eclipse.californium.cose.OneKey;
import net.i2p.crypto.eddsa.Utils;
import se.sics.ace.rs.TokenRepository;

public class Util {

    /**
     *  Convert a positive integer into a byte array of minimal size.
     *  The positive integer can be up to 2,147,483,647
     * @param num
     * @return  the byte array
     */
    public static byte[] intToBytes(final int num) {
    	return intToBytes(num, 0);
    }
	
    /**
     *  Convert a positive integer into a byte array of the specified length (in bytes).
     *  If the specified length is 0, the byte array will be of minimal size.
     *  The positive integer can be up to 2,147,483,647
     * @param num
     * @param length
     * @return  the byte array
     */
    public static byte[] intToBytes(final int num, final int length) {

    	byte[] ret = null;
    	
    	// Big-endian
    	if (num < 0 || length < 0)
    		return null;
        else if (num < 256) {
            ret = new byte[] { (byte) (num) };
        } else if (num < 65536) {
        	ret = new byte[] { (byte) (num >>> 8), (byte) num };
        } else if (num < 16777216) {
        	ret = new byte[] { (byte) (num >>> 16), (byte) (num >>> 8), (byte) num };
        } else { // up to 2,147,483,647
        	ret = new byte[]{ (byte) (num >>> 24), (byte) (num >>> 16), (byte) (num >>> 8), (byte) num };
        }
    	
    	// Little-endian
    	/*
    	if (num < 0)
    		return null;
        else if (num < 256) {
            ret = new byte[] { (byte) (num) };
        } else if (num < 65536) {
            ret = new byte[] { (byte) num, (byte) (num >>> 8) };
        } else if (num < 16777216){
            ret = new byte[] { (byte) num, (byte) (num >>> 8), (byte) (num >>> 16) };
        } else{ // up to 2,147,483,647
            ret = new byte[] { (byte) num, (byte) (num >>> 8), (byte) (num >>> 16), (byte) (num >>> 24) };
        }
    	*/
    	
    	if (length == 0 || length <= ret.length)
    		return ret;
    	
    	int paddingLength = length - ret.length;
    	byte[] retWithPadding = new byte[ret.length + paddingLength];
    	
    	// Big-endian
    	for (int i = 0; i < paddingLength; i++)
    		retWithPadding[i] = (byte) 0x00;
    	for (int i = 0; i < ret.length; i++)
    		retWithPadding[i + paddingLength] = ret[i];
    	
    	// Little-endian
    	/*
    	for (int i = 0; i < ret.length; i++)
    		retWithPadding[i] = ret[i];
    	for (int i = 0; i < paddingLength; i++)
    		retWithPadding[i + paddingLength] = (byte) 0x00;
    	*/
    	
    	return retWithPadding;
    	
    }
	
    /**
     * Convert a byte array into an equivalent unsigned integer.
     * The input byte array can be up to 4 bytes in size.
     *
     * N.B. If the input array is 4 bytes in size, the returned integer may be negative!
     *      The calling method has to check, if relevant!
     * 
     * @param bytes 
     * @return   the converted integer
     */
    public static int bytesToInt(final byte[] bytes) {
    	
    	if (bytes.length > 4)
    		return -1;
    	
    	int ret = 0;

    	// Big-endian
    	for (int i = 0; i < bytes.length; i++)
    		ret = ret + (bytes[bytes.length - 1 - i] & 0xFF) * (int) (Math.pow(256, i));

    	/*
    	// Little-endian
    	for (int i = 0; i < bytes.length; i++)
    		ret = ret + (bytes[i] & 0xFF) * (int) (Math.pow(256, i));
    	*/
    	
    	return ret;
    	
    }
	
    /**
     * Build the "psk_identity" to use in the
     * ClientKeyExchange DTLS Handshake message
     *  
     * @param kid   The 'kid' of the key used as PoP key
     * 
     * @return The "psk_identity" to use in the DTLS Handshake
     */
	public static byte[] buildDtlsPskIdentity(byte[] kid) {
        
        CBORObject identityMap = CBORObject.NewMap();
        CBORObject cnfMap = CBORObject.NewMap();
        CBORObject coseKeyMap = CBORObject.NewMap();
        
        coseKeyMap.Add(CBORObject.FromObject(KeyKeys.KeyType.AsCBOR()), KeyKeys.KeyType_Octet);
        coseKeyMap.Add(CBORObject.FromObject(KeyKeys.KeyId.AsCBOR()), kid);
        cnfMap.Add(Constants.COSE_KEY_CBOR, coseKeyMap);
        identityMap.Add(CBORObject.FromObject(Constants.CNF), cnfMap);
        
        // The serialized identity map to use as "psk_identity" in DTLS
        return identityMap.EncodeToBytes();
		
	}
	
    /**
     * Compute a digital signature
     * 
     * @param signKeyCurve   Elliptic curve used to compute the signature
     * @param privKey  private key of the signer, used to compute the signature
     * @param dataToSign  content to sign
     * @return The computed signature, or null in case of error
     
     */
    public static byte[] computeSignature(int signKeyCurve, PrivateKey privKey, byte[] dataToSign) {

        Signature signCtx = null;
        byte[] signature = null;

        try {
     	   if (signKeyCurve == KeyKeys.EC2_P256.AsInt32())
     		  signCtx = Signature.getInstance("SHA256withECDSA");
     	   else if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32())
     		  signCtx = Signature.getInstance("NonewithEdDSA", "EdDSA");
     	   else {
     		  // At the moment, only ECDSA (EC2_P256) and EDDSA (Ed25519) are supported
     		  System.err.println("Unsupported signature algorithm");
     		  return null;
     	   }
            
        }
        catch (NoSuchAlgorithmException e) {
            System.err.println("Unsupported signature algorithm: " + e.getMessage());
            return null;
        }
        catch (NoSuchProviderException e) {
            System.err.println("Unsopported security provider for signature computing: " + e.getMessage());
            return null;
        }
        
        try {
            if (signCtx != null)
            	signCtx.initSign(privKey);
            else {
                System.err.println("Signature algorithm has not been initialized");
                return null;
            }
        }
        catch (InvalidKeyException e) {
            System.err.println("Invalid key excpetion - Invalid private key: " + e.getMessage());
            return null;
        }
        
        try {
        	if (signCtx != null) {
        		signCtx.update(dataToSign);
        		signature = signCtx.sign();
        	}
        } catch (SignatureException e) {
            System.err.println("Failed signature computation: " + e.getMessage());
            return null;
        }
        
        return signature;
        
    }
    
    /**
     * Verify the correctness of a digital signature
     * 
     * @param signKeyCurve   Elliptic curve used to process the signature
     * @param pubKey   Public key of the signer, used to verify the signature
     * @param signedData   Data over which the signature has been computed
     * @param expectedSignature   Signature to verify
     * @return True if the signature verifies correctly, false otherwise
     */
    public static boolean verifySignature(int signKeyCurve, PublicKey pubKey, byte[] signedData, byte[] expectedSignature) {

        Signature signature = null;
        boolean success = false;
        
        try {
           if (signKeyCurve == KeyKeys.EC2_P256.AsInt32())
        	   signature = Signature.getInstance("SHA256withECDSA");
           else if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32())
        	   signature = Signature.getInstance("NonewithEdDSA", "EdDSA");
           else {
              System.err.println("Unsupported signature algorithm");
              return false;
           }
             
         }
         catch (NoSuchAlgorithmException e) {
             System.err.println("Unsupported signature algorithm: " + e.getMessage());
             return false;
         }
         catch (NoSuchProviderException e) {
             System.err.println("Unsopported security provider for signature computing: " + e.getMessage());
             return false;
         }
         
         try {
             if (signature != null)
            	 signature.initVerify(pubKey);
             else {
                 System.err.println("Signature algorithm has not been initialized");
                 return false;
             }
         }
         catch (InvalidKeyException e) {
             System.err.println("Invalid key excpetion - Invalid public key: " + e.getMessage());
             return false;
         }
         
         try {
        	 signature.update(signedData);
             success = signature.verify(expectedSignature);
         } catch (SignatureException e) {
             System.err.println("Error during signature verification: " + e.getMessage());
             return false;
         }
         
         return success;

    }
    
    /**
     * Return the cryptographic curve to use for a Signature Algorithm or for a Pairwise Key Agreement Algorithm
     * in an OSCORE group, depending on whether the group uses the group mode or not, respectively
     * 
     * @param parameters   A CBOR Map, specifying the parameters for a Signature Algorithm or
     *                     for a Pairwise Key Agreement Algorithm to use in an OSCORE group
     * 
     * @return The cryptographic curve, as a CBOR Object with value an integer, or null in case of error
     */
    public static CBORObject retrieveCurve(final CBORObject parameters) {
    	
    	CBORObject curve = null;
    	
    	CBORObject keyType = parameters.get(0).get(0);
    	
    	if (keyType == null) {
    		return null;
    	}
		if (keyType.equals(org.eclipse.californium.cose.KeyKeys.KeyType_OKP)
				|| keyType.equals(org.eclipse.californium.cose.KeyKeys.KeyType_EC2)) {
    		curve = parameters.get(1).get(1);
    	}
    	
    	return curve;
    	
    }
    
    /**
     * Return the asymmetric key pair of the Group Manager to use, as a OneKey object
     * 
     * @param gmSigningKeyPairs   Asymmetric key pairs of the Group Manager, to be used for signing operations.
     *                            The map key is the cryptographic curve; the map value is the hex string of the key pair
     * @param gmKeyAgreementKeyPairs   Asymmetric key pairs of the Group Manager, to be used for key agreement operations.
     *                                 The map key is the cryptographic curve; the map value is the hex string of the key pair
     * @param useGroupMode   True if the OSCORE group uses the group mode, or false otherwise
     * @param parameters   A CBOR Map, specifying the parameters for the Signature Algorithm or
     *                     for the Pairwise Key Agreement Algorithm, depending on 'useGroupMode'
     *                     being True of False, respectively
     * 
     * @return The asymmetric key pair of the Group Manager to use, or null in case of error
     */
    public static OneKey retrieveGmKeyPair(final Map<CBORObject, String> gmSigningKeyPairs,
    								       final Map<CBORObject, String> gmKeyAgreementKeyPairs,
    							     	   final boolean useGroupMode,
    								       final CBORObject parameters) {
    	
    	OneKey gmKeyPair = null;
    	
    	// Serialization of the COSE Key including both private and public part
    	byte[] gmKeyPairBytes = null;
    	
    	CBORObject curve = retrieveCurve(parameters);
    	
    	if (curve == null) {
    		// This should never happen
    		return null;
    	}

    	if (useGroupMode) {
    		// This group uses the group mode, thus the authentication credential
    		// of the Group Manager has to be specific for signing operations
			if (curve.AsInt32() == org.eclipse.californium.cose.KeyKeys.EC2_P256.AsInt32()) {
				gmKeyPairBytes = Utils.hexToBytes(gmSigningKeyPairs.get(org.eclipse.californium.cose.KeyKeys.EC2_P256));
    		}
			if (curve.AsInt32() == org.eclipse.californium.cose.KeyKeys.OKP_Ed25519.AsInt32()) {
				gmKeyPairBytes = Utils
						.hexToBytes(gmSigningKeyPairs.get(org.eclipse.californium.cose.KeyKeys.OKP_Ed25519));
    		}
    	}
    	else {
    		// This group uses only the pairwise mode, thus the authentication credential
    		// of the Group Manager has to be specific for key agreement operations
			if (curve.AsInt32() == org.eclipse.californium.cose.KeyKeys.EC2_P256.AsInt32()) {
				gmKeyPairBytes = Utils
						.hexToBytes(gmKeyAgreementKeyPairs.get(org.eclipse.californium.cose.KeyKeys.EC2_P256));
    		}
			if (curve.AsInt32() == org.eclipse.californium.cose.KeyKeys.OKP_X25519.AsInt32()) {
				gmKeyPairBytes = Utils
						.hexToBytes(gmKeyAgreementKeyPairs.get(org.eclipse.californium.cose.KeyKeys.OKP_X25519));
    		}
    	}
    	    	
    	try {
			gmKeyPair = new OneKey(CBORObject.DecodeFromBytes(gmKeyPairBytes));
		} catch (CoseException e) {
			e.printStackTrace();
    		return null;
		}
    	
    	return gmKeyPair;
    	
    }
    
    /**
     * Return the authentication credential of the Group Manager to use, as a byte array
     * 
     * @param credFmt                   The format of public authentication credentials used in the OSCORE group 
     * @param gmSigningPublicAuthCred   The public authentication credentials of the Group Manager,
     *                                  including a public key to be used for key agreement operations.
     *                                  For the outer map, the map key is the type of authentication credential.
     *                                  For the inner map, the map key is the cryptographic curve,
     *                                  while the map value is the hex string of the authentication credential
     * @param gmKeyAgreementPublicAuthCred   The public authentication credentials of the Group Manager,
     *                                       including a public key to be used for key agreement operations.
     *                                       For the outer map, the map key is the type of authentication credential.
     *                                       For the inner map, the map key is the cryptographic curve,
     *                                       while the map value is the hex string of the authentication credential
     * @param useGroupMode   True if the OSCORE group uses the group mode, or false otherwise
     * @param parameters   A CBOR Map, specifying the parameters for the Signature Algorithm or
     *                     for the Pairwise Key Agreement Algorithm, depending on 'useGroupMode'
     *                     being True of False, respectively
     * 
     * @return The authentication credential of the Group Manager to use, or null in case of error
     */
    public static byte[] retrieveGmAuthCred(final int credFmt, 
    								        final Map<Integer,  Map<CBORObject, String>> gmSigningPublicAuthCred,
    								        final Map<Integer,  Map<CBORObject, String>> gmKeyAgreementPublicAuthCred,
    								        final boolean useGroupMode,
    								        final CBORObject parameters) {
    	
    	byte[] gmAuthCred = null;
    	
    	CBORObject curve = retrieveCurve(parameters);
    	
    	if (curve == null) {
    		// This should never happen
    		return null;
    	}
    	
    	// Build the authentication credential according to the format used in the group
    	switch (credFmt) {
	        case Constants.COSE_HEADER_PARAM_KCCS:
	            // A CCS including the public key
			if (curve.AsInt32() == org.eclipse.californium.cose.KeyKeys.EC2_P256.AsInt32()) {
	        		if (useGroupMode) {
					gmAuthCred = Utils.hexToBytes(gmSigningPublicAuthCred.get(Constants.COSE_HEADER_PARAM_KCCS)
							.get(org.eclipse.californium.cose.KeyKeys.EC2_P256));
		        		// gmAuthCred = Utils.hexToBytes("A2026008A101A50102032620012158202236658CA675BB62D7B24623DB0453A3B90533B7C3B221CC1C2C73C4E919D540225820770916BC4C97C3C46604F430B06170C7B3D6062633756628C31180FA3BB65A1B");
	        		}
	        		else {
					gmAuthCred = Utils.hexToBytes(gmKeyAgreementPublicAuthCred.get(Constants.COSE_HEADER_PARAM_KCCS)
							.get(org.eclipse.californium.cose.KeyKeys.EC2_P256));
	        		}		
	        	}
			if (curve.AsInt32() == org.eclipse.californium.cose.KeyKeys.OKP_Ed25519.AsInt32()) {
				gmAuthCred = Utils.hexToBytes(gmSigningPublicAuthCred.get(Constants.COSE_HEADER_PARAM_KCCS)
						.get(org.eclipse.californium.cose.KeyKeys.OKP_Ed25519));
	        		// gmAuthCred = Utils.hexToBytes("A2026008A101A4010103272006215820C6EC665E817BD064340E7C24BB93A11E8EC0735CE48790F9C458F7FA340B8CA3");
	        	}
			if (curve.AsInt32() == org.eclipse.californium.cose.KeyKeys.OKP_X25519.AsInt32()) {
				gmAuthCred = Utils.hexToBytes(gmKeyAgreementPublicAuthCred.get(Constants.COSE_HEADER_PARAM_KCCS)
						.get(org.eclipse.californium.cose.KeyKeys.OKP_X25519));
	        	}
	            break;
	        case Constants.COSE_HEADER_PARAM_KCWT:
	            // A CWT including the public key
	            // TODO
	        	gmAuthCred = null;
	            break;
	        case Constants.COSE_HEADER_PARAM_X5CHAIN:
	            // A certificate including the public key
	            // TODO
	        	gmAuthCred = null;
	            break;
    	}
    	
    	return gmAuthCred;
    	
    }
    
    /**
     * Add 'newRole' to the role set, encoded using the AIF-OSCORE-GROUPCOMM data model
     * 
     * @param currentRoleSet  the current set of roles
     * @param newRole  the role to add to the current set
     * 
      * @return  the updated role set
      * @throws AceException  if the role identifier is less than 1
     */
    public static int addGroupOSCORERole (int currentRoleSet, short newRole) throws AceException {

   	 if (newRole < 1) throw new AceException("Invalid identifier of Group OSCORE role");
   	 
   	 int updatedRoleSet = 0;
   	 updatedRoleSet = currentRoleSet | (1 << newRole);
   	 
   	 return updatedRoleSet; 
   	 
    }
    
    /**
     * Remove 'oldRole' from the role set, encoded using the AIF-OSCORE-GROUPCOMM data model
     * 
     * @param currentRoleSet  the current set of roles
     * @param oldRole  the role to remove from the current set
     * 
      * @return  the updated role set
      * @throws AceException  if the role identifier is less than 1
     */
    public static int removeGroupOSCORERole (int currentRoleSet, short oldRole) throws AceException {

   	 if (oldRole < 1) throw new AceException("Invalid identifier of Group OSCORE role");
   	 
   	 int updatedRoleSet = 0;
   	 updatedRoleSet = currentRoleSet & (~(1 << oldRole));
   	 
   	 return updatedRoleSet; 
   	 
    }
       
    /**
     * Check if a role set includes a specified role, encoded using the AIF-OSCORE-GROUPCOMM data model
     * 
     * @param roleSet  the set of roles
     * @param role  the role to remove from the current set
     * 
      * @return  true if the role set includes the specified role, false otherwise
      * @throws AceException  if the set of roles is inconsistent with the AIF-OSCORE-GROUPCOMM data model
      * 					  or the role identifier is less than 1
     */
    public static boolean checkGroupOSCORERole (int roleSet, short role) throws AceException {
   	 
   	 if ((roleSet < 1) || ((roleSet % 2) == 1)) {
   		 throw new AceException("Invalid set of Group OSCORE roles");
   	 }
   	 
   	 if (role < 1) {
   		 throw new AceException("Invalid identifier of Group OSCORE role");
   	 }
   	 
   	 return ((roleSet & (1 << role)) != 0);
   	 
    }
    
    /**
     * Return the array of roles included in the specified role set, encoded using the AIF-OSCORE-GROUPCOMM data model
     * 
     * @param roleSet  the set of roles, encoded using the AIF-OSCORE-GROUPCOMM data model
     * 
      * @return  The set of role identifiers specified in the role set
      * @throws AceException  if the set of roles is inconsistent with the AIF-OSCORE-GROUPCOMM data model
     */
    public static Set<Integer> getGroupOSCORERoles (int roleSet) throws AceException {
   	 
      	 if ((roleSet < 1) || ((roleSet % 2) == 1)) {
       		 throw new AceException("Invalid set of Group OSCORE roles");
       	 }
	   	 
	   	 Set<Integer> mySet = new HashSet<Integer>();
	   	 int roleIdentifier = 0;
	   	 
	   	 while (roleSet != 0) {
	   		 roleSet = roleSet >>> 1;
	   	 	 roleIdentifier++;
	   	 	 if ((roleSet & 1) != 0) {
	   	 		 mySet.add(Integer.valueOf(roleIdentifier));
	   	 	 }
	   	 }
	   	 
	   	 return mySet;
   	 
    }
    
    /**
     * Return the role sets allowed to a subject in a group, based on all the Access Tokens for that subject
     * 
     * @param subject   Subject identity of the node
     * @param groupName   Group name of the OSCORE group
     * @return The sets of allowed roles for the subject in the specified group using the AIF data model,
     *         or null in case of no results
     */
    public static int[] getGroupOSCORERolesFromToken(String subject, String groupName) {

    	Set<Integer> roleSets = new HashSet<Integer>();
    	
    	String kid = TokenRepository.getInstance().getKid(subject);
    	Set<String> ctis = TokenRepository.getInstance().getCtis(kid);
    	
    	// This should never happen at this point, since a valid Access Token
    	// has just made this request pass through 
    	if (ctis == null)
    		return null;
    	
    	for (String cti : ctis) { // All tokens linked to that pop key
    		
	        // Check if we have the claims for that cti
    		
	        // Get the claims
            Map<Short, CBORObject> claims = TokenRepository.getInstance().getClaims(cti);
            if (claims == null || claims.isEmpty()) {
                // No claims found
        		// Move to the next Access Token for this 'kid'
                continue;
            }
            
	        //Check the scope
            CBORObject scope = claims.get(Constants.SCOPE);
            
        	// This should never happen, since a valid Access Token
            // has just reached a handler at the Group Manager
            if (scope == null) {
        		// Move to the next Access Token for this 'kid'
            	continue;
            }
            
            if (!scope.getType().equals(CBORType.ByteString)) {
        		// Move to the next Access Token for this 'kid'
            	continue;
            }
            
            byte[] rawScope = scope.GetByteString();
        	CBORObject cborScope = CBORObject.DecodeFromBytes(rawScope);
        	
        	if (!cborScope.getType().equals(CBORType.Array)) {
        		// Move to the next Access Token for this 'kid'
                continue;
            }

        	for (int entryIndex = 0; entryIndex < cborScope.size(); entryIndex++) {
            	
        		CBORObject scopeEntry = cborScope.get(entryIndex);
        		
        		if (!scopeEntry.getType().equals(CBORType.Array) || scopeEntry.size() != 2) {
        			// Move to the next Access Token for this 'kid'
                    break;
                }
	        	
	        	// Retrieve the group name of the OSCORE group
	        	String scopeStr;
	      	  	CBORObject scopeElement = scopeEntry.get(0);
	      	  	if (scopeElement.getType().equals(CBORType.TextString)) {
	      	  		scopeStr = scopeElement.AsString();
	      	  		if (!scopeStr.equals(groupName)) {
	      	  		    // Move to the next scope entry
	      	  			continue;
	      	  		}
	      	  	}
	      	  	else {
	      	  		// Move to the next scope entry
	                continue;
	      	  	}
	      	  	
	      	  	// Retrieve the role or list of roles
	      	  	scopeElement = scopeEntry.get(1);
	      	  	
	        	if (!scopeElement.getType().equals(CBORType.Integer)) {
      	  		    // Move to the next scope entry
      	  			continue;
	        	}
	        	
        		int roleSetToken = scopeElement.AsInt32();
        		
        		// According to the AIF-OSCORE-GROUPCOMM data model, a valid combination 
        		// of roles has to be a positive integer of even value (i.e., with last bit 0)
        		if (roleSetToken <= 0 || (roleSetToken % 2 == 1)) {
      	  		    // Move to the next scope entry
      	  			continue;
        		}

        		roleSets.add(roleSetToken);
        			        	
        	}
        	
    	}
    	    	
    	// No Access Token allows this node to have any role
    	// with respect to the specified group
    	if (roleSets.size() == 0) {
    		return null;
    	}
    	else {
    		int[] ret = new int[roleSets.size()];
    		
    		int index = 0;
    		for (Integer i : roleSets) {
    			ret[index] = i.intValue();
    			index++;
    		}
    		
    		return ret;
    	}
    	
    }
    
    /**
     * Add 'newPermission' to the admin permission set, encoded using the AIF-OSCORE-GROUPCOMM data model
     * 
     * @param currentPermissionSet  the current set of admin permissions
     * @param newPermission  the admin permission to add to the current set
     * 
      * @return  the updated set of admin permission
      * @throws AceException  if the permission identifier is less than 1
     */
    public static int addGroupOSCOREAdminPermission (int currentPermissionSet, short newPermission) throws AceException {

   	 if (newPermission < 0) throw new AceException("Invalid identifier of Group OSCORE admin permission");
   	 
   	 int updatedPermissionSet = 0;
   	 updatedPermissionSet = currentPermissionSet | (1 << newPermission);
   	 
   	 return updatedPermissionSet; 
   	 
    }
    
    /**
     * Remove 'oldPermission' from the admin permission set, encoded using the AIF-OSCORE-GROUPCOMM data model
     * 
     * @param currentPermissionSet  the current set of admin permissions
     * @param oldPermission  the permission to remove from the current set
     * 
      * @return  the updated set of admin permissions
      * @throws AceException  if the permission identifier is less than 1
     */
    public static int removeGroupOSCOREAdminPermission (int currentPermissionSet, short oldPermission) throws AceException {

   	 if (oldPermission < 0) throw new AceException("Invalid identifier of Group OSCORE admin permission");
   	 
   	 int updatedPermissionSet = 0;
   	 updatedPermissionSet = currentPermissionSet & (~(1 << oldPermission));
   	 
   	 return updatedPermissionSet; 
   	 
    }
    
    /**
     * Check if a permission set includes a specified admin permission, encoded using the AIF-OSCORE-GROUPCOMM data model
     * 
     * @param permissionSet  the set of admin permissions
     * @param permission  the permission whose presence has to be checked in the set of admin permissions
     * 
      * @return  true if the permission set includes the specified admin permission, false otherwise
      * @throws AceException  if the set of admin permissions is inconsistent with the AIF-OSCORE-GROUPCOMM data model
      * 					  or the permission identifier is less than 1
     */
    public static boolean checkGroupOSCOREAdminPermission (int permissionSet, short permission) throws AceException {
   	 
   	 if ((permissionSet < 1) || ((permissionSet % 2) == 0)) {
   		 throw new AceException("Invalid set of Group OSCORE admin permissions");
   	 }
   	 
   	 if (permission < 0) {
   		 throw new AceException("Invalid identifier of Group OSCORE admin permission");
   	 }
   	 
   	 return ((permissionSet & (1 << permission)) != 0);
   	 
    }
    
    /**
     * Return the array of permissions included in the specified set of admin permissions,
     * encoded using the AIF-OSCORE-GROUPCOMM data model
     * 
     * @param permissionSet  the set of admin permissions, encoded using the AIF-OSCORE-GROUPCOMM data model
     * 
      * @return  The set of permission identifiers specified in the set of admin permission
      * @throws AceException  if the set of permissions is inconsistent with the AIF-OSCORE-GROUPCOMM data model
     */
    public static Set<Integer> getGroupOSCOREAdminPermissions (int permissionSet) throws AceException {
   	 
      	 if ((permissionSet < 1) || ((permissionSet % 2) == 0)) {
       		 throw new AceException("Invalid set of Group OSCORE admin permissions");
       	 }
	   	 
	   	 Set<Integer> mySet = new HashSet<Integer>();
	   	 int permissionIdentifier = 0;
	   	 
	   	 // The admin permission "List" is always set in every admin scope entry
	   	 mySet.add(Integer.valueOf(permissionIdentifier));
	   	 
	   	 permissionSet--;
	   	 while (permissionSet != 0) {
	   		permissionSet = permissionSet >>> 1;
   	 		permissionIdentifier++;
	   	 	 if ((permissionSet & 1) != 0) {
	   	 		 mySet.add(Integer.valueOf(permissionIdentifier));
	   	 	 }
	   	 }
	   	 
	   	 return mySet;
   	 
    }
    
    /**
     * Return the sets of admin permissions allowed to a subject, based on all the Access Tokens for that subject
     * 
     * @param subject   Subject identity of the node
     * @param groupName   Group name of the OSCORE group, or null to retrieve all the admin scope entries
     * @return The sets of scope entries such the group name matches with the specified group name pattern
     *         and for which the subject has admin permissions, or null in case of no results
     */
    public static CBORObject[] getGroupOSCOREAdminPermissionsFromToken(String subject, String groupName) {

    	List<CBORObject> scopeEntries = new ArrayList<CBORObject>();
    	
    	String kid = TokenRepository.getInstance().getKid(subject);
    	Set<String> ctis = TokenRepository.getInstance().getCtis(kid);
    	
    	// This should never happen at this point, since a valid Access Token
    	// has just made this request pass through 
    	if (ctis == null)
    		return null;
    	
    	for (String cti : ctis) { // All tokens linked to that pop key
    		
	        // Check if we have the claims for that cti
    		
	        // Get the claims
            Map<Short, CBORObject> claims = TokenRepository.getInstance().getClaims(cti);
            if (claims == null || claims.isEmpty()) {
                // No claims found
        		// Move to the next Access Token for this 'kid'
                continue;
            }
            
	        //Check the scope
            CBORObject scope = claims.get(Constants.SCOPE);
            
        	// This should never happen, since a valid Access Token
            // has just reached a handler at the Group Manager
            if (scope == null) {
        		// Move to the next Access Token for this 'kid'
            	continue;
            }
            
            if (!scope.getType().equals(CBORType.ByteString)) {
        		// Move to the next Access Token for this 'kid'
            	continue;
            }
            
            byte[] rawScope = scope.GetByteString();
        	CBORObject cborScope = CBORObject.DecodeFromBytes(rawScope);
        	
        	if (!cborScope.getType().equals(CBORType.Array)) {
        		// Move to the next Access Token for this 'kid'
                continue;
            }
        	
        	for (int entryIndex = 0; entryIndex < cborScope.size(); entryIndex++) {
            	
        		CBORObject scopeEntry = cborScope.get(entryIndex);
        		
        		if (!scopeEntry.getType().equals(CBORType.Array) || scopeEntry.size() != 2) {
        			// Move to the next Access Token for this 'kid'
                    break;
                }
        		
	      	  	// Retrieve the role or list of admin permissions
        		CBORObject scopeElement = scopeEntry.get(1);
	      	  	
	        	if (!scopeElement.getType().equals(CBORType.Integer)) {
      	  		    // Move to the next scope entry
      	  			continue;
	        	}
	        	
        		int permissionSetToken = scopeElement.AsInt32();
        		
        		// According to the AIF-OSCORE-GROUPCOMM data model, a valid combination 
        		// of admin permissions has to be a positive integer of odd value (i.e., with last bit 1)
        		if (permissionSetToken <= 0 || (permissionSetToken % 2 == 0)) {
      	  		    // Move to the next scope entry
      	  			continue;
        		}
        		
	      	  	if (groupName == null) {
	      	  		// Include this scope entry in the results to return, and move to the next one
	      	  		scopeEntries.add(scopeEntry);
	      	  		continue;
	      	  	}

	        	// Check if the group name of the OSCORE group matches with the group name pattern
	      	  	scopeElement = scopeEntry.get(0);
	      	    if (matchingGroupOscoreName(groupName, scopeElement)) {
	      	    	// There is a match; include this scope entry in the results to return
	      	    	scopeEntries.add(scopeEntry);
	      	    }
	      	    else {
	      	    	// Move to the next scope entry
	      	    	continue;
	      	    }
        			        	
        	}
        	
    	}
    	    	
    	// No Access Token allows this node to have any admin permission,
    	// altogether or with respect to the specified group
    	int size = scopeEntries.size();
    	if (size == 0) {
    		return null;
    	}
    	else {
    		CBORObject[] ret = new CBORObject[size];
    		
    		int index = 0;
    		for (CBORObject entry : scopeEntries) {
        		// Hard copy
    			byte[] binaryElem = entry.EncodeToBytes();
    			ret[index] = CBORObject.DecodeFromBytes(binaryElem);
    			index++;
    		}
    		
    		return ret;
    	}
    	
    }
    
    /**
     * Check if the name of an OSCORE group matches with the group name pattern
     * specified by Toid in a scope entry of the scope claim, according to the
     * AIF-OSCORE-GROUPCOMM data model
     *  
     * @param groupName   The name of the OSCORE group, as a String
     * @param groupNamePattern   The Toid from the scope entry, as a CBOR Object
     * @return  True if the group name matches with the group name pattern, or false otherwise
     */
    public static boolean matchingGroupOscoreName(final String groupName, final CBORObject groupNamePattern) {
    	
  	  	if (groupNamePattern.equals(CBORObject.True)) {
	  		// The group name pattern is the wildcard
  	  		return true;
  	  	}
  	  		
  	  	if (groupNamePattern.getType().equals(CBORType.TextString)) {
  	  		String groupNamePatternString = groupNamePattern.AsString();
  	  		if (groupNamePattern.HasTag(21065)) {
  	  			// The group name pattern is an I-Regexp regular expression
  	  			
  	  			Pattern pat = Pattern.compile(groupNamePatternString);
  	  			Matcher myMatcher = pat.matcher(groupName);
  	  			if (myMatcher.matches() == false) {
  	  				// The target group name does not match with the regular expression
      	  		    return false;
  	  			}
  	  		}
  	  		else if (!groupNamePatternString.equals(groupName)) {
  	  			// The group name pattern is an exact group name,
  	  			// which does not match with the target group name
  	  		    return false;
  	  		}
  	  		
  	  		// The target group name has matched with the group name pattern
  	  		return true;
  	  	}

  	  	return false;
  	  	
    }
    
    /**
     * Build a CWT Claims Set (CCS) including a COSE Key
     * within a "cnf" claim and an additional "sub" claim
     *  
     * @param identityKey   The public key as a OneKey object
     * @param subjectName   The subject name associated to this key, it can be an empty string
     * @return  The serialization of the CCS, or null in case of errors
     */
	public static byte[] oneKeyToCCS(OneKey identityKey, String subjectName) {
		
		if (identityKey  == null || subjectName == null)
			return null;
		
		CBORObject coseKeyMap = CBORObject.NewMap();
		coseKeyMap.Add(KeyKeys.KeyType.AsCBOR(), identityKey.get(KeyKeys.KeyType));
		if (identityKey.get(KeyKeys.KeyType) == KeyKeys.KeyType_OKP) {
			int curve = identityKey.get(KeyKeys.OKP_Curve).AsInt32();
			if (curve == KeyKeys.OKP_Ed25519.AsInt32() || curve == KeyKeys.OKP_Ed448.AsInt32()) {
				coseKeyMap.Add(KeyKeys.Algorithm.AsCBOR(), AlgorithmID.EDDSA.AsCBOR());
			}
			if (curve == KeyKeys.OKP_X25519.AsInt32() || curve == KeyKeys.OKP_X448.AsInt32()) {
				coseKeyMap.Add(KeyKeys.Algorithm.AsCBOR(), AlgorithmID.ECDH_ES_HKDF_256.AsCBOR());
			}
			coseKeyMap.Add(KeyKeys.OKP_Curve.AsCBOR(), identityKey.get(KeyKeys.OKP_Curve));
			coseKeyMap.Add(KeyKeys.OKP_X.AsCBOR(), identityKey.get(KeyKeys.OKP_X));
		}
		else if (identityKey.get(KeyKeys.KeyType) == KeyKeys.KeyType_EC2) {
			int curve = identityKey.get(KeyKeys.EC2_Curve).AsInt32();
			if (curve == KeyKeys.EC2_P256 .AsInt32()) {
				coseKeyMap.Add(KeyKeys.Algorithm.AsCBOR(), AlgorithmID.ECDSA_256.AsCBOR());
			}
			if (curve == KeyKeys.EC2_P384 .AsInt32()) {
				coseKeyMap.Add(KeyKeys.Algorithm.AsCBOR(), AlgorithmID.ECDSA_384.AsCBOR());
			}
			if (curve == KeyKeys.EC2_P521.AsInt32()) {
				coseKeyMap.Add(KeyKeys.Algorithm.AsCBOR(), AlgorithmID.ECDSA_512.AsCBOR());
			}
			coseKeyMap.Add(KeyKeys.EC2_Curve.AsCBOR(), identityKey.get(KeyKeys.EC2_Curve));
			coseKeyMap.Add(KeyKeys.EC2_X.AsCBOR(), identityKey.get(KeyKeys.EC2_X));
			coseKeyMap.Add(KeyKeys.EC2_Y.AsCBOR(), identityKey.get(KeyKeys.EC2_Y));
		}
		else {
			return null;
		}
		
		CBORObject cnfMap = CBORObject.NewMap();
		cnfMap.Add(Constants.COSE_KEY, coseKeyMap);
		
		CBORObject claimSetMap = CBORObject.NewMap();
		claimSetMap.Add(Constants.SUB, subjectName);
		claimSetMap.Add(Constants.CNF, cnfMap);
		
		// Debug print
		System.out.println(claimSetMap);
		
        return claimSetMap.EncodeToBytes();
		
	}
	
    /**
     * Extract a public key from a CWT Claims Set (CCS) and return it as a OneKey object
     *  
     * @param ccs   The CCS as a CBOR map
     * @return  The public key as a OneKey object, or null in case of errors
     */
	public static OneKey ccsToOneKey(CBORObject ccs) {
		
		if (ccs == null)
			return null;
		
		if (ccs.getType() != CBORType.Map)
		    return null;
		
		if (!ccs.ContainsKey(Constants.CNF) || !ccs.get(Constants.CNF).ContainsKey(Constants.COSE_KEY))
			return null;
		
		CBORObject pubKeyCBOR = ccs.get(Constants.CNF).get(Constants.COSE_KEY);
		
		OneKey pubKey = null;
		try {
			pubKey = new OneKey(pubKeyCBOR);
		} catch (CoseException e) {
			System.err.println("Error when building a OneKey from a CCS: " + e.getMessage());
			return null;
		}
		
        return pubKey;
		
	}
	
    /**
     * @param byteArray  the byte array
     * @return  the hex string
     * 
     * Return the printable hexadecimal string corresponding to a byte array
     */
    public static String byteArrayToHexString(final byte[] byteArray) {
    	
    	if (byteArray == null) {
    		return new String("");
    	}
    	else {
    		String str = new String("");
	    	for (byte byteToConvert: byteArray) {
	            str += String.format("%02X", byteToConvert);
	        }
	    	return str;
    	}
    	
    }
	
    /**
     * Read a hex string and transform to bytes
     * 
     * @param hex  the hex string
     * @return  the byte array representation
     */
    public static byte[] hexString2byteArray(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }
	
    /**
     * Build a CBOR map specifying a public key, possibly together with the corresponding private key
     * 
     * @param signKeyCurve  the curve of the signature algorithm
     * @param x  the x-coordinate of the public key
     * @param y  the y-coordinate of the public key, or null if not applicable
     * @param d  the private key, or null if the CBOR map specifies only the public key
     * @return  The CBOR map specifying a public key, possibly together with the corresponding private key
     */
    public static CBORObject buildRpkData (int signKeyCurve, String x, String y, String d) {
    	
    	CBORObject rpkData = CBORObject.NewMap();
    	
    	if (signKeyCurve == KeyKeys.EC2_P256.AsInt32()) {
	        rpkData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_EC2);
	        rpkData.Add(KeyKeys.Algorithm.AsCBOR(), AlgorithmID.ECDSA_256.AsCBOR());
	        rpkData.Add(KeyKeys.EC2_Curve.AsCBOR(), KeyKeys.EC2_P256);
	        CBORObject Cx = CBORObject.FromObject(hexString2byteArray(x));
	        CBORObject Cy = CBORObject.FromObject(hexString2byteArray(y));
	        rpkData.Add(KeyKeys.EC2_X.AsCBOR(), Cx);
	        rpkData.Add(KeyKeys.EC2_Y.AsCBOR(), Cy);
	        if (d != null) {
		        CBORObject Cd = CBORObject.FromObject(hexString2byteArray(d));
		        rpkData.Add(KeyKeys.EC2_D.AsCBOR(), Cd);
	        }
    	}
    	if (signKeyCurve == KeyKeys.OKP_Ed25519.AsInt32()) {
	        rpkData.Add(KeyKeys.KeyType.AsCBOR(), KeyKeys.KeyType_OKP);
	        rpkData.Add(KeyKeys.Algorithm.AsCBOR(), AlgorithmID.EDDSA.AsCBOR());
	        rpkData.Add(KeyKeys.OKP_Curve.AsCBOR(), KeyKeys.OKP_Ed25519);
	        CBORObject Cx = CBORObject.FromObject(hexString2byteArray(x));
	        rpkData.Add(KeyKeys.OKP_X.AsCBOR(), Cx);
	        if (d != null) {
		        CBORObject Cd = CBORObject.FromObject(hexString2byteArray(d));
		        rpkData.Add(KeyKeys.OKP_D.AsCBOR(), Cd);
	        }
    	}
        
    	return rpkData;
    }
    
    /**
     * Return the used major version of Java
     * 
     * @return  The used major version of Java
     */
    public static int getJavaVersion() {
        String version = System.getProperty("java.version");
        
        if(version.startsWith("1.")) {
            version = version.substring(2, 3);
        } else {
            int dot = version.indexOf(".");
            if(dot != -1) {
            	version = version.substring(0, dot);
            }
        }
        
        return Integer.parseInt(version);
    }
    
    public static void prettyPrintCborMap(final CBORObject obj) {

    	if (obj.getType() != CBORType.Map) {
    		System.err.println("Trying to print a CBOR map, while it is not");
    		return;
    	}
    	
    	int counter = 0;
    	System.out.println("{");
    	for (CBORObject elemKey : obj.getKeys()) {
    		System.out.print("  " + elemKey + ": " + obj.get(elemKey));
    		counter++;
    		if (counter != obj.size()) {
    			System.out.println(",");
    		}
    		else {
    			System.out.println("");
    		}
    	}
    	System.out.println("}\n");
    	
    }
    
    public static void printResponsePayloadCBOR(Response res) throws Exception {
        if (res != null) {
            System.out.print(res.getCode().codeClass + ".0" + res.getCode().codeDetail);
            System.out.println(" " + res.getCode().name());

            int contentFormat = res.getOptions().getContentFormat();
            byte[] payload = res.getPayload();
            
            if (payload != null) {
                if (contentFormat == Constants.APPLICATION_ACE_CBOR ||
                	  contentFormat == Constants.APPLICATION_ACE_GROUPCOMM_CBOR ||
                	  contentFormat == Constants.APPLICATION_CONCISE_PROBLEM_DETAILS_CBOR) {
                    CBORObject resCBOR = CBORObject.DecodeFromBytes(payload);
                    System.out.println(resCBOR.toString());
                }
                else {
                    System.out.println(new String(payload));
                }
            }
        } else {
            System.out.println("The response has a null payload!");
        }
    }
    
    /**
     * Returns the size in bytes of the nonce of a COSE encryption algorithm
     * 
     * @param alg  the encryption algorithm
     * @return  The size in bytes of the encryption algorithm, or -1 in case of error
     */
    public static int getSizeOfAlgNonce(final AlgorithmID alg) {
    	
    	switch (alg) {
    		case AES_GCM_128:
    		case AES_GCM_192:
    		case AES_GCM_256:
    			return 12;
    		case AES_CCM_16_64_128:
    		case AES_CCM_16_64_256:
    		case AES_CCM_16_128_128:
    		case AES_CCM_16_128_256:
    			return 13;
    		case AES_CCM_64_64_128:
    		case AES_CCM_64_64_256:
    		case AES_CCM_64_128_128:
    		case AES_CCM_64_128_256:
    			return 7;
    		default:
    			return -1;
    	}
    	
    }
    
}
