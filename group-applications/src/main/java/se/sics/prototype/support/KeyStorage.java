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
package se.sics.prototype.support;

import java.util.HashMap;
import java.util.Map;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * Class to hold asymmetric keys for the group members to use in the OSCORE
 * group.
 *
 */
public class KeyStorage {

	/**
	 * Group names for the two new groups to be created
	 */
	public static String newGroupName1 = "G1000";
	public static String newGroupName2 = "G2000";

	/**
	 * Hold specific Sender IDs for the 2 clients
	 */
	public static Map<String, Bytes> clientIds;
	static {
		clientIds = new HashMap<>();
		clientIds.put("Client1", new Bytes(new byte[] { 0x11 }));
		clientIds.put("Client2", new Bytes(new byte[] { 0x22 }));
	}

	/**
	 * Map holding OSCORE keys (master secret) to use by the group members
	 * towards the AS
	 */
	public static Map<String, byte[]> memberAsKeys;
	static {
		memberAsKeys = new HashMap<>();
		memberAsKeys.put("Client1",
				new byte[] { (byte) 0x06, (byte) 0x7a, (byte) 0xb8, (byte) 0xd3, (byte) 0xfc, (byte) 0x14, (byte) 0x88,
						(byte) 0xe2, (byte) 0x76, (byte) 0xb2, (byte) 0x7e, (byte) 0x7b, (byte) 0x38, (byte) 0x8c,
						(byte) 0x02, (byte) 0xe2 });
		memberAsKeys.put("Client2",
				new byte[] { (byte) 0xe9, (byte) 0xc5, (byte) 0xca, (byte) 0x11, (byte) 0x65, (byte) 0x10, (byte) 0x27,
						(byte) 0xc3, (byte) 0xb1, (byte) 0x8c, (byte) 0x46, (byte) 0x65, (byte) 0xee, (byte) 0x01,
						(byte) 0x34, (byte) 0x67 });
		memberAsKeys.put("Server1",
				new byte[] { (byte) 0x14, (byte) 0xe8, (byte) 0x01, (byte) 0x1e, (byte) 0xf4, (byte) 0x20, (byte) 0x1a,
						(byte) 0x52, (byte) 0x37, (byte) 0xf0, (byte) 0xe9, (byte) 0x8c, (byte) 0xb4, (byte) 0x58,
						(byte) 0x76, (byte) 0x79 });
		memberAsKeys.put("Server2",
				new byte[] { (byte) 0x93, (byte) 0x01, (byte) 0xec, (byte) 0x61, (byte) 0x24, (byte) 0x3c, (byte) 0x4e,
						(byte) 0x97, (byte) 0x11, (byte) 0x0e, (byte) 0xf1, (byte) 0x96, (byte) 0x67, (byte) 0x9f,
						(byte) 0xa5, (byte) 0x8d });
		memberAsKeys.put("Server3",
				new byte[] { (byte) 0xdd, (byte) 0x9c, (byte) 0xc0, (byte) 0x47, (byte) 0x10, (byte) 0x88, (byte) 0x09,
						(byte) 0x64, (byte) 0x33, (byte) 0x4f, (byte) 0x5f, (byte) 0x96, (byte) 0x95, (byte) 0xc0,
						(byte) 0x0c, (byte) 0x2f });
		memberAsKeys.put("Server4",
				new byte[] { (byte) 0xf6, (byte) 0x2e, (byte) 0xf1, (byte) 0xa5, (byte) 0x89, (byte) 0xe8, (byte) 0xd4,
						(byte) 0x82, (byte) 0x1f, (byte) 0xa9, (byte) 0xae, (byte) 0x33, (byte) 0xf7, (byte) 0xcf,
						(byte) 0xb5, (byte) 0x41 });
		memberAsKeys.put("Server5",
				new byte[] { (byte) 0xf3, (byte) 0x45, (byte) 0x89, (byte) 0xa5, (byte) 0x83, (byte) 0x79, (byte) 0x79,
						(byte) 0x74, (byte) 0x36, (byte) 0xb2, (byte) 0xc3, (byte) 0x26, (byte) 0xc2, (byte) 0x15,
						(byte) 0x89, (byte) 0x0f });
		memberAsKeys.put("Server6",
				new byte[] { (byte) 0x0c, (byte) 0x37, (byte) 0xa6, (byte) 0xe3, (byte) 0x9b, (byte) 0xc2, (byte) 0xee,
						(byte) 0xc7, (byte) 0xd0, (byte) 0x3e, (byte) 0x9a, (byte) 0x7f, (byte) 0xa2, (byte) 0x28,
						(byte) 0xe8, (byte) 0x81 });
		memberAsKeys.put("Adversary",
				new byte[] { (byte) 0x79, (byte) 0x5f, (byte) 0x96, (byte) 0x36, (byte) 0xb2, (byte) 0xc0, (byte) 0x47,
						(byte) 0x10, (byte) 0x88, (byte) 0x09, (byte) 0x58, (byte) 0x76, (byte) 0x95, (byte) 0xc0,
						(byte) 0x0c, (byte) 0x74 });
		memberAsKeys.put("admin1",
				new byte[] { (byte) 0xf6, (byte) 0x2e, (byte) 0xf1, (byte) 0xa5, (byte) 0x89, (byte) 0xe8, (byte) 0xd4,
						(byte) 0x52, (byte) 0x37, (byte) 0xf0, (byte) 0xe9, (byte) 0x8c, (byte) 0xb4, (byte) 0x58,
						(byte) 0x0c, (byte) 0x74 });
	}

	/**
	 * Map holding ACE Sender ID indexed by the member name
	 */
	public static Map<String, byte[]> aceSenderIds;
	static {
		aceSenderIds = new HashMap<>();
		aceSenderIds.put("AS", new byte[] { (byte) 0xA0 });
		aceSenderIds.put("Client1", new byte[] { (byte) 0xA3 });
		aceSenderIds.put("Client2", new byte[] { (byte) 0xA4 });
		aceSenderIds.put("Server1", new byte[] { (byte) 0xA5 });
		aceSenderIds.put("Server2", new byte[] { (byte) 0xA6 });
		aceSenderIds.put("Server3", new byte[] { (byte) 0xA7 });
		aceSenderIds.put("Server4", new byte[] { (byte) 0xA8 });
		aceSenderIds.put("Server5", new byte[] { (byte) 0xA9 });
		aceSenderIds.put("Server6", new byte[] { (byte) 0xAA });
		aceSenderIds.put("Adversary", new byte[] { (byte) 0x99 });
		aceSenderIds.put("admin1", new byte[] { (byte) 0x11 });
	}

	/**
	 * Map holding CCS to use by the group members
	 */
	public static Map<String, byte[]> memberCcs;
	static {
		memberCcs = new HashMap<>();
		memberCcs.put("Client1", StringUtil.hex2ByteArray(
				"A501020267436C69656E743122582064CE3DD128CC4EFA6DE209BE8ABD111C7272F612C2DB654057B6EC00FBFB06842158201ADB2AB6AF48F17C9877CF77DB4FA39DC0923FBE215E576FE6F790B1FF2CBC962001"));
		memberCcs.put("Server1", StringUtil.hex2ByteArray(
				"A501020267536572766572312258201897A28666FE1CC4FACEF79CC7BDECDC271F2A619A00844FCD553A12DD679A4F2158200EB313B4D314A1001244776D321F2DD88A5A31DF06A6EEAE0A79832D39408BC12001"));
		memberCcs.put("Server2", StringUtil.hex2ByteArray(
				"A501020267536572766572322258205694315AD17A4DA5E3F69CA02F83E9C3D594712137ED8AFB748A70491598F9CD215820FAD4312A45F45A3212810905B223800F6CED4BC8D5BACBC8D33BB60C45FC98DD2001"));
		memberCcs.put("Server3", StringUtil.hex2ByteArray(
				"A5010202675365727665723322582064CE3DD128CC4EFA6DE209BE8ABD111C7272F612C2DB654057B6EC00FBFB06842158201ADB2AB6AF48F17C9877CF77DB4FA39DC0923FBE215E576FE6F790B1FF2CBC962001"));

		memberCcs.put("Client2", StringUtil.hex2ByteArray(
				"A20267436C69656E743208A101A4010103272006215820C80240E84F3CB886D841DA6F71140F8578E7E27808672DF08521830AE1300F54"));
		memberCcs.put("Server4", StringUtil.hex2ByteArray(
				"A202675365727665723408A101A40101032720062158208ED61CBEAD281DD16FD086280B207AD3FB706DF23E37BC43A00DF13047E4CDC4"));
		memberCcs.put("Server5", StringUtil.hex2ByteArray(
				"A202675365727665723508A101A40101032720062158204F8D92825564057CEAAF1CC8C2ABAD0F0542BEA9A6E171BD9C7086138AF885FB"));
		memberCcs.put("Server6", StringUtil.hex2ByteArray(
				"A202675365727665723608A101A401010327200621582003409CBD38DC73250E79B9F627739ECD78CC89651E89929983FAF8BFC94FDCA2"));

		memberCcs.put("Adversary", StringUtil.hex2ByteArray(
				"A2026941647665727361727908A101A40101032720062158208ED61CBEAD281DD16FD086280B207AD3FB706DF23E37BC43A00DF13047E4CDC4"));
		memberCcs.put("admin1", StringUtil.hex2ByteArray(
				"A2026941647665727361727908A101A40101032720062158208ED61CBEAD281DD16FD086280B207AD3FB706DF23E37BC43A00DF13047E4CDC4"));

	}

	/**
	 * Map holding Private Keys to use by the group members
	 */
	public static Map<String, byte[]> memberPrivateKeys;
	static {
		memberPrivateKeys = new HashMap<>();
		memberPrivateKeys.put("Client1",
				StringUtil.hex2ByteArray("FEA2190084748436543C5EC8E329D2AFBD7068054F595CA1F987B9E43E2205E6"));
		memberPrivateKeys.put("Server1",
				StringUtil.hex2ByteArray("DA2593A6E0BCC81A5941069CB76303487816A2F4E6C0F21737B56A7C90381597"));
		memberPrivateKeys.put("Server2",
				StringUtil.hex2ByteArray("BF31D3F9670A7D1342259E700F48DD9983A5F9DF80D58994C667B6EBFD23270E"));
		memberPrivateKeys.put("Server3",
				StringUtil.hex2ByteArray("FEA2190084748436543C5EC8E329D2AFBD7068054F595CA1F987B9E43E2205E6"));

		memberPrivateKeys.put("Client2",
				StringUtil.hex2ByteArray("7D428B2549E7997E8D8833A17BDA1E09B65C9FDC0F69287F376D7DCE882E1C3F"));
		memberPrivateKeys.put("Server4",
				StringUtil.hex2ByteArray("A90B7D8A9E6D32DDFC794494D446F0E56505094203209BEF64A6800CF35F3988"));
		memberPrivateKeys.put("Server5",
				StringUtil.hex2ByteArray("B414D24D3D45D0AFA4172EE66CEC88685AFEB4FF011A9C04C0AB4CEC763616E9"));
		memberPrivateKeys.put("Server6",
				StringUtil.hex2ByteArray("F444DF1A8899E2C3733F391823A492B4607489820D0304530D15A2BB6B746D9A"));
		memberPrivateKeys.put("Adversary",
				StringUtil.hex2ByteArray("A90B7D8A9E6D32DDFC794494D446F0E56505094203209BEF64A6800CF35F3988"));
	}

}
