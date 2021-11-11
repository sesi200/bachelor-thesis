package de.tum.in.net.WSNDataFramework.Protocols.STiki.Packet;

import java.net.InetSocketAddress;
import java.util.Arrays;

import de.tum.in.net.WSNDataFramework.WSNProtocolPacket;
import de.tum.in.net.WSNDataFramework.Crypto.AES;
import de.tum.in.net.WSNDataFramework.Crypto.AES_CMAC;
import de.tum.in.net.WSNDataFramework.Crypto.CryptoUtils;
import de.tum.in.net.WSNDataFramework.Crypto.KeyStore;
import de.tum.in.net.WSNDataFramework.Protocols.STiki.Session.STikiSessionStore;

public class HandshakePacketM4 extends HandshakePacket {
	
	private int IDa;
	private int IDb;
	private byte[] iv;
	private byte[] token;
 	private byte[] nonce;
 	private byte[] imk;
	private byte[] sessionKey;
	private byte[] _MAC;
 	
	public HandshakePacketM4(long id, byte[] payload, InetSocketAddress source) {
		//M4 structure: [2b header, 15b IV, 24b token, 16b MAC]
		//token = [2b IDa, 2b IDb, 4b nonce, 16b key_ab]
		super(id, payload, source, HandshakePacket.SUBPROTOCOL_M4);
		iv = Arrays.copyOfRange(payload, 2, 17);
		token = Arrays.copyOfRange(payload, 17, 41);
		_MAC = Arrays.copyOfRange(payload, 41, 57);
	}

	@Override
	public boolean macIsValid() {
		imk = KeyStore.getKey(1);
		return AES_CMAC.macIsValid(_payload, imk, _MAC);
	}

	@Override
	public WSNProtocolPacket process() {
		byte[] decryptedToken = AES.ctrCrypt(imk, token, iv);
		IDa = ((decryptedToken[0]&0xff)<<8) | (decryptedToken[1]&0xff);
		IDb = ((decryptedToken[2]&0xff)<<8) | (decryptedToken[3]&0xff);
		sessionKey = Arrays.copyOfRange(decryptedToken, 8, 24);
		STikiSessionStore.getSession(IDb).setSessionKey(sessionKey);
		STikiSessionStore.getSession(IDb).sendStoredPacket();
		
		return null;
	}
	
	public String toString() {
		return "[STiki.HandshakePacketM4:"+
					" IDa: "+IDa+
					" IDb: "+IDb+
					" IV: "+CryptoUtils.bytesToHex(iv)+
					" nonce: "+CryptoUtils.bytesToHex(nonce)+
					" sessionKey: "+CryptoUtils.bytesToHex(sessionKey)+
					" imk: "+CryptoUtils.bytesToHex(imk)+
					" ]";
	}

}
