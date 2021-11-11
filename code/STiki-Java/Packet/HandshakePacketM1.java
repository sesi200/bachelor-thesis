package de.tum.in.net.WSNDataFramework.Protocols.STiki.Packet;

import java.net.InetSocketAddress;

import org.bouncycastle.util.Arrays;

import de.tum.in.net.WSNDataFramework.WSNProtocolException;
import de.tum.in.net.WSNDataFramework.WSNProtocolPacket;
import de.tum.in.net.WSNDataFramework.Crypto.AES;
import de.tum.in.net.WSNDataFramework.Crypto.AES_CMAC;
import de.tum.in.net.WSNDataFramework.Crypto.CryptoUtils;
import de.tum.in.net.WSNDataFramework.Crypto.KeyStore;
import de.tum.in.net.WSNDataFramework.Protocols.STiki.STikiProtocol;
import de.tum.in.net.WSNDataFramework.Protocols.STiki.STikiUtils;
import de.tum.in.net.WSNDataFramework.Protocols.STiki.Session.STikiSession;
import de.tum.in.net.WSNDataFramework.Protocols.STiki.Session.STikiSessionStore;

public class HandshakePacketM1 extends HandshakePacket {
	
	private int IDa;
	private int IDb; //not really needed, but helpful for debugging

	private byte[] nonce;

	public HandshakePacketM1(long id, byte[] payload, InetSocketAddress source) throws WSNProtocolException {
		super(id, payload, source, HandshakePacket.SUBPROTOCOL_M1);
		if(payload.length != 10) throw new WSNProtocolException("message is wrong size for M1: size is "+payload.length+" expected: 10");
		IDa = ((payload[2]&0xff)<<8 | payload[3]&0xff);
		IDb = ((payload[4]&0xff)<<8 | payload[5]&0xff);
		nonce = Arrays.copyOfRange(payload, 6, 10);
	}
	
	@Override
	public boolean macIsValid() {
		//M1 has no MAC, so nothing can be wrong
		return true;
	}

	public int getIDa() {
		return IDa;
	}

	public int getIDb() {
		return IDb;
	}

	public byte[] getNonce() {
		return nonce;
	}

	@Override
	public WSNProtocolPacket process() throws WSNProtocolException {
		if(!KeyStore.containsKey(IDa)) {
			throw new WSNProtocolException("missing Initial Master Key for node "+Integer.toHexString(IDa));
		}
		
		byte[] imk = KeyStore.getKey(IDa);
		byte[] payload = buildResponsePayload(imk);
		byte[] msg = AES_CMAC.signWithMAC(payload, imk);
		respondWith(msg);
		
		return null;
	}
	
	private byte[] buildResponsePayload(byte[] imk) {
		//header
		byte[] header = new byte[2];
		STikiUtils.setMsgHeader(header, STikiProtocol.STIKI_PROTOCOL_HANDSHAKE, HandshakePacket.SUBPROTOCOL_M4);
		
		//token
		byte[] iv = CryptoUtils.randomBytes(15); //this IV is only used for one message. no need to store it
		STikiUtils.logDetail("IV is "+CryptoUtils.bytesToHex(iv));
		byte[] token = buildM4Token();
		STikiUtils.logDetail("token is "+CryptoUtils.bytesToHex(token));
		byte[] encryptedToken = AES.ctrCrypt(imk, token, iv);
		STikiUtils.logDetail("encrypted token is "+CryptoUtils.bytesToHex(encryptedToken));
		
		return Arrays.concatenate(header, iv, encryptedToken);
	}
	
	private byte[] buildM4Token() {
		STikiSession session = STikiSessionStore.getSession(IDa);
		byte[] sessionKey = session.newKey();
		
		//IDa(2b), IDb(2b), nonce(4b), starting after header(2b)
		byte[] idsAndNonce = Arrays.copyOfRange(_payload, 2, 10);
		
		byte[] token = Arrays.concatenate(idsAndNonce, sessionKey);
		return token;
	}
	
	public String toString() {
		return "[STiki.HandshakePacketM1:"+
					" IDa: "+IDa+
					" IDb: "+IDb+
					" nonce: "+CryptoUtils.bytesToHex(nonce)+
					" ]";
	}

}
