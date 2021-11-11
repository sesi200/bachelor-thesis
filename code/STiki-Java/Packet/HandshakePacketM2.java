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

public class HandshakePacketM2 extends HandshakePacket {
	
	private int idA;
	private int idB;
	private byte[] idABytes;
	private byte[] idBBytes;
	private byte[] nonceA;
	private byte[] nonceB;
	
	public HandshakePacketM2(long id, byte[] payload, InetSocketAddress source) throws WSNProtocolException {
		super(id, payload, source, HandshakePacket.SUBPROTOCOL_M2);
		if(payload.length != 14) throw new WSNProtocolException("message is too short for M2");
		idA = ((payload[2]&0xff)<<8 | payload[3]&0xff);
		idB = ((payload[4]&0xff)<<8 | payload[5]&0xff);
		idABytes = Arrays.copyOfRange(payload, 2, 4);
		idBBytes = Arrays.copyOfRange(payload, 4, 6);
		nonceA = Arrays.copyOfRange(payload, 6, 10);
		nonceB = Arrays.copyOfRange(payload, 10, 14);
	}

	@Override
	public boolean macIsValid() {
		//has no MAC, so nothing can be wrong
		return true;
	}

	public int getIDa() {
		return idA;
	}

	public int getIDb() {
		return idB;
	}

	public byte[] getNonceA() {
		return nonceA;
	}

	public byte[] getNonceB() {
		return nonceB;
	}

	@Override
	public WSNProtocolPacket process() throws WSNProtocolException {
		//packet has to come from node b
		if (getSourceId() != idB) {
			throw new WSNProtocolException("M2 comes from the wrong node!");
		}
		
		if (!KeyStore.nodesMayTalk(idA, idB)) {
			throw new WSNProtocolException("Nodes are not allowed to talk!");
		}
		
		//get all keys
		byte[] imkA = KeyStore.getKey(idA);
		byte[] imkB = KeyStore.getKey(idB);
		byte[] sessionKey = CryptoUtils.randomBytes(16);
		STikiUtils.logDetail("session key will be "+CryptoUtils.bytesToHex(sessionKey));
		byte[] iv = CryptoUtils.randomBytes(15);
		STikiUtils.logDetail("IV will be "+CryptoUtils.bytesToHex(iv));
		
		//precompute M4
		byte[] m4Header = getM4Header();
		byte[] tokenA = getTokenA(imkA, sessionKey, iv);
		byte[] packetForA = Arrays.concatenate(m4Header, iv, tokenA);
		byte[] macA = AES_CMAC.computeMAC(packetForA, imkA);
		STikiUtils.logDetail("MAC for A is "+CryptoUtils.bytesToHex(macA));

		//build M3
		byte[] m3Header = getM3Header();
		byte[] tokenB = getTokenB(imkB, sessionKey, iv);
		byte[] dataForB = Arrays.concatenate(Arrays.concatenate(m3Header, iv, tokenA), macA, tokenB);
		
		byte[] m3 = AES_CMAC.signWithMAC(dataForB, imkB);
		
		respondWith(m3);
		
		return null;
	}
	
	private byte[] getM3Header() {
		byte[] m3Header = new byte[2];
		STikiUtils.setMsgHeader(m3Header, STikiProtocol.STIKI_PROTOCOL_HANDSHAKE, SUBPROTOCOL_M3);
		return m3Header;
	}
	
	private byte[] getM4Header() {
		byte[] m3Header = new byte[2];
		STikiUtils.setMsgHeader(m3Header, STikiProtocol.STIKI_PROTOCOL_HANDSHAKE, SUBPROTOCOL_M4);
		return m3Header;
	}
	
	private byte[] getTokenA(byte[] imkA, byte[] sessionKey, byte[] iv) {
		byte[] token = Arrays.concatenate(idABytes, idBBytes, nonceA, sessionKey);
		STikiUtils.logDetail("Token for A is "+CryptoUtils.bytesToHex(token));
		byte[] encryptedToken = AES.ctrCrypt(imkA, token, iv);
		STikiUtils.logDetail("Encryped token for A is "+CryptoUtils.bytesToHex(encryptedToken));
		return encryptedToken;
	}
	
	private byte[] getTokenB(byte[] imkB, byte[] sessionKey, byte[] iv) {
		byte[] token = Arrays.concatenate(idABytes, idBBytes, nonceB, sessionKey);
		STikiUtils.logDetail("Token for B is "+CryptoUtils.bytesToHex(token));
		byte[] encryptedToken = AES.ctrCrypt(imkB, token, iv);
		STikiUtils.logDetail("Encryped token for B is "+CryptoUtils.bytesToHex(encryptedToken));
		return encryptedToken;
	}
	
	public String toString() {
		return "[STiki.HandshakePacketM2:"+
				" IDa: "+Integer.toHexString(idA)+
				" IDb: "+Integer.toHexString(idB)+
				" nonceA: "+CryptoUtils.bytesToHex(nonceA)+
				" nonceB: "+CryptoUtils.bytesToHex(nonceB)+
				" ]";
	}
	
	

}
