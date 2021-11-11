package de.tum.in.net.WSNDataFramework.Protocols.STiki.Packet;

import java.net.InetSocketAddress;

import org.bouncycastle.util.Arrays;

import de.tum.in.net.WSNDataFramework.WSNProtocolException;
import de.tum.in.net.WSNDataFramework.WSNProtocolPacket;
import de.tum.in.net.WSNDataFramework.Crypto.AES;
import de.tum.in.net.WSNDataFramework.Crypto.AES_CMAC;
import de.tum.in.net.WSNDataFramework.Crypto.CryptoUtils;
import de.tum.in.net.WSNDataFramework.Protocols.STiki.STikiProtocol;
import de.tum.in.net.WSNDataFramework.Protocols.STiki.STikiUtils;
import de.tum.in.net.WSNDataFramework.Protocols.STiki.Session.STikiSession;

public abstract class DataTransportPacket extends STikiPacket {
	
	public static final byte STIKI_MSG_TYPE_TRANSPORT_IV = 0x01;
	public static final byte STIKI_MSG_TYPE_TRANSPORT_CTR = 0x02;
	
	private byte[] _MAC;
	private int subprotocol;

	public DataTransportPacket(long packetID, byte[] payload, InetSocketAddress source, byte subprotocol) throws WSNProtocolException {
		super(packetID, payload, source, STikiProtocol.STIKI_PROTOCOL_DATA_TRANSPORT, subprotocol);
		if(payload.length < 20) throw new WSNProtocolException("DataTransport packet is not long enough to contain anything!"); //header: 2b, counter: 1b, MAC: 16b, data: 1+b
		this.subprotocol = subprotocol;
		_MAC = Arrays.copyOfRange(payload, payload.length-16, payload.length);
	}

	@Override
	public boolean macIsValid() {
		return AES_CMAC.macIsValid(Arrays.copyOfRange(_payload, 0, _payload.length-16), getSession().getMicKey(), _MAC);
	}
	
	public String toString() {
		return "[STiki.DataTransportPacket:"+
					" Source: "+_source.getHostString()+
					" MAC: "+CryptoUtils.bytesToHex(_MAC)+
					" subprotocol: "+subprotocol+
					" ]";
	}
	
	public static DataTransportPacket parse(WSNProtocolPacket packet) throws WSNProtocolException{
		byte subprotocol = (byte) (packet.getPayload()[1] & 0x1f); //bits 4-8 in second byte denote the subprotocol
		switch (subprotocol) {
		case STIKI_MSG_TYPE_TRANSPORT_IV:
			return new DataTransportPacketIv(packet.getID(), packet.getPayload(), packet.getSourceAddress());
		case STIKI_MSG_TYPE_TRANSPORT_CTR:
			return new DataTransportPacketCtr(packet.getID(), packet.getPayload(), packet.getSourceAddress());
		default:
			throw new WSNProtocolException("No subprotocol to STIKI_PROTOCOL_DATA_TRANSPORT with ID "+subprotocol+" exists!"); 
		}
	}

	public static byte[] makeDataTransportPacket(STikiSession session, byte[] payload) {
		byte[] header = new byte[2];
		byte[] ivOrMsgCounter;
		
		if(session.localIvIsSet()) {
			STikiUtils.setMsgHeader(header, STikiProtocol.STIKI_PROTOCOL_DATA_TRANSPORT, STIKI_MSG_TYPE_TRANSPORT_CTR);
			ivOrMsgCounter = session.nextMsgCounterBytes();
		} else {
			STikiUtils.setMsgHeader(header, STikiProtocol.STIKI_PROTOCOL_DATA_TRANSPORT, STIKI_MSG_TYPE_TRANSPORT_IV);
			ivOrMsgCounter = session.newLocalIV();
		}
		STikiUtils.logDetail("encrypting "+CryptoUtils.bytesToHex(payload)+" with key "+CryptoUtils.bytesToHex(session.getEncryptionKey())+", IV "+CryptoUtils.bytesToHex(session.getLocalIV()));
		byte[] encryptedPayload = AES.ctrCrypt(session.getEncryptionKey(), payload, session.getLocalIV(), session.nextMsgCounter());
		STikiUtils.logDetail("encrypted result: "+CryptoUtils.bytesToHex(encryptedPayload));
		
		byte[] messageWithoutMac = Arrays.concatenate(header, ivOrMsgCounter, encryptedPayload);
		byte[] message = AES_CMAC.signWithMAC(messageWithoutMac, session.getMicKey());
		STikiUtils.logDetail("with MAC: "+CryptoUtils.bytesToHex(message));
		
		return message;
	}

}
