
package de.tum.in.net.WSNDataFramework.Protocols.STiki.Packet;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.bouncycastle.util.Arrays;

import de.tum.in.net.WSNDataFramework.WSNProtocolException;
import de.tum.in.net.WSNDataFramework.WSNProtocolPacket;
import de.tum.in.net.WSNDataFramework.Crypto.AES_CMAC;
import de.tum.in.net.WSNDataFramework.Crypto.CryptoUtils;
import de.tum.in.net.WSNDataFramework.Crypto.KeyStore;
import de.tum.in.net.WSNDataFramework.Protocols.STiki.STikiProtocol;
import de.tum.in.net.WSNDataFramework.Protocols.STiki.STikiUtils;

public abstract class AlertPacket extends STikiPacket {
	
	private byte[] _MAC;
	protected int idSource;
	protected int idTarget;
	
	public static final byte ALERT_NO_IV = 0x03;
	public static final byte ALERT_INVALID_SESSION_TO_NODE = 0x05;
	public static final byte ALERT_INVALID_SESSION_TO_KS = 0x04;

	public AlertPacket(long id, byte[] payload, InetSocketAddress source, byte subprotocol) throws WSNProtocolException {
		super(id, payload, source, STikiProtocol.STIKI_PROTOCOL_ALERT, subprotocol);
		if(payload.length != 22) throw new WSNProtocolException("Bad alert message length! Expected 22, received " + payload.length);
		idSource = ((payload[2]&0xff)<<8 | payload[3]&0xff);
		idTarget = ((payload[4]&0xff)<<8 | payload[5]&0xff);
		_MAC = Arrays.copyOfRange(payload, 6, 22);
	}

	@Override
	public boolean macIsValid() {
		byte[] key = KeyStore.getKey(getSourceId());
		if(key == null) return false; //node does not belong to our network
		
		return AES_CMAC.macIsValid(Arrays.copyOfRange(_payload, 0, 6), key, _MAC);
	}

	@Override
	abstract public WSNProtocolPacket process();
	
	public String toString() {
		return "[STiki.AlertPacket:"+
				" sourceId: "+Integer.toHexString(idSource)+
				" targetId: "+Integer.toHexString(idTarget)+
				" MAC: "+CryptoUtils.bytesToHex(_MAC)+
				" subprotocol: "+getSubprotocol()+
				" from: "+Integer.toHexString(getSourceId())+
				" ]";
	}

	public static void sendInvalidSession(int sourceId, int destinationId) {
		byte[] msg = AlertPacket.buildInvalidSessionMessage(sourceId, destinationId);
		byte[] nodeKey = KeyStore.getKey(sourceId);
		InetAddress ip = STikiUtils.getIpFromId(sourceId);
		
		STikiUtils.sendTo(ip, AES_CMAC.signWithMAC(msg, nodeKey));
	}

	private static byte[] buildInvalidSessionMessage(int sourceId, int destinationId) {
		byte[] msg = new byte[6];
		STikiUtils.setMsgHeader(msg, STikiProtocol.STIKI_PROTOCOL_ALERT, ALERT_INVALID_SESSION_TO_NODE);
		msg[2] = (byte) (0xff & (sourceId>>8));
		msg[3] = (byte) (0xff & sourceId);
		msg[4] = (byte) (0xff & (destinationId>>8));
		msg[5] = (byte) (0xff & destinationId);
		
		return msg;
	}
	
	public static AlertPacket parse(WSNProtocolPacket packet) throws WSNProtocolException {
		byte subprotocol = (byte) (packet.getPayload()[1] & 0x1f); //bits 4-8 in second byte denote the subprotocol
		
		switch (subprotocol) {
		case ALERT_NO_IV:
			return new AlertPacketNoIv(packet.getID(), packet.getPayload(), packet.getSourceAddress());
		case ALERT_INVALID_SESSION_TO_KS:
			return new AlertPacketInvalidSessionToKs(packet.getID(), packet.getPayload(), packet.getSourceAddress());
		case ALERT_INVALID_SESSION_TO_NODE:
			throw new WSNProtocolException("Don't know how to work with another key server!");
		default:
			throw new WSNProtocolException("ALERT protocol has no subprotocol "+subprotocol);
		}
	}

}
