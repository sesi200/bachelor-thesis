package de.tum.in.net.WSNDataFramework.Protocols.STiki.Packet;

import java.net.InetSocketAddress;
import java.util.Random;

import de.tum.in.net.WSNDataFramework.WSNProtocolException;
import de.tum.in.net.WSNDataFramework.WSNProtocolPacket;
import de.tum.in.net.WSNDataFramework.Protocols.STiki.STikiProtocol;
import de.tum.in.net.WSNDataFramework.Protocols.STiki.STikiUtils;
import de.tum.in.net.WSNDataFramework.Protocols.STiki.Session.STikiSession;
import de.tum.in.net.WSNDataFramework.Protocols.STiki.Session.STikiSessionStore;

public abstract class STikiPacket extends WSNProtocolPacket{
	
	protected byte _protocol;
	protected byte _subprotocol;

	public STikiPacket(long id, byte[] payload, InetSocketAddress source, byte protocol, byte subprotocol) {
		super(id, payload, source);
		_protocol = protocol;
		_subprotocol = subprotocol;
	}
	
	abstract public boolean macIsValid();
	
	//takes action according to protocol
	//returns a packet to use for the next layer, null if the packet contains nothing for the next layer
	abstract public WSNProtocolPacket process() throws WSNProtocolException;

	public byte getProtocol() {
		return _protocol;
	}
	
	public byte getSubprotocol() {
		return _subprotocol;
	}
	
	public void respondWith(byte[] data) {
		STikiUtils.sendTo(STikiUtils.fixEndian(_source), data);
	}
	
	public int getSourceId() {
		byte[] address = STikiUtils.fixEndian(_source).getAddress();
		return STikiUtils.getIdFromIp(address);
		
	}
	
	/**
	 * @return the session with this packet's sender
	 */
	protected STikiSession getSession() {
		return STikiSessionStore.getSession(getSourceId());
	}
	
	public boolean hasActiveSession() {
		return getSession().isActive();
	}
	
	/**
	 * Use case: determining whether or not to send INVALID_SESSION alert
	 * @return true if the packet a) needs an active session to process() AND b) the current session is not active
	 */
	public boolean missesSession() {
		if (!hasActiveSession() && !(this instanceof HandshakePacket)) return true;
		
		Random rand = new Random();
		if (rand.nextDouble()<STikiProtocol.RANDOM_DROP_CHANCE) {
			STikiUtils.logCoarse("Random session Drop!");
			return true;
		}
		
		return false;
	}

	public static STikiPacket parse(WSNProtocolPacket packet) throws WSNProtocolException {
		byte subprotocol = (byte) (packet.getPayload()[1] & 0x1f); //bits 4-8 in second byte denote the subprotocol
		byte protocol = (byte ) ((packet.getPayload()[1] & (0x7<<5))>>5); //bits 1-3 in second byte denote the protocol
		
		STikiUtils.logDetail("Header details: Protocol "+protocol+", Subprotocol: "+subprotocol);
		
		switch(protocol) {
		case STikiProtocol.STIKI_PROTOCOL_ALERT:
			return AlertPacket.parse(packet);
		case STikiProtocol.STIKI_PROTOCOL_DATA_TRANSPORT:
			return DataTransportPacket.parse(packet);
		case STikiProtocol.STIKI_PROTOCOL_HANDSHAKE:
			return HandshakePacket.parse(packet);
		default:
			throw new WSNProtocolException("Found no sTiki protocol with id " + protocol + " and subprotocol with id " + subprotocol);
		}
	}
}
