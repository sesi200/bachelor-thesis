package de.tum.in.net.WSNDataFramework.Protocols.STiki.Packet;

import java.net.InetSocketAddress;

import de.tum.in.net.WSNDataFramework.WSNProtocolException;
import de.tum.in.net.WSNDataFramework.WSNProtocolPacket;
import de.tum.in.net.WSNDataFramework.Protocols.STiki.STikiProtocol;

public abstract class HandshakePacket extends STikiPacket {
	
	public static final byte SUBPROTOCOL_M1 = 0x01;
	public static final byte SUBPROTOCOL_M2 = 0x02;
	public static final byte SUBPROTOCOL_M3 = 0x03;
	public static final byte SUBPROTOCOL_M4 = 0x04;

	public HandshakePacket(long id, byte[] payload, InetSocketAddress source,  byte subprotocol) {
		super(id, payload, source, STikiProtocol.STIKI_PROTOCOL_HANDSHAKE, subprotocol);
	}
	
	public static HandshakePacket parse(WSNProtocolPacket packet) throws WSNProtocolException {
		byte subprotocol = (byte) (packet.getPayload()[1] & 0x1f); //bits 4-8 in second byte denote the subprotocol
		switch(subprotocol) {
		case HandshakePacket.SUBPROTOCOL_M1:
			return new HandshakePacketM1(packet.getID(), packet.getPayload(), packet.getSourceAddress());
		case HandshakePacket.SUBPROTOCOL_M2:
			return new HandshakePacketM2(packet.getID(), packet.getPayload(), packet.getSourceAddress());
		case HandshakePacket.SUBPROTOCOL_M3:
			throw new WSNProtocolException("Received Handshake M3. I don't know how to work with another key server.");
		case HandshakePacket.SUBPROTOCOL_M4:
			return new HandshakePacketM4(packet.getID(), packet.getPayload(), packet.getSourceAddress());
		default:
			throw new WSNProtocolException(subprotocol + " is no valid subprotocol for handshakes!");
		}
	}

}
