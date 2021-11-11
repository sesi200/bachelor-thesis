package de.tum.in.net.WSNDataFramework.Protocols.STiki;

import java.net.InetAddress;
import java.util.Random;

import de.tum.in.net.WSNDataFramework.WSNProtocol;
import de.tum.in.net.WSNDataFramework.WSNProtocolException;
import de.tum.in.net.WSNDataFramework.WSNProtocolPacket;
import de.tum.in.net.WSNDataFramework.Crypto.CryptoUtils;
import de.tum.in.net.WSNDataFramework.Protocols.STiki.Packet.AlertPacket;
import de.tum.in.net.WSNDataFramework.Protocols.STiki.Packet.DataTransportPacket;
import de.tum.in.net.WSNDataFramework.Protocols.STiki.Packet.HandshakePacket;
import de.tum.in.net.WSNDataFramework.Protocols.STiki.Packet.STikiPacket;
import de.tum.in.net.WSNDataFramework.Protocols.STiki.Session.STikiSession;
import de.tum.in.net.WSNDataFramework.Protocols.STiki.Session.STikiSessionStore;

public class STikiProtocol extends WSNProtocol{
	public static final int LOGGING_LEVEL = 0; //0=none, 1=coarse, 2=detailed
	
	//constants to use while testing/debugging
	public static final double RANDOM_DROP_CHANCE = 0;
	public static final double RANDOM_RESPONSE_CHANCE = 0;
	
	public static final byte STIKI_MAGIC_NUMBER = (byte) 0xef;
	public static final byte STIKI_PROTOCOL_DATA_TRANSPORT = (byte) 0x01;
	public static final byte STIKI_PROTOCOL_HANDSHAKE = (byte) 0x02;
	public static final byte STIKI_PROTOCOL_ALERT = (byte) 0x03;
	
	@Override
	public String getName() {
		return "sTiki Protocol";
	}

	@Override
	public WSNProtocolPacket process(WSNProtocolPacket packet) throws WSNProtocolException {
		
		STikiUtils.logDetail("Received data: "+CryptoUtils.bytesToHex(packet.getPayload()));
		
		if(!isSTikiPacket(packet)) {
			STikiUtils.logCoarse("Not an sTiki packet!");
			return packet; //not an sTiki packet, do not touch
		}

		STikiPacket tikiPacket = STikiPacket.parse(packet);
		STikiUtils.logCoarse(tikiPacket.toString());
		
		if(tikiPacket.missesSession()) {
			STikiUtils.logCoarse("No Session found. Sending INVALID_SESSION");
			AlertPacket.sendInvalidSession(tikiPacket.getSourceId(), 1/*Key server ID*/);
			return null;
		}
		
		if(!tikiPacket.macIsValid()) {
			STikiUtils.logCoarse("Invalid MAC!");
			return null;
		} else {
			STikiUtils.logDetail("MAC is valid!");
		}
		
		//useless response, used for testing/debugging
		Random rand = new Random();
		if(rand.nextFloat()<RANDOM_RESPONSE_CHANCE) {
			System.out.println("Responding");
			encryptAndSendTo(new byte[] {(byte) 0x0f, (byte) 0x0f, 0, 0, 0, 0}, STikiUtils.fixEndian(tikiPacket.getSourceAddress()));
		}
		
		return tikiPacket.process();
	}
	
	//this method logically belongs to the class STikiUtils but is kept here because it makes more sense for using sTiki:
	//STikiProtocol.encryptAndSendTo(...) makes more sense (and is easier to find) than STikiUtils.encryptAndSendTo(...)
	public static void encryptAndSendTo(byte[] payload, InetAddress address) {
		STikiSession session = STikiSessionStore.getSession(STikiUtils.getIdFromIp(address.getAddress()));
		if(!session.isActive()) {
			session.storePacket(payload);
			STikiUtils.logDetail("no active session found");
			startHandshake(address);
			return;
		}
		
		byte[] message = DataTransportPacket.makeDataTransportPacket(session, payload);
		
		STikiUtils.sendTo(address, message);
	}
	
	private static void startHandshake(InetAddress target) {
		byte[] m1 = CryptoUtils.randomBytes(10); //fills nonce with random stuff
		STikiUtils.setMsgHeader(m1, STIKI_PROTOCOL_HANDSHAKE, HandshakePacket.SUBPROTOCOL_M1);
		m1[2] = 0; //set my ID
		m1[3] = 1; //set my ID
		m1[4] = target.getAddress()[14]; //remote ID
		m1[5] = target.getAddress()[15]; //remote ID
		
		STikiUtils.sendTo(target, m1);
	}
	
	private static boolean isSTikiPacket(WSNProtocolPacket packet) {
		return packet.getPayload()[0]==STIKI_MAGIC_NUMBER;
	}
}
