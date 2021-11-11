package de.tum.in.net.WSNDataFramework.Protocols.STiki.Packet;

import java.net.InetSocketAddress;
import java.util.Random;

import org.bouncycastle.util.Arrays;

import de.tum.in.net.WSNDataFramework.WSNProtocolException;
import de.tum.in.net.WSNDataFramework.WSNProtocolPacket;
import de.tum.in.net.WSNDataFramework.Crypto.AES;
import de.tum.in.net.WSNDataFramework.Crypto.AES_CMAC;
import de.tum.in.net.WSNDataFramework.Crypto.CryptoUtils;
import de.tum.in.net.WSNDataFramework.Protocols.STiki.STikiProtocol;
import de.tum.in.net.WSNDataFramework.Protocols.STiki.STikiUtils;

public class DataTransportPacketCtr extends DataTransportPacket {

	public DataTransportPacketCtr(long packetID, byte[] payload, InetSocketAddress source)
			throws WSNProtocolException {
		super(packetID, payload, source, DataTransportPacket.STIKI_MSG_TYPE_TRANSPORT_CTR);
	}
	
	@Override
	public WSNProtocolPacket process() throws WSNProtocolException {
		doUnreliableNodeSimulation();
		
		if(!getSession().remoteIvIsSet()) {
			//send alert MISSING_IV
			missingIv();
			return null;
		}
		
		int dataStart = 4;
		byte[] iv = getSession().getRemoteIV();
		getSession().updateLastAction();
		int messageCounter = ((_payload[2]&0xff)<<8)|(_payload[3]&0xff);
		
		byte[] encryptedMessage = Arrays.copyOfRange(_payload, dataStart, _payload.length-16);
		byte[] decryptedMessage = AES.ctrCrypt(getSession().getEncryptionKey(), encryptedMessage, iv, messageCounter);
		STikiUtils.logCoarse("decrypted data is "+CryptoUtils.bytesToHex(decryptedMessage));
		
		return new WSNProtocolPacket(_id, decryptedMessage, _source);
	}
	
	/**
	 * If enabled, randomly makes the key server forget the IV.
	 */
	private void doUnreliableNodeSimulation() {
		Random rand = new Random();
		if(rand.nextFloat()<STikiProtocol.RANDOM_DROP_CHANCE) {
			STikiUtils.logCoarse("Randomly dropping IV!");
			getSession().invalidateRemoteIv();
		}
	}
	
	/**
	 * called when
	 * 1) session is established but
	 * 2) no valid IV is present
	 * 
	 * tells the sender to send a new IV along with the next message
	 */
	private void missingIv() {
		STikiUtils.logCoarse("Missing IV!");
		byte[] headerAndIds = new byte[6];
		STikiUtils.setMsgHeader(headerAndIds, STikiProtocol.STIKI_PROTOCOL_ALERT, AlertPacket.ALERT_NO_IV);
		int sourceId = getSourceId();
		headerAndIds[2] = (byte) ((sourceId>>8) & 0xff);
		headerAndIds[3] = (byte) (sourceId & 0xff);
		headerAndIds[4] = 0; //key server has ID 1
		headerAndIds[5] = 1; //key server has ID 1
		
		byte[] mac = AES_CMAC.computeMAC(headerAndIds, getSession().getMicKey());
		byte[] msg = Arrays.concatenate(headerAndIds, mac);
		
		respondWith(msg);
	}

}
