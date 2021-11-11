package de.tum.in.net.WSNDataFramework.Protocols.STiki.Packet;

import java.net.InetSocketAddress;

import org.bouncycastle.util.Arrays;

import de.tum.in.net.WSNDataFramework.WSNProtocolException;
import de.tum.in.net.WSNDataFramework.WSNProtocolPacket;
import de.tum.in.net.WSNDataFramework.Crypto.AES;
import de.tum.in.net.WSNDataFramework.Crypto.CryptoUtils;
import de.tum.in.net.WSNDataFramework.Protocols.STiki.STikiUtils;

public class DataTransportPacketIv extends DataTransportPacket {

	public DataTransportPacketIv(long packetID, byte[] payload, InetSocketAddress source)
			throws WSNProtocolException {
		super(packetID, payload, source, DataTransportPacket.STIKI_MSG_TYPE_TRANSPORT_IV);
	}
	
	@Override
	public WSNProtocolPacket process() throws WSNProtocolException {
		int dataStart = 15;
		int messageCounter = 0;
		byte[] iv = Arrays.copyOfRange(_payload, 2, 17);
		getSession().setRemoteIV(iv);//new IV was sent along, we need to store it
		STikiUtils.logDetail("new remote IV is "+CryptoUtils.bytesToHex(iv));
		getSession().updateLastAction();
		
		byte[] encryptedMessage = Arrays.copyOfRange(_payload, dataStart, _payload.length-16);
		STikiUtils.logDetail("Encrypted data is "+CryptoUtils.bytesToHex(encryptedMessage));
		byte[] decryptedMessage = AES.ctrCrypt(getSession().getEncryptionKey(), encryptedMessage, iv, messageCounter);
		STikiUtils.logCoarse("Decrypted data is "+CryptoUtils.bytesToHex(decryptedMessage));
		
		return new WSNProtocolPacket(_id, decryptedMessage, _source);
	}

}
