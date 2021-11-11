package de.tum.in.net.WSNDataFramework.Protocols.STiki.Packet;

import java.net.InetSocketAddress;

import org.bouncycastle.util.Arrays;

import de.tum.in.net.WSNDataFramework.WSNProtocolException;
import de.tum.in.net.WSNDataFramework.WSNProtocolPacket;
import de.tum.in.net.WSNDataFramework.Crypto.AES_CMAC;
import de.tum.in.net.WSNDataFramework.Crypto.KeyStore;
import de.tum.in.net.WSNDataFramework.Protocols.STiki.STikiProtocol;
import de.tum.in.net.WSNDataFramework.Protocols.STiki.STikiUtils;

public class AlertPacketInvalidSessionToKs extends AlertPacket{

	public AlertPacketInvalidSessionToKs(long id, byte[] payload, InetSocketAddress source)
			throws WSNProtocolException {
		super(id, payload, source, AlertPacket.ALERT_INVALID_SESSION_TO_KS);
	}

	@Override
	public WSNProtocolPacket process() {
		STikiUtils.logCoarse("Handling invalid Session between "+Integer.toHexString(idSource)+" and "+Integer.toHexString(idTarget));
		
		if(!KeyStore.nodesMayTalk(idSource, idTarget)) {
			STikiUtils.logDetail("Nodes are not allowed to talk");
			return null;
		}
		
		if(idSource==1) {
			//1 is our ID. Different treatment than for other nodes
			getSession().invalidateSession();
		} else {
			notifySourceNode();
		}
		
		return null;
	}
	
	private void notifySourceNode() {
		byte[] msgPayload = getReturnPayload();
		byte[] targetKey = KeyStore.getKey(idTarget);
		byte[] msg = AES_CMAC.signWithMAC(msgPayload, targetKey);
		STikiUtils.sendTo(STikiUtils.getIpFromId(idSource), msg);
	}
	
	private byte[] getReturnPayload() {
		byte[] msgPayload = Arrays.copyOfRange(_payload, 0, 6); //we can reuse the payload, we just need to set the header properly and recompute the MAC
		STikiUtils.setMsgHeader(msgPayload, STikiProtocol.STIKI_PROTOCOL_ALERT, ALERT_INVALID_SESSION_TO_NODE);
		return msgPayload;
	}

}
