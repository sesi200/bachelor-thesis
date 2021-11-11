package de.tum.in.net.WSNDataFramework.Protocols.STiki.Packet;

import java.net.InetSocketAddress;

import de.tum.in.net.WSNDataFramework.WSNProtocolException;
import de.tum.in.net.WSNDataFramework.WSNProtocolPacket;
import de.tum.in.net.WSNDataFramework.Protocols.STiki.STikiUtils;
import de.tum.in.net.WSNDataFramework.Protocols.STiki.Session.STikiSession;
import de.tum.in.net.WSNDataFramework.Protocols.STiki.Session.STikiSessionStore;

public class AlertPacketNoIv extends AlertPacket{

	public AlertPacketNoIv(long id, byte[] payload, InetSocketAddress source)
			throws WSNProtocolException {
		super(id, payload, source, AlertPacket.ALERT_NO_IV);
	}
	
	@Override
	public WSNProtocolPacket process() {
		STikiSession session = STikiSessionStore.getSession(getSourceId());
		STikiUtils.logCoarse("Node "+Integer.toHexString(getSourceId())+" lost the IV");
		session.invalidateLocalIv();
		return null;
	}

}
