package de.tum.in.net.WSNDataFramework.Protocols.STiki;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import de.tum.in.net.WSNDataFramework.Crypto.CryptoUtils;
public class STikiUtils {
	
	private static byte[] nodeIpPrefix = null;

	public static InetAddress fixEndian(InetSocketAddress addr) {
		String[] tokens = addr.getAddress().getHostAddress().split(":");
		List<String> rotated = Arrays.asList(tokens);
		Collections.rotate(rotated, 4);
		String fixed = String.join(":", (String[])rotated.toArray());
		return new InetSocketAddress(fixed, 0).getAddress();
	}

	public static int getIdFromIp(byte[] address) {
		if(nodeIpPrefix == null) {
			nodeIpPrefix = Arrays.copyOfRange(address, 0, 14);
		}
		return (((address[14]<<8)&0xff00) | (address[15]&0xff))&0xffff;
	}

	public static void setMsgHeader(byte[] msg, byte protocol, byte subprotocol) {
		msg[0] = STikiProtocol.STIKI_MAGIC_NUMBER;
		msg[1] = (byte) (((protocol<<5) | (subprotocol&0x1f)) & 0xff);
	}

	public static InetAddress getIpFromId(int sourceId) {
		byte[] ipBytes = org.bouncycastle.util.Arrays.concatenate(nodeIpPrefix, new byte[] {(byte) ((sourceId>>8)&0xff), (byte) (sourceId&0xff)});
		try {
			return InetAddress.getByAddress(ipBytes);
		} catch (UnknownHostException e) {
			e.printStackTrace();
		}
		return null;
	}

	@SuppressWarnings("unused")
	public static void logDetail(String message) {
		if(STikiProtocol.LOGGING_LEVEL>=2) System.out.println("[sTiki] "+message);
	}

	@SuppressWarnings("unused")
	public static void logCoarse(String message) {
		if(STikiProtocol.LOGGING_LEVEL>=1) System.out.println("[sTiki] "+message);
	}

	/**
	 * Sends a message without encrypting
	 * Sends on port 1234, which is the port the nodes listen to when talking with the sink
	 * @param address
	 * @param data
	 */
	public static void sendTo(InetAddress address, byte[] data) {
		logDetail("sending "+CryptoUtils.bytesToHex(data)+" to "+address.toString());
		DatagramSocket clientSocket;
		try {
			clientSocket = new DatagramSocket(1234);
		} catch (SocketException e) {
			e.printStackTrace();
			return;
		}
		
		DatagramPacket sendPacket = new DatagramPacket(data, data.length, address, 1234);
		
		try {
			clientSocket.send(sendPacket);
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			clientSocket.close();
		}
	}

}
