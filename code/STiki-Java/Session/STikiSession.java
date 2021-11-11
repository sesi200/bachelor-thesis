package de.tum.in.net.WSNDataFramework.Protocols.STiki.Session;

import java.time.Instant;

import de.tum.in.net.WSNDataFramework.Crypto.AES;
import de.tum.in.net.WSNDataFramework.Crypto.CryptoUtils;
import de.tum.in.net.WSNDataFramework.Protocols.STiki.STikiProtocol;
import de.tum.in.net.WSNDataFramework.Protocols.STiki.STikiUtils;

public class STikiSession {
	
	public static final long SESSION_TIMEOUT = 3600;
	
	private static final byte[] CRYPT_DERIVE_BLOCK = new byte[] {0x49,0x49,0x49,0x49,0x49,0x49,0x49,0x49,0x49,0x49,0x49,0x49,0x49,0x49,0x49,0x49};
	private static final byte[] INTEG_DERIVE_BLOCK = new byte[] {0x70,0x70,0x70,0x70,0x70,0x70,0x70,0x70,0x70,0x70,0x70,0x70,0x70,0x70,0x70,0x70};
	
	int remoteId;
	Instant lastActive;
	byte[] localIV = null; //length = 13 (because: block size is 16, iv does not contain msg counter(2 bytes) and block counter(1 byte))
	byte[] remoteIV = null;//length = 13 (because: block size is 16, iv does not contain msg counter(2 bytes) and block counter(1 byte))
	int localMsgCounter = 0;
	byte[] encryptionKey = null; //key used for data transport
	byte[] micKey = null; //key used for MAC computation (MIC = message integrity check)
	byte[] storedPacket = null; //packet which initiated the handshake. gets sent after handshake is complete
	
	
	public STikiSession(int remoteId) {
		this.remoteId = remoteId;
		lastActive = Instant.now();
	}
	
	//generates and sets a new session key
	//returns the new key
	public byte[] newKey() {
		byte[] key = new byte[16];
		CryptoUtils.fillWithRandom(key);
		setSessionKey(key);
		return key;
	}
	
	private boolean isTimedOut() {
		return lastActive.plusSeconds(SESSION_TIMEOUT).isBefore(Instant.now());
	}
	
	public boolean isActive() {
		return !isTimedOut() && encryptionKey!=null;
	}
	
	public void setRemoteIV(byte[] iv) {
		remoteIV = iv;
	}
	
	public byte[] getRemoteIV() {
		return remoteIV;
	}
	
	public boolean remoteIvIsSet() {
		return remoteIV != null;
	}
 	
	public byte[] newLocalIV() {
		localIV = CryptoUtils.randomBytes(13);
		return localIV;
	}
	
	public byte[] getLocalIV() {
		return localIV;
	}
	
	public boolean localIvIsSet() {
		return localIV != null;
	}
	
	public int nextMsgCounter() {
		return localMsgCounter++;
	}

	public byte[] nextMsgCounterBytes() {
		byte[] ctr = new byte[2];
		int num = nextMsgCounter();
		ctr[0] = (byte) ((num>>8)&0xff);
		ctr[1] = (byte) (num&0xff);
		return ctr;
	}
	
	public void setSessionKey(byte[] sessionKey) {
		encryptionKey = AES.encrypt(sessionKey, CRYPT_DERIVE_BLOCK);
		micKey = AES.encrypt(sessionKey, INTEG_DERIVE_BLOCK);
		//if we set a new session key, reset the session
		localIV = null;
		remoteIV = null;
		localMsgCounter = 0;
		lastActive = Instant.now();
	}
	
	public byte[] getEncryptionKey() {
		return encryptionKey;
	}
	
	public byte[] getMicKey() {
		return micKey;
	}

	public void invalidateLocalIv() {
		STikiUtils.logDetail("Invalidating local IV for node "+Integer.toHexString((int) remoteId));
		localIV = null;
		localMsgCounter = 0;
	}
	
	public void invalidateRemoteIv() {
		STikiUtils.logDetail("Invalidating remote IV for node "+Integer.toHexString((int) remoteId));
		remoteIV = null;
	}

	public void invalidateSession() {
		STikiUtils.logDetail("Invalidating session for node "+Integer.toHexString((int) remoteId));
		lastActive = Instant.now().minusSeconds(SESSION_TIMEOUT+1);
	}
	
	public void updateLastAction() {
		lastActive = Instant.now();
	}
	
	public void storePacket(byte[] packet) {
		storedPacket = packet;
	}
	
	public void sendStoredPacket() {
		STikiProtocol.encryptAndSendTo(storedPacket, STikiUtils.getIpFromId(remoteId));
		storedPacket = null;
	}
	
	public String toString() {
		return "[STiki.TSSession:"+
				" RemoteID: "+remoteId+
				" Active: "+(isActive()?"YES":"NO ")+
				" Last active: "+lastActive.toString()+
				" localIV: " + (localIV == null ? "null" : "byte["+localIV.length+"] "+CryptoUtils.bytesToHex(localIV))+
				" remoteIV: " + (remoteIV == null ? "null" : ("byte["+remoteIV.length+"]"+CryptoUtils.bytesToHex(remoteIV)))+
				" localMsgCounter: "+localMsgCounter+
				" encryptionKey: " + (encryptionKey == null ? "null" : ("byte["+encryptionKey.length+"]"+CryptoUtils.bytesToHex(encryptionKey)))+
				" micKey: "+ (micKey == null ? "null" : ("byte["+micKey.length+"]"+CryptoUtils.bytesToHex(micKey)))+
				" ]" ;
	}

}
