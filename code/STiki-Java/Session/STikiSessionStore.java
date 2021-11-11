package de.tum.in.net.WSNDataFramework.Protocols.STiki.Session;

import java.util.HashMap;

public class STikiSessionStore {
	
	private static HashMap<Integer, STikiSession> sessions = new HashMap<>();
	
	private STikiSessionStore() {}
	
	public static STikiSession getSession(int id) {
		if(!sessions.containsKey(id)) {
			sessions.put(id, new STikiSession(id));
		}
		return sessions.get(id);
	}
	
	public static String asString() {
		String s = "[STiki.TSSessionStore content:\n";
		for(STikiSession session : sessions.values()) {
			s = s+"    "+session.toString()+"\n";
		}
		s=s+"]";
		return s;
	}

}
