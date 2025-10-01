package com.ubivelox.iccard.task;

public interface ITask {

	HmcProtocol.Response doLogic(HmcProtocol.Request request, long sessionId, String transId);

	default long openSession(String slotLabel) { return 0; }
	default void closeSession(long sessionId) {}
}
