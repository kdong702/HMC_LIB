package com.lotson.cas.task;

import java.util.Map;

public interface ITask {
	public void init(Map<String, Object> params);
	public Map<String, Object> doTask(Map<String, Object> params, long sessionId) throws TaskException;
	public String doTask(String hexData, long sessionId) throws TaskException;
	public String doTask(String hexData, long sessionId, String transId) throws TaskException;
	public Object doLogic(Object request, long sessionId, String transId) throws TaskException;
}
