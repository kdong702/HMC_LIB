package com.ubivelox.iccard.common;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
@Getter
@Setter
public class CustomLog {

    private final String uuid;

    public CustomLog() {
        this.uuid = java.util.UUID.randomUUID().toString().replace("-", "");
    }

    public void info(String message, Object... values)  {
        String format = "[{}] " + message;
        List<Object> objList = new ArrayList<>(Arrays.asList(values));
        objList.add(0, uuid);

        Object[] objects = objList.toArray();

        Method declaredMethod = null;
        try {
            declaredMethod = log.getClass().getDeclaredMethod("info", String.class, Object[].class);
            declaredMethod.invoke(log, format, objects);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    public void error(String message, Object... values)  {
        String format = "[{}] " + message;
        List<Object> objList = new ArrayList<>(Arrays.asList(values));
        objList.add(0, uuid);

        Object[] objects = objList.toArray();

        Method declaredMethod = null;
        try {
            declaredMethod = log.getClass().getDeclaredMethod("error", String.class, Object[].class);
            declaredMethod.invoke(log, format, objects);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }
}
