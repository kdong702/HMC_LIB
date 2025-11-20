package com.ubivelox.iccard.util;

import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import java.util.Properties;

@Slf4j
public class PropertyReader {

    private static final Properties PROPS = new Properties();
    private static final String NAME = "hsm_lib.properties";
    private PropertyReader() {}

    private static synchronized void loadIfNeeded() {
        if (!PROPS.isEmpty()) return;


        // 2) 클래스패스 - 여러 방식으로 시도 (특히 Spring Boot fat JAR / nested JAR 대응)
        // 2.1 현재 클래스의 리소스 (같은 JAR이나 nested JAR에서 찾기 용이)
        if (tryLoadResource(PropertyReader.class.getResourceAsStream("/" + NAME), "class.getResourceAsStream")) {
            return;
        }

        // 2.2 클래스 로더 (클래스의 클래스로더)
        if (tryLoadResource(PropertyReader.class.getClassLoader().getResourceAsStream(NAME), "class.getClassLoader")) {
            return;
        }

        // 2.3 스레드 컨텍스트 클래스로더
        if (tryLoadResource(Thread.currentThread().getContextClassLoader().getResourceAsStream(NAME), "thread.contextClassLoader")) {
            return;
        }

        // 2.4 시스템 클래스로더
        if (tryLoadResource(ClassLoader.getSystemResourceAsStream(NAME), "systemClassLoader")) {
            return;
        }

        // 3) 작업 디렉터리
        Path wd = Path.of(NAME);
        if (Files.exists(wd)) {
            try (InputStream is = Files.newInputStream(wd)) {
                PROPS.load(is);
                log.info("Loaded properties from working dir: {}", wd);
                return;
            } catch (IOException ignored) {}
        }

        // 4) 개발 경로
        Path dev = Path.of("src", "main", "resources", NAME);
        if (Files.exists(dev)) {
            try (InputStream is = Files.newInputStream(dev)) {
                PROPS.load(is);
                log.info("Loaded properties from dev path: {}", dev);
                return;
            } catch (IOException e) {
                log.warn("Failed loading dev properties {}: {}", dev, e.getMessage());
            }
        }

        log.error("No properties loaded. Looked for: system/env, classpath, working dir, and {}", dev);
    }

    private static boolean tryLoadResource(InputStream is, String source) {
        if (is == null) return false;
        try (InputStream input = is) {
            PROPS.load(input);
            log.info("Loaded properties from classpath using: {}", source);
            return true;
        } catch (IOException e) {
            log.warn("Failed loading properties from {}: {}", source, e.getMessage());
            return false;
        }
    }

    public static String getProperty(String key) {
        loadIfNeeded();
        return PROPS.getProperty(key);
    }

    public static String getProperty(String key, String def) {
        loadIfNeeded();
        return Objects.toString(PROPS.getProperty(key), def);
    }
}
