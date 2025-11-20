package com.ubivelox.iccard.common;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.joran.JoranConfigurator;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.Appender;
import ch.qos.logback.core.joran.spi.JoranException;
import ch.qos.logback.core.util.StatusPrinter;
import org.slf4j.ILoggerFactory;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.util.Iterator;

public final class LogbackFallbackInitializer {

    private static String FALLBACK_RESOURCE = "logback.xml";

    private static org.slf4j.Logger logger = LoggerFactory.getLogger(LogbackFallbackInitializer.class);
    private LogbackFallbackInitializer() {}

    /**
     * 애플리케이션 시작 초기에 한 번 호출.
     * - 호스트(상위)의 logback 설정이 있으면 아무것도 하지 않음.
     * - 없으면 라이브러리 내 `logback.xml` 을 찾아 적용함.
     */
    public static void init() {
        try {
            ILoggerFactory factory = LoggerFactory.getILoggerFactory();
            if (!(factory instanceof LoggerContext)) {
                logger.info("Not a Logback logging system detected, skipping fallback initialization.");
                return; // logback 아님 (다른 로거 사용)
            }

            LoggerContext ctx = (LoggerContext) factory;
            Logger root = ctx.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);


            Logger iccard = ctx.getLogger("com.ubivelox.iccard");
            if (iccard != null && iccard.iteratorForAppenders().hasNext()) {
                logger.info("ICCard logger already has appenders, skipping fallback initialization.");
                return;
            }


            // 루트의 appender 수 확인
            Iterator<Appender<ILoggingEvent>> appenderIterator = root.iteratorForAppenders();
            int count = 0;
            while (appenderIterator.hasNext()) {
                Appender<ILoggingEvent> appender = appenderIterator.next();
                logger.info("Found existing appender on root logger: {}", appender != null ? appender.getName() : "unknown");
                count++;
                // 2개 이상이면 더 이상 셀 필요 없음
                if (count >= 2) {
                    // 호스트에서 전체 로깅 설정으로 지정한 경우
                    logger.info("Root logger has {} appenders, skipping fallback initialization.", count);
                    FALLBACK_RESOURCE = "logback-noLog.xml";
                    break;
                }
            }

            InputStream is = findFallbackStream(FALLBACK_RESOURCE);
            logger.info("Attempting to load fallback logback configuration from '{}'", FALLBACK_RESOURCE);
            if (is == null) {
                logger.warn("Fallback logback configuration '{}' not found, skipping fallback initialization.", FALLBACK_RESOURCE);
                return;
            }

//            ctx.reset();
            JoranConfigurator configurator = new JoranConfigurator();
            configurator.setContext(ctx);
            configurator.doConfigure(is);
            StatusPrinter.printInCaseOfErrorsOrWarnings(ctx);
        } catch (JoranException ignored) {
            // 폴백 로딩 실패시 무시(호스트가 로그를 관리하도록 둠)
        } catch (Exception ignored) {
            // 안전을 위해 예외 무시
        }
    }

    private static InputStream findFallbackStream(String name) {
        // 여러 classloader에서 시도 (fat-jar, nested-jar, 외부 로더에 대비)
        InputStream is;

        is = LogbackFallbackInitializer.class.getResourceAsStream("/" + name);
        if (is != null) return is;

        ClassLoader cl = LogbackFallbackInitializer.class.getClassLoader();
        if (cl != null) {
            is = cl.getResourceAsStream(name);
            if (is != null) return is;
        }

        is = Thread.currentThread().getContextClassLoader().getResourceAsStream(name);
        if (is != null) return is;

        return ClassLoader.getSystemResourceAsStream(name);
    }
}
