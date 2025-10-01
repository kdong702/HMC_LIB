package com.ubivelox.iccard.util;

import lombok.extern.slf4j.Slf4j;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

@Slf4j
public class PropertyReader {

    private static Properties properties = new Properties();

    private PropertyReader() {
        this("src/main/resources/application.properties");
    }

    private PropertyReader(String filePath) {
        try (FileInputStream fis = new FileInputStream(filePath)) {
            properties.load(fis);
        } catch (IOException e) {
            log.error("Failed to load properties file: " + filePath, e);
        }
    }

    public static String getProperty(String key) {
        if (properties.isEmpty()) {
            new PropertyReader();
        }
        return properties.getProperty(key);
    }
}
