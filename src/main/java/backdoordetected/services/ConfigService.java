package backdoordetected.services;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Properties;
import java.util.logging.Logger;

public class ConfigService {
    private static final Logger logger = Logger.getLogger(ConfigService.class.getName());
    private static final String CONFIG_FILE_NAME = "config.properties";
    private static ConfigService instance;
    private final Properties properties = new Properties();

    private ConfigService() {
        loadConfig();
    }

    public static synchronized ConfigService getInstance() {
        if (instance == null) {
            instance = new ConfigService();
        }
        return instance;
    }

    private void loadConfig() {
        File configFile = new File(CONFIG_FILE_NAME);
        if (!configFile.exists()) {
            createDefaultConfig(configFile);
        }

        try (FileInputStream fis = new FileInputStream(configFile)) {
            properties.load(fis);
        } catch (IOException e) {
            logger.severe("Could not load config.properties: " + e.getMessage());
        }
    }

    private void createDefaultConfig(File configFile) {
        try (FileOutputStream fos = new FileOutputStream(configFile)) {
            Properties defaultProps = new Properties();
            defaultProps.setProperty("gemini_api_key", "YOUR_FIRST_API_KEY");
            defaultProps.setProperty("gemini_model", "gemini-1.5-pro-latest");
            defaultProps.setProperty("enable_gemini_2", "true");
            defaultProps.setProperty("gemini_api_key_2", "YOUR_SECOND_API_KEY");
            defaultProps.setProperty("gemini_model_2", "gemini-1.5-flash-latest");
            defaultProps.setProperty("codeql_executable_path", "");
            defaultProps.setProperty("ai_parallel_scanning", "false");
            defaultProps.setProperty("enable_analyzer_parallel", "false");
            defaultProps.setProperty("analyzer_parallel_threads", "3");
            defaultProps.store(fos, "Backdoor Detector Configuration");

            System.out.println("Created config.properties file");
            System.out.println("Add your Gemini API keys to use AI features\n");
        } catch (IOException e) {
            logger.severe("Could not create config.properties: " + e.getMessage());
        }
    }

    public String getProperty(String key) {
        return properties.getProperty(key);
    }

    public String getProperty(String key, String defaultValue) {
        return properties.getProperty(key, defaultValue);
    }

    public boolean getBooleanProperty(String key, boolean defaultValue) {
        return Boolean.parseBoolean(getProperty(key, String.valueOf(defaultValue)));
    }

    public int getIntProperty(String key, int defaultValue) {
        try {
            return Integer.parseInt(getProperty(key, String.valueOf(defaultValue)));
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    public void setProperty(String key, String value) {
        properties.setProperty(key, value);
        try (FileOutputStream fos = new FileOutputStream(CONFIG_FILE_NAME)) {
            properties.store(fos, "Backdoor Detector Configuration");
        } catch (IOException e) {
            logger.warning("Could not save property to config file: " + e.getMessage());
        }
    }
}
