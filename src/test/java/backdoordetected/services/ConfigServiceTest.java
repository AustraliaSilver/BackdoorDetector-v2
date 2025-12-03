package backdoordetected.services;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Field;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ConfigServiceTest {

  private ConfigService configService;

  @TempDir
  File tempDir;
  private File testConfigFile;

  @BeforeEach
  void setUp() throws IOException, NoSuchFieldException, IllegalAccessException {
    testConfigFile = new File(tempDir, "test-config.properties");

    try (FileWriter writer = new FileWriter(testConfigFile)) {
      writer.write("test_key=test_value\n");
      writer.write("test_bool=true\n");
      writer.write("test_int=123\n");
    }

    configService = ConfigService.getTestInstance(testConfigFile);
  }

  @AfterEach
  void tearDown() throws NoSuchFieldException, IllegalAccessException {
    Field instance = ConfigService.class.getDeclaredField("instance");
    instance.setAccessible(true);
    instance.set(null, null);
  }

  @Test
  void testGetProperty() {
    assertEquals("test_value", configService.getProperty("test_key"));
  }

  @Test
  void testGetPropertyWithDefault() {
    assertEquals("default", configService.getProperty("non_existent_key", "default"));
  }

  @Test
  void testGetBooleanProperty() {
    assertTrue(configService.getBooleanProperty("test_bool", false));
  }

  @Test
  void testGetIntProperty() {
    assertEquals(123, configService.getIntProperty("test_int", 456));
  }

  @Test
  void testSetProperty() throws IOException {
    configService.setProperty("new_key", "new_value");
    assertEquals("new_value", configService.getProperty("new_key"));

    ConfigService newInstance = ConfigService.getTestInstance(testConfigFile);
    assertEquals("new_value", newInstance.getProperty("new_key"));
  }
}
