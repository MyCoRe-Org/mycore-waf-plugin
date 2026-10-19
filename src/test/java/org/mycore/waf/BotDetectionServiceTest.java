package org.mycore.waf;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class BotDetectionServiceTest {

  private BotDetectionService service;

  private JsonObject info;

  @BeforeEach
  void setUp() {
    service = new BotDetectionService();
    info = new JsonObject();
    info.addProperty("userAgent", "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0");
    info.addProperty("headless", false);
    info.addProperty("webdriver", false);
    info.addProperty("cookieEnabled", true);
    info.addProperty("hardwareConcurrency", 8);
    info.addProperty("screenResolution", "1920x1080");
    info.addProperty("colorDepth", 24);
    JsonArray languages = new JsonArray();
    languages.add("de-DE");
    info.add("languages", languages);
  }

  @Test
  void browserInformation_isAccepted() {
    assertTrue(service.checkClientInformation(info.toString()));
  }

  @Test
  void missingWebdriver_isAccepted() {
    info.remove("webdriver");
    assertTrue(service.checkClientInformation(info.toString()));
  }

  @Test
  void emptyObject_isRejected() {
    assertFalse(service.checkClientInformation("{}"));
  }

  @Test
  void jsonNull_isRejected() {
    assertFalse(service.checkClientInformation("null"));
  }

  @ParameterizedTest
  @ValueSource(strings = { "headless", "cookieEnabled", "hardwareConcurrency", "screenResolution", "colorDepth",
      "languages" })
  void missingField_isRejected(String field) {
    info.remove(field);
    assertFalse(service.checkClientInformation(info.toString()));
  }

  @Test
  void headless_isRejected() {
    info.addProperty("headless", true);
    assertFalse(service.checkClientInformation(info.toString()));
  }

  @Test
  void webdriver_isRejected() {
    info.addProperty("webdriver", true);
    assertFalse(service.checkClientInformation(info.toString()));
  }

  @ParameterizedTest
  @ValueSource(strings = { "0x0", "x", "foo", "" })
  void invalidScreenResolution_isRejected(String resolution) {
    info.addProperty("screenResolution", resolution);
    assertFalse(service.checkClientInformation(info.toString()));
  }

  @Test
  void nonNumericHardwareConcurrency_isRejected() {
    info.addProperty("hardwareConcurrency", "many");
    assertFalse(service.checkClientInformation(info.toString()));
  }

  @Test
  void emptyLanguages_isRejected() {
    info.add("languages", new JsonArray());
    assertFalse(service.checkClientInformation(info.toString()));
  }
}
