package org.mycore.waf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class WAFFilterTest {

  @Test
  void sanitizeForLog_keepsRegularValue() {
    String json = "{\"headless\":false,\"languages\":[\"de-DE\"]}";
    assertEquals(json, WAFFilter.sanitizeForLog(json));
  }

  @Test
  void sanitizeForLog_replacesLineBreaks() {
    assertEquals("Mozilla??2026-10-19 INFO forged", WAFFilter.sanitizeForLog("Mozilla\r\n2026-10-19 INFO forged"));
  }

  @Test
  void sanitizeForLog_handlesNull() {
    assertEquals("-", WAFFilter.sanitizeForLog(null));
  }

  @Test
  void sanitizeForLog_truncatesLongValue() {
    String sanitized = WAFFilter.sanitizeForLog("a".repeat(5000));
    assertEquals(2003, sanitized.length());
    assertTrue(sanitized.endsWith("..."));
  }
}
