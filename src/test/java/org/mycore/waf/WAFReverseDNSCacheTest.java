package org.mycore.waf;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mycore.common.config.MCRConfigurationBase;

class WAFReverseDNSCacheTest {

  @BeforeAll
  static void initConfiguration() {
    MCRConfigurationBase.initialize(Map.of(), Map.of("MCR.WAF.Enabled", "true"), true);
  }

  /**
   * Allow list checker that counts DNS queries instead of sending them.
   */
  private static class CountingChecker extends WAFAllowListChecker {

    final AtomicInteger reverseLookups = new AtomicInteger();

    final AtomicInteger forwardLookups = new AtomicInteger();

    volatile String reverseResult;

    volatile boolean forwardResult;

    volatile CountDownLatch blockReverseLookup;

    @Override
    String performReverseDNSLookup(String ip) {
      reverseLookups.incrementAndGet();
      CountDownLatch latch = blockReverseLookup;
      if (latch != null) {
        try {
          latch.await(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        }
      }
      return reverseResult;
    }

    @Override
    boolean verifyForwardDNS(String hostname, String originalIP) {
      forwardLookups.incrementAndGet();
      return forwardResult;
    }
  }

  @Test
  void verifiedHostname_isLookedUpOnce() {
    CountingChecker checker = new CountingChecker();
    checker.reverseResult = "crawl-66-249-66-1.googlebot.com";
    checker.forwardResult = true;

    for (int i = 0; i < 5; i++) {
      assertEquals("crawl-66-249-66-1.googlebot.com", checker.getVerifiedHostname("66.249.66.1"));
    }
    assertEquals(1, checker.reverseLookups.get());
    assertEquals(1, checker.forwardLookups.get());
  }

  @Test
  void missingReverseDNS_isCached() {
    CountingChecker checker = new CountingChecker();
    checker.reverseResult = null;

    for (int i = 0; i < 5; i++) {
      assertEquals("", checker.getVerifiedHostname("77.189.1.153"));
    }
    assertEquals(1, checker.reverseLookups.get());
    assertEquals(0, checker.forwardLookups.get());
  }

  @Test
  void failedForwardVerification_isCached() {
    CountingChecker checker = new CountingChecker();
    checker.reverseResult = "fake.googlebot.com.example.org";
    checker.forwardResult = false;

    for (int i = 0; i < 5; i++) {
      assertEquals("", checker.getVerifiedHostname("86.103.50.246"));
    }
    assertEquals(1, checker.reverseLookups.get());
    assertEquals(1, checker.forwardLookups.get());
  }

  @Test
  void concurrentRequests_shareOneLookup() throws InterruptedException {
    CountingChecker checker = new CountingChecker();
    checker.reverseResult = null;
    CountDownLatch release = new CountDownLatch(1);
    checker.blockReverseLookup = release;

    List<Thread> threads = new ArrayList<>();
    for (int i = 0; i < 10; i++) {
      Thread thread = new Thread(() -> checker.getVerifiedHostname("89.0.208.63"));
      threads.add(thread);
      thread.start();
    }
    // give all threads time to reach the lookup before the first one finishes
    Thread.sleep(200);
    release.countDown();
    for (Thread thread : threads) {
      thread.join();
    }
    assertEquals(1, checker.reverseLookups.get());
  }
}
