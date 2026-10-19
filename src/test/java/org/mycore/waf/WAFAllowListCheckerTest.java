package org.mycore.waf;

import static org.junit.jupiter.api.Assertions.assertEquals;

import jakarta.servlet.http.HttpServletRequest;
import java.lang.reflect.Proxy;
import org.junit.jupiter.api.Test;

class WAFAllowListCheckerTest {

  /**
   * Creates a request that only answers the path related methods, like a container would after
   * it decoded and normalized the raw request URI.
   */
  private static HttpServletRequest request(String requestURI, String servletPath, String pathInfo) {
    return (HttpServletRequest) Proxy.newProxyInstance(WAFAllowListCheckerTest.class.getClassLoader(),
        new Class<?>[] { HttpServletRequest.class }, (proxy, method, args) -> switch (method.getName()) {
          case "getRequestURI" -> requestURI;
          case "getServletPath" -> servletPath;
          case "getPathInfo" -> pathInfo;
          default -> throw new UnsupportedOperationException(method.getName());
        });
  }

  @Test
  void pathFromDefaultServlet() {
    assertEquals("/robots.txt",
        WAFAllowListChecker.getApplicationRelativePath(request("/mir/robots.txt", "/robots.txt", null)));
  }

  @Test
  void pathFromPrefixMappedServlet() {
    assertEquals("/api/v2/objects",
        WAFAllowListChecker.getApplicationRelativePath(request("/mir/api/v2/objects", "/api", "/v2/objects")));
  }

  @Test
  void pathParameterTraversal_usesNormalizedPath() {
    // Tomcat dispatches /api/..;/receive/foo to /receive/foo
    assertEquals("/receive/foo",
        WAFAllowListChecker.getApplicationRelativePath(request("/mir/api/..;/receive/foo", "/receive", "/foo")));
  }

  @Test
  void encodedDotTraversal_usesNormalizedPath() {
    assertEquals("/receive/foo",
        WAFAllowListChecker.getApplicationRelativePath(request("/mir/api/%2e%2e/receive/foo", "/receive", "/foo")));
  }
}
