package org.mycore.waf;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.SchemaOutputResolver;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import javax.xml.XMLConstants;
import javax.xml.transform.Result;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import org.junit.Before;
import org.junit.Test;
import org.mycore.common.MCRClassTools;
import org.mycore.common.MCRTestCase;
import org.mycore.waf.fact.AllowList;
import org.xml.sax.SAXException;

public class WAFAllowRulesTest extends MCRTestCase {

    private static final String TEST_RESOURCE = "waf/allow-list-test.xml";

    private AllowList allowList;

    @Before
    public void loadSampleAllowList() {
        allowList = WAFAllowRules.loadAllowList(TEST_RESOURCE);
        assertNotNull("test resource should be loadable from the classpath", allowList);
    }

    private HttpServletRequest request(String method, String path) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn(method);
        when(request.getRequestURI()).thenReturn(path);
        when(request.getContextPath()).thenReturn("");
        when(request.getScheme()).thenReturn("http");
        when(request.getServerName()).thenReturn("localhost");
        when(request.getServerPort()).thenReturn(80);
        when(request.getRemoteAddr()).thenReturn("93.184.216.34");
        when(request.getParameterMap()).thenReturn(Map.of());
        return request;
    }

    @Test
    public void soleUniqueParameterIsAllowed() {
        HttpServletRequest request = request("GET", "/sru");
        when(request.getParameterMap()).thenReturn(Map.of("style", new String[] { "xml" }));
        assertTrue(allowList.isAllowed(request));
    }

    @Test
    public void repeatedParameterIsRejected() {
        HttpServletRequest request = request("GET", "/sru");
        when(request.getParameterMap()).thenReturn(Map.of("style", new String[] { "xml", "json" }));
        assertFalse(allowList.isAllowed(request));
    }

    @Test
    public void additionalParameterIsRejected() {
        HttpServletRequest request = request("GET", "/sru");
        when(request.getParameterMap())
            .thenReturn(Map.of("style", new String[] { "xml" }, "foo", new String[] { "bar" }));
        assertFalse(allowList.isAllowed(request));
    }

    @Test
    public void wrongMethodIsRejected() {
        HttpServletRequest request = request("POST", "/sru");
        when(request.getParameterMap()).thenReturn(Map.of("style", new String[] { "xml" }));
        assertFalse(allowList.isAllowed(request));
    }

    @Test
    public void contextPathIsStrippedFromRequestPath() {
        HttpServletRequest request = request("GET", "/myapp/sru");
        when(request.getContextPath()).thenReturn("/myapp");
        when(request.getParameterMap()).thenReturn(Map.of("style", new String[] { "xml" }));
        assertTrue(allowList.isAllowed(request));
    }

    @Test
    public void subResourceWithFetchDestIsAllowed() {
        HttpServletRequest request = request("GET", "/rfs/style.css");
        when(request.getHeader("Sec-Fetch-Dest")).thenReturn("style");
        assertTrue(allowList.isAllowed(request));
    }

    @Test
    public void subResourceWithWrongFetchDestIsRejected() {
        HttpServletRequest request = request("GET", "/rfs/style.css");
        when(request.getHeader("Sec-Fetch-Dest")).thenReturn("document");
        assertFalse(allowList.isAllowed(request));
    }

    @Test
    public void googlebotFromVerifiedRangeIsAllowed() {
        HttpServletRequest request = request("GET", "/");
        when(request.getHeader("User-Agent"))
            .thenReturn("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)");
        when(request.getRemoteAddr()).thenReturn("66.249.66.1");
        assertTrue(allowList.isAllowed(request));
    }

    @Test
    public void googlebotUserAgentFromForeignRangeIsRejected() {
        HttpServletRequest request = request("GET", "/");
        when(request.getHeader("User-Agent"))
            .thenReturn("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)");
        when(request.getRemoteAddr()).thenReturn("8.8.8.8");
        assertFalse(allowList.isAllowed(request));
    }

    @Test
    public void internalAddressIsAllowedByRegex() {
        HttpServletRequest request = request("GET", "/");
        when(request.getRemoteAddr()).thenReturn("192.168.0.5");
        assertTrue(allowList.isAllowed(request));
    }

    @Test
    public void cleanGetWithoutParametersIsAllowed() {
        assertTrue(allowList.isAllowed(request("GET", "/search")));
        assertTrue(allowList.isAllowed(request("HEAD", "/search/documents")));
    }

    @Test
    public void cleanGetWithParametersIsRejected() {
        HttpServletRequest request = request("GET", "/search");
        when(request.getParameterMap()).thenReturn(Map.of("q", new String[] { "test" }));
        assertFalse(allowList.isAllowed(request));
    }

    @Test
    public void tagSearchWithValueCountIsAllowed() {
        HttpServletRequest request = request("GET", "/tags");
        when(request.getParameterMap()).thenReturn(Map.of("tag", new String[] { "history", "1867" }));
        assertTrue(allowList.isAllowed(request));
    }

    @Test
    public void tagSearchWithTooManyValuesIsRejected() {
        HttpServletRequest request = request("GET", "/tags");
        when(request.getParameterMap())
            .thenReturn(Map.of("tag", new String[] { "a", "b", "c", "d" }));
        assertFalse(allowList.isAllowed(request));
    }

    @Test
    public void rssRequestWithCookieContentTypeAndQueryStringIsAllowed() {
        HttpServletRequest request = request("GET", "/rss");
        when(request.getCookies()).thenReturn(new Cookie[] { new Cookie("session", "abc123") });
        when(request.getContentType()).thenReturn("application/rss+xml");
        when(request.getQueryString()).thenReturn("sort=date&limit=10");
        assertTrue(allowList.isAllowed(request));
    }

    @Test
    public void rssRequestWithoutCookieIsRejected() {
        HttpServletRequest request = request("GET", "/rss");
        when(request.getContentType()).thenReturn("application/rss+xml");
        when(request.getQueryString()).thenReturn("sort=date&limit=10");
        assertFalse(allowList.isAllowed(request));
    }

    @Test
    public void requestWithoutStyleParameterIsAllowed() {
        assertTrue(allowList.isAllowed(request("GET", "/plain")));
    }

    @Test
    public void requestWithStyleParameterIsRejectedByNotFact() {
        HttpServletRequest request = request("GET", "/plain");
        when(request.getParameterMap()).thenReturn(Map.of("style", new String[] { "xml" }));
        assertFalse(allowList.isAllowed(request));
    }

    @Test
    public void unknownPathIsRejected() {
        assertFalse(allowList.isAllowed(request("GET", "/documents/42")));
    }

    @Test
    public void sampleRulesAreValidAgainstGeneratedSchema() throws Exception {
        Schema schema = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI)
            .newSchema(new StreamSource(new ByteArrayInputStream(generateSchema())));
        Validator validator = schema.newValidator();
        try (InputStream input = MCRClassTools.getClassLoader().getResourceAsStream(TEST_RESOURCE)) {
            validator.validate(new StreamSource(input));
        }
    }

    @Test(expected = SAXException.class)
    public void ruleWithTwoFactsIsInvalidAgainstGeneratedSchema() throws Exception {
        Schema schema = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI)
            .newSchema(new StreamSource(new ByteArrayInputStream(generateSchema())));
        Validator validator = schema.newValidator();
        String invalid = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            + "<allow-list xmlns=\"http://www.mycore.org/waf\">"
            + "<rule><and><method value=\"GET\"/></and><path pattern=\"/x\"/></rule>"
            + "</allow-list>";
        validator.validate(new StreamSource(new ByteArrayInputStream(invalid.getBytes(StandardCharsets.UTF_8))));
    }

    private byte[] generateSchema() throws Exception {
        JAXBContext context = JAXBContext.newInstance(AllowList.class);
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        context.generateSchema(new SchemaOutputResolver() {

            @Override
            public Result createOutput(String namespaceUri, String suggestedFileName) {
                StreamResult result = new StreamResult(buffer);
                result.setSystemId(suggestedFileName);
                return result;
            }

        });
        return buffer.toByteArray();
    }

}
