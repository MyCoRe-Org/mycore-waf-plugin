package org.mycore.waf.suspicion;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import java.util.List;

/**
 * A fact that matches a Java regex against the URL the client originally requested before it was
 * redirected to the challenge, relative to the base URL and including the query string, for
 * example {@code <redirect-url pattern="/servlets/solr/find\?.*"/>}.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class RedirectURLFact extends PatternFact {

    @Override
    protected List<String> getValues(ClientInformation information) {
        String redirectURL = information.redirectURL();
        return redirectURL == null ? List.of() : List.of(redirectURL);
    }

}
