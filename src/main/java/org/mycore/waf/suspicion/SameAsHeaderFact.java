package org.mycore.waf.suspicion;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import java.util.List;

/**
 * A fact that is true if a field of the client information equals a header of the challenge
 * solution request, for example {@code <same-as-header field="userAgent" header="User-Agent"/>}.
 * Wrapped in {@code not} it detects clients that report a different value in JavaScript than in
 * HTTP. The fact never matches if the field or the header is missing.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class SameAsHeaderFact extends ClientFact {

    @XmlAttribute(required = true)
    private String field;

    @XmlAttribute(required = true)
    private String header;

    @Override
    public boolean matches(ClientInformation information) {
        List<String> values = information.getValues(field);
        String headerValue = information.request().getHeader(header);
        return values.size() == 1 && headerValue != null && headerValue.equals(values.get(0));
    }

}
