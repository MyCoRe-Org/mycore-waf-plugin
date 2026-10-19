package org.mycore.waf.suspicion;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * A fact that checks the autonomous system (network operator) of the client IP address, for
 * example {@code <asn number="45090|132203"/>} or {@code <asn organization=".*Tencent.*"/>}. Both
 * attributes are Java regexes that must match the whole value, if both are given both must match.
 * The autonomous system is looked up in the GeoIP database {@code asn} (or the one given in the
 * {@code database} attribute), which must use the GeoLite2 ASN layout
 * ({@code autonomous_system_number}, {@code autonomous_system_organization}).
 * <p>
 * If the autonomous system cannot be determined, for example for private addresses or while the
 * database is missing, the whole rule does not match, see {@link UndeterminableFactException}. A
 * record without organization does not match an {@code organization} pattern.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class ASNFact extends GeoIPFact {

    @XmlAttribute
    private String number;

    @XmlAttribute
    private String organization;

    private transient volatile boolean validated;

    private transient Pattern compiledNumber;

    private transient Pattern compiledOrganization;

    @Override
    public boolean matches(ClientInformation information) {
        if (!validated) {
            validate();
        }
        Map<String, Object> record = lookup(information);
        Object asNumber = getValue(record, "autonomous_system_number");
        if (asNumber == null) {
            throw new UndeterminableFactException("GeoIP record without ASN for " + information.remoteAddress());
        }
        if (compiledNumber != null && !compiledNumber.matcher(asNumber.toString()).matches()) {
            return false;
        }
        if (compiledOrganization != null) {
            Object asOrganization = getValue(record, "autonomous_system_organization");
            return asOrganization != null && compiledOrganization.matcher(asOrganization.toString()).matches();
        }
        return true;
    }

    @Override
    protected String getDefaultDatabase() {
        return "asn";
    }

    @Override
    void validate() {
        if (number == null && organization == null) {
            throw new IllegalArgumentException("asn fact has neither number nor organization");
        }
        compiledNumber = compile(number, "number");
        compiledOrganization = compile(organization, "organization");
        validated = true;
    }

}
