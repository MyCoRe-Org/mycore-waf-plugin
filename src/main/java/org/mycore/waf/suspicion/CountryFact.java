package org.mycore.waf.suspicion;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * A fact that matches a Java regex against the ISO 3166 country code of the client IP address,
 * for example {@code <country code="CN|RU"/>}. The country is looked up in the GeoIP database
 * {@code country} (or the one given in the {@code database} attribute). Both the flat layout of the
 * ip-location-db files ({@code country_code}) and the nested layout of GeoLite2 and DB-IP
 * ({@code country.iso_code}) are supported.
 * <p>
 * If the country cannot be determined, for example for private addresses or while the database is
 * missing, the whole rule does not match, see {@link UndeterminableFactException}.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class CountryFact extends GeoIPFact {

    @XmlAttribute(required = true)
    private String code;

    private transient volatile Pattern compiledCode;

    @Override
    public boolean matches(ClientInformation information) {
        if (compiledCode == null) {
            validate();
        }
        Map<String, Object> record = lookup(information);
        Object country = getValue(record, "country_code");
        if (country == null) {
            country = getValue(record, "country", "iso_code");
        }
        if (country == null) {
            throw new UndeterminableFactException("GeoIP record without country for " + information.remoteAddress());
        }
        return compiledCode.matcher(country.toString()).matches();
    }

    @Override
    protected String getDefaultDatabase() {
        return "country";
    }

    @Override
    void validate() {
        if (code == null) {
            throw new IllegalArgumentException("country fact without code");
        }
        compiledCode = compile(code, "code");
    }

}
