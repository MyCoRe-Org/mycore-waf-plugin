package org.mycore.waf.suspicion;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;

/**
 * A fact that is true if the reported {@code timezone} does not fit the reported
 * {@code timezoneOffset} at the reported {@code timestamp}. A timezone that is unknown to the JVM
 * cannot be evaluated, see {@link UndeterminableFactException}. Real browsers derive both values
 * from the same operating system setting, while scripts that fake the timezone often forget to fake
 * the offset as well. The fact never matches if the timezone or the offset is missing, use
 * {@link MissingFact} to detect that.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class TimezoneOffsetMismatchFact extends ClientFact {

    @Override
    public boolean matches(ClientInformation information) {
        List<String> timezone = information.getValues("timezone");
        Double reportedOffset = information.getNumber("timezoneOffset");
        if (timezone.size() != 1 || reportedOffset == null) {
            return false;
        }
        Double timestamp = information.getNumber("timestamp");
        Instant instant = timestamp == null ? Instant.now() : Instant.ofEpochMilli(timestamp.longValue());
        int expectedOffset;
        try {
            // Date.getTimezoneOffset() is UTC minus local time, so it has the opposite sign
            expectedOffset = -ZoneId.of(timezone.get(0)).getRules().getOffset(instant).getTotalSeconds() / 60;
        } catch (DateTimeException e) {
            // Unknown to the tzdata of this JVM, which may be older than the browser (Europe/Kyiv)
            throw new UndeterminableFactException("Unknown timezone " + timezone.get(0));
        }
        return reportedOffset.intValue() != expectedOffset;
    }

}
