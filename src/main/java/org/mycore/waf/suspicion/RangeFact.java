package org.mycore.waf.suspicion;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;

/**
 * Base class for facts that check a number against an inclusive range given by {@code min} and
 * {@code max}. At least one bound is required. The fact never matches if there is no number.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class RangeFact extends ClientFact {

    @XmlAttribute
    private Double min;

    @XmlAttribute
    private Double max;

    @Override
    public boolean matches(ClientInformation information) {
        Double value = getNumber(information);
        if (value == null) {
            return false;
        }
        return (min == null || value >= min) && (max == null || value <= max);
    }

    /**
     * Returns the number this fact checks.
     *
     * @param information the client information and the request that submitted it
     * @return the number, or null if it is not present
     */
    protected abstract Double getNumber(ClientInformation information);

    @Override
    void validate() {
        if (min == null && max == null) {
            throw new IllegalArgumentException(getClass().getSimpleName() + " has neither min nor max");
        }
        if (min != null && max != null && min > max) {
            throw new IllegalArgumentException(getClass().getSimpleName() + " has min greater than max");
        }
    }

}
