package org.mycore.waf.suspicion;

import jakarta.xml.bind.annotation.XmlEnum;
import jakarta.xml.bind.annotation.XmlEnumValue;

/**
 * Defines whether a fact with several values requires any or all values to match.
 */
@XmlEnum(String.class)
public enum MatchMode {

    /** At least one value has to match. */
    @XmlEnumValue("any")
    ANY,

    /** Every value has to match. */
    @XmlEnumValue("all")
    ALL

}
