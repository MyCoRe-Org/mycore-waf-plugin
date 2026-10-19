package org.mycore.waf.suspicion;

import com.google.gson.JsonArray;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;

/**
 * A fact that checks the number of elements of an array field of the client information against an
 * inclusive range, for example {@code <count field="plugins" max="0"/>}. A missing or non array
 * field never matches.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class CountFact extends RangeFact {

    @XmlAttribute(required = true)
    private String field;

    @Override
    protected Double getNumber(ClientInformation information) {
        JsonArray array = information.getArray(field);
        return array == null ? null : (double) array.size();
    }

}
