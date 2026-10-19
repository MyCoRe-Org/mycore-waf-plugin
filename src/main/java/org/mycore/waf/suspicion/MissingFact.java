package org.mycore.waf.suspicion;

import com.google.gson.JsonElement;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;

/**
 * A fact that is true if a field of the client information is missing, JSON null, an empty string
 * or an empty array, for example {@code <missing field="timezone"/>}.
 */
@XmlAccessorType(XmlAccessType.FIELD)
public class MissingFact extends ClientFact {

    @XmlAttribute(required = true)
    private String field;

    @Override
    public boolean matches(ClientInformation information) {
        JsonElement element = information.get(field);
        if (element == null) {
            return true;
        }
        if (element.isJsonArray()) {
            return element.getAsJsonArray().isEmpty();
        }
        return element.isJsonPrimitive() && element.getAsString().isBlank();
    }

}
