package org.mycore.waf.suspicion;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;

/**
 * The data a suspicion rule is evaluated against: the client information gathered by the
 * challenge page JavaScript, the request that submitted it and values derived from the request.
 *
 * @param json the parsed client information
 * @param request the challenge solution request
 * @param remoteAddress the client IP address, honoring trusted proxies
 * @param redirectURL the URL the client originally requested, relative to the base URL
 * @param geoIP the lookup in the GeoIP databases
 */
public record ClientInformation(JsonObject json, HttpServletRequest request, String remoteAddress,
    String redirectURL, GeoIPLookup geoIP) {

    /**
     * Returns the field with the given name, or null if it is missing or JSON null.
     *
     * @param field the name of a top level field of the client information
     * @return the field value or null
     */
    public JsonElement get(String field) {
        JsonElement element = json.get(field);
        return element == null || element.isJsonNull() ? null : element;
    }

    /**
     * Returns the values of a field as strings. A primitive field yields one value, an array field
     * yields one value per primitive element. Objects, nested arrays and JSON null are skipped.
     *
     * @param field the name of a top level field of the client information
     * @return the values of the field, empty if the field is missing
     */
    public List<String> getValues(String field) {
        JsonElement element = get(field);
        List<String> values = new ArrayList<>();
        if (element == null) {
            return values;
        }
        if (element.isJsonArray()) {
            for (JsonElement child : element.getAsJsonArray()) {
                if (child.isJsonPrimitive()) {
                    values.add(child.getAsString());
                }
            }
        } else if (element.isJsonPrimitive()) {
            values.add(element.getAsString());
        }
        return values;
    }

    /**
     * Returns the field as number, or null if it is missing or not a number.
     *
     * @param field the name of a top level field of the client information
     * @return the numeric value or null
     */
    public Double getNumber(String field) {
        JsonElement element = get(field);
        if (element == null || !element.isJsonPrimitive() || !element.getAsJsonPrimitive().isNumber()) {
            return null;
        }
        return element.getAsDouble();
    }

    /**
     * Returns the field as array, or null if it is missing or not an array.
     *
     * @param field the name of a top level field of the client information
     * @return the array or null
     */
    public JsonArray getArray(String field) {
        JsonElement element = get(field);
        return element != null && element.isJsonArray() ? element.getAsJsonArray() : null;
    }

}
