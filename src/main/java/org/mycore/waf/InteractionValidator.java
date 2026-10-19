package org.mycore.waf;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import java.util.ArrayList;
import java.util.List;

/**
 * Validates the events recorded by the interaction challenge page. The page draws a checkbox on a
 * canvas at a position chosen by the server and records the pointer events that lead to the click.
 * <p>
 * The checkbox position is given as fractions (per mille) of the canvas size. Its pixel position is
 * computed the same way by the page and by this validator:
 * {@code left = clamp(round(x * width / 1000), MARGIN, width - BOX_SIZE - MARGIN)}, likewise for
 * the top position.
 * <p>
 * The recorded data is a JSON object with an {@code events} array. Every event has the fields
 * {@code type}, {@code t} (milliseconds since the page was shown), {@code x}, {@code y},
 * {@code trusted} (Event.isTrusted) and, for pointer events, {@code pointerType}. Click events also
 * carry the canvas size {@code w} and {@code h} at the time of the click.
 */
public class InteractionValidator {

    /** Edge length of the drawn checkbox in CSS pixels. */
    public static final int BOX_SIZE = 32;

    /** Minimal distance of the checkbox to the canvas border in CSS pixels. */
    public static final int MARGIN = 16;

    // Clicks slightly outside the drawn box are accepted, rounding differs between browsers
    private static final double TOLERANCE = 4;

    private final Gson gson = new Gson();

    private final long minDurationMillis;

    private final int minPointerMoves;

    /**
     * Creates a validator.
     *
     * @param minDurationMillis the minimal time between showing the page and the click
     * @param minPointerMoves the minimal number of pointer moves before a mouse click
     */
    public InteractionValidator(long minDurationMillis, int minPointerMoves) {
        this.minDurationMillis = minDurationMillis;
        this.minPointerMoves = minPointerMoves;
    }

    /**
     * Validates the recorded events.
     *
     * @param recordedEvents the JSON data sent by the interaction challenge page
     * @param boxX the horizontal checkbox position in per mille of the canvas width
     * @param boxY the vertical checkbox position in per mille of the canvas height
     * @return the problems found, empty if the interaction looks like a human click on the checkbox
     */
    public List<String> validate(String recordedEvents, int boxX, int boxY) {
        List<String> problems = new ArrayList<>();
        JsonArray events = parseEvents(recordedEvents);
        if (events == null) {
            problems.add("unparsable events");
            return problems;
        }

        int untrusted = 0;
        JsonObject click = null;
        int clickIndex = -1;
        for (int i = 0; i < events.size(); i++) {
            JsonObject event = asObject(events.get(i));
            if (event == null) {
                continue;
            }
            if (!getBoolean(event, "trusted")) {
                untrusted++;
                continue;
            }
            if (click == null && "click".equals(getString(event, "type")) && isOnCheckbox(event, boxX, boxY)) {
                click = event;
                clickIndex = i;
            }
        }
        if (untrusted > 0) {
            problems.add(untrusted + " untrusted events");
        }
        if (click == null) {
            problems.add("no trusted click on the checkbox");
            return problems;
        }

        double clickTime = getNumber(click, "t", -1);
        if (clickTime < minDurationMillis) {
            problems.add("click after " + Math.round(clickTime) + " ms");
        }

        String pointerType = findPointerType(events, clickIndex, click);
        if (!"touch".equals(pointerType) && !"pen".equals(pointerType)) {
            int moves = countPointerMoves(events, clickIndex);
            if (moves < minPointerMoves) {
                problems.add(moves + " pointer moves before the click");
            }
        }
        return problems;
    }

    /**
     * Computes the pixel position of one checkbox coordinate.
     *
     * @param perMille the position in per mille of the canvas extent
     * @param extent the canvas width or height in CSS pixels
     * @return the left or top edge of the checkbox in CSS pixels
     */
    static double boxPosition(int perMille, double extent) {
        double position = Math.round(perMille * extent / 1000);
        return Math.max(MARGIN, Math.min(position, extent - BOX_SIZE - MARGIN));
    }

    private boolean isOnCheckbox(JsonObject click, int boxX, int boxY) {
        double width = getNumber(click, "w", -1);
        double height = getNumber(click, "h", -1);
        double x = getNumber(click, "x", -1);
        double y = getNumber(click, "y", -1);
        if (width <= 0 || height <= 0) {
            return false;
        }
        double left = boxPosition(boxX, width);
        double top = boxPosition(boxY, height);
        return x >= left - TOLERANCE && x <= left + BOX_SIZE + TOLERANCE
            && y >= top - TOLERANCE && y <= top + BOX_SIZE + TOLERANCE;
    }

    private static String findPointerType(JsonArray events, int clickIndex, JsonObject click) {
        String pointerType = getString(click, "pointerType");
        if (pointerType != null && !pointerType.isEmpty()) {
            return pointerType;
        }
        // Older browsers fire click as MouseEvent without pointerType, use the preceding pointerdown
        for (int i = clickIndex - 1; i >= 0; i--) {
            JsonObject event = asObject(events.get(i));
            if (event != null && "pointerdown".equals(getString(event, "type"))) {
                return getString(event, "pointerType");
            }
        }
        return null;
    }

    private static int countPointerMoves(JsonArray events, int clickIndex) {
        int moves = 0;
        for (int i = 0; i < clickIndex; i++) {
            JsonObject event = asObject(events.get(i));
            if (event != null && getBoolean(event, "trusted") && "pointermove".equals(getString(event, "type"))) {
                moves++;
            }
        }
        return moves;
    }

    private JsonArray parseEvents(String recordedEvents) {
        if (recordedEvents == null || recordedEvents.isEmpty()) {
            return null;
        }
        try {
            JsonObject json = gson.fromJson(recordedEvents, JsonObject.class);
            if (json == null || !json.has("events") || !json.get("events").isJsonArray()) {
                return null;
            }
            return json.getAsJsonArray("events");
        } catch (JsonParseException | ClassCastException e) {
            return null;
        }
    }

    private static JsonObject asObject(JsonElement element) {
        return element != null && element.isJsonObject() ? element.getAsJsonObject() : null;
    }

    private static String getString(JsonObject event, String field) {
        JsonElement element = event.get(field);
        return element != null && element.isJsonPrimitive() ? element.getAsString() : null;
    }

    private static boolean getBoolean(JsonObject event, String field) {
        JsonElement element = event.get(field);
        return element != null && element.isJsonPrimitive() && element.getAsJsonPrimitive().isBoolean()
            && element.getAsBoolean();
    }

    private static double getNumber(JsonObject event, String field, double defaultValue) {
        JsonElement element = event.get(field);
        if (element == null || !element.isJsonPrimitive() || !element.getAsJsonPrimitive().isNumber()) {
            return defaultValue;
        }
        return element.getAsDouble();
    }

}
