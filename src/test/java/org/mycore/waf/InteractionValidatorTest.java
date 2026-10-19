package org.mycore.waf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class InteractionValidatorTest {

    private static final int WIDTH = 1000;

    private static final int HEIGHT = 800;

    // Box at 20 % / 10 %: left = 200, top = 80
    private static final int BOX_X = 200;

    private static final int BOX_Y = 100;

    private InteractionValidator validator;

    private JsonArray events;

    @BeforeEach
    void setUp() {
        validator = new InteractionValidator(600, 3);
        events = new JsonArray();
    }

    private JsonObject event(String type, double t, double x, double y, boolean trusted, String pointerType) {
        JsonObject event = new JsonObject();
        event.addProperty("type", type);
        event.addProperty("t", t);
        event.addProperty("x", x);
        event.addProperty("y", y);
        event.addProperty("trusted", trusted);
        if (pointerType != null) {
            event.addProperty("pointerType", pointerType);
        }
        events.add(event);
        return event;
    }

    private void click(double t, double x, double y, boolean trusted, String pointerType) {
        event("pointerdown", t - 80, x, y, trusted, pointerType);
        event("pointerup", t - 5, x, y, trusted, pointerType);
        JsonObject click = event("click", t, x, y, trusted, pointerType);
        click.addProperty("w", WIDTH);
        click.addProperty("h", HEIGHT);
    }

    private void moves(int count) {
        for (int i = 0; i < count; i++) {
            event("pointermove", 100 + i * 20, 600 - i * 30, 400 - i * 20, true, "mouse");
        }
    }

    private List<String> validate() {
        JsonObject data = new JsonObject();
        data.add("events", events);
        return validator.validate(data.toString(), BOX_X, BOX_Y);
    }

    @Test
    void humanMouseClickIsAccepted() {
        moves(15);
        click(1400, 215, 95, true, "mouse");
        assertEquals(List.of(), validate());
    }

    @Test
    void touchWithoutMovesIsAccepted() {
        click(1400, 215, 95, true, "touch");
        assertEquals(List.of(), validate());
    }

    @Test
    void clickBesideCheckboxIsRejected() {
        moves(15);
        click(1400, 300, 95, true, "mouse");
        assertEquals(List.of("no trusted click on the checkbox"), validate());
    }

    @Test
    void syntheticClickIsRejected() {
        moves(15);
        click(1400, 215, 95, false, null);
        List<String> problems = validate();
        assertTrue(problems.contains("3 untrusted events"));
        assertTrue(problems.contains("no trusted click on the checkbox"));
    }

    @Test
    void mouseClickWithoutMovesIsRejected() {
        moves(1);
        click(1400, 215, 95, true, "mouse");
        assertEquals(List.of("1 pointer moves before the click"), validate());
    }

    @Test
    void tooFastClickIsRejected() {
        moves(15);
        click(300, 215, 95, true, "mouse");
        assertEquals(List.of("click after 300 ms"), validate());
    }

    @Test
    void pointerTypeIsTakenFromPointerDown() {
        event("pointerdown", 1300, 215, 95, true, "touch");
        JsonObject click = event("click", 1400, 215, 95, true, null);
        click.addProperty("w", WIDTH);
        click.addProperty("h", HEIGHT);
        assertEquals(List.of(), validate());
    }

    @Test
    void boxIsClampedToCanvas() {
        assertEquals(InteractionValidator.MARGIN, InteractionValidator.boxPosition(0, 500));
        assertEquals(500 - InteractionValidator.BOX_SIZE - InteractionValidator.MARGIN,
            InteractionValidator.boxPosition(1000, 500));
        assertEquals(250, InteractionValidator.boxPosition(500, 500));
    }

    @Test
    void invalidDataIsRejected() {
        assertEquals(List.of("unparsable events"), validator.validate("[]", BOX_X, BOX_Y));
        assertEquals(List.of("unparsable events"), validator.validate("{\"events\":5}", BOX_X, BOX_Y));
        assertEquals(List.of("unparsable events"), validator.validate("{", BOX_X, BOX_Y));
        assertEquals(List.of("unparsable events"), validator.validate(null, BOX_X, BOX_Y));
    }

}
