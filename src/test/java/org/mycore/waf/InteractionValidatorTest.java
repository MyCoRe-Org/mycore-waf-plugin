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
        click(t, x, y, trusted, pointerType, WIDTH, HEIGHT);
    }

    private void click(double t, double x, double y, boolean trusted, String pointerType, int width, int height) {
        event("pointerdown", t - 80, x, y, trusted, pointerType);
        JsonObject pointerUp = event("pointerup", t - 5, x, y, trusted, pointerType);
        pointerUp.addProperty("w", width);
        pointerUp.addProperty("h", height);
        JsonObject click = event("click", t, x, y, trusted, pointerType);
        click.addProperty("w", width);
        click.addProperty("h", height);
    }

    private void moves(int count) {
        for (int i = 0; i < count; i++) {
            event("pointermove", 100 + i * 20, 600 - i * 30, 400 - i * 20, true, "mouse");
        }
    }

    private List<String> validate() {
        JsonObject data = new JsonObject();
        data.add("events", events);
        return validator.validate(data.toString(), BOX_X, BOX_Y, 5000);
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
        assertEquals(List.of("no trusted click on the checkbox"), validate());
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
        assertEquals(List.of("click after 295 ms"), validate());
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
        assertEquals(List.of("unparsable events"), validator.validate("[]", BOX_X, BOX_Y, 5000));
        assertEquals(List.of("unparsable events"), validator.validate("{\"events\":5}", BOX_X, BOX_Y, 5000));
        assertEquals(List.of("unparsable events"), validator.validate("{", BOX_X, BOX_Y, 5000));
        assertEquals(List.of("unparsable events"), validator.validate(null, BOX_X, BOX_Y, 5000));
    }

    @Test
    void tinyCanvasIsRejected() {
        // With a 1 x 1 canvas every box position would be clamped to the margin
        moves(15);
        click(1400, 30, 30, true, "mouse", 1, 1);
        assertEquals(List.of("no trusted click on the checkbox"), validate());
    }

    @Test
    void forgedTimestampsAreCheckedOnTheServer() {
        moves(15);
        click(1400, 215, 95, true, "mouse");
        JsonObject data = new JsonObject();
        data.add("events", events);
        assertEquals(List.of("submitted 50 ms after the page was issued"),
            validator.validate(data.toString(), BOX_X, BOX_Y, 50));
    }

    @Test
    void touchPointerUpWithoutClickIsAccepted() {
        // iOS may not synthesize a click for a tap on the canvas
        event("pointerdown", 1300, 215, 95, true, "touch");
        JsonObject pointerUp = event("pointerup", 1400, 215, 95, true, "touch");
        pointerUp.addProperty("w", WIDTH);
        pointerUp.addProperty("h", HEIGHT);
        assertEquals(List.of(), validate());
    }

    @Test
    void unrelatedUntrustedEventsAreIgnored() {
        // Browser extensions may dispatch synthetic events
        event("focus", 50, 0, 0, false, null);
        moves(15);
        click(1400, 215, 95, true, "mouse");
        event("keydown", 1500, 0, 0, false, null);
        assertEquals(List.of(), validate());
    }

}
