// Interaction challenge for clients whose fingerprint looks suspicious. The checkbox is drawn on a
// canvas at a position chosen by the server, so it cannot be found in the DOM. All events that
// lead to the click are recorded and sent to the server, where they are validated and logged.
(function () {
    'use strict';

    const config = {{interaction_config}};
    const FONT = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif';
    const MAX_EVENTS = 2000;
    const MOVE_INTERVAL_MILLIS = 16;
    const LABEL_GAP = 10;

    const canvas = document.getElementById('interaction');
    const ctx = canvas.getContext('2d');
    const start = performance.now();
    const events = [];

    let width = 0;
    let height = 0;
    let lastMove = -Infinity;
    let hover = false;
    let checked = false;

    function elapsed() {
        return Math.round((performance.now() - start) * 10) / 10;
    }

    function round(value) {
        return Math.round(value * 10) / 10;
    }

    // Must match InteractionValidator.boxPosition on the server
    function boxPosition(perMille, extent) {
        const position = Math.round(perMille * extent / 1000);
        return Math.max(config.margin, Math.min(position, extent - config.boxSize - config.margin));
    }

    function box() {
        return {
            x: boxPosition(config.boxX, width),
            y: boxPosition(config.boxY, height),
            size: config.boxSize
        };
    }

    function isOnBox(x, y) {
        const b = box();
        return x >= b.x && x <= b.x + b.size && y >= b.y && y <= b.y + b.size;
    }

    function record(event, extra) {
        if (events.length >= MAX_EVENTS) {
            return;
        }
        const entry = { type: event.type, t: elapsed(), trusted: event.isTrusted };
        const point = event.changedTouches && event.changedTouches.length > 0 ? event.changedTouches[0] : event;
        if (typeof point.clientX === 'number') {
            entry.x = round(point.clientX);
            entry.y = round(point.clientY);
        }
        if (typeof event.pointerType === 'string') {
            entry.pointerType = event.pointerType;
        }
        if (typeof event.buttons === 'number') {
            entry.buttons = event.buttons;
        }
        if (typeof event.pressure === 'number') {
            entry.pressure = round(event.pressure);
        }
        if (typeof event.code === 'string') {
            entry.code = event.code;
        }
        Object.assign(entry, extra);
        events.push(entry);
    }

    function wrapText(text, maxWidth) {
        const lines = [];
        let line = '';
        for (const word of text.split(/\s+/)) {
            const candidate = line ? line + ' ' + word : word;
            if (line && ctx.measureText(candidate).width > maxWidth) {
                lines.push(line);
                line = word;
            } else {
                line = candidate;
            }
        }
        if (line) {
            lines.push(line);
        }
        return lines;
    }

    function roundedRect(x, y, w, h, r) {
        ctx.beginPath();
        ctx.moveTo(x + r, y);
        ctx.arcTo(x + w, y, x + w, y + h, r);
        ctx.arcTo(x + w, y + h, x, y + h, r);
        ctx.arcTo(x, y + h, x, y, r);
        ctx.arcTo(x, y, x + w, y, r);
        ctx.closePath();
    }

    function drawCard() {
        const cardWidth = Math.min(440, width - 2 * config.margin);
        const padding = 24;
        const textWidth = cardWidth - 2 * padding;

        ctx.font = 'bold 22px ' + FONT;
        const headingLines = wrapText(config.i18n.heading, textWidth);
        ctx.font = '16px ' + FONT;
        const descriptionLines = wrapText(config.i18n.description, textWidth);

        const cardHeight = 2 * padding + headingLines.length * 28 + 12 + descriptionLines.length * 22;
        const cardX = (width - cardWidth) / 2;
        const cardY = (height - cardHeight) / 2;

        ctx.save();
        ctx.shadowColor = 'rgba(0, 0, 0, 0.1)';
        ctx.shadowBlur = 40;
        ctx.shadowOffsetY = 10;
        ctx.fillStyle = '#ffffff';
        roundedRect(cardX, cardY, cardWidth, cardHeight, 10);
        ctx.fill();
        ctx.restore();

        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        let y = cardY + padding;
        ctx.fillStyle = '#333333';
        ctx.font = 'bold 22px ' + FONT;
        for (const line of headingLines) {
            ctx.fillText(line, width / 2, y);
            y += 28;
        }
        y += 12;
        ctx.fillStyle = '#555555';
        ctx.font = '16px ' + FONT;
        for (const line of descriptionLines) {
            ctx.fillText(line, width / 2, y);
            y += 22;
        }
    }

    function drawCheckbox() {
        const b = box();
        ctx.fillStyle = hover && !checked ? '#f0f0f0' : '#ffffff';
        ctx.strokeStyle = hover || checked ? '#222222' : '#555555';
        ctx.lineWidth = 2;
        roundedRect(b.x, b.y, b.size, b.size, 5);
        ctx.fill();
        ctx.stroke();

        if (checked) {
            ctx.strokeStyle = '#2e7d32';
            ctx.lineWidth = 4;
            ctx.lineCap = 'round';
            ctx.lineJoin = 'round';
            ctx.beginPath();
            ctx.moveTo(b.x + b.size * 0.22, b.y + b.size * 0.52);
            ctx.lineTo(b.x + b.size * 0.42, b.y + b.size * 0.72);
            ctx.lineTo(b.x + b.size * 0.78, b.y + b.size * 0.3);
            ctx.stroke();
        }

        const label = checked ? config.i18n.verifying : config.i18n.label;
        ctx.font = '16px ' + FONT;
        ctx.textBaseline = 'middle';
        ctx.fillStyle = '#333333';
        const labelWidth = ctx.measureText(label).width;
        if (b.x + b.size + LABEL_GAP + labelWidth <= width - config.margin) {
            ctx.textAlign = 'left';
            ctx.fillText(label, b.x + b.size + LABEL_GAP, b.y + b.size / 2);
        } else {
            ctx.textAlign = 'right';
            ctx.fillText(label, b.x - LABEL_GAP, b.y + b.size / 2);
        }
    }

    function draw() {
        ctx.fillStyle = '#e8e9eb';
        ctx.fillRect(0, 0, width, height);
        drawCard();
        drawCheckbox();
    }

    function resize() {
        const dpr = window.devicePixelRatio || 1;
        width = window.innerWidth;
        height = window.innerHeight;
        canvas.width = Math.round(width * dpr);
        canvas.height = Math.round(height * dpr);
        canvas.style.width = width + 'px';
        canvas.style.height = height + 'px';
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        draw();
    }

    function submit() {
        const data = {
            version: 1,
            viewport: { w: width, h: height, dpr: window.devicePixelRatio || 1 },
            screen: { w: screen.width, h: screen.height },
            box: box(),
            events: events
        };
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = window.location.pathname;
        const fields = {
            'interaction_token': config.token,
            'interaction_events': JSON.stringify(data)
        };
        for (const [name, value] of Object.entries(fields)) {
            const input = document.createElement('input');
            input.type = 'hidden';
            input.name = name;
            input.value = value;
            form.appendChild(input);
        }
        document.body.appendChild(form);
        form.submit();
    }

    window.addEventListener('pointermove', function (event) {
        const now = performance.now();
        if (now - lastMove >= MOVE_INTERVAL_MILLIS) {
            lastMove = now;
            record(event);
        }
        const onBox = isOnBox(event.clientX, event.clientY);
        if (onBox !== hover) {
            hover = onBox;
            canvas.style.cursor = hover ? 'pointer' : 'default';
            draw();
        }
    }, { capture: true, passive: true });

    for (const type of ['pointerdown', 'pointerup', 'pointercancel', 'touchstart', 'touchend', 'wheel', 'keydown',
        'focus', 'blur']) {
        window.addEventListener(type, record, { capture: true, passive: true });
    }

    document.addEventListener('visibilitychange', function (event) {
        record(event, { state: document.visibilityState });
    }, true);

    window.addEventListener('resize', function (event) {
        resize();
        record(event, { w: width, h: height });
    });

    window.addEventListener('click', function (event) {
        record(event, { w: width, h: height });
        if (checked || !isOnBox(event.clientX, event.clientY)) {
            return;
        }
        checked = true;
        canvas.style.cursor = 'default';
        draw();
        setTimeout(submit, 300);
    }, true);

    resize();
})();
