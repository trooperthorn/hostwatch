"""Boot classifications and hardware events sent to Home Assistant over MQTT.

Events go to `<base topic>/events`, one JSON message per event, not retained: an event is a
moment in time, and a retained copy would be replayed to every new subscriber as if it just
happened. Each message carries the store's event id, which is the deduplication key.

Progress is a cursor (the last event id sent) kept in the store table `publish_cursors`, and
it moves forward only after the broker connection accepted the publish. A restart therefore
neither replays old events nor skips unsent ones. A failed publish stops the batch and the
next tick retries from the same event. If the process dies between a publish and the cursor
write, that one event is sent again (at-least-once), and consumers can drop it by id.

The first run, when no cursor exists yet, starts at the newest event already stored, so
enabling MQTT does not flood Home Assistant with history.
"""

from __future__ import annotations

import json
import logging
import threading

from ..config import Config
from .mqtt_client import MqttClient

log = logging.getLogger(__name__)

CURSOR_NAME = "ha_events"
# Boot classifications and hardware events only. Samples and ordinary status are not events.
EVENT_SOURCES = ("boot", "pstore", "rasdaemon", "thresholds", "journal")
BATCH = 100


class HomeAssistantEventPublisher:
    def __init__(self, config: Config, client: MqttClient, store) -> None:
        self.config = config
        self.client = client
        self.store = store
        self.topic = f"{config.mqtt_base_topic}/events"
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @staticmethod
    def payload(event: dict) -> str:
        return json.dumps({
            "id": event["id"], "host": event["host"], "ts": event["ts"], "kind": event["kind"],
            "severity": event["severity"], "source": event["source"], "title": event["title"],
            "detail": event["detail"], "boot_id": event.get("boot_id"),
        }, sort_keys=True, ensure_ascii=False)

    def tick(self) -> int:
        """Publish events newer than the cursor. Returns how many were sent this tick."""
        if not self.client.ensure_connected():
            return 0
        cursor = self.store.get_cursor(CURSOR_NAME)
        if cursor is None:
            cursor = self.store.max_event_id()
            self.store.set_cursor(CURSOR_NAME, cursor)
        sent = 0
        while True:
            batch = self.store.events_after(cursor, EVENT_SOURCES, BATCH)
            for event in batch:
                if not self.client.publish(self.topic, self.payload(event), retain=False):
                    return sent
                cursor = event["id"]
                self.store.set_cursor(CURSOR_NAME, cursor)
                sent += 1
            if len(batch) < BATCH:
                return sent

    def _run(self) -> None:
        while True:
            try:
                self.tick()
            except Exception as exc:  # noqa: BLE001 - the loop must survive a bad tick
                log.warning("Home Assistant events publish failed (%s)", type(exc).__name__)
            if self._stop.wait(self.config.mqtt_events_interval):
                return

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="ha-events", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=10)
            self._thread = None
