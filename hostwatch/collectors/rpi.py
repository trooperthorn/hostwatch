"""Raspberry Pi throttling, under-voltage and SoC temperature.

A Pi that browns out or throttles is the most common reason it misbehaves, so the firmware
throttled bitmask is read and decoded into one sample per flag. Reported:
  throttle_flag  1 or 0 with label flag=<name>, one per decoded bit (see FLAGS)
  throttled_raw  the whole bitmask as a number
  soc_temp       degrees C from the thermal zone whose type is cpu-thermal

The bitmask file is the firmware get_throttled attribute under sysfs, or any path given in
HOSTWATCH_RPI_THROTTLED_PATH. Whether that attribute exists on a Pi 5 running Debian, and the
exact bit meanings, are unconfirmed (UNVERIFIED.md). A Pi without the file is unavailable
with the reason and the vcgencmd alternative, never reported as zero. A host that is not a Pi
is reported not present only when the model files were looked for and show no Pi.
"""

from __future__ import annotations

from pathlib import Path

from .base import Collector, read_int, read_text

DEFAULT_THROTTLED = Path("devices") / "platform" / "soc" / "soc:firmware" / "get_throttled"

# bit -> flag name. Bits 0 to 3 are the current state, bits 16 to 19 have occurred since boot.
FLAGS = {
    0: "under_voltage_now",
    1: "freq_capped_now",
    2: "throttled_now",
    3: "soft_temp_limit_now",
    16: "under_voltage_occurred",
    17: "freq_capped_occurred",
    18: "throttled_occurred",
    19: "soft_temp_limit_occurred",
}


def decode_throttled(raw: int) -> dict[str, bool]:
    return {name: bool(raw >> bit & 1) for bit, name in FLAGS.items()}


class RpiCollector(Collector):
    id = "rpi"

    def __init__(self, sysfs: Path, procfs: Path, throttled_path: str = "") -> None:
        super().__init__(sysfs, procfs)
        self._throttled_cfg = throttled_path.strip()

    @property
    def _model_files(self) -> list[Path]:
        return [self.procfs / "device-tree" / "model",
                self.sysfs / "firmware" / "devicetree" / "base" / "model"]

    @property
    def throttled_file(self) -> Path:
        if self._throttled_cfg:
            return Path(self._throttled_cfg)
        return self.sysfs / DEFAULT_THROTTLED

    def _model(self) -> str | None:
        for f in self._model_files:
            text = read_text(f)
            if text is not None:
                return text.replace("\x00", "").strip()
        return None

    def is_absent(self) -> bool:
        """Absent when a model file was read and is not a Pi, or when both procfs and sysfs are
        readable directories and neither holds a model file. Anything else stays unavailable."""
        model = self._model()
        if model is not None:
            return not model.startswith("Raspberry Pi")
        return self.procfs.is_dir() and self.sysfs.is_dir()

    def _raw(self) -> tuple[int | None, str]:
        text = read_text(self.throttled_file)
        if text is None:
            return None, (f"throttled bitmask {self.throttled_file} is not readable; the vcgencmd "
                          "alternative is 'vcgencmd get_throttled' on the host")
        try:
            return int(text, 0), ""
        except ValueError:
            return None, f"throttled bitmask {self.throttled_file} holds {text!r}, not a number"

    def detect(self) -> tuple[bool, str]:
        model = self._model()
        if model is None or not model.startswith("Raspberry Pi"):
            return False, "not a Raspberry Pi (no Raspberry Pi device tree model)"
        raw, reason = self._raw()
        if raw is None:
            return False, reason
        return True, f"throttled bitmask {hex(raw)}"

    def _soc_temp(self) -> float | None:
        base = self.sysfs / "class" / "thermal"
        try:
            zones = sorted(p for p in base.iterdir() if p.name.startswith("thermal_zone"))
        except OSError:
            return None
        for z in zones:
            if read_text(z / "type") == "cpu-thermal":
                milli = read_int(z / "temp")
                return None if milli is None else round(milli / 1000.0, 1)
        return None

    def collect(self):
        out = []
        raw, _ = self._raw()
        if raw is None:
            for name in FLAGS.values():
                out.append(self.sample("throttle_flag", None, "", flag=name))
            out.append(self.sample("throttled_raw", None, ""))
        else:
            for name, on in decode_throttled(raw).items():
                out.append(self.sample("throttle_flag", 1 if on else 0, "", flag=name))
            out.append(self.sample("throttled_raw", float(raw), ""))
        out.append(self.sample("soc_temp", self._soc_temp(), "C"))
        return out
