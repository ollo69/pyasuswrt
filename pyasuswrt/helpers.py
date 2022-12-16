"""PyAsusWRT Parser implementation"""
from __future__ import annotations

import json
import re
from typing import Any

from .exceptions import AsusWrtValueError

_MAP_TEMPERATURES: dict[str, list[str]] = {
    "2.4GHz": [
        'curr_coreTmp_2_raw="([0-9.]+)&deg;C',
        'curr_coreTmp_0_raw="([0-9.]+)&deg;C',
        'curr_coreTmp_wl0_raw="([0-9.]+)&deg;C',
    ],
    "5.0GHz": [
        'curr_coreTmp_5_raw="([0-9.]+)&deg;C',
        'curr_coreTmp_1_raw="([0-9.]+)&deg;C',
        'curr_coreTmp_wl1_raw="([0-9.]+)&deg;C',
    ],
    "5.0GHz_2": [
        'curr_coreTmp_52_raw="([0-9.]+)&deg;C',
        'curr_coreTmp_2_raw="([0-9.]+)&deg;C',
        'curr_coreTmp_wl2_raw="([0-9.]+)&deg;C',
    ],
    "6.0GHz": [
        'curr_coreTmp_3_raw="([0-9.]+)&deg;C',
        'curr_coreTmp_wl3_raw="([0-9.]+)&deg;C',
    ],
    "CPU": ['curr_cpuTemp="([0-9.]+)"', 'curr_coreTmp_cpu="([0-9.]+)"'],
}


def _get_json_result(result: str, json_key: str | None = None):
    """Return the json result from a text result."""
    try:
        json_res = json.loads(result)
    except json.JSONDecodeError as exc:
        raise AsusWrtValueError(str(exc)) from exc

    if not json_key:
        return json_res

    if (json_val := json_res.get(json_key)) is None:
        raise AsusWrtValueError("No value available")
    return json_val


def _parse_temperatures(raw: str) -> dict[str, Any]:
    """Temperature parser"""

    if type(raw) != str:
        raise AsusWrtValueError("Invalid temperatures values")
    if raw.strip() == str():
        return {}

    to_parse = raw.replace(" = ", "=")
    temps = dict()

    for sensor in _MAP_TEMPERATURES:
        for reg in _MAP_TEMPERATURES[sensor]:
            value = re.search(reg, to_parse)
            if value:
                temps[sensor] = round(float(value[1]), 1)

    return temps
