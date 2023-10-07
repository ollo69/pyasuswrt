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

_MAP_SYSINFO: dict[str, list[str]] = {
    "conn_stats_arr": [
        "conn_total",
        "conn_active",
    ],
    "cpu_stats_arr": [
        "load_avg_1",
        "load_avg_5",
        "load_avg_15",
    ],
    "mem_stats_arr": [
        "ram_total",
        "ram_free",
        "buffers",
        "cache",
        "swap_size",
        "swap_total",
        "nvram_used",
        "jffs",
    ],
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


def _parse_sysinfo(raw: str) -> dict[str, Any]:
    """Sysinfo parser"""

    if type(raw) != str:
        raise AsusWrtValueError("Invalid sysinfo values")
    if raw.strip() == str():
        return {}

    raw = raw.replace("\n", "")
    raw = raw.replace("\ufeff", "")
    raw = raw.replace(" = ", "=")
    raw = raw.replace("=", '": ')
    raw = raw.replace(";", ',"')
    raw = '{"' + raw[:-2] + "}"

    to_parse = _get_json_result(raw)

    sys_info = dict()
    for cat_info in _MAP_SYSINFO:
        if cat_info not in to_parse:
            continue
        cat = {}
        values = to_parse[cat_info]
        for idx, key in enumerate(_MAP_SYSINFO[cat_info]):
            try:
                value = values[idx]
            except (IndexError, ValueError):
                value = None
            cat[key] = value
        sys_info[cat_info] = cat

    return sys_info


def _calculate_cpu_usage(cur_val: dict[str, int], prev_val: dict[str, int]) -> float:
    """Calculate cpu usage as percentage."""
    values = {}
    for key in ["total", "usage"]:
        if key not in cur_val or key not in prev_val:
            return 0.0
        values[key] = cur_val[key] - prev_val[key]

    total = values["total"]
    usage = values["usage"]
    if total <= 0 or usage < 0:
        return 0.0

    try:
        return round((usage / total) * 100, 2)
    except ValueError:
        return 0.0


def _parse_fw_info(fw_info: str | None) -> str | None:
    """Parse information related to new firmware."""

    if not fw_info:
        return None
    split_info = fw_info.split(";")
    new_ver = None
    for prop in split_info:
        if prop.find("webs_state_info") >= 0:
            res = prop.split("=")
            if len(res) >= 2:
                new_ver = res[1].strip().replace("'", "")
            break

    return new_ver
