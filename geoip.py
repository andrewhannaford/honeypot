"""
GeoIP enrichment via geoip2fast (bundled DB, no external API).
"""

import ipaddress
import threading
from typing import Any, Dict

_geo_engine = None
_geo_lock = threading.Lock()


def _as_dict(detail: Any) -> Dict[str, Any]:
    if detail is None:
        return {}
    if isinstance(detail, dict):
        return detail
    to_dict = getattr(detail, "to_dict", None)
    if callable(to_dict):
        try:
            return to_dict()
        except Exception:
            pass
    try:
        return dict(detail)
    except (TypeError, ValueError):
        return {}


def _engine():
    global _geo_engine
    with _geo_lock:
        if _geo_engine is None:
            from geoip2fast import GeoIP2Fast

            _geo_engine = GeoIP2Fast()
        return _geo_engine


def lookup(ip: str) -> dict:
    """Return fields for DB/JSONL: country, city, lat, lon (only keys that are set).

    Private/reserved addresses, bad input, or lookup errors return {}.
    """
    if not ip or not isinstance(ip, str):
        return {}
    ip = ip.strip()
    if not ip:
        return {}
    try:
        addr = ipaddress.ip_address(ip)
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
        ):
            return {}
    except ValueError:
        return {}

    try:
        detail = _as_dict(_engine().lookup(ip))
        if not detail or detail.get("is_private"):
            return {}
        out = {}
        cc = detail.get("country_code")
        if cc:
            out["country"] = str(cc)
        city = detail.get("city") or detail.get("city_name")
        if city:
            out["city"] = str(city)
        lat = detail.get("latitude")
        lon = detail.get("longitude")
        if lat is not None:
            try:
                out["lat"] = float(lat)
            except (TypeError, ValueError):
                pass
        if lon is not None:
            try:
                out["lon"] = float(lon)
            except (TypeError, ValueError):
                pass
        return out
    except Exception:
        return {}
