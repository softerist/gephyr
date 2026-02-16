import json
import os
from datetime import datetime, timezone
from threading import Lock
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


OUT_PATH = os.environ.get("GEPHYR_MITM_OUT", "output/known_good.jsonl")
DIAG_PATH = os.environ.get(
    "GEPHYR_MITM_DIAG_OUT", "output/known_good_capture_hosts.json"
)
DEFAULT_TARGET_HOSTS = {"oauth2.googleapis.com", "cloudcode-pa.googleapis.com"}
DEFAULT_TARGET_SUFFIXES = {".googleapis.com", ".google.com"}
TARGET_PATH_MARKERS = (
    "streamgeneratecontent",
    "generatecontent",
    "completecode",
    "/v1internal",
    "v1internal:",
)
CAPTURE_ALL = os.environ.get("GEPHYR_MITM_CAPTURE_ALL", "").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)
CAPTURE_NOISE = os.environ.get("GEPHYR_MITM_CAPTURE_NOISE", "").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)
LOCK = Lock()
HOST_COUNTS = {}
TARGET_COUNTS = {}
UA_COUNTS = {}
TARGET_UA_COUNTS = {}
DROPPED_UA_COUNTS = {}
TARGET_HOSTS = set()
TARGET_SUFFIXES = set()
UA_CONTAINS = set()
UA_EXCLUDE_CONTAINS = set()
SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-goog-api-key",
    "proxy-authorization",
}
SENSITIVE_QUERY_KEYS = {
    "access_token",
    "id_token",
    "refresh_token",
    "token",
    "code",
    "client_secret",
    "api_key",
    "key",
}


def _parse_csv_set(raw: str) -> set[str]:
    values = set()
    if not raw:
        return values
    for part in raw.split(","):
        token = part.strip().lower()
        # Allow values to be passed with shell quotes, e.g. "'antigravity/'" or "\"antigravity/\"".
        if len(token) >= 2 and ((token[0] == "'" and token[-1] == "'") or (token[0] == '"' and token[-1] == '"')):
            token = token[1:-1].strip().lower()
        if token:
            values.add(token)
    return values


TARGET_HOSTS = _parse_csv_set(
    os.environ.get("GEPHYR_MITM_TARGET_HOSTS", "oauth2.googleapis.com,cloudcode-pa.googleapis.com")
) or DEFAULT_TARGET_HOSTS
TARGET_SUFFIXES = _parse_csv_set(
    os.environ.get("GEPHYR_MITM_TARGET_SUFFIXES", ".googleapis.com,.google.com")
) or DEFAULT_TARGET_SUFFIXES
UA_CONTAINS = _parse_csv_set(os.environ.get("GEPHYR_MITM_UA_CONTAINS", ""))
UA_EXCLUDE_CONTAINS = _parse_csv_set(os.environ.get("GEPHYR_MITM_UA_EXCLUDE_CONTAINS", ""))

if CAPTURE_ALL:
    # When capturing all hosts, also keep "noise" requests unless explicitly disabled.
    CAPTURE_NOISE = True if not os.environ.get("GEPHYR_MITM_CAPTURE_NOISE") else CAPTURE_NOISE


def _ua_allowed(user_agent: str) -> bool:
    lowered = (user_agent or "").lower()
    if UA_EXCLUDE_CONTAINS and lowered:
        if any(token in lowered for token in UA_EXCLUDE_CONTAINS):
            return False
    if not UA_CONTAINS:
        return True
    if not lowered:
        return False
    return any(token in lowered for token in UA_CONTAINS)


def _is_target_host(host: str) -> bool:
    if CAPTURE_ALL:
        return True
    if not host:
        return False
    lowered = host.lower()
    if lowered in TARGET_HOSTS:
        return True
    return any(lowered.endswith(suffix) for suffix in TARGET_SUFFIXES)


def _is_target_path(path: str) -> bool:
    lowered = (path or "").lower()
    if not lowered:
        return False
    return any(marker in lowered for marker in TARGET_PATH_MARKERS)


def _is_noise_request(host: str, path: str) -> bool:
    lowered_host = (host or "").lower()
    lowered_path = (path or "").lower()
    return lowered_host == "oauth2.googleapis.com" and lowered_path.startswith("/tokeninfo")


def _sanitize_url(url: str) -> str:
    if not url:
        return url
    try:
        parts = urlsplit(url)
        query_pairs = parse_qsl(parts.query, keep_blank_values=True)
        sanitized_pairs = []
        for key, value in query_pairs:
            lowered = key.lower()
            if lowered in SENSITIVE_QUERY_KEYS or "token" in lowered or "secret" in lowered:
                sanitized_pairs.append((key, "<redacted>"))
            else:
                sanitized_pairs.append((key, value))
        sanitized_query = urlencode(sanitized_pairs, doseq=True)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, sanitized_query, ""))
    except Exception:
        return url


def _write_diag_snapshot() -> None:
    sorted_hosts = sorted(HOST_COUNTS.items(), key=lambda item: item[1], reverse=True)
    sorted_targets = sorted(TARGET_COUNTS.items(), key=lambda item: item[1], reverse=True)
    sorted_uas = sorted(UA_COUNTS.items(), key=lambda item: item[1], reverse=True)
    sorted_target_uas = sorted(TARGET_UA_COUNTS.items(), key=lambda item: item[1], reverse=True)
    sorted_dropped_uas = sorted(DROPPED_UA_COUNTS.items(), key=lambda item: item[1], reverse=True)
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "capture_all": CAPTURE_ALL,
        "capture_noise": CAPTURE_NOISE,
        "target_hosts": sorted(TARGET_HOSTS),
        "target_suffixes": sorted(TARGET_SUFFIXES),
        "ua_contains": sorted(UA_CONTAINS),
        "ua_exclude_contains": sorted(UA_EXCLUDE_CONTAINS),
        "total_requests_seen": sum(HOST_COUNTS.values()),
        "total_target_requests_seen": sum(TARGET_COUNTS.values()),
        "top_user_agents": [
            {"user_agent": ua, "count": count} for ua, count in sorted_uas[:30]
        ],
        "top_target_user_agents": [
            {"user_agent": ua, "count": count} for ua, count in sorted_target_uas[:30]
        ],
        "top_dropped_user_agents": [
            {"user_agent": ua, "count": count} for ua, count in sorted_dropped_uas[:30]
        ],
        "top_hosts": [
            {"host": host, "count": count} for host, count in sorted_hosts[:30]
        ],
        "top_target_hosts": [
            {"host": host, "count": count} for host, count in sorted_targets[:30]
        ],
    }
    os.makedirs(os.path.dirname(DIAG_PATH) or ".", exist_ok=True)
    with open(DIAG_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, separators=(",", ":"), ensure_ascii=False)


class GoogleCapture:
    def __init__(self):
        with LOCK:
            _write_diag_snapshot()

    def requestheaders(self, flow):
        host = getattr(flow.request, "host", "")
        path = getattr(flow.request, "path", "") or ""
        lowered_host = (host or "").lower()
        user_agent = flow.request.headers.get("user-agent", "") or ""
        ua_key = str(user_agent).strip()
        if len(ua_key) > 200:
            ua_key = ua_key[:200] + "..."
        with LOCK:
            HOST_COUNTS[lowered_host] = HOST_COUNTS.get(lowered_host, 0) + 1
            if ua_key:
                UA_COUNTS[ua_key] = UA_COUNTS.get(ua_key, 0) + 1

        if (not _is_target_host(host)) and (not _is_target_path(path)):
            # Persist host/UA counters even for non-target traffic so diagnostics remain
            # accurate when mitmdump is terminated immediately after capture.
            with LOCK:
                _write_diag_snapshot()
            return
        if (not CAPTURE_NOISE) and _is_noise_request(host, path):
            with LOCK:
                _write_diag_snapshot()
            return

        # Optional allowlist to keep captures "apples-to-apples" when multiple clients share the proxy.
        if not _ua_allowed(user_agent):
            with LOCK:
                if ua_key:
                    DROPPED_UA_COUNTS[ua_key] = DROPPED_UA_COUNTS.get(ua_key, 0) + 1
                _write_diag_snapshot()
            return

        with LOCK:
            TARGET_COUNTS[lowered_host] = TARGET_COUNTS.get(lowered_host, 0) + 1
            if ua_key:
                TARGET_UA_COUNTS[ua_key] = TARGET_UA_COUNTS.get(ua_key, 0) + 1

        headers = {}
        for key, value in flow.request.headers.items(multi=True):
            lowered = str(key).lower()
            if lowered in SENSITIVE_HEADERS:
                headers[lowered] = "<redacted>"
            else:
                headers[lowered] = str(value)

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "endpoint": _sanitize_url(flow.request.pretty_url),
            "method": str(getattr(flow.request, "method", "") or ""),
            "mode": "known_good",
            "headers": headers,
        }

        line = json.dumps(record, separators=(",", ":"))
        with LOCK:
            os.makedirs(os.path.dirname(OUT_PATH) or ".", exist_ok=True)
            with open(OUT_PATH, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            _write_diag_snapshot()

    def done(self):
        with LOCK:
            _write_diag_snapshot()


addons = [GoogleCapture()]
