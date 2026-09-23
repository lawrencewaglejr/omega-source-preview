"""Cross-source evidence summaries and a standalone, escaped OMEGA report.

Counts consume every supplied normalized record. Correlations are candidates:
shared device addresses in overlapping time windows are not proof of causation.
No log text is interpreted as markup, code, or model instructions here.
"""
from __future__ import annotations

import collections
import csv
import heapq
import io
import datetime as dt
import hashlib
import html
import ipaddress
import json
import math
from functools import lru_cache

SOURCE_LABELS = {"suricata": "Suricata", "wazuh": "Wazuh", "pihole": "Pi-hole"}
SOURCE_ORDER = {name: number for number, name in enumerate(SOURCE_LABELS)}
UTC = dt.timezone.utc
LOCAL_NETWORKS = tuple(ipaddress.ip_network(value) for value in
                       ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10"))


def _text(value, limit=240):
    return "" if value is None else str(value)[:limit]


def _time(value):
    if not isinstance(value, str) or not value:
        return None
    try:
        value = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if value.tzinfo is None:
            return None
        return value.timestamp()
    except (ValueError, OverflowError, OSError):
        return None


def _iso(timestamp):
    return dt.datetime.fromtimestamp(timestamp, UTC).isoformat()


def _severity(event):
    value = event.get("severity")
    return value if type(value) is int and value in (1, 2, 3) else None


def _address(value):
    return _cached_address(str(value))


@lru_cache(maxsize=8192)
def _cached_address(value):
    try:
        address = ipaddress.ip_address(str(value))
        if address.is_multicast or address.is_unspecified or address.is_loopback:
            return None
        return address
    except ValueError:
        return None


def _entities(event, known_ips):
    """Avoid joining unrelated clients just because they used one public server."""
    details = event.get("details") if isinstance(event.get("details"), dict) else {}
    return _entity_addresses(_text(event.get("source")), _origin(event),
                             _text(event.get("source_ip")), _text(event.get("destination_ip")),
                             _text(details.get("agent_ip")), frozenset(known_ips))


@lru_cache(maxsize=8192)
def _entity_addresses(source, origin, source_ip, destination_ip, agent_ip, known_ips):
    # A sensor relaying captured traffic is not necessarily a traffic endpoint.
    explicit = [] if origin == "suricata" else [agent_ip]
    if source == "pihole":
        explicit.append(source_ip)
    result = set()
    for value in explicit:
        address = _address(value)
        if address:
            result.add(str(address))
    for value in (source_ip, destination_ip):
        address = _address(value)
        if address and (str(address) in known_ips or any(address in network for network in LOCAL_NETWORKS if address.version == network.version)):
            result.add(str(address))
    return tuple(sorted(result))


def _origin(event):
    source = _text(event.get("source") or "unknown", 40)
    details = event.get("details") if isinstance(event.get("details"), dict) else {}
    location = _text(details.get("location"), 400).lower()
    if source == "wazuh" and (details.get("origin") == "suricata" or "suricata" in location and "eve.json" in location):
        return "suricata"
    return source


def _mirror_key(event):
    details = event.get("details") if isinstance(event.get("details"), dict) else {}
    flow = details.get("community_id") or details.get("flow_id")
    signature = details.get("signature_id")
    timestamp = _time(details.get("origin_timestamp") or event.get("timestamp"))
    if _origin(event) != "suricata" or flow is None or signature is None or timestamp is None:
        return None
    # Exact originating timestamp + flow + signature; never guess from matching prose.
    return hashlib.sha256(f"{flow}|{signature}|{timestamp}".encode()).hexdigest()[:24]


def _event_view(event):
    return {"origin": _origin(event), "_mirror_key": _mirror_key(event),"id": _text(event.get("id"), 128), "source": _text(event.get("source"), 40),
            "timestamp": _text(event.get("timestamp"), 80), "severity": _severity(event),
            "event_type": _text(event.get("event_type"), 80), "title": _text(event.get("title"), 220),
            "source_ip": _text(event.get("source_ip"), 80), "destination_ip": _text(event.get("destination_ip"), 80),
            "hostname": _text(event.get("hostname"), 120), "domain": _text(event.get("domain"), 180),
            "rule_id": _text(event.get("rule_id"), 80), "action": _text(event.get("action"), 80)}


def _event_rank(event):
    return (_severity(event) or 4, event.get("event_type") != "alert", _text(event.get("timestamp"),80), _text(event.get("id"),128))


def _keep_example(examples, event, limit):
    if len(examples) >= limit and _event_rank(event) >= _event_rank(examples[-1]):
        return
    if any(item["id"] == event["id"] for item in examples):
        return
    # Only construct bounded descriptions/hashes for evidence actually selected.
    examples.append(_event_view(event))
    examples.sort(key=_event_rank)
    del examples[limit:]


def _ordered(counter):
    return dict(sorted(counter.items(), key=lambda pair: (-pair[1], str(pair[0]))))


def analyze_events(events, *, coverage=None, sources=None, window_seconds=300,
                   max_candidates=40, known_ips=(), max_active_windows=12000):
    """Summarize a timestamp-ascending iterator without retaining raw history.

    Each event enters two half-offset windows. Totals are exact for the supplied
    iterator; groups overlap, and their counts must not be added together. The
    active-window bound affects candidate discovery only and is reported.
    """
    if window_seconds < 2 or max_candidates < 0 or max_active_windows < 1:
        raise ValueError("Invalid correlation bounds")
    source_counts, stream_counts, type_counts, severity_counts = (collections.Counter() for _ in range(4))
    source_type_counts = collections.defaultdict(collections.Counter)
    examples = collections.defaultdict(list)
    active, candidates, expiry = {}, [], []
    total = untimed = unordered = unassociated = pressure_drops = candidate_total = relayed = relay_only_windows = 0
    first = last = watermark = None
    known_ips = frozenset(str(address) for value in known_ips if (address := _address(value)))
    half = window_seconds / 2

    def complete(key):
        nonlocal candidate_total, relay_only_windows
        group = active.pop(key)
        if len(group["source_counts"]) < 2:
            return
        if len(group["origin_counts"]) < 2:
            relay_only_windows += 1
            return
        candidate_total += 1
        device = key[1]
        names = sorted(group["source_counts"], key=lambda name: (SOURCE_ORDER.get(name, 99), name))
        selected = [event for name in names for event in group["examples"][name]]
        selected.sort(key=lambda event: (SOURCE_ORDER.get(event["source"], 99), _event_rank(event)))
        matched = []
        for value in {event.get("_mirror_key") for event in selected} - {None}:
            records = [event for event in selected if event.get("_mirror_key") == value]
            if {event["source"] for event in records} >= {"suricata", "wazuh"}:
                matched.append([event["id"] for event in records])
        selected = [{key: value for key, value in event.items() if key != "_mirror_key"} for event in selected]
        group_id = hashlib.sha256(f"{key[0]}|{device}|{','.join(names)}".encode()).hexdigest()[:16]
        severity = min((event["severity"] for event in selected if event["severity"]), default=None)
        candidate = {"id": "corr-" + group_id, "device": device,
                     "title": " + ".join(SOURCE_LABELS.get(name, name) for name in names) + " activity",
                     "summary": f"{group['event_count']} observations shared {device} within a {window_seconds}-second window. This is a temporal association, not proof of a related attack.",
                     "sources": names, "source_counts": _ordered(group["source_counts"]),
                     "first_seen": _iso(group["first"]), "last_seen": _iso(group["last"]),
                     "window_start": _iso(key[0]), "window_end": _iso(key[0] + window_seconds),
                     "event_count": group["event_count"], "severity": severity,
                     "origin_counts": _ordered(group["origin_counts"]),
                     "relayed_suricata_events": group["relayed"], "matching_relay_event_ids": matched,
                     "event_ids": [event["id"] for event in selected], "events": selected}
        candidates.append(candidate)
        # Keep enough alternatives for per-device diversity without keeping every window.
        if len(candidates) > max(80, max_candidates * 8):
            candidates.sort(key=_candidate_rank)
            del candidates[max(40, max_candidates * 4):]

    for event in events:
        total += 1
        source = _text(event.get("source") or "unknown", 40)
        kind = _text(event.get("event_type") or "unknown", 80)
        source_counts[source] += 1
        stream_counts[_text(event.get("stream") or source, 80)] += 1
        type_counts[kind] += 1
        source_type_counts[source][kind] += 1
        severity_counts[str(_severity(event) or "unrated")] += 1
        origin = _origin(event)
        if source == "wazuh" and origin == "suricata":
            relayed += 1
        _keep_example(examples[source], event, 3)
        timestamp = _time(event.get("timestamp"))
        if timestamp is None:
            untimed += 1
            continue
        first = timestamp if first is None else min(first, timestamp)
        last = timestamp if last is None else max(last, timestamp)
        if watermark is not None and timestamp < watermark:
            unordered += 1
            continue
        watermark = timestamp
        while expiry and expiry[0][0] <= timestamp:
            _, key = heapq.heappop(expiry)
            if key in active:
                complete(key)
        entities = _entities(event, known_ips)
        if not entities:
            unassociated += 1
            continue
        starts = (math.floor(timestamp / window_seconds) * window_seconds,
                  math.floor((timestamp - half) / window_seconds) * window_seconds + half)
        for device in entities:
            for start in starts:
                key = (start, device)
                if key not in active:
                    if len(active) >= max_active_windows:
                        pressure_drops += 1
                        continue
                    heapq.heappush(expiry, (start + window_seconds, key))
                    active[key] = {"first": timestamp, "last": timestamp, "event_count": 0,
                                   "source_counts": collections.Counter(), "origin_counts": collections.Counter(), "relayed": 0, "examples": collections.defaultdict(list)}
                group = active[key]
                group["event_count"] += 1
                group["last"] = timestamp
                group["source_counts"][source] += 1
                group["origin_counts"][origin] += 1
                group["relayed"] += source == "wazuh" and origin == "suricata"
                _keep_example(group["examples"][source], event, 2)
    for key in list(active):
        complete(key)
    candidates.sort(key=_candidate_rank)
    chosen = []
    per_device = collections.Counter()
    for candidate in candidates:
        # Suppress the two half-offset representations of identical evidence.
        if any(candidate["device"] == item["device"] and set(candidate["sources"]).issubset(item["sources"])
               and set(candidate["event_ids"]).issubset(item["event_ids"])
               and candidate["event_count"] <= item["event_count"]
               and candidate["first_seen"] >= item["first_seen"] and candidate["last_seen"] <= item["last_seen"] for item in chosen):
            continue
        if per_device[candidate["device"]] >= max(2, max_candidates // 4):
            continue
        if len(chosen) >= max_candidates:
            break
        chosen.append(candidate)
        per_device[candidate["device"]] += 1
    limitations = [
        "Counts cover every retained normalized event in this report, not events unavailable to OMEGA or already removed by source retention.",
        "Correlation candidates share a local or known device IP in overlapping time windows; timing and address overlap do not establish causation or compromise.",
        "Wazuh may relay Suricata records; multiple streams do not establish independent evidence. Explicit Suricata relay records are assigned the Suricata origin when forming cross-source candidates.",
        "An IP can be reassigned or shared through NAT. Hostnames and device names are observations, not verified identity.",
        "Candidate groups overlap and their event counts are not additive. Selected candidates and evidence examples are representative, not an exhaustive list of relationships.",
        "AI receives aggregate counts from retained events and selected evidence excerpts. It does not individually inspect every raw event or decrypt communications.",
        "AI evidence omits complete source log messages. The report's source-events.jsonl preserves the original collected sensor records separately, subject to the declared collection coverage.",
    ]
    if untimed:
        limitations.append(f"{untimed} records had no timezone-aware timestamp; included in counts and export but excluded from temporal matching.")
    if unordered:
        limitations.append(f"{unordered} out-of-order records were included in counts and export but excluded from temporal matching.")
    if pressure_drops:
        limitations.append(f"The active-window memory limit skipped {pressure_drops} window associations; aggregate counts still include those records.")
    return {"events_analyzed": total, "source_counts": _ordered(source_counts),
            "stream_counts": _ordered(stream_counts), "event_types": _ordered(type_counts),
            "source_event_types": {source: _ordered(counts) for source, counts in sorted(source_type_counts.items())},
            "severity_counts": _ordered(severity_counts), "first_event": _iso(first) if first is not None else None,
            "last_event": _iso(last) if last is not None else None, "correlations": chosen,
            "candidate_windows": candidate_total, "selected_correlations": len(chosen),
            "representative_events": {source: [{key: value for key, value in event.items() if key != "_mirror_key"} for event in values] for source, values in sorted(examples.items())},
            "relayed_suricata_events": relayed, "relay_only_windows_excluded": relay_only_windows,
            "without_timestamp": untimed, "without_device_address": unassociated,
            "out_of_order": unordered, "window_associations_skipped": pressure_drops,
            "window_seconds": window_seconds, "coverage": coverage or {}, "sources": sources or [],
            "limitations": limitations}


def _candidate_rank(candidate):
    return (candidate.get("severity") or 4, -len(candidate["sources"]), -candidate["event_count"],
            candidate["first_seen"], candidate["device"], candidate["id"])


def build_ai_evidence(analysis, *, max_candidates=2, max_events_per_candidate=3, max_chars=3000):
    """Full-source totals and compact, explicitly selected model evidence."""
    if max_chars < 2000 or max_candidates < 0 or max_events_per_candidate < 0:
        raise ValueError("Invalid AI evidence bounds")
    def compact_event(event):
        return {key: _text(event[key],80 if key in {"title","domain"} else 128)
                for key in ("id","source","title","source_ip","domain","rule_id") if event.get(key)}
    result = {
        "scope":"All retained events counted; AI sees selected examples only.",
        "events_analyzed":analysis["events_analyzed"],
        "source_counts":analysis["source_counts"],"stream_counts":analysis["stream_counts"],
        "event_types":analysis["event_types"],"severity_counts":analysis["severity_counts"],
        "first_event":analysis["first_event"],"last_event":analysis["last_event"],
        "relayed_suricata_events":analysis["relayed_suricata_events"],
        "sources":[{key:source.get(key) for key in ("id","available","caught_up","notice") if source.get(key) is not None and source.get(key)!=""} for source in analysis["sources"]],
        "coverage":{key:analysis["coverage"].get(key) for key in ("pruned_events","collection_started","collection_mode")},
        "correlations":[],
        "representative_events":[compact_event(events[0]) for events in analysis["representative_events"].values() if events],
        "correlation_exclusions":{key:analysis[key] for key in ("without_timestamp","without_device_address","out_of_order","window_associations_skipped") if analysis[key]},
        "limitations":["Shared IP/time is not causation. IPs may be reassigned. Suricata relays in Wazuh are not independent corroboration. Examples and correlations are selected; unavailable or pre-start data is outside scope."],
        "selection":{"raw_events_individually_analyzed":False,"candidate_windows_found":analysis["candidate_windows"],"character_budget":max_chars},
    }
    # Keep the highest-ranked candidate, then spend the remaining evidence slots
    # on new sources/origins before another device. Equal gains keep input rank.
    remaining = list(analysis["correlations"])
    selected = []
    seen_sources, seen_origins, seen_devices = set(), set(), set()
    while remaining and len(selected) < max_candidates:
        def diversity(group):
            added = len(set(group["source_counts"]) - seen_sources)
            added += len(set(group["origin_counts"]) - seen_origins)
            return added, group["device"] not in seen_devices
        index = 0 if not selected else max(range(len(remaining)), key=lambda index: diversity(remaining[index]))
        group = remaining.pop(index)
        selected.append(group)
        seen_sources.update(group["source_counts"])
        seen_origins.update(group["origin_counts"])
        seen_devices.add(group["device"])
    for group in selected:
        result["correlations"].append({key:group[key] for key in ("id","device","source_counts","origin_counts","first_seen","last_seen","event_count")})
        result["correlations"][-1]["event_ids"]=group["event_ids"][:max_events_per_candidate]
    def length():
        return len(json.dumps(result,separators=(",",":"),ensure_ascii=False))
    while length()>max_chars and len(result["correlations"])>1:
        result["correlations"].pop()
    if length()>max_chars:
        result["representative_events"]=[{**event,"title":event.get("title","")[:40]} for event in result["representative_events"]]
    if length()>max_chars and result["correlations"]:
        result["correlations"].pop()
    result["selection"]["correlations_supplied"]=len(result["correlations"])
    if length()>max_chars:
        raise ValueError("Aggregate source coverage exceeds the local model evidence budget")
    return result


def format_ai_evidence(evidence, *, max_chars=4000):
    """Label global totals, selected windows, and exclusions separately for AI."""
    def clean(value, limit=180):
        return " ".join(_text(value, limit).split())
    def counts(values):
        return "; ".join(f"{clean(key, 60)}={value}" for key, value in values.items())
    base = [
        "Sample data." if evidence.get("sample_data") else "Observed network data.",
        "DATASET TOTALS (all retained records, not counts of a specific alert):",
        f"Normalized records: {evidence.get('events_analyzed', 'unknown')}.",
        "Observations by source: " + counts(evidence.get("source_counts", {})),
        "Observations by input stream: " + counts(evidence.get("stream_counts", {})),
        "SOURCE CONNECTIONS:",
    ]
    for source in evidence.get("sources", []):
        base.append(f"{clean(source.get('id', 'unknown'), 60)}: "
                    + ("readable" if source.get("available") else "unavailable")
                    + (", caught up" if source.get("caught_up") else ", freshness or backlog needs checking")
                    + ("; " + clean(source["notice"]) if source.get("notice") else ""))
    coverage = evidence.get("coverage", {})
    base.append("Collection begins: " + clean(coverage.get("collection_started") or "not supplied")
                + "; mode: " + clean(coverage.get("collection_mode") or "retained snapshot"))
    exclusions = evidence.get("correlation_exclusions", {})
    labels = {"without_device_address":"records without a usable device address",
              "without_timestamp":"records without a usable timestamp",
              "out_of_order":"records arriving out of timestamp order",
              "window_associations_skipped":"window associations skipped at the memory limit"}
    if exclusions:
        base.append("DATASET-LEVEL MATCHING EXCLUSIONS (not candidate totals): "
                    + "; ".join(f"{value} {labels.get(key, clean(key))}" for key, value in exclusions.items()))
        base.append("These exclusions do not mean a selected candidate lacks its listed address.")
    base.append("AI reviews selected evidence only. Shared IP/time is an association, not proof of attack. "
                "Wazuh copies of Suricata are not independent evidence. Full coverage details are in the report.")
    candidates = []
    for group in evidence.get("correlations", []):
        candidates.append("CANDIDATE " + clean(group["id"]) + ":\n"
                          + f"Shared device address: {clean(group['device'])}. "
                          + f"Window: {clean(group['first_seen'])} through {clean(group['last_seen'])}.\n"
                          + f"This window contains {group['event_count']} observations in total; "
                          + "source totals within this window: " + counts(group["source_counts"]) + ".\n"
                          + "Origins within this window (copies retain their original source): "
                          + counts(group["origin_counts"]) + "."
                          + " Selected event IDs: " + ", ".join(group.get("event_ids", [])))
    examples = [f"Selected event {clean(event.get('id'))}, source {clean(event.get('source'))}: "
                + clean(event.get("title")) for event in evidence.get("representative_events", [])]
    def render():
        return "\n".join(base + candidates
                         + (["OTHER SELECTED EVENTS (may be outside the candidate windows):"] + examples if examples else []))
    while len(render()) > max_chars and examples:
        examples.pop()
    while len(render()) > max_chars and candidates:
        candidates.pop()
    if len(render()) > max_chars:
        raise ValueError("Source coverage exceeds the model evidence budget")
    return render()


def _escape(value):
    return html.escape("" if value is None else str(value), quote=True)


def _json(value):
    return _escape(json.dumps(value, ensure_ascii=False, sort_keys=True, default=str, indent=2))


def iter_html_report(events, analysis, *, ai_analysis=None, model="", generated=None, demo=False, devices=None, include_events=True):
    """Yield a portable HTML report including every normalized event supplied.

    Supply a fresh iterator over the same immutable/cutoff-bounded dataset used
    for analyze_events. The rendered final record count exposes export mismatch.
    """
    generated = generated or dt.datetime.now(UTC).isoformat()
    yield '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'"><title>OMEGA security report</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#0d0d0b;color:#e9e6dc;font:15px/1.6 system-ui,sans-serif}main{max-width:1250px;margin:auto;padding:44px 30px}h1,h2,h3{line-height:1.2}h1{font-size:34px}h2{margin-top:38px;color:#daba63}h3{font-size:17px}.brand{color:#daba63;font-weight:700;letter-spacing:.25em}.muted{color:#b2afa4}.card{padding:20px;border:1px solid #3c3726;border-radius:10px;margin:12px 0;background:#151410}.stats{display:flex;gap:14px;flex-wrap:wrap}.stats .card{flex:1;min-width:170px}.number{font-size:28px;color:#e4c36b}table{width:100%;border-collapse:collapse;table-layout:fixed;font-size:12px}th,td{text-align:left;vertical-align:top;border-bottom:1px solid #39372e;padding:9px;overflow-wrap:anywhere}th{color:#e4c36b}thead{display:table-header-group}pre,.prose{white-space:pre-wrap;overflow-wrap:anywhere;font:inherit}.tag{font-size:12px;color:#daba63}details{font-size:11px}summary{cursor:pointer}.event-time{width:16%}.event-source{width:10%}.event-device{width:22%}.event-data{width:42%}.event-severity{width:10%}a{color:#e4c36b}.notice{border-left:3px solid #daba63;padding-left:14px}@media print{:root{color-scheme:light}body{color:#111;background:#fff}main{padding:0}h2,th,.number,.brand,.tag,a{color:#76580b}.muted{color:#555}.card{background:#fff;border-color:#bbb}th,td{border-color:#ddd}h2,h3{break-after:avoid}tr,.card{break-inside:avoid}details>pre{display:block}summary{display:none}}
</style></head><body><main><div class="brand">Ω OMEGA</div><h1>Combined security report</h1>'''
    yield f'<p class="muted">Generated {_escape(generated)} · {"SAMPLE DATA" if demo else "Live retained evidence"}</p>'
    if analysis['coverage'].get('collection_started'):
        yield '<p>New-event collection began '+_escape(analysis['coverage']['collection_started'])+'. Pre-existing history is outside this report.</p>'
    yield '<p class="notice">This report combines observed Suricata, Wazuh and Pi-hole evidence where available. Correlations indicate shared timing and device addresses; they do not by themselves prove a compromise.</p>'
    yield '<div class="stats">'
    for label, value in (("Normalized events analyzed", analysis["events_analyzed"]), ("Telemetry sources represented", len(analysis["source_counts"])), ("Selected correlation candidates", len(analysis["correlations"]))):
        yield f'<div class="card"><div class="number">{_escape(value)}</div>{_escape(label)}</div>'
    yield '</div><h2>Evidence coverage</h2>'
    yield f'<p>Event timestamps: {_escape(analysis.get("first_event") or "unavailable")} to {_escape(analysis.get("last_event") or "unavailable")}.</p>'
    yield '<table><thead><tr><th>Source</th><th>Status</th><th>Retained events</th><th>Coverage details</th></tr></thead><tbody>'
    if analysis["sources"]:
        for source in analysis["sources"]:
            state = "Available" if source.get("available") else ("Unavailable" if source.get("configured") else "Not configured")
            if source.get("sync_current") is False: state = "Sync interrupted"
            elif source.get("available") and source.get("caught_up") is False: state = "Importing history"
            detail = source.get("notice") or "Collected records are available."
            if source.get("backlog_rows"): detail += f' {source["backlog_rows"]:,} records remain to import.'
            if source.get("backlog_bytes"): detail += f' At least {source["backlog_bytes"]/1024/1024:,.1f} MB remain to import.'
            if source.get("updated"): detail += ' Latest event: '+str(source["updated"])+'.'
            yield f'<tr><td>{_escape(source.get("label") or source.get("name"))}</td><td>{state}</td><td>{_escape(source.get("events", 0))}</td><td>{_escape(detail)}</td></tr>'
    else:
        for name, count in analysis["source_counts"].items():
            yield f'<tr><td>{_escape(SOURCE_LABELS.get(name, name))}</td><td>Records supplied; connection status not supplied</td><td>{count}</td><td>See collection limitations below.</td></tr>'
    yield '</tbody></table><details><summary>Detailed collection record</summary><pre>' + _json({"coverage":analysis["coverage"],"sources":analysis["sources"]}) + '</pre></details>'
    yield '<h2>AI analysis</h2>'
    if ai_analysis:
        answer = ai_analysis.get("answer", "") if isinstance(ai_analysis, dict) else ai_analysis
        model_name = ai_analysis.get("model", model) if isinstance(ai_analysis, dict) else model
        analysis_time = ai_analysis.get("generated", generated) if isinstance(ai_analysis, dict) else generated
        yield f'<p class="muted">Local model: {_escape(model_name or "not recorded")} · Analysis generated: {_escape(analysis_time)}</p><div class="card prose">{_escape(answer)}</div>'
        yield '<p class="muted">AI interpretation can be wrong. It received aggregate counts across the retained dataset and selected evidence excerpts; it did not individually review every raw event. Verify important findings against the event records and original sensor logs.</p>'
    else:
        yield '<div class="card">AI analysis was not generated for this report. The deterministic evidence summary and event export remain available.</div>'
    yield '<h2>Cross-source correlation candidates</h2>'
    yield f'<p class="muted">Explicit Wazuh observations relaying Suricata: {_escape(analysis["relayed_suricata_events"])}. Windows containing only Suricata and its relayed copies excluded from cross-source candidates: {_escape(analysis["relay_only_windows_excluded"])}.</p>'
    if not analysis["correlations"]:
        yield '<p>No candidate shared-address relationships were found in the examined windows. This does not establish that the network is safe or that all sources are connected.</p>'
    for group in analysis["correlations"]:
        yield f'<article class="card"><div class="tag">{_escape(group["id"])}</div><h3>{_escape(group["title"])} · {_escape(group["device"])}</h3><p>{_escape(group["summary"])}</p><p class="muted">{_escape(group["first_seen"])} to {_escape(group["last_seen"])}</p><p>Source counts: {_escape(json.dumps(group["source_counts"], ensure_ascii=False))}</p><p>Representative event IDs: {_escape(", ".join(group["event_ids"]))}</p></article>'
    yield '<h2>All-event aggregate counts</h2><div class="card"><pre>' + _json({key: analysis[key] for key in ("source_counts", "stream_counts", "source_event_types", "severity_counts")}) + '</pre></div>'
    if devices is not None:
        values = devices.get("devices", []) if isinstance(devices, dict) else devices
        yield '<h2>Observed devices</h2><p class="muted">Names and addresses are observations. A saved device is not proof it is currently online.</p><table><thead><tr><th>Name</th><th>Hostname</th><th>Address</th><th>Type / last seen</th></tr></thead><tbody>'
        for device in values:
            yield f'<tr><td>{_escape(device.get("display_name"))}</td><td>{_escape(device.get("hostname"))}</td><td>{_escape(device.get("ip"))}</td><td>{_escape(device.get("device_type"))}<br>{_escape(device.get("last_seen"))}</td></tr>'
        yield '</tbody></table>'
    yield '<h2>Limitations and missing evidence</h2><ul>'
    extra = analysis["coverage"].get("limitations", []) if isinstance(analysis["coverage"], dict) else []
    for limitation in dict.fromkeys(analysis["limitations"] + list(extra)):
        yield '<li>' + _escape(limitation) + '</li>'
    if not include_events:
        yield '</ul><h2>Complete event export</h2><p>The companion events.jsonl file contains every retained normalized record selected for this report. source-events.jsonl preserves the original collected sensor records and their additional fields. Keep these files with this summary. Coverage, backfill, and missing upstream history are disclosed above.</p><footer class="muted">OMEGA · Your network. Your control.</footer></main></body></html>'
        return
    yield '</ul><h2>Complete retained normalized event record</h2><p>Every event supplied for export is included below. Expand a record for normalized details. Raw packet contents and complete original log lines are not embedded.</p><table><thead><tr><th class="event-time">Timestamp / ID</th><th class="event-source">Source</th><th class="event-device">Device / address</th><th class="event-data">Observed event</th><th class="event-severity">Severity</th></tr></thead><tbody>'
    exported = 0
    for event in events:
        exported += 1
        source = event.get("source") or "unknown"
        path = " → ".join(str(event.get(key)) for key in ("source_ip", "destination_ip") if event.get(key))
        name = event.get("hostname") or event.get("agent_name") or ""
        severity = {1: "High", 2: "Medium", 3: "Low"}.get(_severity(event), "Unrated")
        yield f'<tr><td>{_escape(event.get("timestamp") or "No source timestamp")}<br><small>{_escape(event.get("id"))}</small></td><td>{_escape(SOURCE_LABELS.get(source, source))}<br>{_escape(event.get("stream"))}</td><td>{_escape(name)}<br>{_escape(path)}</td><td>{_escape(event.get("title") or event.get("event_type"))}<br>{_escape(event.get("domain") or "")}<details><summary>Normalized details</summary><pre>{_json(event)}</pre></details></td><td>{severity}</td></tr>'
    yield f'</tbody></table><p class="muted">Normalized records exported: {exported}. Records used for aggregate analysis: {_escape(analysis["events_analyzed"])}.</p>'
    if exported != analysis["events_analyzed"]:
        yield '<p class="notice">The exported record count differs from the analysis count. Collection changed between analysis and export; do not treat this report as a consistent dataset snapshot.</p>'
    yield '<footer class="muted">OMEGA · Your network. Your insight.</footer></main></body></html>'


def iter_jsonl_events(events):
    """Lossless normalized-record export; no record cap or sampling."""
    for event in events:
        yield json.dumps(event, ensure_ascii=False, separators=(",", ":"), default=str) + "\n"


def iter_csv_events(events):
    """Full normalized event export with spreadsheet formula cells neutralized."""
    columns = ("id", "timestamp", "observed_at", "source", "stream", "event_type", "severity", "title", "category", "source_ip", "destination_ip", "hostname", "domain", "agent_id", "agent_name", "rule_id", "action", "details")
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    writer.writerow(columns)
    yield buffer.getvalue()
    for event in events:
        buffer.seek(0)
        buffer.truncate(0)
        values = []
        for key in columns:
            value = event.get(key)
            value = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str) if isinstance(value, (dict, list)) else str(value) if value is not None else ""
            # JSONL preserves the exact value; CSV stays safe to open in a spreadsheet.
            if value.lstrip().startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r", "\n")):
                value = "'" + value
            values.append(value)
        writer.writerow(values)
        yield buffer.getvalue()
