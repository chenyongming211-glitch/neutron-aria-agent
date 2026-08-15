from __future__ import absolute_import

MAX_BUCKET_ROWS = 512


def _rate(prev, curr, elapsed_seconds):
    if prev is None or curr is None or elapsed_seconds <= 0:
        return None
    return float(curr - prev) / elapsed_seconds


def _row_dict(kind, key_dict, packets, bytes_value, dropped_packets,
              dropped_bytes, pps, bps):
    return {
        "kind": kind,
        "key": key_dict,
        "packets": packets,
        "bytes": bytes_value,
        "dropped_packets": dropped_packets,
        "dropped_bytes": dropped_bytes,
        "pps": pps,
        "bps": bps,
    }


def diff_port_counters(previous, current):
    """Difference two consecutive counter snapshots for one port.

    Returns (rows, reset_detected). Rows are dicts with kind in
    (port|bucket|reason), a key dict identifying the row, cumulative
    counters, and pps/bps rates. First snapshot and reset snapshots
    report None rates. A negative cumulative delta on the port summary
    OR on any matched bucket/reason row marks a reset, because bucket
    sets can be rebuilt while the port total still grows. Elapsed time
    always comes from the datapath `sampled_at_ms` stamps (single clock
    source per the spec), never from the local wall clock.
    """
    current_sampled = float(current.get("sampled_at_ms") or 0)
    previous_sampled = float((previous or {}).get("sampled_at_ms") or 0)
    elapsed = max(0.0, (current_sampled - previous_sampled) / 1000.0)

    def matched_previous_row(kind, key_dict):
        if previous is None:
            return None
        prev_list = previous.get(
            "buckets" if kind == "bucket" else "reasons"
        ) or []
        for candidate in prev_list:
            if all(candidate.get(k) == v for k, v in key_dict.items()):
                return candidate
        return None

    reset_detected = False
    if previous is not None:
        for field in ("policy_packets", "policy_dropped_packets",
                      "drop_packets"):
            if (current.get(field) or 0) < (previous.get(field) or 0):
                reset_detected = True
                break
        if not reset_detected:
            for bucket in current.get("buckets") or []:
                prev_row = matched_previous_row("bucket", {
                    "src_id": bucket.get("src_id"),
                    "dst_id": bucket.get("dst_id"),
                    "proto": bucket.get("proto"),
                    "direction": bucket.get("direction"),
                })
                if prev_row is not None and (
                    (bucket.get("packets") or 0) < (prev_row.get("packets") or 0)
                    or (bucket.get("bytes") or 0) < (prev_row.get("bytes") or 0)
                ):
                    reset_detected = True
                    break
        if not reset_detected:
            for reason in current.get("reasons") or []:
                prev_row = matched_previous_row("reason", {
                    "reason": reason.get("reason"),
                    "direction": reason.get("direction"),
                    "proto": reason.get("proto"),
                })
                if prev_row is not None and (
                    (reason.get("packets") or 0) < (prev_row.get("packets") or 0)
                    or (reason.get("bytes") or 0) < (prev_row.get("bytes") or 0)
                ):
                    reset_detected = True
                    break

    rows = []

    # Port summary row: rates diffed against the previous port summary.
    port_prev = previous or {}
    port_packets = current.get("policy_packets") or 0
    port_bytes = current.get("policy_bytes") or 0
    port_dropped = current.get("policy_dropped_packets") or 0
    port_dropped_bytes = current.get("policy_dropped_bytes") or 0
    port_pps = None
    port_bps = None
    if previous is not None and not reset_detected:
        port_pps = _rate(port_prev.get("policy_packets"), port_packets, elapsed)
        port_bps = _rate(port_prev.get("policy_bytes"), port_bytes, elapsed)
    rows.append(_row_dict("port", {}, port_packets, port_bytes, port_dropped,
                          port_dropped_bytes, port_pps, port_bps))

    def diff_row(kind, key_dict, row, has_drop_fields):
        row_packets = row.get("packets") or 0
        row_bytes = row.get("bytes") or 0
        row_dropped = row.get("dropped_packets") or 0
        row_dropped_bytes = row.get("dropped_bytes") or 0
        prev_row = matched_previous_row(kind, key_dict)
        pps = None
        bps = None
        if prev_row is not None and not reset_detected:
            pps = _rate(prev_row.get("packets") or 0, row_packets, elapsed)
            bps = _rate(prev_row.get("bytes") or 0, row_bytes, elapsed)
        return _row_dict(
            kind,
            key_dict,
            row_packets,
            row_bytes,
            row_dropped if has_drop_fields else None,
            row_dropped_bytes if has_drop_fields else None,
            pps,
            bps,
        )

    for bucket in (current.get("buckets") or [])[:MAX_BUCKET_ROWS]:
        key_dict = {
            "src_id": bucket.get("src_id"),
            "dst_id": bucket.get("dst_id"),
            "proto": bucket.get("proto"),
            "direction": bucket.get("direction"),
        }
        rows.append(diff_row("bucket", key_dict, bucket, True))
    for reason in current.get("reasons") or []:
        key_dict = {
            "reason": reason.get("reason"),
            "direction": reason.get("direction"),
            "proto": reason.get("proto"),
        }
        rows.append(diff_row("reason", key_dict, reason, False))
    return rows, reset_detected
