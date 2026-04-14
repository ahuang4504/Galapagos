#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

RESULTS_ROOT="${RESULTS_ROOT:-results}"
TIMESTAMP="$(date -u +"%Y%m%dT%H%M%SZ")"
RUN_DIR="$RESULTS_ROOT/evaluation_$TIMESTAMP"
TABLE_FILE="$RUN_DIR/results_table.md"

BASELINE_DURATION_SECONDS="${BASELINE_DURATION_SECONDS:-300}"
ATTACK_BACKGROUND_DURATION_SECONDS="${ATTACK_BACKGROUND_DURATION_SECONDS:-120}"
BASELINE_QPS="${BASELINE_QPS:-5}"
BASELINE_JITTER_RATIO="${BASELINE_JITTER_RATIO:-0.25}"
BASELINE_CACHE_HIT_RATIO="${BASELINE_CACHE_HIT_RATIO:-0.35}"
POST_ATTACK_SETTLE_SECONDS="${POST_ATTACK_SETTLE_SECONDS:-10}"
ENABLE_VERIFICATION="${ENABLE_VERIFICATION:-1}"
SUMMARY_INTERVAL_SECONDS="${SUMMARY_INTERVAL_SECONDS:-5}"

KAMINSKY_TARGET_DOMAIN="${KAMINSKY_TARGET_DOMAIN:-example.com}"
KAMINSKY_SPOOFED_IP="${KAMINSKY_SPOOFED_IP:-6.6.6.6}"
KAMINSKY_ATTEMPTS="${KAMINSKY_ATTEMPTS:-10}"
KAMINSKY_TXID_COUNT="${KAMINSKY_TXID_COUNT:-1000}"
KAMINSKY_THRESHOLD="${KAMINSKY_THRESHOLD:-5}"
KAMINSKY_WINDOW_SECONDS="${KAMINSKY_WINDOW_SECONDS:-30}"
KAMINSKY_COOLDOWN_SECONDS="${KAMINSKY_COOLDOWN_SECONDS:-10}"

BAILIWICK_QUERY_NAME="${BAILIWICK_QUERY_NAME:-example.com}"
BAILIWICK_INJECTED_NAME="${BAILIWICK_INJECTED_NAME:-bankofamerica.com}"
BAILIWICK_INJECTED_IP="${BAILIWICK_INJECTED_IP:-6.6.6.6}"
BAILIWICK_ATTEMPTS="${BAILIWICK_ATTEMPTS:-10}"
BAILIWICK_TXID_COUNT="${BAILIWICK_TXID_COUNT:-1000}"

mkdir -p "$RUN_DIR"

cat > "$TABLE_FILE" <<'EOF'
| Scenario | Config | Passive Alerts | Verification | Cache Poisoned | Detection Latency |
|---|---|---|---|---|---|
EOF

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "Missing required command: $1" >&2
        exit 1
    }
}

require_command docker
require_command python3

compose_up() {
    local config="$1"
    echo "=== Bringing stack up with config: $config ==="
    UNBOUND_CONFIG="$config" \
    ENABLE_VERIFICATION="$ENABLE_VERIFICATION" \
    SUMMARY_INTERVAL_SECONDS="$SUMMARY_INTERVAL_SECONDS" \
    KAMINSKY_THRESHOLD="$KAMINSKY_THRESHOLD" \
    KAMINSKY_WINDOW_SECONDS="$KAMINSKY_WINDOW_SECONDS" \
    KAMINSKY_COOLDOWN_SECONDS="$KAMINSKY_COOLDOWN_SECONDS" \
    docker compose up -d --build
}

compose_down() {
    echo "=== Bringing stack down ==="
    docker compose down -v --remove-orphans >/dev/null 2>&1 || true
}

start_detector_capture() {
    local logfile="$1"
    : > "$logfile"
    docker compose logs -f --no-log-prefix detector > "$logfile" 2>&1 &
    DETECTOR_LOG_PID=$!
}

stop_detector_capture() {
    if [[ -n "${DETECTOR_LOG_PID:-}" ]]; then
        kill "$DETECTOR_LOG_PID" >/dev/null 2>&1 || true
        wait "$DETECTOR_LOG_PID" 2>/dev/null || true
        unset DETECTOR_LOG_PID
    fi
}

utc_now() {
    python3 - <<'PY'
from datetime import datetime, timezone
print(datetime.now(timezone.utc).isoformat())
PY
}

run_baseline_traffic() {
    local logfile="$1"
    docker compose exec -T client python3 /app/traffic_generator.py \
        --resolver 172.28.0.10 \
        --duration "$BASELINE_DURATION_SECONDS" \
        --qps "$BASELINE_QPS" \
        --jitter-ratio "$BASELINE_JITTER_RATIO" \
        --cache-hit-ratio "$BASELINE_CACHE_HIT_RATIO" \
        > "$logfile" 2>&1
}

run_background_traffic() {
    local logfile="$1"
    docker compose exec -T client python3 /app/traffic_generator.py \
        --resolver 172.28.0.10 \
        --duration "$ATTACK_BACKGROUND_DURATION_SECONDS" \
        --qps "$BASELINE_QPS" \
        --jitter-ratio "$BASELINE_JITTER_RATIO" \
        --cache-hit-ratio "$BASELINE_CACHE_HIT_RATIO" \
        > "$logfile" 2>&1 &
    TRAFFIC_PID=$!
}

wait_for_background_traffic() {
    if [[ -n "${TRAFFIC_PID:-}" ]]; then
        wait "$TRAFFIC_PID" || true
        unset TRAFFIC_PID
    fi
}

parse_log_to_file() {
    local logfile="$1"
    local start_time="$2"
    local summary_file="$3"
    python3 scripts/parse_detector_log.py "$logfile" --start-time "$start_time" > "$summary_file"
}

extract_summary_field() {
    local summary_file="$1"
    local expr="$2"
    python3 - "$summary_file" "$expr" <<'PY'
import json
import sys

summary_path = sys.argv[1]
expr = sys.argv[2]
payload = json.load(open(summary_path))
value = eval(expr, {"__builtins__": {}}, {"payload": payload})
if isinstance(value, (dict, list)):
    import json as _json
    print(_json.dumps(value))
else:
    print("" if value is None else value)
PY
}

format_passive_alerts() {
    local summary_file="$1"
    python3 - "$summary_file" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1]))
alert_counts = payload.get("alert_counts", {})
if not alert_counts:
    print("0")
else:
    print(" + ".join(alert_counts))
PY
}

format_verification_status() {
    local summary_file="$1"
    python3 - "$summary_file" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1]))
counts = payload.get("verification_counts", {})
priority = ["CONFIRMED", "MATCH", "VERIFICATION_FAILED"]
for key in priority:
    if counts.get(key):
        print(key)
        break
else:
    print("N/A")
PY
}

append_result_row() {
    local scenario="$1"
    local config="$2"
    local passive="$3"
    local verification="$4"
    local cache_poisoned="$5"
    local latency="$6"
    printf '| %s | %s | %s | %s | %s | %s |\n' \
        "$scenario" "$config" "$passive" "$verification" "$cache_poisoned" "$latency" \
        >> "$TABLE_FILE"
}

scenario_normal_traffic() {
    local config="$1"
    local label="$2"
    local scenario_dir="$RUN_DIR/${label}_${config}"
    mkdir -p "$scenario_dir"

    compose_down
    compose_up "$config"
    start_detector_capture "$scenario_dir/detector.log"
    local start_time
    start_time="$(utc_now)"
    run_baseline_traffic "$scenario_dir/client.log"
    sleep 2
    stop_detector_capture

    parse_log_to_file "$scenario_dir/detector.log" "$start_time" "$scenario_dir/summary.json"
    local passive verification
    passive="$(format_passive_alerts "$scenario_dir/summary.json")"
    verification="N/A"
    append_result_row "$label" "$config" "$passive" "$verification" "No" "N/A"
}

scenario_kaminsky() {
    local config="$1"
    local label="$2"
    local scenario_dir="$RUN_DIR/${label}_${config}"
    mkdir -p "$scenario_dir"

    compose_down
    compose_up "$config"
    start_detector_capture "$scenario_dir/detector.log"
    local start_time
    start_time="$(utc_now)"
    run_background_traffic "$scenario_dir/client.log"
    docker compose exec -T attacker python3 /app/kaminsky_flood.py \
        --resolver-ip 172.28.0.10 \
        --target-domain "$KAMINSKY_TARGET_DOMAIN" \
        --spoofed-ip "$KAMINSKY_SPOOFED_IP" \
        --attempts "$KAMINSKY_ATTEMPTS" \
        --txid-count "$KAMINSKY_TXID_COUNT" \
        > "$scenario_dir/attacker.log" 2>&1 || true
    wait_for_background_traffic
    sleep "$POST_ATTACK_SETTLE_SECONDS"
    docker compose exec -T client dig +short @172.28.0.10 "$KAMINSKY_TARGET_DOMAIN" \
        > "$scenario_dir/post_attack_dig.txt" 2>&1 || true
    stop_detector_capture

    parse_log_to_file "$scenario_dir/detector.log" "$start_time" "$scenario_dir/summary.json"
    local passive verification latency cache_poisoned
    passive="$(format_passive_alerts "$scenario_dir/summary.json")"
    verification="$(format_verification_status "$scenario_dir/summary.json")"
    latency="$(extract_summary_field "$scenario_dir/summary.json" 'payload["first_alert_latency_seconds"]')"
    if grep -q "$KAMINSKY_SPOOFED_IP" "$scenario_dir/post_attack_dig.txt"; then
        cache_poisoned="Yes"
    else
        cache_poisoned="No"
    fi
    append_result_row "$label" "$config" "$passive" "$verification" "$cache_poisoned" "${latency:-N/A}"
}

scenario_bailiwick() {
    local config="$1"
    local label="$2"
    local scenario_dir="$RUN_DIR/${label}_${config}"
    mkdir -p "$scenario_dir"

    compose_down
    compose_up "$config"
    start_detector_capture "$scenario_dir/detector.log"
    local start_time
    start_time="$(utc_now)"
    docker compose exec -T attacker python3 /app/bailiwick_inject.py \
        --resolver-ip 172.28.0.10 \
        --query-name "$BAILIWICK_QUERY_NAME" \
        --injected-name "$BAILIWICK_INJECTED_NAME" \
        --injected-ip "$BAILIWICK_INJECTED_IP" \
        --attempts "$BAILIWICK_ATTEMPTS" \
        --txid-count "$BAILIWICK_TXID_COUNT" \
        > "$scenario_dir/attacker.log" 2>&1 || true
    sleep "$POST_ATTACK_SETTLE_SECONDS"
    docker compose exec -T client dig +short @172.28.0.10 "$BAILIWICK_INJECTED_NAME" \
        > "$scenario_dir/post_attack_dig.txt" 2>&1 || true
    stop_detector_capture

    parse_log_to_file "$scenario_dir/detector.log" "$start_time" "$scenario_dir/summary.json"
    local passive verification latency cache_poisoned
    passive="$(format_passive_alerts "$scenario_dir/summary.json")"
    verification="$(format_verification_status "$scenario_dir/summary.json")"
    latency="$(extract_summary_field "$scenario_dir/summary.json" 'payload["first_alert_latency_seconds"]')"
    if grep -q "$BAILIWICK_INJECTED_IP" "$scenario_dir/post_attack_dig.txt"; then
        cache_poisoned="Yes"
    else
        cache_poisoned="No"
    fi
    append_result_row "$label" "$config" "$passive" "$verification" "$cache_poisoned" "${latency:-N/A}"
}

main() {
    echo "Evaluation results will be written to: $RUN_DIR"

    scenario_normal_traffic weak "Normal traffic"
    scenario_normal_traffic hardened "Normal traffic"
    scenario_kaminsky weak "Kaminsky flood"
    scenario_kaminsky hardened "Kaminsky flood"
    scenario_bailiwick weak "Bailiwick injection"
    scenario_bailiwick hardened "Bailiwick injection"

    compose_down

    echo ""
    echo "=== Evaluation complete ==="
    echo "Results table: $TABLE_FILE"
    cat "$TABLE_FILE"
}

main "$@"
