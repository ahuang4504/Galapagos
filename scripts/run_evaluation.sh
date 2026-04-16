#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

RESULTS_ROOT="${RESULTS_ROOT:-results}"
TIMESTAMP="$(date -u +"%Y%m%dT%H%M%SZ")"
RUN_DIR="$RESULTS_ROOT/evaluation_$TIMESTAMP"
TABLE_FILE="$RUN_DIR/results_table.md"
RESULTS_JSONL="$RUN_DIR/results_rows.jsonl"
REPORT_JSON="$RUN_DIR/results_summary.json"
CHART_FILE="$RUN_DIR/asr_chart.svg"

POST_ATTACK_SETTLE_SECONDS="${POST_ATTACK_SETTLE_SECONDS:-10}"
SUMMARY_INTERVAL_SECONDS="${SUMMARY_INTERVAL_SECONDS:-5}"

KAMINSKY_TARGET_DOMAIN="${KAMINSKY_TARGET_DOMAIN:-example.com}"
KAMINSKY_SPOOFED_IP="${KAMINSKY_SPOOFED_IP:-6.6.6.6}"
KAMINSKY_ATTEMPTS="${KAMINSKY_ATTEMPTS:-1}"
KAMINSKY_TXID_COUNT="${KAMINSKY_TXID_COUNT:-65536}"
KAMINSKY_THRESHOLD="${KAMINSKY_THRESHOLD:-5}"
KAMINSKY_WINDOW_SECONDS="${KAMINSKY_WINDOW_SECONDS:-30}"
KAMINSKY_COOLDOWN_SECONDS="${KAMINSKY_COOLDOWN_SECONDS:-10}"

ATTACK_SUCCESS_SAMPLE_COUNT="${ATTACK_SUCCESS_SAMPLE_COUNT:-3}"
ATTACK_SUCCESS_SAMPLE_DELAY_SECONDS="${ATTACK_SUCCESS_SAMPLE_DELAY_SECONDS:-1}"

mkdir -p "$RUN_DIR"
: > "$RESULTS_JSONL"

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
    local defense="$2"
    echo "=== Bringing stack up with config: $config ==="
    UNBOUND_CONFIG="$config" \
    ENABLE_DEFENSE="$defense" \
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

parse_log_to_file() {
    local logfile="$1"
    local start_time="$2"
    local summary_file="$3"
    python3 - "$logfile" "$start_time" "$summary_file" <<'PY'
import sys

sys.path.insert(0, "scripts")

from parse_detector_log import write_detector_log_summary

logfile, start_time, summary_file = sys.argv[1:]
write_detector_log_summary(summary_file, logfile=logfile, start_time=start_time)
PY
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
priority = ["CONFIRMED", "TRANSIENT_DIVERGENCE", "MATCH", "VERIFICATION_FAILED"]
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
    local defense="$3"
    local passive="$4"
    local verification="$5"
    local cache_poisoned="$6"
    local latency="$7"
    local attack_success_rate="$8"
    local attack_successes="$9"
    local attack_candidates="${10}"
    python3 - \
        "$RESULTS_JSONL" \
        "$scenario" \
        "$config" \
        "$defense" \
        "$passive" \
        "$verification" \
        "$cache_poisoned" \
        "$latency" \
        "$attack_success_rate" \
        "$attack_successes" \
        "$attack_candidates" <<'PY'
import json
import sys


def optional_float(value: str):
    if value in {"", "N/A"}:
        return None
    return float(value)


def optional_int(value: str):
    if value in {"", "N/A"}:
        return None
    return int(value)


output_path, scenario, config, defense, passive, verification, cache_poisoned, latency, attack_success_rate, attack_successes, attack_candidates = sys.argv[1:]
row = {
    "scenario": scenario,
    "config": config,
    "defense": defense,
    "passive_alerts": passive,
    "verification": verification,
    "cache_poisoned": cache_poisoned,
    "detection_latency_seconds": optional_float(latency),
    "attack_success_rate": optional_float(attack_success_rate),
    "attack_successes": optional_int(attack_successes),
    "attack_candidates": optional_int(attack_candidates),
}
with open(output_path, "a") as handle:
    json.dump(row, handle)
    handle.write("\n")
PY
}

measure_attack_success() {
    local attacker_log="$1"
    local field="$2"
    local expected_ip="$3"
    local output_file="$4"
    python3 - "$attacker_log" "$field" "$expected_ip" "$output_file" "$ATTACK_SUCCESS_SAMPLE_COUNT" "$ATTACK_SUCCESS_SAMPLE_DELAY_SECONDS" <<'PY'
import sys

sys.path.insert(0, "scripts")

from compute_attack_success import AttackSuccessConfig, measure_attack_success, write_attack_success

attacker_log, field, expected_ip, output_file, sample_count, sample_delay = sys.argv[1:]
payload = measure_attack_success(
    AttackSuccessConfig(
        attacker_log=attacker_log,
        field=field,
        expected_ip=expected_ip,
        resolver="172.28.0.10",
        sample_count=int(sample_count),
        sample_delay_seconds=float(sample_delay),
    )
)
write_attack_success(output_file, payload)
PY
}

scenario_kaminsky_matrix() {
    local config="$1"
    local defense="$2"
    local defense_label="$3"
    local scenario_dir="$RUN_DIR/kaminsky_${config}_${defense_label}"
    mkdir -p "$scenario_dir"

    compose_down
    compose_up "$config" "$defense"
    start_detector_capture "$scenario_dir/detector.log"
    local start_time
    start_time="$(utc_now)"
    (
    docker compose exec -T attacker python3 - "$KAMINSKY_TARGET_DOMAIN" "$KAMINSKY_SPOOFED_IP" "$KAMINSKY_ATTEMPTS" "$KAMINSKY_TXID_COUNT" 2>&1 <<'PY' | tee "$scenario_dir/attacker.log"
from kaminsky_flood import KaminskyAttackConfig, run_attack
import sys

target_domain, spoofed_ip, attempts, txid_count = sys.argv[1:]
run_attack(
    KaminskyAttackConfig(
        resolver_ip="172.28.0.10",
        target_domain=target_domain,
        spoofed_ip=spoofed_ip,
        attempts=int(attempts),
        txid_count=int(txid_count),
    )
)
PY
    ) || true
    sleep "$POST_ATTACK_SETTLE_SECONDS"

    measure_attack_success \
        "$scenario_dir/attacker.log" \
        "qname" \
        "$KAMINSKY_SPOOFED_IP" \
        "$scenario_dir/attack_success.json"
    stop_detector_capture

    local passive verification latency attack_success_rate attack_successes attack_candidates cache_poisoned
    attack_success_rate="$(extract_summary_field "$scenario_dir/attack_success.json" 'payload["attack_success_rate"]')"
    attack_successes="$(extract_summary_field "$scenario_dir/attack_success.json" 'payload["successful_candidates"]')"
    attack_candidates="$(extract_summary_field "$scenario_dir/attack_success.json" 'payload["total_candidates"]')"
    if [[ "$defense" == "1" ]]; then
        parse_log_to_file "$scenario_dir/detector.log" "$start_time" "$scenario_dir/summary.json"
        passive="$(format_passive_alerts "$scenario_dir/summary.json")"
        verification="$(format_verification_status "$scenario_dir/summary.json")"
        latency="$(extract_summary_field "$scenario_dir/summary.json" 'payload["first_alert_latency_seconds"]')"
    else
        passive="N/A"
        verification="N/A"
        latency="N/A"
    fi
    if [[ "${attack_successes:-0}" -gt 0 ]]; then
        cache_poisoned="Yes"
    else
        cache_poisoned="No"
    fi
    append_result_row \
        "Kaminsky flood" \
        "$config" \
        "$defense_label" \
        "$passive" \
        "$verification" \
        "$cache_poisoned" \
        "${latency:-N/A}" \
        "${attack_success_rate:-N/A}" \
        "${attack_successes:-N/A}" \
        "${attack_candidates:-N/A}"
}

main() {
    echo "Evaluation results will be written to: $RUN_DIR"

    scenario_kaminsky_matrix weak 0 "off"
    scenario_kaminsky_matrix hardened 0 "off"
    scenario_kaminsky_matrix weak 1 "on"

    compose_down
    python3 - "$RESULTS_JSONL" "$TABLE_FILE" "$CHART_FILE" "$REPORT_JSON" <<'PY'
import sys

sys.path.insert(0, "scripts")

from render_evaluation_report import EvaluationReportOutputs, load_rows, write_outputs

rows_jsonl, table_file, chart_file, report_json = sys.argv[1:]
rows = load_rows(rows_jsonl)
write_outputs(
    rows,
    outputs=EvaluationReportOutputs(
        markdown_output=table_file,
        svg_output=chart_file,
        json_output=report_json,
    ),
)
PY

    echo ""
    echo "=== Evaluation complete ==="
    echo "Results table: $TABLE_FILE"
    echo "Results summary: $REPORT_JSON"
    echo "ASR chart: $CHART_FILE"
    cat "$TABLE_FILE"
}

main "$@"
