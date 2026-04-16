#!/usr/bin/env python3
import json
from html import escape
from dataclasses import dataclass
from pathlib import Path


@dataclass
class EvaluationReportOutputs:
    markdown_output: str | Path
    svg_output: str | Path
    json_output: str | Path


def load_rows(path: str | Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for raw_line in Path(path).read_text().splitlines():
        line = raw_line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


def format_latency(value: object) -> str:
    if value is None:
        return "N/A"
    return f"{float(value):.1f}s"


def format_asr(row: dict[str, object]) -> str:
    rate = row.get("attack_success_rate")
    successes = row.get("attack_successes")
    candidates = row.get("attack_candidates")
    if rate is None or successes is None or candidates is None:
        return "N/A"
    return f"{float(rate) * 100:.1f}% ({int(successes)}/{int(candidates)})"


def render_markdown(rows: list[dict[str, object]]) -> str:
    lines = [
        "| Scenario | Resolver Config | Defense | Passive Alerts | Verification | Cache Poisoned | ASR | Detection Latency |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            "| {scenario} | {config} | {defense} | {passive} | {verification} | {cache_poisoned} | {asr} | {latency} |".format(
                scenario=row["scenario"],
                config=row["config"],
                defense=row.get("defense", "N/A"),
                passive=row["passive_alerts"],
                verification=row["verification"],
                cache_poisoned=row["cache_poisoned"],
                asr=format_asr(row),
                latency=format_latency(row.get("detection_latency_seconds")),
            )
        )
    return "\n".join(lines) + "\n"


def render_svg(rows: list[dict[str, object]]) -> str:
    attack_rows = [row for row in rows if row.get("attack_success_rate") is not None]
    if not attack_rows:
        return (
            '<svg xmlns="http://www.w3.org/2000/svg" width="720" height="160">'
            '<rect width="100%" height="100%" fill="#fffaf2"/>'
            '<text x="40" y="85" font-size="20" fill="#3d2b1f" '
            'font-family="Helvetica, Arial, sans-serif">No ASR data available.</text>'
            "</svg>"
        )

    configs: list[str] = []
    defenses: list[str] = []
    for row in attack_rows:
        config = str(row["config"])
        defense = str(row.get("defense", "N/A"))
        if config not in configs:
            configs.append(config)
        if defense not in defenses:
            defenses.append(defense)

    width = 920
    height = 520
    margin_left = 80
    margin_right = 40
    margin_top = 80
    margin_bottom = 110
    chart_width = width - margin_left - margin_right
    chart_height = height - margin_top - margin_bottom
    group_width = chart_width / max(len(configs), 1)
    inner_group_width = min(group_width * 0.7, 220)
    bar_gap = 16
    bars_per_group = max(len(defenses), 1)
    bar_width = (inner_group_width - bar_gap * max(bars_per_group - 1, 0)) / bars_per_group
    colors = {
        "off": "#d95f02",
        "on": "#1f78b4",
    }

    lookup = {
        (str(row["config"]), str(row.get("defense", "N/A"))): row
        for row in attack_rows
    }

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">',
        '<rect width="100%" height="100%" fill="#fffaf2"/>',
        '<text x="80" y="42" font-size="28" fill="#2b2118" font-family="Helvetica, Arial, sans-serif">'
        "Attack Success Rate by Resolver Configuration and Defense State"
        "</text>",
        '<text x="80" y="66" font-size="14" fill="#6b5a4a" font-family="Helvetica, Arial, sans-serif">'
        "Success means every post-attack cache probe returned the known attacker IP."
        "</text>",
    ]

    for tick in range(0, 101, 25):
        y = margin_top + chart_height - (tick / 100.0) * chart_height
        parts.append(
            f'<line x1="{margin_left}" y1="{y:.1f}" x2="{width - margin_right}" y2="{y:.1f}" '
            'stroke="#d8cbbd" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{margin_left - 12}" y="{y + 5:.1f}" text-anchor="end" font-size="12" '
            'fill="#6b5a4a" font-family="Helvetica, Arial, sans-serif">'
            f"{tick}%</text>"
        )

    parts.append(
        f'<line x1="{margin_left}" y1="{margin_top}" x2="{margin_left}" y2="{margin_top + chart_height}" '
        'stroke="#5a4a3a" stroke-width="2"/>'
    )
    parts.append(
        f'<line x1="{margin_left}" y1="{margin_top + chart_height}" x2="{width - margin_right}" y2="{margin_top + chart_height}" '
        'stroke="#5a4a3a" stroke-width="2"/>'
    )

    legend_x = width - margin_right - 180
    legend_y = 36
    for idx, defense in enumerate(defenses):
        color = colors.get(defense, "#7a6a5a")
        y = legend_y + idx * 22
        parts.append(
            f'<rect x="{legend_x}" y="{y - 12}" width="14" height="14" fill="{color}" rx="2"/>'
        )
        parts.append(
            f'<text x="{legend_x + 22}" y="{y}" font-size="13" fill="#3d2b1f" '
            f'font-family="Helvetica, Arial, sans-serif">{escape(defense.title())}</text>'
        )

    for config_index, config in enumerate(configs):
        group_left = margin_left + config_index * group_width + (group_width - inner_group_width) / 2
        for defense_index, defense in enumerate(defenses):
            row = lookup.get((config, defense))
            rate = float(row["attack_success_rate"]) * 100 if row is not None else 0.0
            bar_height = chart_height * (rate / 100.0)
            x = group_left + defense_index * (bar_width + bar_gap)
            y = margin_top + chart_height - bar_height
            color = colors.get(defense, "#7a6a5a")

            parts.append(
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_width:.1f}" height="{bar_height:.1f}" '
                f'fill="{color}" rx="6"/>'
            )

            label = "N/A" if row is None else f"{rate:.1f}%"
            label_y = y - 8 if bar_height > 0 else margin_top + chart_height - 8
            parts.append(
                f'<text x="{x + bar_width / 2:.1f}" y="{label_y:.1f}" text-anchor="middle" '
                'font-size="12" fill="#3d2b1f" font-family="Helvetica, Arial, sans-serif">'
                f"{escape(label)}</text>"
            )

            parts.append(
                f'<text x="{x + bar_width / 2:.1f}" y="{margin_top + chart_height + 18:.1f}" text-anchor="middle" '
                'font-size="12" fill="#6b5a4a" font-family="Helvetica, Arial, sans-serif">'
                f"{escape(defense)}</text>"
            )

        parts.append(
            f'<text x="{group_left + inner_group_width / 2:.1f}" y="{height - 42}" text-anchor="middle" '
            'font-size="14" fill="#2b2118" font-family="Helvetica, Arial, sans-serif">'
            f"{escape(config.title())}</text>"
        )

    parts.append("</svg>")
    return "".join(parts)


def write_outputs(
    rows: list[dict[str, object]],
    *,
    outputs: EvaluationReportOutputs,
) -> None:
    Path(outputs.markdown_output).write_text(render_markdown(rows))
    Path(outputs.svg_output).write_text(render_svg(rows))
    Path(outputs.json_output).write_text(json.dumps({"rows": rows}, indent=2) + "\n")
