#!/usr/bin/env python3
"""Render the README's performance figures as SVG, light and dark.

Numbers are the ones recorded in docs/research/2026-10-fixed-base-verify.md,
docs/research/2026-10-verifier-throughput.md,
docs/research/2026-10-producer-contention.md and the sources cited in the
README's performance section; change them there first, then here. No plotting library: the figures are a few rectangles and
circles, and a dependency would be the heavier thing to maintain.

Run from the repository root:  python3 docs/figures/make_figures.py
"""

import math
from pathlib import Path

OUT = Path(__file__).resolve().parent

# The reference palette's tokens, per mode (dataviz skill, palette.md).
MODES = {
    "light": {
        "surface": "#fcfcfb", "ink": "#0b0b0b", "ink2": "#52514e", "muted": "#898781",
        "grid": "#e1e0d9", "axis": "#c3c2b7",
        "s1": "#2a78d6", "s2": "#eb6834", "s3": "#1baf7a",
        "ord_light": "#86b6ef", "ord_dark": "#2a78d6",
    },
    "dark": {
        "surface": "#1a1a19", "ink": "#f0efec", "ink2": "#c3c2b7", "muted": "#898781",
        "grid": "#2c2c2a", "axis": "#383835",
        "s1": "#3987e5", "s2": "#d95926", "s3": "#199e70",
        "ord_light": "#1c5cab", "ord_dark": "#3987e5",
    },
}
FONT = 'system-ui, -apple-system, "Segoe UI", sans-serif'


def text(x, y, s, size=12, fill="ink", anchor="start", weight="normal", t=None, extra=""):
    return (f'<text x="{x:.1f}" y="{y:.1f}" font-family=\'{FONT}\' font-size="{size}" '
            f'fill="{t[fill]}" text-anchor="{anchor}" font-weight="{weight}" {extra}>{s}</text>')


def compact(v):
    if v >= 1_000_000:
        return f"{v / 1e6:g}M"
    if v >= 1000:
        return f"{v / 1e3:g}K"
    return f"{v:g}"


def svg(width, height, body, t):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
            f'viewBox="0 0 {width} {height}" role="img">\n'
            f'<rect width="{width}" height="{height}" fill="{t["surface"]}"/>\n'
            + "\n".join(body) + "\n</svg>\n")


def rounded_end_bar(x, y, w, h, fill, r=4):
    """A bar growing rightward from x: square at the baseline, rounded at the data end."""
    if w <= r:
        return f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" fill="{fill}"/>'
    return (f'<path d="M{x:.1f},{y:.1f} H{x + w - r:.1f} a{r},{r} 0 0 1 {r},{r} '
            f'V{y + h - r:.1f} a{r},{r} 0 0 1 -{r},{r} H{x:.1f} Z" fill="{fill}"/>')


# Figure 1: entries verified per second, by configuration ----------------------

# Rows from docs/research/2026-10-fixed-base-verify.md, worst of two. The first row is the sequential
# reference: the signature kernel alone on one thread, no sparks.
FIG1 = [
    ("Signature kernel alone, 1 thread", 44_400),
    ("Fan-out, 1 capability", 73_300),
    ("Fan-out, 12 capabilities", 293_100),
    ("Fan-out, 16 capabilities", 294_600),
]


def figure1(t):
    W, H = 720, 298
    left, right, top = 230, 60, 64
    band = 40
    plot_w = W - left - right
    vmax = 150_000
    body = [
        text(24, 30, "Entries verified per second, one machine", 15, weight="600", t=t),
        text(24, 48, "100k-line AOF, ~330-byte Entries, one Producer key · 12 performance + 4 efficiency cores",
             11, "ink2", t=t),
    ]
    # gridlines and ticks
    for v in range(0, vmax + 1, 50_000):
        x = left + plot_w * v / vmax
        body.append(f'<line x1="{x:.1f}" y1="{top - 6}" x2="{x:.1f}" y2="{top + band * len(FIG1)}" '
                    f'stroke="{t["grid"]}" stroke-width="1"/>')
        body.append(text(x, top + band * len(FIG1) + 16, compact(v), 11, "muted", "middle", t=t,
                         extra='font-variant-numeric="tabular-nums"'))
    # baseline
    body.append(f'<line x1="{left}" y1="{top - 6}" x2="{left}" y2="{top + band * len(FIG1)}" '
                f'stroke="{t["axis"]}" stroke-width="1"/>')
    for i, (label, v) in enumerate(FIG1):
        y = top + i * band + (band - 20) / 2
        w = plot_w * v / vmax
        body.append(text(left - 12, y + 14, label, 12, "ink", "end", t=t))
        body.append(rounded_end_bar(left, y, w, 20, t["s1"]))
        body.append(text(left + w + 8, y + 14, f"{v:,}", 12, "ink2", t=t,
                         extra='font-variant-numeric="tabular-nums"'))
    body.append(text(24, H - 28, "Bars: lines/s, every verdict forced; the first is the sequential reference, a fold with no sparks.",
                     11, "muted", t=t))
    body.append(text(24, H - 12, "Capabilities are GHC's -N, not cores; see docs/research/2026-10-verifier-throughput.md.",
                     11, "muted", t=t))
    return svg(W, H, body, t)


# Figure 2: where one line's time goes, sequentially --------------------------

FIG2 = [("Decode", 6.9, "s1"), ("Signature check", 15.6, "s2"), ("Fold", 1.0, "s3")]


def figure2(t):
    W, H = 720, 150
    left, right, top = 24, 24, 64
    total = sum(v for _, v, _ in FIG2)
    plot_w = W - left - right
    bar_h = 24
    gap = 2
    body = [
        text(24, 30, "Where one line's time goes, sequentially", 15, weight="600", t=t),
        text(24, 48, f"{total:g} µs per line on one thread · the signature kernel is ~{FIG2[1][1] / total:.0%} of it",
             11, "ink2", t=t),
    ]
    x = left
    for i, (label, v, slot) in enumerate(FIG2):
        w = plot_w * v / total - (gap if i < len(FIG2) - 1 else 0)
        body.append(f'<rect x="{x:.1f}" y="{top}" width="{w:.1f}" height="{bar_h}" fill="{t[slot]}"/>')
        inside = f"{v:g} µs"
        if w > 70:  # label only where it fits with padding
            fill = "#ffffff" if slot != "s3" else "#0b0b0b"
            body.append(f'<text x="{x + 8:.1f}" y="{top + 16}" font-family=\'{FONT}\' font-size="12" '
                        f'fill="{fill}">{inside}</text>')
        x += w + gap
    # legend
    lx = left
    ly = top + bar_h + 28
    for label, v, slot in FIG2:
        body.append(f'<rect x="{lx}" y="{ly - 9}" width="10" height="10" rx="2" fill="{t[slot]}"/>')
        body.append(text(lx + 16, ly, f"{label} · {v:g} µs", 12, "ink2", t=t))
        lx += 16 + 9 * len(label) + 60
    return svg(W, H, body, t)


# Figure 3: one machine verifying vs networks writing ---------------------------

# (name, sustained tx/s, peak tx/s). Networks: chainspect.app, trailing hour and
# max over 100 blocks, read 2026-10-13. Fabric: FastFabric paper, baseline and
# re-architected lab peak. EventChain: this repository's bench, -N12.
FIG3 = [
    ("EventChain Verifier · 12 cores", 293_100, None),
    ("Hyperledger Fabric (lab)", 3_000, 20_000),
    ("Solana", 2_000, 11_000),
    ("BNB Chain", 213, 3_300),
    ("Sui", 132, 1_200),
    ("Aptos", 125, 13_000),
    ("Ethereum", 22.7, 74.9),
    ("Hedera", 7.56, 3_300),
    ("Bitcoin", 7.31, 13.48),
]


def figure3(t):
    W, H = 720, 420
    left, right, top = 240, 40, 72
    band = 30
    plot_w = W - left - right
    lo, hi = 1, 1_000_000

    def xof(v):
        return left + plot_w * (math.log10(v) - math.log10(lo)) / (math.log10(hi) - math.log10(lo))

    body = [
        text(24, 30, "Verifying on one machine against what networks write", 15, weight="600", t=t),
        text(24, 48, "Per second, log scale. Networks: transactions committed by consensus. "
             "EventChain: Entries checked from a file.", 11, "ink2", t=t),
    ]
    rows = len(FIG3)
    for e in range(0, 7):
        v = 10 ** e
        x = xof(v)
        body.append(f'<line x1="{x:.1f}" y1="{top - 8}" x2="{x:.1f}" y2="{top + band * rows}" '
                    f'stroke="{t["grid"]}" stroke-width="1"/>')
        body.append(text(x, top + band * rows + 16, compact(v), 11, "muted", "middle", t=t,
                         extra='font-variant-numeric="tabular-nums"'))
    sustained_c = t["ink2"]
    peak_c = t["muted"]
    for i, (name, sustained, peak) in enumerate(FIG3):
        y = top + i * band + band / 2
        emphasis = i == 0
        body.append(text(left - 12, y + 4, name, 12, "ink" if emphasis else "ink2", "end",
                         weight="600" if emphasis else "normal", t=t))
        x1 = xof(sustained)
        if peak is not None:
            x2 = xof(peak)
            body.append(f'<line x1="{x1:.1f}" y1="{y}" x2="{x2:.1f}" y2="{y}" stroke="{peak_c}" stroke-width="2" '
                        f'stroke-linecap="round"/>')
            body.append(f'<circle cx="{x2:.1f}" cy="{y}" r="6" fill="{peak_c}" stroke="{t["surface"]}" stroke-width="2"/>')
        color = t["s1"] if emphasis else sustained_c
        body.append(f'<circle cx="{x1:.1f}" cy="{y}" r="6" fill="{color}" stroke="{t["surface"]}" stroke-width="2"/>')
        if emphasis:
            body.append(text(x1 - 12, y + 4, f"{sustained:,.0f} entries/s", 12, "ink", "end", t=t,
                             extra='font-variant-numeric="tabular-nums"'))
        elif name == "Solana":
            body.append(text(x1 - 12, y + 4, f"{sustained:,.0f}", 11, "ink2", "end", t=t,
                             extra='font-variant-numeric="tabular-nums"'))
    # legend
    ly = top + band * rows + 44
    items = [
        (24, t["s1"], "EventChain, measured (-N12)"),
        (250, sustained_c, "Network, sustained (trailing hour)"),
        (490, peak_c, "Network, peak (100 blocks, or lab)"),
    ]
    for lx, c, label in items:
        body.append(f'<circle cx="{lx + 5}" cy="{ly - 4}" r="5" fill="{c}"/>')
        body.append(text(lx + 16, ly, label, 11, "ink2", t=t))
    body.append(text(24, H - 12, "Sources in the README table. Different quantities on one axis: a network's rate is "
                     "bounded by consensus, a verifier's by one CPU.", 11, "muted", t=t))
    return svg(W, H, body, t)


# Figure 4: signatures per committed Entry as Producers race for one head ----

# Midpoints of two runs, the saturating block of
# docs/research/2026-10-producer-contention.md. Delays are as delivered by
# the runtime (the 2 ms and 20 ms requests landed at 2.28 and 20.9).
FIG4_X = [1, 2, 4, 8, 12]
FIG4 = [
    ("20 ms in flight", [1.01, 2.01, 4.02, 8.05, 11.95], "s1"),
    ("2 ms in flight", [1.00, 2.00, 4.00, 7.98, 11.95], "s2"),
    ("no delay", [1.00, 1.99, 3.97, 7.77, 10.91], "s3"),
]


def figure4(t):
    W, H = 720, 356
    left, right, top, bottom = 64, 170, 84, 64
    plot_w, plot_h = W - left - right, H - top - bottom
    xmax, ymax = 12, 12

    def sx(x):
        return left + plot_w * (x - 1) / (xmax - 1)

    def sy(y):
        return top + plot_h * (1 - y / ymax)

    body = [
        text(24, 30, "Signatures per committed Entry, Producers racing for one head", 15, weight="600", t=t),
        text(24, 48, "Saturating load, one key and one core per Producer · commits/s stay at one per window whatever the count",
             11, "ink2", t=t),
    ]
    # legend row
    lx = 24
    for label, _, slot in FIG4:
        body.append(f'<rect x="{lx}" y="{62 - 9}" width="10" height="10" rx="2" fill="{t[slot]}"/>')
        body.append(text(lx + 16, 62, label, 12, "ink2", t=t))
        lx += 16 + 6 * len(label) + 20
    body.append(f'<line x1="{lx}" y1="{62 - 4}" x2="{lx + 18}" y2="{62 - 4}" stroke="{t["muted"]}" '
                f'stroke-width="2" stroke-dasharray="4 3"/>')
    body.append(text(lx + 24, 62, "One per Producer", 12, "ink2", t=t))
    # gridlines, y
    for v in range(0, ymax + 1, 4):
        y = sy(v)
        body.append(f'<line x1="{left}" y1="{y:.1f}" x2="{left + plot_w}" y2="{y:.1f}" stroke="{t["grid"]}" stroke-width="1"/>')
        body.append(text(left - 10, y + 4, str(v), 11, "muted", "end", t=t, extra='font-variant-numeric="tabular-nums"'))
    # x ticks
    for x in FIG4_X:
        body.append(text(sx(x), top + plot_h + 18, str(x), 11, "muted", "middle", t=t,
                         extra='font-variant-numeric="tabular-nums"'))
    body.append(text(left + plot_w / 2, top + plot_h + 36, "Producers", 11, "muted", "middle", t=t))
    body.append(f'<line x1="{left}" y1="{top + plot_h}" x2="{left + plot_w}" y2="{top + plot_h}" '
                f'stroke="{t["axis"]}" stroke-width="1"/>')
    # reference: one signature per Producer
    body.append(f'<line x1="{sx(1):.1f}" y1="{sy(1):.1f}" x2="{sx(12):.1f}" y2="{sy(12):.1f}" '
                f'stroke="{t["muted"]}" stroke-width="2" stroke-dasharray="4 3"/>')
    # series: 2px lines, 8px markers with a 2px surface ring, direct label at the end
    for label, ys, slot in FIG4:
        pts = " ".join(f"{sx(x):.1f},{sy(y):.1f}" for x, y in zip(FIG4_X, ys))
        body.append(f'<polyline points="{pts}" fill="none" stroke="{t[slot]}" stroke-width="2" '
                    f'stroke-linejoin="round"/>')
        for x, y in zip(FIG4_X, ys):
            body.append(f'<circle cx="{sx(x):.1f}" cy="{sy(y):.1f}" r="5" fill="{t[slot]}" '
                        f'stroke="{t["surface"]}" stroke-width="2"/>')
    # direct labels at the line ends, merged where two series end on the same value
    ends = {}
    for label, ys, _ in FIG4:
        ends.setdefault(f"{ys[-1]:.1f}", []).append(label)
    for value, labels in ends.items():
        joined = " and ".join(l.replace(" in flight", "") for l in labels) + (" in flight" if "in flight" in labels[0] else "")
        body.append(text(sx(12) + 12, sy(float(value)) + 4, f"{value} · {joined}", 12, "ink2", t=t,
                         extra='font-variant-numeric="tabular-nums"'))
    body.append(text(24, H - 10, "Hub modelled as compare-and-swap append; every file verified. "
                     "docs/research/2026-10-producer-contention.md.", 11, "muted", t=t))
    return svg(W, H, body, t)


# Figure 5: commits per second against the race window ------------------------

# Saturating rows of the main run, worst of two runs. The window is the
# 22 µs signature plus the in-flight delay as delivered (0, 200, 2,281, 20,940 µs).
FIG5_W = [22, 222, 2303, 20962]
FIG5 = [
    ("1 Producer", [43_530, 4_440, 345, 46], "s1"),
    ("12 Producers", [25_328, 4_279, 422, 48], "s2"),
]
FIG5_PRED = [44_924, 4_499, 434, 48]


def figure5(t):
    W, H = 720, 340
    left, right, top, bottom = 64, 150, 84, 64
    plot_w, plot_h = W - left - right, H - top - bottom
    xlo, xhi = 10, 100_000
    ylo, yhi = 10, 100_000

    def sx(x):
        return left + plot_w * (math.log10(x) - math.log10(xlo)) / (math.log10(xhi) - math.log10(xlo))

    def sy(y):
        return top + plot_h * (1 - (math.log10(y) - math.log10(ylo)) / (math.log10(yhi) - math.log10(ylo)))

    body = [
        text(24, 30, "Entries committed per second against the race window", 15, weight="600", t=t),
        text(24, 48, "Saturating load, log–log · the window is the signature plus the time a signed line is in flight to the Hub",
             11, "ink2", t=t),
    ]
    lx = 24
    for label, _, slot in FIG5:
        body.append(f'<rect x="{lx}" y="{62 - 9}" width="10" height="10" rx="2" fill="{t[slot]}"/>')
        body.append(text(lx + 16, 62, label, 12, "ink2", t=t))
        lx += 16 + 6 * len(label) + 20
    body.append(f'<line x1="{lx}" y1="{62 - 4}" x2="{lx + 18}" y2="{62 - 4}" stroke="{t["muted"]}" '
                f'stroke-width="2" stroke-dasharray="4 3"/>')
    body.append(text(lx + 24, 62, "One commit per window", 12, "ink2", t=t))
    for v in (10, 100, 1_000, 10_000, 100_000):
        body.append(f'<line x1="{left}" y1="{sy(v):.1f}" x2="{left + plot_w}" y2="{sy(v):.1f}" stroke="{t["grid"]}" stroke-width="1"/>')
        body.append(text(left - 10, sy(v) + 4, compact(v), 11, "muted", "end", t=t, extra='font-variant-numeric="tabular-nums"'))
        body.append(f'<line x1="{sx(v):.1f}" y1="{top}" x2="{sx(v):.1f}" y2="{top + plot_h}" stroke="{t["grid"]}" stroke-width="1"/>')
        body.append(text(sx(v), top + plot_h + 18, compact(v) + " µs", 11, "muted", "middle", t=t,
                         extra='font-variant-numeric="tabular-nums"'))
    body.append(text(left + plot_w / 2, top + plot_h + 36, "Race window", 11, "muted", "middle", t=t))
    body.append(f'<line x1="{left}" y1="{top + plot_h}" x2="{left + plot_w}" y2="{top + plot_h}" stroke="{t["axis"]}" stroke-width="1"/>')
    pts = " ".join(f"{sx(w):.1f},{sy(v):.1f}" for w, v in zip(FIG5_W, FIG5_PRED))
    body.append(f'<polyline points="{pts}" fill="none" stroke="{t["muted"]}" stroke-width="2" stroke-dasharray="4 3"/>')
    for label, ys, slot in FIG5:
        pts = " ".join(f"{sx(w):.1f},{sy(v):.1f}" for w, v in zip(FIG5_W, ys))
        body.append(f'<polyline points="{pts}" fill="none" stroke="{t[slot]}" stroke-width="2" stroke-linejoin="round"/>')
        for w, v in zip(FIG5_W, ys):
            body.append(f'<circle cx="{sx(w):.1f}" cy="{sy(v):.1f}" r="5" fill="{t[slot]}" stroke="{t["surface"]}" stroke-width="2"/>')
    # the start values, in the empty upper right rather than on the lines
    body.append(text(sx(900), sy(60_000) + 4, f"At 22 µs: {FIG5[0][1][0]:,} with 1 Producer,", 12, "ink2", t=t,
                     extra='font-variant-numeric="tabular-nums"'))
    body.append(text(sx(900), sy(60_000) + 20, f"{FIG5[1][1][0]:,} with 12 signing at once", 12, "ink2", t=t,
                     extra='font-variant-numeric="tabular-nums"'))
    body.append(text(sx(FIG5_W[-1]) + 12, sy(FIG5[1][1][-1]) + 4, f"{FIG5[1][1][-1]} and {FIG5[0][1][-1]}", 12, "ink2", t=t,
                     extra='font-variant-numeric="tabular-nums"'))
    body.append(text(24, H - 10, "Twelve Producers commit no faster than one; past 200 µs the two lines are the same line. "
                     "docs/research/2026-10-producer-contention.md.", 11, "muted", t=t))
    return svg(W, H, body, t)


def main():
    for mode, t in MODES.items():
        for name, fn in (("verifier-throughput", figure1), ("line-cost", figure2), ("versus-networks", figure3),
                         ("producer-contention", figure4), ("commit-ceiling", figure5)):
            (OUT / f"{name}-{mode}.svg").write_text(fn(t))
            print(f"wrote {name}-{mode}.svg")


if __name__ == "__main__":
    main()
