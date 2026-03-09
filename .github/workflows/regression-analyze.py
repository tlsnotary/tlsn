#!/usr/bin/env python3
"""
Benchmark regression detection for TLSNotary.

Compares two benchmark CSV files and flags regressions:
- time_total: must not regress more than 3%
- uploaded_total / downloaded_total: must not regress more than 0.1%
"""

import argparse
import os
import sys
import pandas as pd


def parse_args():
    parser = argparse.ArgumentParser(description='Detect benchmark regressions')
    parser.add_argument('baseline', help='Path to baseline metrics CSV')
    parser.add_argument('comparison', help='Path to comparison metrics CSV')
    parser.add_argument('--commit1', required=True, help='Baseline commit identifier')
    parser.add_argument('--commit2', required=True, help='Comparison commit identifier')
    return parser.parse_args()


def load_csv(path):
    try:
        return pd.read_csv(path)
    except Exception as e:
        print(f"::error::Failed to load CSV {path}: {e}")
        sys.exit(1)


METRICS = {
    'time_total': 3.0,
    'uploaded_total': 0.1,
    'downloaded_total': 0.1,
}


def analyze(df1, df2):
    results = []
    regression_detected = False

    for metric, threshold in METRICS.items():
        if metric not in df1.columns or metric not in df2.columns:
            continue

        baseline_mean = df1[metric].mean()
        comparison_mean = df2[metric].mean()

        if baseline_mean != 0:
            pct_change = ((comparison_mean - baseline_mean) / baseline_mean) * 100
        else:
            pct_change = 0

        if pct_change > threshold:
            regression_detected = True
            status = "REGRESSION"
        elif pct_change < -threshold:
            status = "IMPROVEMENT"
        else:
            status = "OK"

        results.append({
            'metric': metric,
            'threshold': threshold,
            'baseline': baseline_mean,
            'comparison': comparison_mean,
            'pct_change': pct_change,
            'status': status,
        })

    return results, regression_detected


def write_summary(results, commit1, commit2, regression_detected):
    summary_file = os.environ.get('GITHUB_STEP_SUMMARY')

    if not summary_file:
        f = sys.stdout
    else:
        f = open(summary_file, 'a')

    try:
        f.write(f"**Baseline:** `{commit1}`\n\n")
        f.write(f"**Comparison:** `{commit2}`\n\n")

        if regression_detected:
            f.write("### REGRESSION DETECTED\n\n")
        else:
            f.write("### No regression detected\n\n")

        f.write("| Metric | Threshold | Baseline | Comparison | Change | Status |\n")
        f.write("|--------|-----------|----------|------------|--------|--------|\n")

        for r in results:
            f.write(f"| {r['metric']} | {r['threshold']}% | {r['baseline']:.2f} | {r['comparison']:.2f} | {r['pct_change']:+.2f}% | {r['status']} |\n")
    finally:
        if summary_file:
            f.close()


def main():
    args = parse_args()

    df1 = load_csv(args.baseline)
    df2 = load_csv(args.comparison)

    results, regression_detected = analyze(df1, df2)
    write_summary(results, args.commit1, args.commit2, regression_detected)

    if regression_detected:
        print("::error::Performance regression detected!")
        sys.exit(1)
    else:
        print("::notice::No regression detected")
        sys.exit(0)


if __name__ == '__main__':
    main()
