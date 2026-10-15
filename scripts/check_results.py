#!/usr/bin/env python3
"""Compare client JSON with the input order and the expected identifications."""

import json
import sys

FIELDS = ("ip", "port", "protocol", "product", "version", "os_hint", "confidence")


def load(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def fail(message):
    print(message, file=sys.stderr)
    sys.exit(1)


def main():
    if len(sys.argv) != 4:
        fail("usage: check_results.py input.json expected.json client-output.json")
    inputs = load(sys.argv[1])
    expected = load(sys.argv[2])
    actual = load(sys.argv[3])
    if not isinstance(actual, list):
        fail("client output is not a JSON array")
    if len(actual) != len(inputs) or len(actual) != len(expected):
        fail(f"length mismatch input={len(inputs)} expected={len(expected)} actual={len(actual)}")
    for index, (src, want, got) in enumerate(zip(inputs, expected, actual)):
        if not isinstance(got, dict):
            fail(f"record {index} is not an object")
        missing = [field for field in FIELDS if field not in got]
        if missing:
            fail(f"record {index} missing {missing}")
        if got["ip"] != src["ip"] or got["port"] != src["port"]:
            fail(f"record {index} identity {got['ip']}:{got['port']} != {src['ip']}:{src['port']}")
        if got["ip"] != want["ip"] or got["port"] != want["port"]:
            fail(f"record {index} drifted from expected identity")
        for field in ("protocol", "product", "version", "os_hint"):
            if got[field] != want[field]:
                fail(f"record {index} {field}={got[field]!r} want {want[field]!r}")
        confidence = got["confidence"]
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            fail(f"record {index} confidence is {type(confidence).__name__}")
        if not 0 <= float(confidence) <= 1:
            fail(f"record {index} confidence {confidence} out of range")
        if abs(float(confidence) - float(want["confidence"])) > 1e-9:
            fail(f"record {index} confidence {confidence} want {want['confidence']}")
    print(f"checked {len(actual)} records")


if __name__ == "__main__":
    main()
