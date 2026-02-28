#!/usr/bin/env python3
"""
Compare JSON entries in two text files.
Handles newlines and different ordering of entries.
"""

import json
import sys
from typing import Set, Dict, Any


def extract_path(obj: dict) -> str:
    """
    Extract the path field from BaseRuntimeMetadata.arguments.path
    Returns empty string if path cannot be found.
    """
    try:
        return obj.get('BaseRuntimeMetadata', {}).get('arguments', {}).get('path', '')
    except (AttributeError, TypeError):
        return ''


def normalize_json(obj: Any) -> str:
    """
    Extract only the path field for comparison.
    """
    path = extract_path(obj)
    return path


def load_json_entries(filepath: str) -> Dict[str, Any]:
    """
    Load JSON entries from a file (one JSON object per line).
    Returns a dict mapping normalized JSON -> original object.
    """
    entries = {}
    with open(filepath, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                normalized = normalize_json(obj)
                entries[normalized] = obj
            except json.JSONDecodeError as e:
                print(f"Warning: Failed to parse line {line_num} in {filepath}: {e}", file=sys.stderr)
    return entries


def compare_files(file1: str, file2: str):
    """
    Compare two files containing JSON entries.
    """
    print(f"Loading {file1}...")
    entries1 = load_json_entries(file1)
    print(f"  Found {len(entries1)} unique entries")

    print(f"\nLoading {file2}...")
    entries2 = load_json_entries(file2)
    print(f"  Found {len(entries2)} unique entries")

    # Get sets of normalized JSON strings
    set1 = set(entries1.keys())
    set2 = set(entries2.keys())

    # Find differences
    only_in_file1 = set1 - set2
    only_in_file2 = set2 - set1
    common = set1 & set2

    print("\n" + "="*80)
    print("COMPARISON RESULTS (comparing paths only)")
    print("="*80)
    print(f"\nPaths in both files: {len(common)}")
    print(f"Paths only in {file1}: {len(only_in_file1)}")
    print(f"Paths only in {file2}: {len(only_in_file2)}")

    if only_in_file1:
        print(f"\n{'='*80}")
        print(f"PATHS ONLY IN {file1}:")
        print(f"{'='*80}")
        for i, path in enumerate(sorted(only_in_file1), 1):
            if path:  # Only show non-empty paths
                print(f"{i}. {path}")

    if only_in_file2:
        print(f"\n{'='*80}")
        print(f"PATHS ONLY IN {file2}:")
        print(f"{'='*80}")
        for i, path in enumerate(sorted(only_in_file2), 1):
            if path:  # Only show non-empty paths
                print(f"{i}. {path}")

    # Save paths to files
    if only_in_file1:
        output_file = f"{file1}.only_paths"
        with open(output_file, 'w') as f:
            for path in sorted(only_in_file1):
                if path:
                    f.write(path + '\n')
        print(f"\n✓ Paths only in {file1} saved to: {output_file}")

    if only_in_file2:
        output_file = f"{file2}.only_paths"
        with open(output_file, 'w') as f:
            for path in sorted(only_in_file2):
                if path:
                    f.write(path + '\n')
        print(f"✓ Paths only in {file2} saved to: {output_file}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python compare_json.py <file1> <file2>")
        sys.exit(1)

    file1 = sys.argv[1]
    file2 = sys.argv[2]

    compare_files(file1, file2)
