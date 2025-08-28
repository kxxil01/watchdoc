from typing import List, Optional, Any, Tuple


def parse_semver(version: str) -> Tuple[int, int, int, Optional[List[Any]]]:
    """Parse a semantic version string into components.

    Supports common prefixes like 'v' or 'release-'. Returns a tuple of
    (major, minor, patch, prerelease_list or None).
    """
    import re

    # Strip common prefixes (e.g., 'v1.2.3', 'release-1.2.3')
    m = re.search(r"(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?", version)
    if not m:
        raise ValueError(f"Invalid semver string: {version}")
    major, minor, patch, prerelease = m.group(1), m.group(2), m.group(3), m.group(4)

    pre_list: Optional[List[Any]] = None
    if prerelease:
        pre_list = []
        for ident in prerelease.split('.'):
            if ident.isdigit():
                # Numeric identifiers MUST NOT include leading zeroes
                if len(ident) > 1 and ident[0] == '0':
                    # treat as string to avoid numeric precedence with leading zero
                    pre_list.append(ident)
                else:
                    pre_list.append(int(ident))
            else:
                pre_list.append(ident)
    return (int(major), int(minor), int(patch), pre_list)


def compare_semver(version1: str, version2: str) -> int:
    """Compare two semantic versions per SemVer 2.0.0.

    Returns 1 if v1 > v2, -1 if v1 < v2, 0 if equal.
    """
    m1 = parse_semver(version1)
    m2 = parse_semver(version2)

    for a, b in zip(m1[:3], m2[:3]):
        if a != b:
            return 1 if a > b else -1

    pre1, pre2 = m1[3], m2[3]
    if pre1 is None and pre2 is None:
        return 0
    if pre1 is None:
        return 1  # stable > prerelease
    if pre2 is None:
        return -1  # prerelease < stable

    # Compare prerelease identifiers
    for i in range(min(len(pre1), len(pre2))):
        a, b = pre1[i], pre2[i]
        if a == b:
            continue
        # Numeric identifiers have lower precedence than non-numeric
        a_is_int = isinstance(a, int)
        b_is_int = isinstance(b, int)
        if a_is_int and b_is_int:
            return 1 if a > b else -1
        if a_is_int and not b_is_int:
            return -1
        if not a_is_int and b_is_int:
            return 1
        # Both strings
        return 1 if str(a) > str(b) else -1

    # If all shared identifiers equal, longer prerelease list has higher precedence
    if len(pre1) == len(pre2):
        return 0
    return 1 if len(pre1) > len(pre2) else -1

