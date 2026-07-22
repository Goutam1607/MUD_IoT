"""
mud_validator.py — Validates MUD file structure per RFC 8520
Checks that required fields are present and well-formed.
"""


REQUIRED_MUD_FIELDS = [
    "mud-version",
    "mud-url",
    "last-update",
    "cache-validity",
    "is-supported",
    "systeminfo",
]


def validate_mud_file(mud_data: dict) -> tuple[bool, list[str]]:
    """
    Validate the structure of a MUD file.

    Returns:
        (True, [])          if valid
        (False, [errors])   if invalid
    """
    errors = []

    # Check top-level MUD block
    mud_block = mud_data.get("ietf-mud:mud")
    if mud_block is None:
        errors.append("Missing required top-level key: 'ietf-mud:mud'")
        return False, errors

    # Check required fields inside the MUD block
    for field in REQUIRED_MUD_FIELDS:
        if field not in mud_block:
            errors.append(f"Missing required MUD field: '{field}'")

    # Validate mud-version must be 1
    if mud_block.get("mud-version") != 1:
        errors.append(f"Invalid mud-version: {mud_block.get('mud-version')} (expected 1)")

    # Validate mud-url is a string starting with http
    mud_url = mud_block.get("mud-url", "")
    if not isinstance(mud_url, str) or not mud_url.startswith("http"):
        errors.append(f"Invalid mud-url: '{mud_url}'")

    # Validate cache-validity is a positive integer
    cache_validity = mud_block.get("cache-validity", 0)
    if not isinstance(cache_validity, int) or cache_validity <= 0:
        errors.append(f"Invalid cache-validity: {cache_validity} (must be positive integer)")

    # Check ACL block presence
    acl_block = mud_data.get("ietf-access-control-list:acls")
    if acl_block is None:
        errors.append("Missing 'ietf-access-control-list:acls' block")
    else:
        acls = acl_block.get("acl", [])
        if not isinstance(acls, list) or len(acls) == 0:
            errors.append("ACL block must contain at least one ACL entry")
        else:
            for acl in acls:
                if "name" not in acl:
                    errors.append("An ACL entry is missing the 'name' field")
                if "aces" not in acl or "ace" not in acl.get("aces", {}):
                    errors.append(f"ACL '{acl.get('name', '?')}' is missing ACE entries")

    # Check from/to device policy
    if "from-device-policy" not in mud_block:
        errors.append("Missing 'from-device-policy' in MUD block")
    if "to-device-policy" not in mud_block:
        errors.append("Missing 'to-device-policy' in MUD block")

    is_valid = len(errors) == 0
    if is_valid:
        print(f"[MUD VALIDATOR] ✅ MUD file is valid (URL: {mud_url})")
    else:
        print(f"[MUD VALIDATOR] ❌ MUD file validation failed with {len(errors)} error(s):")
        for err in errors:
            print(f"  - {err}")

    return is_valid, errors


if __name__ == "__main__":
    import json, sys, os

    # Quick standalone test — validate a file passed as argument
    if len(sys.argv) < 2:
        print("Usage: python mud_validator.py <path_to_mud_file.json>")
        sys.exit(1)

    path = sys.argv[1]
    if not os.path.exists(path):
        print(f"File not found: {path}")
        sys.exit(1)

    with open(path) as f:
        data = json.load(f)

    valid, errs = validate_mud_file(data)
    sys.exit(0 if valid else 1)
