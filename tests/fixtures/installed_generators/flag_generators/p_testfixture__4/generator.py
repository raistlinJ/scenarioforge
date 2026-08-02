"""Fixture generator: writes a deterministic flag. Never executed by the
unit tests, which only need the manifest to be discoverable."""
import hashlib, json, os, sys

def main() -> int:
    cfg = json.loads(os.environ.get("CONFIG_JSON") or "{}")
    seed = str(cfg.get("seed") or "0")
    digest = hashlib.sha256(seed.encode()).hexdigest()[:12]
    print(json.dumps({"Flag(flag_id)": f"FLAG{{{digest}}}"}))
    return 0

if __name__ == "__main__":
    sys.exit(main())
