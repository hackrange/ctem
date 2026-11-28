#!/bin/sh
# Regenerate both CycloneDX SBOMs inside the exact base images they describe, so each lists what really ships:
#   sbom.cdx.json            the CTEM image: requirements.txt on docker/Dockerfile's base image
#   sbom-collector.cdx.json  the shipper image: the packages api/collector/agent/Dockerfile pins, on its base image
# Each also names its base image and its Python runtime. Run it whenever a base image or a pinned package changes;
# the precheck fails until the SBOMs match. Needs Docker and network access to PyPI.
set -eu
cd "$(dirname "$0")/.."
TOOL="cyclonedx-bom==9.0.0"

base_of() { sed -n 's/^FROM \(python:[^ ]*\).*/\1/p' "$1" | head -1; }

make() {   # make <image> <requirements file inside the repo> <output>
  docker run --rm -v "$PWD":/src -w /src "$1" sh -ec '
    python -m venv /env >/dev/null && /env/bin/pip -q --disable-pip-version-check install -r "$1"
    python -m venv /tool >/dev/null && /tool/bin/pip -q --disable-pip-version-check install "$3"
    /tool/bin/cyclonedx-py environment /env/bin/python --of JSON -o "$2"
    /env/bin/python - "$2" "$4" <<PYEOF
import json, platform, sys
path, image = sys.argv[1], sys.argv[2]
sb = json.load(open(path))
tag = image.split(":", 1)[1]
runtime = [{"type": "container", "name": "python", "version": tag, "purl": f"pkg:docker/library/python@{tag}",
            "bom-ref": f"base-image:python@{tag}"},
           {"type": "application", "name": "cpython", "version": platform.python_version(),
            "purl": f"pkg:generic/cpython@{platform.python_version()}", "bom-ref": f"runtime:cpython@{platform.python_version()}"}]
sb["components"] = runtime + [c for c in sb.get("components", []) if c.get("name") not in ("python", "cpython")]
json.dump(sb, open(path, "w"), indent=2)
open(path, "a").write("\n")
PYEOF
  ' sh "$2" "$3" "$TOOL" "$1"
  echo "wrote $3 ($1)"
}

APP=$(base_of docker/Dockerfile)
COLLECTOR=$(base_of api/collector/agent/Dockerfile)
make "$APP" requirements.txt sbom.cdx.json

# The shipper's packages, as its Dockerfile pins them (name==version on the pip install line)
REQ=.sbom-collector-requirements.txt
grep -o '[A-Za-z0-9_.-]*==[0-9][A-Za-z0-9_.+-]*' api/collector/agent/Dockerfile > "$REQ"
trap 'rm -f "$REQ"' EXIT
make "$COLLECTOR" "$REQ" sbom-collector.cdx.json
