#!/usr/bin/env python3
"""Publish llama.cpp CPU runtime archives to the PUBLIC HuggingFace runtime repo.

WHAT THIS DOES (and only this):
  * Downloads llama.cpp's OFFICIAL CPU prebuilt release assets for Windows x64,
    Intel-Mac x64 and Apple-Silicon arm64 (pinned to exactly one llama.cpp
    b-tag, same engine the app already runs for Apple Silicon).
  * FLATTENS them: llama.cpp's official .zip assets nest the binaries under a
    top-level prefix dir (e.g. llama-b5205-bin-win-avx2-x64/). The app's
    bootstrap.rs writes each archive entry verbatim to its bin dir and then
    looks for llama-server(.exe) at the archive ROOT — so a prefixed archive
    would leave the binary at bin/<prefix>/llama-server(.exe) and the app
    would report it missing. We strip the prefix so the archive root directly
    contains llama-server(.exe) + all sibling runtime libs, exactly what the
    app expects.
  * Re-archives to the exact names bootstrap.rs downloads:
        windows/x86_64  ->  llama-win-x64.zip           (from official ..-win-avx2-x64.zip)
        macos/x86_64    ->  llama-macos-x64.tar.gz      (from official ..-macos-x64.zip)
        macos/aarch64   ->  llama-macos-arm64.tar.gz    (from official ..-macos-arm64.zip)
    (macOS ships as .tar.gz because bootstrap.rs uses `tar -xzf` on non-Windows.)
  * Uploads ONLY those three archives to ahmadnan/pci-sentinel-runtime
    (public model repo). NO repo file is ever uploaded; no source can leak.
  * Verifies each publicly over HTTPS with no auth (same check a tester gets).

The repo IS checked out for this job (the workflow file lives in it); that is
deliberate and safe: the ONLY bytes pushed to public HF are the flattened
llama archives. Nothing in this script touches the repo tree.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

OUT_DIR = Path("_runtime_out")
IN_ZIP = Path("/tmp/llama_in.zip")


def masked(s: str) -> str:
    return s[:4] + "…" + s[-4:] if len(s) > 8 else "****"


def http_get(url: str) -> bytes:
    return subprocess.run(
        ["curl", "-fsSL", url], capture_output=True, check=True
    ).stdout


def flatten(src_zip: Path) -> list[Path]:
    """Extract everything into a scratch dir, then return the FILES at the
    archive ROOT only (their names with any prefix dir stripped)."""
    scratch = Path("/tmp/llama_flat")
    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.mkdir()
    with zipfile.ZipFile(src_zip) as z:
        z.extractall(scratch)
    # Every entry in llama.cpp CPU zips live under ONE top-level prefix dir;
    # flatten = take all files, drop the prefix, keep them by basename.
    files = [p for p in scratch.rglob("*") if p.is_file()]
    return files


def repackage(files: list[Path], out_name: str, kind: str) -> None:
    OUT_DIR.mkdir(exist_ok=True)
    out = OUT_DIR / out_name
    if kind == "zip":
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            for p in files:
                z.write(p, arcname=p.name)
    else:  # tar.gz (macOS — bootstrap.rs uses `tar -xzf`)
        with tarfile.open(out, "w:gz") as t:
            for p in files:
                t.add(p, arcname=p.name)
    print(f"  [{out_name}] flat + repackaged ok ({out.stat().st_size/1e6:.1f} MB)")


def main() -> None:
    tag = os.environ.get("LLAMA_TAG", "b5205")
    token = os.environ.get("HF_WRITE_TOKEN", "")
    if not token:
        raise SystemExit("HF_TOKEN secret is not set (nothing uploaded)")

    api = "https://api.github.com/repos/ggml-org/llama.cpp/releases/tags"
    rel = json.loads(http_get(f"{api}/{tag}").decode())
    url_by_name = {a["name"]: a["browser_download_url"] for a in rel.get("assets", [])}

    # (official asset suffix,            our flat archive name,          kind)
    targets = [
        ("bin-win-avx2-x64", "llama-win-x64.zip", "zip"),
        ("bin-macos-x64",    "llama-macos-x64.tar.gz", "tgz"),
        ("bin-macos-arm64",  "llama-macos-arm64.tar.gz", "tgz"),
    ]

    print(f"=== llama.cpp {tag} official CPU prebuilts -> flat archives (token masked: {masked(token)}) ===")
    for suffix, out_name, kind in targets:
        in_name = f"llama-{tag}-{suffix}.zip"
        url = url_by_name.get(in_name)
        if not url:
            raise SystemExit(f"official asset not found for {in_name} at tag {tag}")
        print(f"\n[{out_name}] downloading official {in_name} …")
        IN_ZIP.write_bytes(http_get(url))
        files = flatten(IN_ZIP)
        repackage(files, out_name, kind)

    print("\n=== uploading 3 archives to ahmadnan/pci-sentinel-runtime (public) ===")
    import huggingface_hub

    hub = huggingface_hub.HfApi(token=token, endpoint="https://huggingface.co")
    for _, out_name, _ in targets:
        api_resp = hub.upload_file(
            path_or_fileobj=str(OUT_DIR / out_name),
            path_in_repo=out_name,
            repo_id="ahmadnan/pci-sentinel-runtime",
            repo_type="model",
            commit_message=f"runtime: publish {out_name} (llama.cpp {tag})",
        )
        print(f"  [{out_name}] uploaded ok")

    print("\n=== PUBLIC verification (no auth, exactly what a tester sees) ===")
    for _, out_name, _ in targets:
        code = subprocess.run(
            [
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                f"https://huggingface.co/ahmadnan/pci-sentinel-runtime/resolve/main/{out_name}",
            ],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        print(f"  {out_name}: HTTP {code}")


if __name__ == "__main__":
    main()
