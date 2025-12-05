import argparse
import json
import os
import sys
import zipfile
from pathlib import Path
import hashlib
import base64
import requests


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def load_payload_hash(payload_zip: Path, inner_name: str = "QuorumExecutor.exe") -> str:
    if not payload_zip.exists():
        raise FileNotFoundError(f"payload zip not found: {payload_zip}")
    with zipfile.ZipFile(payload_zip, "r") as zf:
        try:
            with zf.open(inner_name) as f:
                data = f.read()
        except KeyError as exc:
            raise FileNotFoundError(f"{inner_name} not found inside {payload_zip}") from exc
    return sha256_bytes(data)


def main() -> int:
    parser = argparse.ArgumentParser(description="Update payload.manifest.json with the current payload hash.")
    parser.add_argument("--zip", default="payload.zip", help="Path to payload.zip (default: payload.zip)")
    parser.add_argument("--manifest", default="payload.manifest.json", help="Path to manifest file")
    parser.add_argument("--exe-name", default="QuorumExecutor.exe", help="Name of exe inside the zip (default: QuorumExecutor.exe)")
    parser.add_argument("--version", help="Optional new version string to set in the manifest")
    parser.add_argument("--upload", action="store_true", help="Upload payload.zip and manifest to GitHub via Contents API")
    parser.add_argument("--repo", default="TsAGenesis/Geckohubexecuter", help="owner/repo for upload (default: TsAGenesis/Geckohubexecuter)")
    parser.add_argument("--branch", default="main", help="Branch name (default: main)")
    parser.add_argument("--payload-remote", default="payload.zip", help="Remote path for payload.zip (default: payload.zip)")
    parser.add_argument("--manifest-remote", default="payload.manifest.json", help="Remote path for manifest (default: payload.manifest.json)")
    args = parser.parse_args()

    zip_path = Path(args.zip)
    manifest_path = Path(args.manifest)

    try:
        new_hash = load_payload_hash(zip_path, args.exe_name)
    except FileNotFoundError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    if manifest_path.exists():
        with manifest_path.open("r", encoding="utf-8") as f:
            manifest = json.load(f)
    else:
        manifest = {}

    old_hash = manifest.get("payloadSha256")
    manifest["payloadSha256"] = new_hash
    if args.version:
        manifest["version"] = args.version
    manifest.setdefault("version", "embedded")
    manifest.setdefault("payloadUrl", "")

    # Signature must be regenerated externally; clearing avoids stale sig.
    if manifest.get("signature"):
        manifest["signature"] = ""

    with manifest_path.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
        f.write("\n")

    print(f"[OK] payloadSha256 updated")
    print(f"     old: {old_hash}")
    print(f"     new: {new_hash}")
    print(f"[INFO] version: {manifest.get('version')}")
    print(f"[INFO] manifest: {manifest_path}")
    print(f"[INFO] zip: {zip_path}")

    if args.upload:
        token = os.environ.get("GECKOHUB_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if not token:
            print("[ERROR] --upload set but GECKOHUB_GITHUB_TOKEN/GITHUB_TOKEN not provided.", file=sys.stderr)
            return 1
        try:
            upload_files(
                token=token,
                repo=args.repo,
                branch=args.branch,
                payload_local=zip_path,
                manifest_local=manifest_path,
                payload_remote=args.payload_remote,
                manifest_remote=args.manifest_remote,
            )
        except Exception as exc:
            print(f"[ERROR] upload failed: {exc}", file=sys.stderr)
            return 1
        print("[OK] uploaded payload.zip and manifest to GitHub")

    return 0


def upload_files(
    *,
    token: str,
    repo: str,
    branch: str,
    payload_local: Path,
    manifest_local: Path,
    payload_remote: str,
    manifest_remote: str,
) -> None:
    session = requests.Session()
    session.headers.update(
        {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "GeckoHub-Manifest-Uploader/1.0",
        }
    )
    api_base = f"https://api.github.com/repos/{repo}/contents"

    def put_file(local_path: Path, remote_path: str, message: str) -> None:
        content = local_path.read_bytes()
        encoded = base64.b64encode(content).decode("utf-8")
        sha = get_remote_sha(session, f"{api_base}/{remote_path}", branch)
        payload = {
            "message": message,
            "content": encoded,
            "branch": branch,
        }
        if sha:
            payload["sha"] = sha
        resp = session.put(f"{api_base}/{remote_path}", json=payload, timeout=30)
        if resp.status_code not in (200, 201):
            raise RuntimeError(f"Failed to upload {remote_path}: {resp.status_code} {resp.text}")

    put_file(payload_local, payload_remote, f"Update payload {payload_remote}")
    put_file(manifest_local, manifest_remote, f"Update manifest {manifest_remote}")


def get_remote_sha(session: requests.Session, url: str, branch: str) -> str | None:
    resp = session.get(url, params={"ref": branch}, timeout=15)
    if resp.status_code == 200:
        try:
            return resp.json().get("sha")
        except Exception:
            return None
    if resp.status_code == 404:
        return None
    raise RuntimeError(f"Failed to get remote sha: {resp.status_code} {resp.text}")


if __name__ == "__main__":
    sys.exit(main())
