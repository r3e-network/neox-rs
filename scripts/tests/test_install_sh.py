"""Hermetic tests for the neox-rs curl installer (scripts/install.sh)."""

from __future__ import annotations

import hashlib
import os
import pathlib
import platform
import shutil
import subprocess
import tarfile
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "install.sh"


def bash_script_path() -> str:
    """Return `SCRIPT` in the form the spawned `bash` accepts.

    `bash` is a native process, so on Windows a backslash-separated path has its separators
    eaten by the MSYS runtime before bash sees it, and an absolute `D:/...` argument is not
    executable either. A path relative to the current directory has neither problem; fall back
    to the forward-slash absolute form when the caller runs from another drive.
    """
    try:
        return pathlib.Path(os.path.relpath(SCRIPT)).as_posix()
    except ValueError:  # cwd on another drive
        return SCRIPT.as_posix()


def resolved_bash() -> str:
    """Return the `bash` executable the tests spawn.

    On Windows, CreateProcess resolves a bare `bash` from System32 *before* the PATH, which
    finds the WSL launcher: WSL bash cannot use the Windows-style fixture paths or PATH this
    harness passes. `shutil.which` scans only the PATH, so it selects the MSYS/Git Bash that
    `bash_script_path` documents. On POSIX the lookup changes nothing.
    """
    return shutil.which("bash") or "bash"


BASH = resolved_bash()


REPO_API = "https://api.github.com/repos/r3e-network/neox-rs"
TEST_TAG = "neox-v9.9.9"
TEST_VERSION = "9.9.9"

FAKE_CURL = """#!/usr/bin/env bash
set -eu
out=""
url=""
want_status=0
skip_next=0
for arg in "$@"; do
    if [ "$skip_next" = "out" ]; then out="$arg"; skip_next=0; continue; fi
    if [ "$skip_next" = "drop" ]; then skip_next=0; continue; fi
    case "$arg" in
        -o) skip_next=out ;;
        -w) want_status=1; skip_next=drop ;;
        -H | --proto | --retry) skip_next=drop ;;
        http*) url="$arg" ;;
        *) : ;;
    esac
done
[ -n "$url" ] || exit 2
line="$(awk -F'\\t' -v u="$url" '$1 == u { print; exit }' "$FAKE_CURL_DIR/urls.tsv")"
if [ -z "$line" ]; then
    if [ "$want_status" = 1 ]; then printf '\\n404'; exit 0; fi
    exit 22
fi
path="$(printf '%s' "$line" | cut -f2)"
status="$(printf '%s' "$line" | cut -f3)"
[ -n "$status" ] || status=200
if [ -n "$out" ]; then
    [ "$status" -lt 400 ] || exit 22
    cp "$path" "$out"
else
    cat "$path"
    if [ "$want_status" = 1 ]; then printf '\\n%s' "$status"; fi
fi
"""

FAKE_BINARY = f"""#!/bin/sh
echo "neox-rs test {TEST_VERSION}"
"""


def host_target() -> str | None:
    """Mirrors install.sh platform detection for the machine running the tests."""
    system = platform.system()
    machine = platform.machine()
    if system == "Linux":
        return {
            "x86_64": "x86_64-unknown-linux-gnu",
            "aarch64": "aarch64-unknown-linux-gnu",
        }.get(machine)
    if system == "Darwin" and machine == "arm64":
        return "aarch64-apple-darwin"
    return None


def bundle_binaries(target: str) -> tuple[str, ...]:
    """Returns the binaries published for a release target."""
    binaries = ("neox-rs", "neox-dkg-migrate")
    if target.endswith("-linux-gnu"):
        return (*binaries, "neox-dkg-prover")
    return binaries


class InstallerHarness:
    """Builds a release-bundle fixture and a fake curl serving it offline."""

    def __init__(self, root: pathlib.Path, target: str, binary_body: str = FAKE_BINARY) -> None:
        self.root = root
        self.target = target
        self.binary_body = binary_body
        self.home = root / "home"
        self.install_dir = root / "opt" / "bin"
        self.fixtures = root / "fixtures"
        self.fakebin = root / "fakebin"
        for path in (self.home, self.fixtures, self.fakebin):
            path.mkdir(parents=True)
        curl = self.fakebin / "curl"
        curl.write_text(FAKE_CURL, newline="\n")
        curl.chmod(0o755)
        self.bundle_name = f"neox-rs-{TEST_VERSION}-{target}"
        self.tarball = self.fixtures / f"{self.bundle_name}.tar.gz"
        self._build_bundle()
        self._write_api_fixtures()

    def _build_bundle(self) -> None:
        bundle_dir = self.fixtures / self.bundle_name
        bundle_dir.mkdir()
        for binary in bundle_binaries(self.target):
            path = bundle_dir / binary
            path.write_text(self.binary_body, newline="\n")
            path.chmod(0o755)
        with tarfile.open(self.tarball, "w:gz") as archive:
            archive.add(bundle_dir, arcname=self.bundle_name)
        digest = hashlib.sha256(self.tarball.read_bytes()).hexdigest()
        self.sha_file = self.fixtures / f"{self.bundle_name}.tar.gz.sha256"
        self.sha_file.write_text(f"{digest}  {self.bundle_name}.tar.gz\n", newline="\n")

    def _write_api_fixtures(self) -> None:
        tarball_url = f"https://fake.invalid/dl/{self.bundle_name}.tar.gz"
        sha_url = f"{tarball_url}.sha256"
        latest = self.fixtures / "latest.json"
        latest.write_text(f'{{"tag_name": "{TEST_TAG}", "prerelease": false}}\n', newline="\n")
        releases = self.fixtures / "releases.json"
        releases.write_text(f'[{{"tag_name": "{TEST_TAG}", "draft": false}}]\n', newline="\n")
        tag = self.fixtures / "tag.json"
        tag.write_text(
            f'{{"tag_name": "{TEST_TAG}", "assets": ['
            f'{{"browser_download_url": "{tarball_url}"}},'
            f'{{"browser_download_url": "{sha_url}"}}]}}\n',
            newline="\n",
        )
        self.url_map = {
            f"{REPO_API}/releases/latest": latest,
            f"{REPO_API}/releases?per_page=30": releases,
            f"{REPO_API}/releases/tags/{TEST_TAG}": tag,
            tarball_url: self.tarball,
            sha_url: self.sha_file,
        }
        self.url_status: dict[str, int] = {}
        self.flush_url_map()

    def flush_url_map(self) -> None:
        lines = []
        for url, path in self.url_map.items():
            status = self.url_status.get(url)
            suffix = f"\t{status}" if status is not None else ""
            lines.append(f"{url}\t{path}{suffix}")
        (self.fixtures / "urls.tsv").write_text("\n".join(lines) + "\n", newline="\n")

    def env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["PATH"] = f"{self.fakebin}{os.pathsep}{env['PATH']}"
        env["HOME"] = str(self.home)
        env["SHELL"] = "/bin/zsh"
        env["NEOX_INSTALL_DIR"] = str(self.install_dir)
        env["FAKE_CURL_DIR"] = str(self.fixtures)
        env.pop("ZDOTDIR", None)
        env.pop("NEOX_VERSION", None)
        env.pop("NEOX_NO_MODIFY_PATH", None)
        env.pop("NEOX_REPO", None)
        return env

    def run(self, *args: str, **env_overrides: str) -> subprocess.CompletedProcess[str]:
        env = self.env()
        env.update(env_overrides)
        return subprocess.run(
            [BASH, bash_script_path(), *args],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )


class InstallScriptStaticTest(unittest.TestCase):
    def test_syntax_is_valid(self) -> None:
        result = subprocess.run(
            [BASH, "-n", bash_script_path()], capture_output=True, text=True, timeout=30
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_help_prints_usage(self) -> None:
        result = subprocess.run(
            [BASH, bash_script_path(), "--help"], capture_output=True, text=True, timeout=30
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("neox-rs installer", result.stdout)
        self.assertIn("--install-dir", result.stdout)

    def test_unknown_option_is_rejected(self) -> None:
        result = subprocess.run(
            [BASH, bash_script_path(), "--bogus"], capture_output=True, text=True, timeout=30
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown option", result.stderr)

    def test_unsupported_platform_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fakebin = pathlib.Path(tmp) / "bin"
            fakebin.mkdir()
            uname = fakebin / "uname"
            uname.write_text(
                '#!/usr/bin/env bash\ncase "${1:-}" in -m) echo amd64 ;; *) echo FreeBSD ;; esac\n',
                newline="\n",
            )
            uname.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = f"{fakebin}{os.pathsep}{env['PATH']}"
            result = subprocess.run(
                [BASH, bash_script_path()],
                capture_output=True,
                text=True,
                env=env,
                timeout=30,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsupported operating system", result.stderr)

    def test_macos_bundle_does_not_require_linux_only_prover(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            harness = InstallerHarness(
                pathlib.Path(tmp), "aarch64-apple-darwin"
            )
            uname = harness.fakebin / "uname"
            uname.write_text(
                '#!/usr/bin/env bash\ncase "${1:-}" in\n'
                "  -s) echo Darwin ;;\n"
                "  -m) echo arm64 ;;\n"
                "  *) echo Darwin ;;\n"
                "esac\n",
                newline="\n",
            )
            uname.chmod(0o755)

            result = harness.run()

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((harness.install_dir / "neox-rs").is_file())
            self.assertTrue((harness.install_dir / "neox-dkg-migrate").is_file())
            self.assertFalse((harness.install_dir / "neox-dkg-prover").exists())
            self.assertIn(
                "installed neox-rs neox-dkg-migrate into", result.stdout
            )


@unittest.skipUnless(host_target(), "host platform is not covered by release binaries")
class InstallScriptEndToEndTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        target = host_target()
        assert target is not None
        self.harness = InstallerHarness(pathlib.Path(self.tmp.name), target)

    def test_installs_latest_release_and_updates_path(self) -> None:
        result = self.harness.run()
        self.assertEqual(result.returncode, 0, result.stderr)
        for binary in bundle_binaries(self.harness.target):
            installed = self.harness.install_dir / binary
            self.assertTrue(installed.is_file(), f"{binary} missing")
            self.assertTrue(os.access(installed, os.X_OK), f"{binary} not executable")
        if not self.harness.target.endswith("-linux-gnu"):
            self.assertFalse((self.harness.install_dir / "neox-dkg-prover").exists())
        self.assertIn("checksum verified", result.stdout)
        self.assertIn(f"installed version: neox-rs test {TEST_VERSION}", result.stdout)
        zshenv = self.harness.home / ".zshenv"
        self.assertTrue(zshenv.is_file())
        self.assertIn(str(self.harness.install_dir), zshenv.read_text())

    def test_no_modify_path_flag_skips_profile_update(self) -> None:
        result = self.harness.run("--no-modify-path")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.harness.home / ".zshenv").exists())
        self.assertIn("add the install directory to PATH", result.stdout)

    def test_explicit_version_skips_release_listing(self) -> None:
        del self.harness.url_map[f"{REPO_API}/releases?per_page=30"]
        del self.harness.url_map[f"{REPO_API}/releases/latest"]
        self.harness.flush_url_map()
        result = self.harness.run("--version", TEST_TAG)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.harness.install_dir / "neox-rs").is_file())

    def test_stable_release_is_preferred_without_prerelease_warning(self) -> None:
        result = self.harness.run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("installing prerelease", result.stderr)

    def test_falls_back_to_prerelease_when_no_stable_exists(self) -> None:
        del self.harness.url_map[f"{REPO_API}/releases/latest"]
        self.harness.flush_url_map()
        result = self.harness.run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"installing prerelease {TEST_TAG}", result.stderr)
        self.assertTrue((self.harness.install_dir / "neox-rs").is_file())

    def test_rate_limit_is_reported_clearly(self) -> None:
        limited = self.harness.fixtures / "limited.json"
        limited.write_text('{"message": "API rate limit exceeded for 1.2.3.4."}\n')
        url = f"{REPO_API}/releases/latest"
        self.harness.url_map[url] = limited
        self.harness.url_status[url] = 403
        self.harness.flush_url_map()
        result = self.harness.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rate limit exceeded", result.stderr)

    def test_unpublished_tag_reports_draft_guidance(self) -> None:
        result = self.harness.run("--version", "neox-v0.0.1-rc.9")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not published", result.stderr)

    def test_rerun_does_not_duplicate_the_path_entry(self) -> None:
        first = self.harness.run()
        self.assertEqual(first.returncode, 0, first.stderr)
        second = self.harness.run()
        self.assertEqual(second.returncode, 0, second.stderr)
        profile = (self.harness.home / ".zshenv").read_text()
        self.assertEqual(profile.count(str(self.harness.install_dir)), 1)

    def test_install_dir_with_spaces_produces_a_valid_profile_line(self) -> None:
        spaced = pathlib.Path(self.tmp.name) / "spa ced" / "bin"
        result = self.harness.run(NEOX_INSTALL_DIR=str(spaced))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((spaced / "neox-rs").is_file())
        profile = self.harness.home / ".zshenv"
        check = subprocess.run(
            [BASH, "-c", f'source "{profile}" && printf "%s" "$PATH"'],
            capture_output=True,
            text=True,
            env={"PATH": "/usr/bin:/bin"},
            timeout=30,
        )
        self.assertEqual(check.returncode, 0, check.stderr)
        self.assertTrue(check.stdout.startswith(f"{spaced}:"), check.stdout)

    def test_broken_installed_binary_fails_the_install(self) -> None:
        broken = InstallerHarness(
            pathlib.Path(self.tmp.name) / "broken",
            host_target() or "",
            binary_body='#!/bin/sh\nexit 7\n',
        )
        result = broken.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("failed to run", result.stderr)

    def test_checksum_mismatch_aborts_install(self) -> None:
        tampered = self.harness.fixtures / "tampered.tar.gz"
        shutil.copy(self.harness.tarball, tampered)
        with tampered.open("ab") as handle:
            handle.write(b"corruption")
        tarball_url = f"https://fake.invalid/dl/{self.harness.bundle_name}.tar.gz"
        self.harness.url_map[tarball_url] = tampered
        self.harness.flush_url_map()
        result = self.harness.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum verification failed", result.stderr)
        self.assertFalse((self.harness.install_dir / "neox-rs").exists())

    def test_missing_published_release_reports_clearly(self) -> None:
        empty = self.harness.fixtures / "empty.json"
        empty.write_text("[]\n")
        del self.harness.url_map[f"{REPO_API}/releases/latest"]
        self.harness.url_map[f"{REPO_API}/releases?per_page=30"] = empty
        self.harness.flush_url_map()
        result = self.harness.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no published neox-rs release found", result.stderr)


if __name__ == "__main__":
    unittest.main()
