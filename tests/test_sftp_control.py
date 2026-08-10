"""Fake-SFTP tests for atomic upload/download, bounded recursion and cleanup.

These tests exercise `server._sftp_put_atomic`, `_sftp_get_atomic` and
`_bounded_walk` against an in-memory fake, so they run offline and are
deterministic.
"""
from __future__ import annotations

import pathlib

import pytest

from server import (
    ChecksumMismatchError,
    ResourceLimitError,
    _bounded_walk,
    _sftp_get_atomic,
    _sftp_put_atomic,
)


class FakeSFTPFile:
    """In-memory file handle returned by FakeSFTP.open()."""

    def __init__(self, buffer: bytes) -> None:
        self._buf = buffer
        self._pos = 0

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            data = self._buf[self._pos:]
            self._pos = len(self._buf)
            return data
        data = self._buf[self._pos:self._pos + size]
        self._pos += len(data)
        return data

    def write(self, data: bytes) -> int:
        self._buf += data
        return len(data)

    def close(self) -> None:
        pass

    def __enter__(self) -> "FakeSFTPFile":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class FakeSFTP:
    """Minimal in-memory SFTP client for atomic-transfer tests."""

    def __init__(self, initial: dict[str, bytes] | None = None) -> None:
        # name -> (is_dir, size, content)
        self.files: dict[str, tuple[bool, int, bytes]] = {}
        self.removed: list[str] = []
        self.renames: list[tuple[str, str]] = []
        if initial:
            for name, content in initial.items():
                self.files[name] = (False, len(content), content)

    def stat(self, name: str) -> object:
        if name not in self.files:
            raise FileNotFoundError(name)
        is_dir, size, _ = self.files[name]
        return SimpleNamespace(st_size=size, st_mode=0o100644 if not is_dir else 0o040755)

    def open(self, name: str, mode: str = "rb") -> FakeSFTPFile:
        if "r" in mode and name not in self.files:
            raise FileNotFoundError(name)
        if "r" in mode:
            return FakeSFTPFile(self.files[name][2])
        return FakeSFTPFile(bytearray())

    def putfo(self, fileobj: object, name: str, confirm: bool = True) -> None:
        buf = fileobj.read()
        if not isinstance(buf, bytes):
            buf = bytes(buf)
        self.files[name] = (False, len(buf), buf)

    def get(self, name: str, local: str) -> None:
        if name not in self.files:
            raise FileNotFoundError(name)
        pathlib.Path(local).write_bytes(self.files[name][2])

    def remove(self, name: str) -> None:
        if name not in self.files:
            raise FileNotFoundError(name)
        del self.files[name]
        self.removed.append(name)

    def rename(self, a: str, b: str) -> None:
        self.renames.append((a, b))
        if a not in self.files:
            raise FileNotFoundError(a)
        self.files[b] = self.files[a]
        del self.files[a]

    def posix_rename(self, a: str, b: str) -> None:
        self.rename(a, b)

    def listdir_attr(self, name: str) -> list[object]:
        if name not in self.files:
            raise FileNotFoundError(name)
        prefix = "" if name == "/" else name + "/"
        names = sorted(
            k[len(prefix):]
            for k in self.files
            if k.startswith(prefix) and "/" not in k[len(prefix):]
        )
        out: list[object] = []
        for n in names:
            is_dir, size, _ = self.files.get(prefix + n, (False, 0, b""))
            mode = 0o040755 if is_dir else 0o100644
            out.append(SimpleNamespace(filename=n, st_mode=mode, st_size=size))
        return out


from types import SimpleNamespace


@pytest.fixture
def fake_sftp() -> FakeSFTP:
    return FakeSFTP()


@pytest.fixture
def local_file(tmp_path: pathlib.Path) -> pathlib.Path:
    p = tmp_path / "src.txt"
    p.write_bytes(b"hello world" * 100)
    return p


class TestAtomicPut:
    def test_upload_writes_tmp_then_renames(self, fake_sftp: FakeSFTP, local_file: pathlib.Path) -> None:
        info = _sftp_put_atomic(fake_sftp, local_file, "/dst/file.txt", overwrite=False)

        assert info["bytes"] == local_file.stat().st_size
        assert info["atomic"] is True
        assert fake_sftp.files["/dst/file.txt"][1] == local_file.stat().st_size
        # 涓存椂鏂囦欢宸叉浛鎹负鐩爣锛屾棤娈嬬暀
        assert any(name.startswith(".file.txt.") for name in fake_sftp.files) is False
        assert fake_sftp.renames

    def test_upload_without_overwrite_rejects_existing(
        self, fake_sftp: FakeSFTP, local_file: pathlib.Path
    ) -> None:
        fake_sftp.files["/dst/file.txt"] = (False, 5, b"other")

        with pytest.raises(FileExistsError):
            _sftp_put_atomic(fake_sftp, local_file, "/dst/file.txt", overwrite=False)

    def test_upload_overwrite_allows_existing(
        self, fake_sftp: FakeSFTP, local_file: pathlib.Path
    ) -> None:
        fake_sftp.files["/dst/file.txt"] = (False, 5, b"other")

        info = _sftp_put_atomic(fake_sftp, local_file, "/dst/file.txt", overwrite=True)

        assert info["bytes"] == local_file.stat().st_size
        assert fake_sftp.files["/dst/file.txt"][1] == local_file.stat().st_size

    def test_checksum_mismatch_cleans_tmp(
        self, fake_sftp: FakeSFTP, local_file: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import server

        calls: list[bytes] = []

        def tampered_local(_path: pathlib.Path) -> str:
            return "0" * 64

        def tampered_remote(_sftp: object, _remote: str) -> str:
            return "f" * 64

        monkeypatch.setattr(server, "_sha256_local", tampered_local)
        monkeypatch.setattr(server, "_sha256_remote", tampered_remote)

        with pytest.raises(ChecksumMismatchError):
            _sftp_put_atomic(fake_sftp, local_file, "/dst/file.txt", overwrite=False)
        # 鐩爣鏈瑕嗙洊锛屼复鏃舵枃浠跺凡娓呯悊
        assert "/dst/file.txt" not in fake_sftp.files
        assert any(name.startswith(".file.txt.") for name in fake_sftp.files) is False


class TestAtomicGet:
    def test_download_writes_tmp_then_replaces(
        self, fake_sftp: FakeSFTP, tmp_path: pathlib.Path
    ) -> None:
        fake_sftp.files["/src/data.bin"] = (False, 1000, b"x" * 1000)
        target = tmp_path / "data.bin"
        target.write_bytes(b"old")

        info = _sftp_get_atomic(fake_sftp, "/src/data.bin", target)

        assert info["bytes"] == 1000
        assert target.read_bytes() == b"x" * 1000

    def test_download_byte_mismatch_keeps_existing(
        self, fake_sftp: FakeSFTP, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_sftp.files["/src/data.bin"] = (False, 1000, b"x" * 900)
        target = tmp_path / "data.bin"
        target.write_bytes(b"precious")

        with pytest.raises(ChecksumMismatchError):
            _sftp_get_atomic(fake_sftp, "/src/data.bin", target)

        # 澶辫触涓嶈鐩栧凡鏈夋枃浠讹紝涓斾复鏃舵枃浠惰娓呯悊
        assert target.read_bytes() == b"precious"
        assert list(tmp_path.iterdir()) == [target]


class TestBoundedWalk:
    def test_recursion_limits_file_count(self, fake_sftp: FakeSFTP) -> None:
        fake_sftp.files["/root"] = (True, 0, b"")
        for i in range(5):
            fake_sftp.files[f"/root/f{i}.txt"] = (False, 10, b"a" * 10)

        with pytest.raises(ResourceLimitError):
            _bounded_walk("/root", sftp=fake_sftp, max_files=3)

    def test_recursion_limits_total_bytes(self, fake_sftp: FakeSFTP) -> None:
        fake_sftp.files["/root"] = (True, 0, b"")
        fake_sftp.files["/root/a.txt"] = (False, 100, b"a" * 100)
        fake_sftp.files["/root/b.txt"] = (False, 200, b"b" * 200)

        with pytest.raises(ResourceLimitError):
            _bounded_walk("/root", sftp=fake_sftp, max_files=10, max_bytes=250)

    def test_recursion_limits_depth(self, fake_sftp: FakeSFTP) -> None:
        fake_sftp.files["/root"] = (True, 0, b"")
        fake_sftp.files["/root/d1"] = (True, 0, b"")
        fake_sftp.files["/root/d1/d2"] = (True, 0, b"")
        fake_sftp.files["/root/d1/d2/file.txt"] = (False, 10, b"a" * 10)

        with pytest.raises(ResourceLimitError):
            _bounded_walk("/root", sftp=fake_sftp, max_depth=1)

    def test_returns_flat_entries(self, fake_sftp: FakeSFTP) -> None:
        fake_sftp.files["/root"] = (True, 0, b"")
        fake_sftp.files["/root/a.txt"] = (False, 10, b"a" * 10)
        fake_sftp.files["/root/sub"] = (True, 0, b"")
        fake_sftp.files["/root/sub/b.txt"] = (False, 20, b"b" * 20)

        entries = _bounded_walk("/root", sftp=fake_sftp, max_files=100, max_bytes=100000, max_depth=10)

        paths = {e["path"] for e in entries}
        assert paths == {"/root/a.txt", "/root/sub", "/root/sub/b.txt"}

    def test_sftp_walk_rejects_symlink_escape(
        self, fake_sftp: FakeSFTP, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from types import SimpleNamespace

        fake_sftp.files["/root"] = (True, 0, b"")
        fake_sftp.files["/root/real.txt"] = (False, 10, b"a" * 10)

        def listdir_with_symlink(name: str) -> list[object]:
            if name == "/root":
                return [
                    SimpleNamespace(filename="real.txt", st_mode=0o100644, st_size=10),
                    SimpleNamespace(filename="escape", st_mode=0o120777, st_size=20),
                ]
            return fake_sftp.listdir_attr(name)

        monkeypatch.setattr(fake_sftp, "listdir_attr", listdir_with_symlink)

        with pytest.raises(ResourceLimitError):
            _bounded_walk("/root", sftp=fake_sftp)

    def test_sftp_walk_limits_file_count_for_dirs(
        self, fake_sftp: FakeSFTP
    ) -> None:
        fake_sftp.files["/root"] = (True, 0, b"")
        fake_sftp.files["/root/a"] = (True, 0, b"")
        fake_sftp.files["/root/b"] = (True, 0, b"")
        fake_sftp.files["/root/a/f1"] = (False, 1, b"x")
        fake_sftp.files["/root/b/f2"] = (False, 1, b"y")

        with pytest.raises(ResourceLimitError):
            _bounded_walk("/root", sftp=fake_sftp, max_files=3)


class TestLocalBoundedWalk:
    def test_local_walk_rejects_symlink(self, tmp_path: pathlib.Path) -> None:
        (tmp_path / "real.txt").write_text("hi", encoding="utf-8")
        (tmp_path / "link.txt").symlink_to(tmp_path / "real.txt")

        with pytest.raises(ResourceLimitError):
            _bounded_walk(tmp_path)

    def test_local_walk_limits_bytes(self, tmp_path: pathlib.Path) -> None:
        (tmp_path / "a.txt").write_bytes(b"a" * 100)
        (tmp_path / "b.txt").write_bytes(b"b" * 200)

        with pytest.raises(ResourceLimitError):
            _bounded_walk(tmp_path, max_files=10, max_bytes=250)

    def test_local_walk_limits_file_count(self, tmp_path: pathlib.Path) -> None:
        for i in range(5):
            (tmp_path / f"f{i}.txt").write_bytes(b"x")

        with pytest.raises(ResourceLimitError):
            _bounded_walk(tmp_path, max_files=3)

    def test_local_walk_limits_depth(self, tmp_path: pathlib.Path) -> None:
        d = tmp_path / "d1" / "d2"
        d.mkdir(parents=True)
        (d / "file.txt").write_bytes(b"x")

        with pytest.raises(ResourceLimitError):
            _bounded_walk(tmp_path, max_depth=1)

    def test_local_walk_returns_flat_entries(self, tmp_path: pathlib.Path) -> None:
        (tmp_path / "a.txt").write_bytes(b"a" * 10)
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "b.txt").write_bytes(b"b" * 20)

        entries = _bounded_walk(tmp_path, max_files=100, max_bytes=100000, max_depth=10)

        paths = {e["path"].relative_to(tmp_path).as_posix() for e in entries}
        assert paths == {"a.txt", "sub", "sub/b.txt"}
