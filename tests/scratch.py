import tempfile
from pathlib import Path

import secureguard.reader as reader

with tempfile.TemporaryDirectory() as tmpdir:
    tmp = Path(tmpdir)

    binfile = tmp / "bin.py"
    binfile.write_bytes(b"\x00\x01\x02")
    print("binary:", reader.read_file_safely(binfile))

    utf16_file = tmp / "utf16.py"
    utf16_file.write_text("x = 1", encoding="utf-16")
    print("utf16:", reader.read_file_safely(utf16_file))

    cp_file = tmp / "cp1252.py"
    cp_file.write_bytes("café".encode("cp1252"))
    print("cp1252:", reader.read_file_safely(cp_file))

    reader.MAX_FILE_SIZE_BYTES = 10
    big_file = tmp / "big.py"
    big_file.write_text("x" * 50, encoding="utf-8")
    print("oversized:", reader.read_file_safely(big_file))
    reader.MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024