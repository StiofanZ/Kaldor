"""Build a static Linux Kaldor executable with Cargo and Zig 0.14.1."""
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys


def main():
    arch = sys.argv[1]
    triples = {
        "armv7": ("armv7-unknown-linux-musleabihf", "arm-linux-musleabihf", "arm"),
        "aarch64": ("aarch64-unknown-linux-musl", "aarch64-linux-musl", "aarch64"),
    }
    target, zig_target, headers = triples[arch]
    cargo_dir = Path(os.getenv("CARGO_TARGET_DIR", "target")).resolve()
    tools = cargo_dir / "cross" / arch
    tools.mkdir(parents=True, exist_ok=True)
    zig = shutil.which(os.getenv("ZIG", "zig"))
    if not zig:
        sys.exit("Zig 0.14.1 required. Set ZIG to the compiler executable.")
    lib = Path(json.loads(subprocess.check_output([zig, "env"]))["lib_dir"])
    if not lib.is_absolute():
        lib = lib.resolve()
    root = Path.cwd().resolve()
    sysroot = Path(subprocess.check_output(["rustc","--print","sysroot"], text=True).strip()).resolve()
    # Rust panic locations and BoringSSL diagnostics travel in the released ELF.
    mappings = [(sysroot, "/rust-toolchain"), (Path(zig).resolve().parent, "/zig-toolchain"),
                (cargo_dir, "/cargo-target"), (root, "/kaldor")]
    flags = ["-target", zig_target]
    c_maps = ["-ffile-prefix-map=" + str(src) + "=" + dst for src, dst in mappings]
    rust_flags = ["-C", "link-self-contained=no"]
    rust_flags.extend("--remap-path-prefix=" + str(src) + "=" + dst for src, dst in mappings)
    if arch == "armv7":
        flags += ["-mcpu=cortex_a9"]
    for name, operation in [("cc", "cc"), ("cxx", "c++"), ("ar", "ar"), ("ranlib", "ranlib")]:
        wrapper = tools / name
        args = [zig, operation] + (flags + c_maps if operation in ("cc", "c++") else [])
        # CMake probes Clang and may append a quadruple Zig cannot parse.
        wrapper.write_text(
            "#!/usr/bin/env python3\nimport os, sys\n"
            f"args = {args!r}\n"
            "os.execv(args[0], args + [v for v in sys.argv[1:] if not v.startswith('--target=')])\n"
        )
        wrapper.chmod(0o755)
    cmake = tools / "toolchain.cmake"
    cmake.write_text(
        f'set(CMAKE_SYSTEM_NAME Linux)\nset(CMAKE_SYSTEM_PROCESSOR {arch})\n'
        + "".join(f'set(CMAKE_{key} "{tools / name}")\n' for key, name in
                  [("C_COMPILER", "cc"), ("CXX_COMPILER", "cxx"), ("ASM_COMPILER", "cc"),
                   ("AR", "ar"), ("RANLIB", "ranlib")])
        + "set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)\n"
    )
    includes = [f"{headers}-linux-musl", "generic-musl", f"{headers}-linux-any", "any-linux-any"]
    key = target.replace("-", "_")
    env = dict(os.environ)
    env.update({
        "CARGO_TARGET_DIR": str(cargo_dir),
        "CC_" + key: str(tools / "cc"),
        "CXX_" + key: str(tools / "cxx"),
        "AR_" + key: str(tools / "ar"),
        "CMAKE_TOOLCHAIN_FILE_" + key: str(cmake),
        "BINDGEN_EXTRA_CLANG_ARGS_" + key: shlex.join(["-I" + str(lib / "libc/include" / p) for p in includes]),
        "CARGO_TARGET_" + key.upper() + "_LINKER": str(tools / "cxx"),
        "CARGO_ENCODED_RUSTFLAGS": chr(31).join(rust_flags),
        "BORING_BSSL_RUST_CPPLIB": "c++",
    })
    subprocess.run(["cargo", *sys.argv[2:], "--target", target], check=True, env=env)


if __name__ == "__main__":
    main()
