import json

from scripts.launch_postmount_probe import (
    collect_seed_syscalls,
    disable_bare_syscall_variants,
    write_callfile,
)


def test_write_callfile_builds_target_specific_entries(tmp_path):
    source = tmp_path / "source.json"
    source.write_text("[]\n", encoding="utf-8")
    output = tmp_path / "output.json"

    write_callfile(
        source,
        output,
        None,
        [],
        [],
        ["openat:read,close", "socket:sendmsg"],
    )

    assert json.loads(output.read_text(encoding="utf-8")) == [
        {"Target": "openat", "Relate": ["read", "close"]},
        {"Target": "socket", "Relate": ["sendmsg"]},
    ]


def test_seed_syscalls_filter_unselected_mount_variants(tmp_path):
    seed = tmp_path / "seed.syz"
    seed.write_text(
        "r0 = syz_mount_image$ext4(&(0x7f0000000000), 0x0)\n"
        "r1 = syz_mount_image$ntfs(&(0x7f0000001000), 0x0)\n"
        "read(r0, &(0x7f0000002000), 0x10)\n",
        encoding="utf-8",
    )

    calls = collect_seed_syscalls([seed], {"syz_mount_image$ext4"})

    assert calls == {"syz_mount_image$ext4", "read"}


def test_bare_syscall_variants_are_disabled_unless_allowed():
    disabled = disable_bare_syscall_variants(
        {"sendmsg", "read", "syz_mount_image$ext4"},
        {"sendmsg", "read"},
        {"read"},
    )

    assert disabled == ["sendmsg$*"]
