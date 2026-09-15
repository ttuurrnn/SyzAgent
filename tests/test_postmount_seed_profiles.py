from scripts.make_postmount_seeds import build_seed, resolve_runs


def test_resolve_runs_uses_configurable_pattern(tmp_path):
    selected = tmp_path / "ext4_smoke_custom"
    selected.mkdir()
    (tmp_path / "ext4_postmount_smoke_custom").mkdir()
    (tmp_path / "unrelated").mkdir()

    assert resolve_runs(tmp_path, [], "*_smoke_*") == [selected]


def test_build_seed_keeps_selected_mount_and_appends_profile():
    program = (
        "r0 = syz_mount_image$ext4(&(0x7f0000000000), 0x0)\n"
        "r1 = syz_mount_image$ntfs(&(0x7f0000001000), 0x0)\n"
    )

    seed = build_seed(program, "syz_mount_image$ext4", "ro")

    assert seed is not None
    assert "syz_mount_image$ext4" in seed
    assert "syz_mount_image$ntfs" not in seed
    assert "getdents64(r0" in seed
