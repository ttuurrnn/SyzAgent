import concurrent.futures
import copy
import datetime
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import pandas as pd

import Config


# syz-manager stats line pattern:
# 2026/03/17 14:41:12 VMs 1, executed 2, cover 248, signal 285/0, crashes 0, repro 0, dist 42/100
_STATS_RE = re.compile(
    r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*"
    r"executed (\d+).*cover (\d+).*signal (\d+).*crashes (\d+)"
    r"(?:.*dist (\d+)/(\d+))?"
)


def _parse_stats_line(line):
    """Parse a syz-manager stats line into a metrics dict, or None."""
    m = _STATS_RE.search(line)
    if not m:
        return None
    try:
        ts = int(datetime.datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S").timestamp())
    except ValueError:
        ts = int(time.time())
    result = {
        "timestamp": ts,
        "exec_total": int(m.group(2)),
        "corpus_cover": int(m.group(3)),
        "signal": int(m.group(4)),
        "crashes": int(m.group(5)),
    }
    if m.group(6) is not None:
        result["dist_min"] = int(m.group(6))
        result["dist_max"] = int(m.group(7))
    return result


def _ensure_syzkaller_ready(syzdirect_path):
    """Use an existing syzkaller build if present; only build when a Makefile exists."""
    manager = os.path.join(syzdirect_path, "bin", "syz-manager")
    if os.path.exists(manager):
        return manager

    makefile_names = ("Makefile", "makefile", "GNUmakefile")
    if any(os.path.exists(os.path.join(syzdirect_path, name)) for name in makefile_names):
        rc = os.system(f"cd {syzdirect_path}; make")
        assert rc == 0, f"failed to build syzdirect_fuzzer in {syzdirect_path}"

    assert os.path.exists(manager), (
        f"syz-manager not found: {manager}. "
        f"Provide a built syzdirect_fuzzer/bin tree or a Makefile-backed source tree."
    )
    return manager


def _alloc_free_tcp_port():
    """Pick an ephemeral TCP port for syz-manager's HTTP endpoint."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return sock.getsockname()[1]


def MultirunFuzzer():
    run_items = []
    clean_image_path = Config.CleanImageTemplatePath
    syzdirect_path = Config.FuzzerDir
    manager_path = _ensure_syzkaller_ready(syzdirect_path)

    for datapoint in Config.datapoints:
        case_idx = datapoint['idx']
        template_config = Config.LoadJson(Config.TemplateConfigPath)
        assert template_config, "Fail to load fuzzing config template"
        template_config["sshkey"] = Config.KeyPath

        tfmap = Config.ParseTargetFunctionsInfoFile(case_idx)
        print(tfmap)

        Config.PrepareDir(Config.getFuzzInpDirPathByCase(case_idx))

        for xidx in tfmap.keys():
            callfile = Config.getFuzzInpDirPathByCaseAndXidx(case_idx, xidx)
            kernel_image = Config.getInstrumentedKernelImageByCaseAndXidx(case_idx, xidx)
            assert os.path.exists(callfile), \
                f"[case {case_idx} xidx {xidx}] fuzz input file not exists"
            assert os.path.exists(kernel_image), \
                f"[case {case_idx} xidx {xidx}] bzimage file not exists"

            work_root_dir = Config.getFuzzResultDirByCaseAndXidx(case_idx, xidx)
            customized_syzkaller = Config.getCustomizedSyzByCaseAndXidx(case_idx, xidx)
            syzkaller_path = customized_syzkaller if os.path.exists(customized_syzkaller) else syzdirect_path
            os.makedirs(work_root_dir, exist_ok=True)

            rounds = Config.FuzzRounds
            Config.logging.info(f"[case {case_idx} xidx {xidx}] Preparing fuzzing for {rounds}")
            for i in range(rounds):
                config_path = os.path.join(work_root_dir, f"config{i}")
                sub_workdir = os.path.join(work_root_dir, f"run{i}")
                config = copy.deepcopy(template_config)
                shutil.rmtree(sub_workdir, ignore_errors=True)

                config["image"] = clean_image_path
                config["workdir"] = sub_workdir
                config["http"] = f"0.0.0.0:{_alloc_free_tcp_port()}"
                config["vm"]["kernel"] = kernel_image
                config["syzkaller"] = syzkaller_path
                config["hitindex"] = int(xidx)
                # kernel_obj: directory containing vmlinux (needed for coverage
                # symbolization during machine check).
                kernel_obj_dir = os.path.dirname(kernel_image)
                if os.path.isdir(kernel_obj_dir):
                    config["kernel_obj"] = kernel_obj_dir
                    # syz-manager expects 'vmlinux' in kernel_obj; ensure symlink exists
                    vm_link = os.path.join(kernel_obj_dir, "vmlinux")
                    vm_0    = os.path.join(kernel_obj_dir, "vmlinux_0")
                    if not os.path.exists(vm_link) and os.path.exists(vm_0):
                        os.symlink(vm_0, vm_link)

                bug_title = datapoint['repro bug title']
                if not pd.isna(bug_title):
                    config["bugdesc"] = bug_title

                with open(config_path, "w") as fp:
                    json.dump(config, fp, indent="\t")

                fuzzer_file = manager_path if syzkaller_path == syzdirect_path else os.path.join(
                    syzkaller_path, "bin", "syz-manager")
                log_dir = os.path.join(work_root_dir, f"logs{i}")
                run_items.append((fuzzer_file, config_path, callfile, log_dir))

    with ThreadPoolExecutor(max_workers=75) as executor:
        futures = []
        for run_arg in run_items:
            fuzzer_file, config_path, callfile, log_dir = run_arg
            futures.append(executor.submit(
                runFuzzer, fuzzer_file, config_path, callfile,
                log_dir=log_dir,
                dist_stall_timeout=600,
            ))
            time.sleep(5)
        for future in concurrent.futures.as_completed(futures):
            future.result()


def runFuzzer(fuzzerFile, configPath, callFile, log_dir=None, stall_timeout=0,
              dist_stall_timeout=600, seed_corpus=None):
    """Run syz-manager. If log_dir is given, capture output to manager.log + metrics.jsonl.

    stall_timeout: seconds of zero coverage growth before early termination (0=disabled).
    dist_stall_timeout: seconds of no distance improvement before early termination
                        (default 600s=10min). Set 0 to disable.
    seed_corpus: path to a corpus.db file to pre-populate the workdir before fuzzing.
    Only active when log_dir is set (agent-loop mode).
    """
    command = f"{fuzzerFile} -config={configPath} -callfile={callFile} -uptime={Config.FuzzUptime}"
    Config.logging.info(f"Start running {command}")

    if log_dir is None:
        rc = os.system(command)
        Config.logging.info(f"Finish running {command} (exit={rc})")
        if rc != 0:
            raise RuntimeError(f"syz-manager exited with status {rc}: {command}")
        return None, None

    # Pre-populate workdir with seed corpus if provided
    if seed_corpus and os.path.exists(seed_corpus):
        try:
            with open(configPath) as f:
                cfg = json.load(f)
            workdir = cfg.get("workdir", "")
            if workdir:
                os.makedirs(workdir, exist_ok=True)
                dest = os.path.join(workdir, "corpus.db")
                shutil.copy2(seed_corpus, dest)
                Config.logging.info(f"Seeded corpus: {seed_corpus} -> {dest}")
        except Exception as e:
            Config.logging.warning(f"Failed to seed corpus: {e}")

    os.makedirs(log_dir, exist_ok=True)
    manager_log = os.path.join(log_dir, "manager.log")
    metrics_jsonl = os.path.join(log_dir, "metrics.jsonl")

    with open(manager_log, "w") as log_f, open(metrics_jsonl, "w") as met_f:
        proc = subprocess.Popen(
            shlex.split(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        saw_metric = False
        qemu_eof_count = 0
        early_boot_failure = False
        stall_terminated = False
        target_reached = False
        last_cover_growth_ts = time.time()
        fuzz_start_ts = time.time()
        peak_cover = 0
        best_dist_min = None
        last_dist_improvement_ts = time.time()
        for line in proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            log_f.write(line)
            log_f.flush()
            metric = _parse_stats_line(line)
            if metric:
                saw_metric = True
                met_f.write(json.dumps(metric) + "\n")
                met_f.flush()
                # stall detection: track coverage growth
                if metric["corpus_cover"] > peak_cover:
                    peak_cover = metric["corpus_cover"]
                    last_cover_growth_ts = time.time()
                elif stall_timeout > 0 and peak_cover > 0:
                    stall_seconds = time.time() - last_cover_growth_ts
                    if stall_seconds >= stall_timeout:
                        stall_terminated = True
                        msg = (f"STALL_TIMEOUT: coverage stuck at {peak_cover} "
                               f"for {int(stall_seconds)}s (limit={stall_timeout}s), "
                               f"terminating early\n")
                        log_f.write(msg)
                        log_f.flush()
                        Config.logging.info(msg.strip())
                        proc.terminate()
                        break
                # distance tracking: stop immediately when target reached (dist=0)
                cur_dist = metric.get("dist_min")
                if cur_dist is not None:
                    # Skip initial dist=0 before real fuzzing starts (best_dist_min not yet set)
                    if cur_dist == 0 and best_dist_min is None:
                        pass  # ignore default 0 emitted before any exec
                    elif cur_dist == 0 and best_dist_min is not None:
                        # Target reached — record time and terminate immediately
                        elapsed = time.time() - fuzz_start_ts
                        msg = (f"TARGET_REACHED: dist_min=0 after {elapsed:.1f}s "
                               f"({elapsed/60:.1f}min)\n")
                        log_f.write(msg)
                        log_f.flush()
                        Config.logging.info(msg.strip())
                        target_reached = True
                        proc.terminate()
                        break
                    elif best_dist_min is None or cur_dist < best_dist_min:
                        best_dist_min = cur_dist
                        last_dist_improvement_ts = time.time()
                    elif dist_stall_timeout > 0 and best_dist_min is not None and best_dist_min > 0:
                        dist_stall_secs = time.time() - last_dist_improvement_ts
                        if dist_stall_secs >= dist_stall_timeout:
                            stall_terminated = True
                            msg = (f"DIST_STALL_TIMEOUT: dist_min stuck at "
                                   f"{best_dist_min} for {int(dist_stall_secs)}s "
                                   f"(limit={dist_stall_timeout}s), "
                                   f"terminating early\n")
                            log_f.write(msg)
                            log_f.flush()
                            Config.logging.info(msg.strip())
                            proc.terminate()
                            break
            if "failed to create instance: failed to read from qemu: EOF" in line:
                qemu_eof_count += 1
                if not saw_metric and qemu_eof_count >= 6:
                    early_boot_failure = True
                    log_f.write("EARLY_BOOT_FAILURE: repeated qemu EOF before metrics\n")
                    log_f.flush()
                    proc.terminate()
                    break
        proc.wait()

    Config.logging.info(f"Finish running {command} (exit={proc.returncode})")
    if proc.returncode != 0 and not early_boot_failure and not stall_terminated and not target_reached:
        raise RuntimeError(f"syz-manager exited with status {proc.returncode}: {command}")
    return manager_log, metrics_jsonl
