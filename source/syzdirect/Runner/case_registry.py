"""Case registry for prebuilt SyzDirect fuzzing targets."""


# Syscall names MUST match syzkaller sys/linux/gen/amd64.go.
PREBUILT_TARGETS = [
    {"idx": 0, "name": "teql_uaf", "function": "teql_destroy",
     "func_path": "net/sched/sch_teql.c",
     "syscalls": [{"Target": "sendmsg$nl_route_sched",
                   "Relate": ["socket$nl_route", "sendmsg$nl_route", "bind", "close"]}]},
    {"idx": 1, "name": "qdisc_create", "function": "qdisc_create",
     "func_path": "net/sched/sch_api.c",
     "syscalls": [{"Target": "sendmsg$nl_route_sched",
                   "Relate": ["socket$nl_route", "sendmsg$nl_route", "bind", "close"]}]},
    {"idx": 2, "name": "fifo_set_limit", "function": "fifo_set_limit",
     "func_path": "net/sched/sch_fifo.c",
     "syscalls": [{"Target": "sendmsg$nl_route_sched",
                   "Relate": ["socket$nl_route", "sendmsg$nl_route", "bind", "close"]}]},
    {"idx": 3, "name": "tcp_cleanup_congestion_control",
     "function": "tcp_cleanup_congestion_control",
     "func_path": "net/ipv4/tcp_cong.c",
     "syscalls": [{"Target": "setsockopt$inet_tcp_TCP_CONGESTION",
                   "Relate": ["socket$inet_tcp", "bind$inet", "close"]}]},
    {"idx": 4, "name": "vsock_race", "function": "virtio_transport_close",
     "func_path": "net/vmw_vsock/virtio_transport_common.c",
     "syscalls": [{"Target": "connect$vsock_stream",
                   "Relate": ["socket$vsock_stream", "bind", "listen",
                              "shutdown", "close", "accept4"]}]},
    {"idx": 5, "name": "bpf_verifier", "function": "do_check",
     "func_path": "kernel/bpf/verifier.c",
     "syscalls": [{"Target": "bpf$PROG_LOAD",
                   "Relate": ["bpf", "close"]}]},
    {"idx": 6, "name": "tcf_exts_init_ex", "function": "tcf_exts_init_ex",
     "func_path": "net/sched/cls_api.c",
     "syscalls": [{"Target": "sendmsg$nl_route_sched",
                   "Relate": ["socket$nl_route", "sendmsg$nl_route", "bind", "close"]}]},
    {"idx": 7, "name": "nf_tables_newrule", "function": "nf_tables_newrule",
     "func_path": "net/netfilter/nf_tables_api.c",
     "syscalls": [{"Target": "sendmsg$nl_netfilter",
                   "Relate": ["socket$nl_netfilter", "bind", "close"]}]},
    {"idx": 8, "name": "sctp_sf_do_prm_asoc", "function": "sctp_sf_do_prm_asoc",
     "func_path": "net/sctp/sm_statefuns.c",
     "syscalls": [{"Target": "connect$inet_sctp",
                   "Relate": ["socket$inet_sctp", "bind$inet",
                              "setsockopt$inet_sctp_SCTP_SOCKOPT_BINDX_ADD",
                              "sendmsg$inet_sctp", "close"]}]},
    {"idx": 9, "name": "xfrm_state_find", "function": "xfrm_state_find",
     "func_path": "net/xfrm/xfrm_state.c",
     "syscalls": [{"Target": "sendmsg$nl_xfrm",
                   "Relate": ["socket$nl_xfrm", "bind", "close"]}]},
    {"idx": 10, "name": "packet_snd", "function": "packet_snd",
     "func_path": "net/packet/af_packet.c",
     "syscalls": [{"Target": "sendto$packet",
                   "Relate": ["socket$packet", "bind$packet", "setsockopt$packet_int",
                              "close"]}]},
    {"idx": 11, "name": "llc_ui_sendmsg", "function": "llc_ui_sendmsg",
     "func_path": "net/llc/af_llc.c",
     "syscalls": [{"Target": "sendmsg$llc",
                   "Relate": ["syz_init_net_socket$llc", "bind$llc", "connect$llc",
                              "close"]}]},
]


def get_prebuilt_target(case_idx):
    """Return a copy of the registry entry for one prebuilt case."""
    for target in PREBUILT_TARGETS:
        if target["idx"] == case_idx:
            return dict(target)
    raise KeyError(f"Unknown prebuilt case: {case_idx}")


def select_prebuilt_targets(case_indices=None):
    """Return registry entries for all cases or the requested case indices."""
    if case_indices is None:
        return [dict(target) for target in PREBUILT_TARGETS]
    if not case_indices:
        raise KeyError("No prebuilt cases selected")
    requested = set(case_indices)
    selected = [dict(target) for target in PREBUILT_TARGETS if target["idx"] in requested]
    missing = sorted(requested - {target["idx"] for target in selected})
    if missing:
        raise KeyError(f"Unknown prebuilt case(s): {missing}")
    return selected
