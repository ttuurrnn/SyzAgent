"""Target structure profiling for the SyzDirect agent loop."""

from dataclasses import asdict, dataclass, field


@dataclass
class TargetProfile:
    case_id: int
    target_function: str = ""
    target_path: str = ""
    syscall_family: str = ""
    primary_syscall: str = ""
    related_syscalls: list[str] = field(default_factory=list)
    resource_chain: list[str] = field(default_factory=list)
    payload_model: str = "unknown"
    subsystem: str = "unknown"
    callfile_subsystem: str = "unknown"
    subsystem_state: str = "unknown"
    dispatch_model: str = "direct"
    dispatch_selector: str = "unknown"
    likely_preconditions: list[str] = field(default_factory=list)
    structure_mismatch: list[str] = field(default_factory=list)
    blocking_layer: str = "unknown"
    confidence: float = 0.0

    def to_dict(self):
        return asdict(self)

    def one_line(self):
        parts = [
            f"case={self.case_id}",
            f"target={self.target_function or '?'}",
            f"family={self.syscall_family or '?'}",
            f"subsystem={self.subsystem}",
            f"callfile_subsystem={self.callfile_subsystem}",
            f"payload={self.payload_model}",
            f"dispatch={self.dispatch_model}",
            f"block={self.blocking_layer}",
            f"confidence={self.confidence:.2f}",
        ]
        return " ".join(parts)


def build_target_profile(target_info, callfile_entries=None, health=None):
    """Build a first-pass structural profile from local metadata."""
    callfile_entries = callfile_entries or []
    health = health or {}

    case_id = target_info.get("idx", -1)
    target_function = target_info.get("function", "") or target_info.get("name", "")
    target_path = target_info.get("func_path", "")

    primary, related = _extract_syscalls(callfile_entries, target_info)
    family = _syscall_family(primary)
    target_subsystem = _infer_subsystem(target_path, target_function, "", [])
    callfile_subsystem = _infer_subsystem("", "", primary, related)
    subsystem = target_subsystem if target_subsystem != "unknown" else callfile_subsystem
    mismatch = _infer_structure_mismatch(subsystem, callfile_subsystem)
    payload_model = _infer_payload_model(primary, related, subsystem)
    dispatch_model, dispatch_selector = _infer_dispatch(subsystem, target_function, target_path)
    subsystem_state = _infer_subsystem_state(subsystem, target_function, target_path)
    resource_chain = _infer_resource_chain(primary, related)
    preconditions = _infer_preconditions(subsystem, target_function, target_path)
    blocking_layer = _infer_blocking_layer(
        health, payload_model, subsystem_state, dispatch_model, mismatch
    )
    confidence = _confidence(primary, subsystem, payload_model, dispatch_model, mismatch)

    return TargetProfile(
        case_id=case_id,
        target_function=target_function,
        target_path=target_path,
        syscall_family=family,
        primary_syscall=primary,
        related_syscalls=related,
        resource_chain=resource_chain,
        payload_model=payload_model,
        subsystem=subsystem,
        callfile_subsystem=callfile_subsystem,
        subsystem_state=subsystem_state,
        dispatch_model=dispatch_model,
        dispatch_selector=dispatch_selector,
        likely_preconditions=preconditions,
        structure_mismatch=mismatch,
        blocking_layer=blocking_layer,
        confidence=confidence,
    )


def _extract_syscalls(callfile_entries, target_info):
    targets = []
    related = []
    for entry in callfile_entries:
        target = entry.get("Target")
        if target:
            targets.append(target)
        for rel in entry.get("Relate", []) or []:
            if rel:
                related.append(rel)

    if not targets:
        for entry in target_info.get("syscalls", []) or []:
            target = entry.get("Target")
            if target:
                targets.append(target)
            for rel in entry.get("Relate", []) or []:
                if rel:
                    related.append(rel)

    primary = targets[0] if targets else ""
    return primary, _dedupe(related)


def _syscall_family(syscall_name):
    return syscall_name.split("$", 1)[0].lower() if syscall_name else ""


def _infer_subsystem(path, function, primary, related):
    target_text = " ".join([path, function]).lower()
    if "net/sched" in target_text or "tcindex" in target_text or "qdisc" in target_text:
        return "tc"
    if "net/tls" in target_text or "tls_" in target_text:
        return "tls"
    if "nf_tables" in target_text or "netfilter" in target_text:
        return "nftables"
    if "xfrm" in target_text:
        return "xfrm"
    if "net/bluetooth" in target_text or "sco_" in target_text:
        return "bluetooth"
    if "tipc" in target_text:
        return "tipc"
    if "net/smc" in target_text or "smc_" in target_text:
        return "smc"
    if "gtp" in target_text:
        return "gtp"
    if "dma-buf" in target_text or "udmabuf" in target_text:
        return "dma_buf"
    if "tunnel" in target_text:
        return "tunnel"
    if "io_uring" in target_text or "iouring" in target_text:
        return "io_uring"
    if "mm/" in target_text or "madvise" in target_text or "mremap" in target_text:
        return "mm"
    if target_text.startswith("fs/") or " fs/" in target_text:
        return "fs"
    if "packet" in target_text:
        return "packet"
    if "llc" in target_text:
        return "llc"
    if "vsock" in target_text or "virtio_transport" in target_text:
        return "vsock"
    if "bpf" in target_text:
        return "bpf"
    if "sctp" in target_text:
        return "sctp"
    if "tcp" in target_text:
        return "tcp"

    haystack = " ".join([primary] + related).lower()
    if "net/sched" in haystack or "nl_route_sched" in haystack:
        return "tc"
    if "tls" in haystack or "tcp_ulp" in haystack:
        return "tls"
    if "nf_tables" in haystack or "netfilter" in haystack or "nl_netfilter" in haystack:
        return "nftables"
    if "xfrm" in haystack or "nl_xfrm" in haystack:
        return "xfrm"
    if "tipc" in haystack:
        return "tipc"
    if "smc" in haystack:
        return "smc"
    if "gtp" in haystack:
        return "gtp"
    if "udmabuf" in haystack or "dma_buf" in haystack:
        return "dma_buf"
    if "tunnel" in haystack:
        return "tunnel"
    if "io_uring" in haystack or "iouring" in haystack:
        return "io_uring"
    if "mmap" in haystack or "madvise" in haystack or "mremap" in haystack:
        return "mm"
    if "packet" in haystack:
        return "packet"
    if "llc" in haystack:
        return "llc"
    if "vsock" in haystack or "virtio_transport" in haystack:
        return "vsock"
    if "bluetooth" in haystack or "bt_" in haystack or "sco" in haystack:
        return "bluetooth"
    if "bpf" in haystack:
        return "bpf"
    if "sctp" in haystack:
        return "sctp"
    if "tcp" in haystack or "inet_tcp" in haystack:
        return "tcp"
    return "unknown"


def _infer_payload_model(primary, related, subsystem):
    calls = " ".join([primary] + related).lower()
    if "nl_route" in calls or "nl_netfilter" in calls or "nl_xfrm" in calls:
        return "netlink_nested_attrs"
    if "gtp_cmd" in calls or subsystem == "gtp":
        return "generic_netlink_nested_attrs"
    if primary.startswith("sendmsg"):
        return "msghdr_iovec_payload"
    if primary.startswith("setsockopt"):
        return "setsockopt_opt_struct"
    if primary.startswith("ioctl"):
        return "ioctl_cmd_struct"
    if subsystem == "bluetooth":
        return "socket_state"
    if subsystem in {"tipc", "smc", "llc", "tls"}:
        return "socket_state"
    if subsystem == "dma_buf":
        return "ioctl_cmd_struct"
    if subsystem == "io_uring":
        return "io_uring_sqe_or_ring_state"
    if subsystem == "mm":
        return "memory_mapping_state"
    if primary.startswith("bpf") or subsystem == "bpf":
        return "bpf_program_object"
    if primary.startswith("sendto") and subsystem == "packet":
        return "packet_frame"
    if primary.startswith("connect") or primary.startswith("socket"):
        return "socket_state"
    return "scalar_or_struct"


def _infer_dispatch(subsystem, function, path):
    target = " ".join([function, path]).lower()
    if subsystem == "tc":
        if "cls_" in target or "tcf_" in target or "tcindex" in target:
            return "tcf_proto_ops", "TCA_KIND -> classifier change handler"
        if "sch_" in target or "qdisc" in target or "fifo" in target:
            return "qdisc_ops", "TCA_KIND -> qdisc change/create handler"
        return "rtnetlink", "RTM_* + TCA_KIND"
    if subsystem == "nftables":
        return "nfnetlink", "nft message type + nested expression attrs"
    if subsystem == "xfrm":
        return "xfrm_netlink", "XFRM_MSG_* + state/policy attrs"
    if subsystem == "gtp":
        return "generic_netlink", "genl family + GTP_CMD_* + nested attrs"
    if subsystem == "tls":
        return "setsockopt", "TCP_ULP/TLS_RX/TLS_TX optname"
    if subsystem == "dma_buf":
        return "ioctl_cmd", "UDMABUF_* ioctl command"
    if subsystem == "tunnel":
        return "ioctl_cmd", "SIOC* tunnel ioctl command"
    if subsystem == "io_uring":
        return "io_uring_ops", "opcode + ring state"
    if subsystem == "mm":
        return "direct", "memory mapping syscall sequence"
    if subsystem in {"tcp", "sctp", "vsock", "llc", "packet"}:
        return "proto_ops", "socket family/type/protocol state"
    if subsystem in {"tipc", "smc"}:
        return "proto_ops", "socket family/type/protocol state"
    if subsystem == "bluetooth":
        return "proto_ops", "Bluetooth socket family/type/protocol state"
    if subsystem == "bpf":
        return "bpf_cmd", "BPF command + verifier object type"
    return "direct", "syscall argument path"


def _infer_subsystem_state(subsystem, function, path):
    target = " ".join([function, path]).lower()
    if subsystem == "tc":
        if "fifo" in target:
            return "qdisc create/change + child fifo state"
        if "tcf_" in target or "cls_" in target or "tcindex" in target:
            return "qdisc setup + filter/classifier create/change"
        return "qdisc/filter state"
    if subsystem == "nftables":
        return "table -> chain -> rule transaction"
    if subsystem == "xfrm":
        return "state/policy create + lookup flow"
    if subsystem == "gtp":
        return "netdevice + generic netlink tunnel state"
    if subsystem == "tls":
        return "TCP socket + ULP/TLS crypto state"
    if subsystem == "dma_buf":
        return "memfd/file sealing + dma-buf ioctl state"
    if subsystem == "tunnel":
        return "netdevice tunnel create/change state"
    if subsystem == "io_uring":
        return "ring setup + SQE submission/completion state"
    if subsystem == "mm":
        return "mmap/mremap/madvise VMA state"
    if subsystem in {"tcp", "sctp", "vsock", "llc", "packet"}:
        return "socket lifecycle state"
    if subsystem in {"tipc", "smc"}:
        return "socket lifecycle state"
    if subsystem == "bluetooth":
        return "Bluetooth socket lifecycle state"
    if subsystem == "bpf":
        return "map/program/verifier state"
    return "unknown"


def _infer_resource_chain(primary, related):
    chain = []
    for call in related + ([primary] if primary else []):
        base = call.split("$", 1)[0]
        if base and base not in chain:
            chain.append(base)
    return chain


def _infer_preconditions(subsystem, function, path):
    target = " ".join([function, path]).lower()
    if subsystem == "tc":
        if "fifo" in target:
            return ["create TBF qdisc", "set TCA_OPTIONS", "preserve child fifo state"]
        if "tcindex" in target:
            return ["create base qdisc", "create tcindex filter", "set tcindex options"]
        if "tcf_" in target or "cls_" in target:
            return ["create base qdisc", "select classifier kind", "set kind-specific options"]
        return ["create qdisc or filter", "select TCA_KIND"]
    if subsystem == "nftables":
        return ["create table", "create chain", "create rule transaction", "set expression attrs"]
    if subsystem == "xfrm":
        return ["create xfrm state", "create xfrm policy", "perform matching lookup"]
    if subsystem == "gtp":
        return ["create generic netlink socket", "resolve gtp family", "set GTP_CMD_* attrs"]
    if subsystem == "tls":
        return ["create TCP socket", "set TCP_ULP to tls", "set TLS_RX/TLS_TX crypto info"]
    if subsystem == "dma_buf":
        return ["create memfd", "apply required seals", "issue UDMABUF ioctl"]
    if subsystem == "tunnel":
        return ["create tunnel-capable socket", "select SIOC* tunnel command", "provide ifreq payload"]
    if subsystem == "io_uring":
        return ["setup io_uring", "submit target opcode sequence", "reap completions"]
    if subsystem == "mm":
        return ["create mapping", "drive VMA state", "call target mm syscall"]
    if subsystem in {"tcp", "sctp", "vsock", "llc", "packet"}:
        return ["create socket", "drive protocol state", "reuse socket resource"]
    if subsystem in {"tipc", "smc"}:
        return ["create socket", "drive protocol state", "reuse socket resource"]
    if subsystem == "bluetooth":
        return ["create Bluetooth socket", "select SCO/L2CAP/RFCOMM kind", "drive socket state"]
    if subsystem == "bpf":
        return ["create map if needed", "load program", "satisfy verifier constraints"]
    return []


def _infer_structure_mismatch(target_subsystem, callfile_subsystem):
    if (
        target_subsystem != "unknown"
        and callfile_subsystem != "unknown"
        and target_subsystem != callfile_subsystem
    ):
        return [f"target_subsystem={target_subsystem} callfile_subsystem={callfile_subsystem}"]
    return []


def _infer_blocking_layer(health, payload_model, subsystem_state, dispatch_model,
                          structure_mismatch=None):
    if structure_mismatch:
        return "syscall_family_or_callfile_mismatch"
    dist = health.get("effective_dist_min_best")
    if dist == 0:
        return "target_reached"
    if dist is None:
        return "unknown"
    if dist >= 1000 and dispatch_model != "direct":
        return "dispatch_selection"
    if dist <= 10 and payload_model == "netlink_nested_attrs":
        return "state_or_nested_attr_precision"
    if dist <= 10 and subsystem_state != "unknown":
        return "subsystem_state"
    return "argument_or_state"


def _confidence(primary, subsystem, payload_model, dispatch_model, structure_mismatch=None):
    score = 0.0
    if primary:
        score += 0.25
    if subsystem != "unknown":
        score += 0.25
    if payload_model != "unknown":
        score += 0.25
    if dispatch_model != "direct":
        score += 0.25
    if structure_mismatch:
        score -= 0.25
    return score


def _dedupe(items):
    seen = set()
    out = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out
