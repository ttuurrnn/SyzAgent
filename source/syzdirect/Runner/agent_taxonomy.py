"""Shared structural taxonomy prompt for agent planning."""


KERNEL_TARGET_STRUCTURE_TAXONOMY = """KERNEL TARGET STRUCTURE TAXONOMY

Do not assume a kernel target is solved by choosing one syscall.
Classify the target as a combination of these layers:

1. syscall family:
   sendmsg / setsockopt / ioctl / bpf / socket / fs / mm / packet /
   netlink / io_uring

2. resource chain:
   producer-consumer sequence such as socket -> bind -> sendmsg,
   open -> ioctl, bpf map -> bpf prog, table -> chain -> rule,
   memfd -> seal -> ioctl, mmap -> mremap/madvise

3. payload grammar:
   scalar, pointer struct, ioctl command struct, setsockopt opt struct,
   msghdr/iovec, netlink nested attrs, generic-netlink nested attrs,
   packet frame, BPF bytecode, io_uring SQE

4. subsystem state:
   TC qdisc/filter, nft table/chain/rule transaction, xfrm state/policy,
   socket lifecycle, TLS ULP state, dma-buf/memfd state, BPF map/prog/verifier,
   filesystem namespace, mm VMA state

5. dispatch selector:
   TCA_KIND, nft message type, XFRM_MSG_*, ioctl cmd, optname,
   proto_ops, Qdisc_ops, tcf_proto_ops, nfnetlink, genl family,
   io_uring opcode

6. blocking layer:
   If dist is large, suspect wrong syscall family or dispatch selector.
   If dist is small, suspect exact payload attrs, branch condition, or missing state.
   If target subsystem and callfile subsystem disagree, fix syscall family first.

Before generating any seed:
- classify the layers above
- choose exactly one blocking layer
- generate only seeds that attack that layer
- preserve existing working resource/state setup
"""
