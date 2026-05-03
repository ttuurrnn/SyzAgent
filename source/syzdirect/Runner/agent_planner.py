"""Planning helpers for the SyzDirect agent loop."""

from dataclasses import asdict, dataclass, field


@dataclass
class AgentPlan:
    phase: str
    hypothesis: str
    focus_layer: str
    actions: list[str] = field(default_factory=list)
    prompt_guardrails: list[str] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)

    def to_log_lines(self):
        lines = [
            f"phase={self.phase}",
            f"focus={self.focus_layer}",
            f"hypothesis={self.hypothesis}",
        ]
        for action in self.actions:
            lines.append(f"action={action}")
        return lines


def build_agent_plan(profile, health=None, triage_result=None):
    """Choose one structural layer for the next agent action."""
    health = health or {}
    triage_result = triage_result or {}
    status = health.get("status", "unknown")
    failure_class = triage_result.get("primary", "unknown")

    if status == "healthy" or profile.blocking_layer == "target_reached":
        return AgentPlan(
            phase="verify",
            hypothesis="target appears reachable; keep fuzzing without structural intervention",
            focus_layer="none",
            actions=["continue current fuzzing strategy"],
        )

    if profile.blocking_layer == "syscall_family_or_callfile_mismatch":
        details = "; ".join(profile.structure_mismatch)
        return AgentPlan(
            phase="profile",
            hypothesis=(
                "callfile syscall family does not match target subsystem"
                + (f" ({details})" if details else "")
            ),
            focus_layer="syscall_family",
            actions=[
                "discard seeds from the mismatched callfile subsystem",
                "regenerate callfile from target subsystem and required resource chain",
                "verify the primary syscall before payload or dispatch tuning",
            ],
            prompt_guardrails=[
                "do not preserve a corpus whose syscall family conflicts with the target",
                "choose syscalls from the target subsystem before generating payload attrs",
            ],
        )

    if failure_class == "R4" and profile.blocking_layer == "dispatch_selection":
        return AgentPlan(
            phase="hypothesize",
            hypothesis=(
                f"{profile.primary_syscall or 'syscall family'} is present, but "
                f"{profile.dispatch_model} selector is not reaching the target handler"
            ),
            focus_layer="dispatch_selector",
            actions=[
                "rank corpus by syscall family and subsystem selector",
                "prefer seeds that explicitly set dispatch kind/type fields",
                "ask LLM to validate profile and selector before generating seed code",
            ],
            prompt_guardrails=[
                "classify syscall family, payload grammar, state, and dispatch first",
                "do not generate broad generic seeds",
            ],
        )

    if failure_class == "R4" and profile.blocking_layer == "state_or_nested_attr_precision":
        return AgentPlan(
            phase="plan",
            hypothesis=(
                f"target is close, but {profile.payload_model} or "
                f"{profile.subsystem_state} is not precise enough"
            ),
            focus_layer="payload_or_state_precision",
            actions=[
                "filter closest corpus by target subsystem and payload shape",
                "preserve multi-step resource/state setup programs",
                "generate seed variants for one missing precondition only",
            ],
            prompt_guardrails=[
                "choose one blocking layer",
                "keep existing working resource chain intact",
            ],
        )

    if profile.payload_model == "netlink_nested_attrs":
        return AgentPlan(
            phase="profile",
            hypothesis="netlink target needs nested attribute grammar and subsystem state",
            focus_layer="payload_grammar",
            actions=[
                "identify netlink family and message kind",
                "identify required nested attrs and subsystem state",
                "route to subsystem-specific encoder when available",
            ],
            prompt_guardrails=[
                "explain netlink headers and nested attrs before seed generation",
            ],
        )

    if profile.subsystem_state != "unknown":
        return AgentPlan(
            phase="profile",
            hypothesis=f"{profile.subsystem} target likely requires stateful setup",
            focus_layer="subsystem_state",
            actions=[
                "preserve producer-consumer resource chain",
                "generate setup sequence before target syscall",
            ],
            prompt_guardrails=[
                "list required preconditions before generating seed",
            ],
        )

    return AgentPlan(
        phase="observe",
        hypothesis="insufficient structural signal; observe another round or use generic triage",
        focus_layer="unknown",
        actions=["fall back to existing triage and enhancement path"],
    )
