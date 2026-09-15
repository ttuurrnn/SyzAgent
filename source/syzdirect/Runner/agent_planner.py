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


def _is_repeating(prev_signatures, focus_layer, repeat_threshold):
    """True if `focus_layer` matches the last `repeat_threshold` history entries."""
    if not prev_signatures or repeat_threshold <= 0:
        return False
    tail = prev_signatures[-repeat_threshold:]
    if len(tail) < repeat_threshold:
        return False
    return all(sig and sig[1] == focus_layer for sig in tail)


def _escalate_plan(base, prev_signatures):
    """Mutate the base plan when the same focus_layer keeps firing.

    Past runs show the planner returns the same `(focus=dispatch_selector, …)`
    plan for 16 rounds in a row when the LLM cannot break through the
    dispatcher. When the previous N rounds had the same focus_layer, return an
    `escalate` plan that drops the layer and asks for a different angle.
    """
    blocked_layer = base.focus_layer
    return AgentPlan(
        phase="escalate",
        hypothesis=(
            f"focus={blocked_layer} has not moved distance for "
            f"{len(prev_signatures)} consecutive plans — escalating"
        ),
        focus_layer="cross_layer_recovery",
        actions=[
            f"drop {blocked_layer} as the primary focus this round",
            "rebuild target reachability from prebuilt syscall variants ($-suffixed)",
            "generate seeds that pair the target syscall with adjacent setup/destroy ops",
            "if a hand-crafted seed corpus is available, prefer it over LLM-only seeds",
        ],
        prompt_guardrails=[
            f"do not re-emit a {blocked_layer}-only plan; the last round already tried it",
            "explore a different syscall family or resource chain",
        ],
    )


def _stall_escalate_plan(base, stall_rounds):
    """Escalation plan when best_dist_min hasn't moved for `stall_rounds` rounds.

    Distinct from `_escalate_plan` (which fires on a same-focus_layer streak):
    here the planner IS varying its focus, but the fuzzer is still parked at
    the same dist. That means the LLM's seed-generation context is missing
    the trigger condition itself — patch diff + commit msg are present (A)
    yet the seeds keep landing in the same BB. Tell the LLM explicitly that
    its previous N rounds of seeds did NOT progress, and demand a different
    trigger hypothesis (race window, specific arg value, allocator state)
    rather than another structural variant of the same call shape.
    """
    return AgentPlan(
        phase="stall_escalate",
        hypothesis=(
            f"best_dist_min has not improved for {stall_rounds} consecutive "
            "rounds despite varied structural focus — the trigger condition "
            "inside the target function is the bottleneck, not the call shape"
        ),
        focus_layer="trigger_condition",
        actions=[
            "treat previous round seeds as proven-insufficient — do not minor-variant them",
            "re-read the VULN HINT / patch diff and extract the EXACT precondition "
            "(arg value range, kernel object state, race partner, allocator slab)",
            "generate seeds that target ONE specific precondition per program",
            "if the bug is a race, emit paired programs that exercise both sides concurrently",
            "if the bug is OOB/UAF, generate boundary-value variants of the implicated arg",
        ],
        prompt_guardrails=[
            f"do NOT re-emit the seed shape from the last {stall_rounds} rounds — it has been shown not to trigger",
            "name the specific trigger precondition you are aiming for in each seed comment",
        ],
    )


def build_agent_plan(profile, health=None, triage_result=None,
                     prev_signatures=None, dist_stall_rounds=0,
                     stall_threshold=5):
    """Choose one structural layer for the next agent action.

    `prev_signatures` is an optional iterable of prior `(failure_class,
    focus_layer, hypothesis)` tuples. When the proposed plan's focus_layer
    matches the last two history entries, the plan is escalated to drop that
    focus rather than emit it for a fourth round in a row.

    `dist_stall_rounds` is the count of consecutive rounds where
    `best_dist_min_ever` did not improve. When it reaches `stall_threshold`
    (default 5), emit a stall-escalation plan that tells the LLM its prior
    seeds have been proven insufficient and demands a different trigger
    hypothesis — addresses the case where the fuzzer keeps re-entering the
    target function without exercising its vulnerable branch.
    """
    base = _build_base_plan(profile, health, triage_result)
    if dist_stall_rounds >= stall_threshold:
        return _stall_escalate_plan(base, dist_stall_rounds)
    if _is_repeating(prev_signatures or [], base.focus_layer, repeat_threshold=2):
        return _escalate_plan(base, prev_signatures)
    return base


def _build_base_plan(profile, health=None, triage_result=None):
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
