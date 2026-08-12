"""Escaping for shell text embedded in a docker-compose file.

A command written for a container's shell passes two readers before the shell
ever sees it, and each one treats ``$`` as its own:

1. **Mako.** CORE renders a node's compose file as a Mako template
   (``DockerNode.startup``). Mako parses ``${...}`` as an expression and raises
   ``NameError`` for an unknown name -- measured, and it raises on ``$${VAR}``
   too, because it starts parsing at the second ``$``. So no ``${`` may survive
   into the file at all.
2. **Docker Compose.** Compose then interpolates ``$VAR`` *and* ``${VAR}`` from
   its own environment, where a variable belonging to the image is not defined,
   silently substituting an empty string. ``$$`` is Compose's escape for a
   literal ``$``.

The form satisfying both is ``$$NAME``: no ``${`` for Mako, and Compose's
``$$`` escape leaves the container's shell a literal ``$NAME`` to expand from
the image's own ENV.

This module exists because the same mistake was made independently in four
places in one day -- a hand-written wrapper command, CORE's compose writer, an
image-derived ``CMD``, and a Mako workaround that "fixed" ``$${VAR}`` by
rewriting it to a bare ``$VAR`` that Compose then ate. Each looked correct
against the one reader its author had in mind. Routing every such value through
one function is what stops the fifth.

Failure mode when it is skipped: ``vulhub/nexus`` ships
``sh -c ${SONATYPE_DIR}/start-nexus-repository-manager.sh``; unescaped it ran as
``sh -c /start-nexus-repository-manager.sh``, exited 127 on every restart, and
surfaced two layers away as "container PID remained 0" -- with Compose's own
warning, ``The "SONATYPE_DIR" variable is not set``, buried in the log.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = ["shell_text_for_compose", "COMPOSE_SAFE_HINT"]

COMPOSE_SAFE_HINT = (
    "shell text in a compose file must survive Mako (no `${`) and Compose "
    "(`$$` escapes a literal `$`); use shell_text_for_compose()"
)

# `${NAME}` / `${ NAME }`. Compose accepts modifiers such as `${NAME:-default}`,
# which are deliberately not matched: those are meant *for Compose*, so they are
# left for it to resolve rather than being handed to the container's shell.
_BRACED_VAR = re.compile(r"\$\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}")

# Placeholder while the remaining `$` are doubled, so a rewritten `${NAME}` is
# not doubled a second time. NUL cannot occur in a compose scalar.
_SENTINEL = "\x00coretg-var\x00"


def shell_text_for_compose(text: Any) -> str:
    """Return ``text`` so the container's shell receives it verbatim.

    Takes shell text exactly as it would be written in a shell script and makes
    it safe to embed in a compose file that will be Mako-rendered first.

    Apply once, to raw shell text. Applying it to a value already escaped for
    Compose would double the escaping and hand the shell a literal ``$$``.
    """
    value = str(text)
    if "$" not in value:
        return value
    # Braces must go before anything else: Mako latches onto `${` wherever it
    # appears, so leaving them and doubling the `$` is not enough.
    value = _BRACED_VAR.sub(lambda m: _SENTINEL + m.group(1), value)
    # Every literal `$` the shell should see has to reach Compose doubled.
    value = value.replace("$", "$$")
    return value.replace(_SENTINEL, "$$")


def dump_compose_yaml(compose_obj: Any) -> str:
    """Serialize a compose document, forcing literal block style for multiline strings.

    Every compose file this project writes has to survive one more reader after
    YAML: the host-side ``printf`` that CORE renders it through, which escapes
    each backslash. PyYAML's default emitter writes a multiline string as a
    *double-quoted* scalar, spelling newlines ``\\n`` and inner quotes ``\\"``.
    Backslash-doubling that text turns ``\\"`` into ``\\\\\\\\"``, and inside a
    double-quoted scalar those two escaped backslashes leave the ``"`` free to
    close the string early -- so the remainder of the command is reparsed as
    YAML.

    Observed on ``rocketchat/CVE-2021-22911``, whose ``mongo-init-replica``
    command embeds ``--eval \\"...\\"``. One pass re-dumped the file with a
    plain ``yaml.safe_dump``, the printf escaping ran over the result, and the
    inner ``_id: 'rs0'`` became a stray mapping key. ``docker compose`` refused
    the file with "mapping values are not allowed in this context", the node
    never started, and the run failed as a CORE startup timeout.

    A literal block scalar (``|``) holds real newlines and needs no escapes, so
    backslash-doubling cannot break the quoting. PyYAML falls back to a quoted
    style on its own for any value a block scalar cannot represent, so this is
    always safe to ask for.

    Use this for every compose write. A single writer that reaches for
    ``yaml.safe_dump`` puts the escapes back and the failure returns.
    """
    import yaml  # local import: keeps this module importable without PyYAML

    try:
        class _LiteralMultilineDumper(yaml.SafeDumper):
            pass

        def _represent_str(dumper: Any, value: str) -> Any:
            style = '|' if '\n' in value else None
            return dumper.represent_scalar('tag:yaml.org,2002:str', value, style=style)

        _LiteralMultilineDumper.add_representer(str, _represent_str)
        return yaml.dump(compose_obj, Dumper=_LiteralMultilineDumper, sort_keys=False)
    except Exception:
        return yaml.safe_dump(compose_obj, sort_keys=False)
