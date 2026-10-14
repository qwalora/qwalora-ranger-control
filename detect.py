"""A safe, bounded Sigma-subset evaluator for board 3 (detection engineering).

Rangers submit detection rules; the server runs them against a holdout corpus.
We never execute candidate code and never compile candidate regex (no ReDoS):
a rule is a set of field/modifier selections combined by a tiny boolean
condition parser. Matching is plain string containment / equality over a fixed
whitelist of event fields, so evaluation cost is bounded and predictable.

Rule shape (parsed from YAML/JSON):

    name: lsass_comsvcs_minidump
    technique: T1003.001           # optional, for the ranger's own mapping
    detection:
      sel:
        image: rundll32.exe
        command|contains|all:
          - comsvcs.dll
          - MiniDump
      condition: sel

Modifiers on a field key (pipe-separated): contains | startswith | endswith,
optionally followed by `all` (every value must match; default is any). A bare
field is case-insensitive equality. A list value is OR unless `all` is set.
Across keys in one selection, logic is AND (standard Sigma).

condition supports selection names combined with and / or / not and
parentheses, plus the aggregates `all of them`, `any of them`, `1 of them`,
`N of them`. Anything else is a RuleError, surfaced to the ranger as feedback.
"""
import re as _re

# The only fields a detection may match on. `id` and `timestamp` are
# deliberately excluded so a rule cannot overfit to a unique event identifier.
FIELDS = {"event_type", "host", "user", "image", "parent", "command", "dest", "domain"}
_MODS = {"contains", "startswith", "endswith"}

MAX_RULES = 40
MAX_SELECTIONS = 12
MAX_VALUES = 40
_NAME_RE = _re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class RuleError(Exception):
    pass


def _norm(s):
    return str(s if s is not None else "").strip().lower()


def _parse_key(key):
    parts = str(key).split("|")
    field = parts[0].strip().lower()
    mod = None
    allmod = False
    rest = [p.strip().lower() for p in parts[1:]]
    for p in rest:
        if p == "all":
            allmod = True
        elif p in _MODS and mod is None:
            mod = p
        else:
            raise RuleError("unknown modifier %r in %r" % (p, key))
    if field not in FIELDS:
        raise RuleError("field %r is not a detectable field (allowed: %s)"
                        % (field, ", ".join(sorted(FIELDS))))
    return field, mod, allmod


def _match_selection(sel, ev):
    if not isinstance(sel, dict) or not sel:
        raise RuleError("a selection must be a non-empty map of field: value")
    if len(sel) > MAX_SELECTIONS:
        raise RuleError("selection has too many conditions")
    for key, val in sel.items():
        field, mod, allmod = _parse_key(key)
        ev_val = _norm(ev.get(field))
        vals = val if isinstance(val, list) else [val]
        if len(vals) > MAX_VALUES:
            raise RuleError("too many values under %r" % key)
        vals = [_norm(v) for v in vals]
        if mod is None:
            ok = ev_val in vals                              # equality, list = any
        else:
            if mod == "contains":
                tests = [v in ev_val for v in vals]
            elif mod == "startswith":
                tests = [ev_val.startswith(v) for v in vals]
            else:  # endswith
                tests = [ev_val.endswith(v) for v in vals]
            ok = all(tests) if allmod else any(tests)
        if not ok:
            return False
    return True


# --- condition: a tiny boolean parser over selection names ------------------
def _tokenize(cond):
    return _re.findall(r"\(|\)|\b(?:and|or|not)\b|[A-Za-z_][A-Za-z0-9_]*", cond.lower())


def _eval_condition(cond, results):
    sel_names = list(results.keys())
    cond = (cond or "").strip()
    if not cond:
        if len(results) != 1:
            raise RuleError("condition is required when a rule has more than one selection")
        return next(iter(results.values()))

    m = _re.match(r"^(all|any|\d+)\s+of\s+them$", cond.lower())
    if m:
        hits = sum(1 for v in results.values() if v)
        q = m.group(1)
        if q == "all":
            return hits == len(results)
        if q == "any":
            return hits >= 1
        return hits >= int(q)

    toks = _tokenize(cond)
    if not toks:
        raise RuleError("empty or unparseable condition")
    pos = {"i": 0}

    def peek():
        return toks[pos["i"]] if pos["i"] < len(toks) else None

    def nxt():
        t = peek()
        pos["i"] += 1
        return t

    def factor():
        t = peek()
        if t == "not":
            nxt()
            return not factor()
        if t == "(":
            nxt()
            v = expr()
            if nxt() != ")":
                raise RuleError("unbalanced parentheses in condition")
            return v
        if t is None or t in ("and", "or", ")"):
            raise RuleError("unexpected token in condition near %r" % t)
        nxt()
        if t not in results:
            raise RuleError("condition references unknown selection %r" % t)
        return results[t]

    def term():
        v = factor()
        while peek() == "and":
            nxt()
            v = factor() and v
        return v

    def expr():
        v = term()
        while peek() == "or":
            nxt()
            v = term() or v
        return v

    v = expr()
    if pos["i"] != len(toks):
        raise RuleError("trailing tokens in condition")
    return v


def compile_rule(rule):
    """Validate a rule's structure and return a matcher fn(event)->bool, or
    raise RuleError with a human message. Compilation does no matching, so a
    structural error is caught before any event is scanned."""
    if not isinstance(rule, dict):
        raise RuleError("a rule must be a map")
    name = rule.get("name") or rule.get("id") or "rule"
    det = rule.get("detection")
    if not isinstance(det, dict) or not det:
        raise RuleError("rule %r needs a non-empty detection block" % name)
    cond = det.get("condition")
    sels = {k: v for k, v in det.items() if k != "condition"}
    if not sels:
        raise RuleError("rule %r needs at least one selection" % name)
    for sk in sels:
        if not _NAME_RE.match(str(sk)):
            raise RuleError("selection name %r is not a valid identifier" % sk)
        _match_selection(sels[sk], {})  # validates keys/modifiers up front

    def matcher(ev):
        results = {sk: _match_selection(sv, ev) for sk, sv in sels.items()}
        return _eval_condition(cond, results)

    return name, matcher


def compile_ruleset(rules):
    """Return (matchers, errors). matchers: list of (name, fn). errors: list of
    {rule, error}. Non-dict / overflowing input is reported, not raised."""
    matchers, errors = [], []
    if not isinstance(rules, list):
        return [], [{"rule": "(ruleset)", "error": "rules must be a list"}]
    if len(rules) > MAX_RULES:
        rules = rules[:MAX_RULES]
        errors.append({"rule": "(ruleset)", "error": "only the first %d rules were evaluated" % MAX_RULES})
    for i, r in enumerate(rules):
        try:
            name, fn = compile_rule(r)
            matchers.append((name, fn))
        except RuleError as e:
            nm = (r.get("name") or r.get("id") or ("rule[%d]" % i)) if isinstance(r, dict) else ("rule[%d]" % i)
            errors.append({"rule": nm, "error": str(e)})
    return matchers, errors
