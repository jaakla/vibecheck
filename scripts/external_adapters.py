# -*- coding: utf-8 -*-
"""External specialist tool adapters (RFC 0001 §8.4,
§11.6).

Vibecheck's own detection is a grep. These adapters let a maintained specialist
tool do the detecting and hand its result back as normalized Evidence, so the
review keeps one vocabulary — Signals, scoped Evidence, open Actions — whatever
produced the material:

  import_gitleaks_json(data, run=...)      secrets over git history
  import_trufflehog_json(data, run=...)    secrets over git history
  import_osv_scanner_json(data, run=...)   dependency advisories
  import_trivy_json(data, run=...)         dependency, image and licence audit
  import_semgrep_json(data, run=...)       SAST
  import_codeql_sarif(data, run=...)       SAST (SARIF)
  import_codex_security_sarif(data, run=...)  SAST (SARIF, LLM-validated)
  import_owasp_zap_json(data, run=...)     DAST against an authorized target
  import_playwright_json(data, run=...)    two-account browser flows

Nothing here runs a tool, installs one, or uploads anything. Each function
takes output somebody already produced, plus an optional ``run_record`` saying
how it was produced, and returns an envelope. Four properties are what make
that worth doing rather than pasting tool output into a report:

**A green run is never a pass.** Zero findings becomes one *neutral* evidence
that says so in its scope. Rule R3 means neutral evidence can never support a
pass, so a clean Gitleaks run cannot close "no secrets in the repository" — it
records that one ruleset found nothing.

**A claim never exceeds the capability.** Every claim is intersected with the
provider's declared coverage in the registry (`_claim_within`), so an adapter
cannot claim a control its provider never said it could observe, and rule R24
has something true to check. A rule that maps to nothing the provider declares
becomes an open triage Action rather than an invented claim.

**Failure stays visible.** Tool-not-installed, crash, timeout, cancellation,
unparseable output and partial results are five distinct outcomes, each one an
open verify Action naming the coverage that is still missing. A timeout keeps
the findings it did produce *and* the gap — a partial result is not a clean one.

**Raw output is bounded and redacted, never copied.** Secret-bearing fields
(`Secret`, `Match`, `Raw`, `RawV2`) are dropped before anything enters the
envelope, and what remains goes through `canonical.bound_raw`, which is the
same redaction the bundled scanner uses.

Only the live tools (ZAP, Playwright) can fill an authorization coverage cell,
and only when the assertion names the object it touched: a browser test that
does not say which record it asked for observed something, but not one cell
(rule R20). The envelope builder, claim builder and capability stamp are the
ones ``adapters.py`` uses, so a specialist result and a bundled result are the
same shape.

Stdlib only.
"""
import datetime
import functools
import json
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import canonical
import controls as controls_mod
import providers as providers_mod
# One envelope shape for bundled and external results alike: these are the
# builders adapters.py uses for the scanner and the probe, not copies of them.
from adapters import (EVIDENCE_VALIDITY_DAYS, _attach_capability, _claim,
                      _envelope, _iso, _parse_now)

GITLEAKS_PROVIDER = "prov-gitleaks"
TRUFFLEHOG_PROVIDER = "prov-trufflehog"
OSV_SCANNER_PROVIDER = "prov-osv-scanner"
TRIVY_PROVIDER = "prov-trivy"
SEMGREP_PROVIDER = "prov-semgrep-ce"
CODEQL_PROVIDER = "prov-codeql"
CODEX_SECURITY_PROVIDER = "prov-codex-security"
ZAP_PROVIDER = "prov-owasp-zap"
PLAYWRIGHT_PROVIDER = "prov-playwright-two-account"

#: Adapter identity per provider: the tool name that lands on signals, and the
#: short slug that ids and action keys are built from.
_TOOLS = {
    GITLEAKS_PROVIDER: ("gitleaks", "gitleaks"),
    TRUFFLEHOG_PROVIDER: ("trufflehog", "trufflehog"),
    OSV_SCANNER_PROVIDER: ("osv-scanner", "osv"),
    TRIVY_PROVIDER: ("trivy", "trivy"),
    SEMGREP_PROVIDER: ("semgrep", "semgrep"),
    CODEQL_PROVIDER: ("codeql", "codeql"),
    CODEX_SECURITY_PROVIDER: ("codex-security", "codex-security"),
    ZAP_PROVIDER: ("owasp-zap", "zap"),
    PLAYWRIGHT_PROVIDER: ("playwright", "playwright"),
}

#: Fields whose value is the credential itself. Dropped before the finding is
#: archived: a secret scanner's report is the one artifact most likely to carry
#: a live key, and bound_raw's pattern list is a backstop, not a guarantee.
_SECRET_FIELDS = ("Secret", "Match", "Raw", "RawV2", "raw", "secret",
                  "StructuredData")

_R3_NOTE = ("Absence of a signal is not evidence of absence and can never "
            "support a pass (rule R3).")


# ------------------------------------------------------------- availability

def required_tools(provider_id):
    """Executables this provider needs on PATH, from the registry."""
    record = providers_mod.capability(provider_id, control_ids=[])
    if record is None:
        raise KeyError("no such provider: %r" % (provider_id,))
    return list((record.get("availability") or {}).get("requires_tools") or [])


def tool_availability(provider_id, path_lookup=None):
    """Whether this provider's tools are installed, and which are missing.

    Detection only. Nothing here installs anything, and a missing tool is a
    reported gap rather than something to fix silently — the user decides what
    runs on their machine — tools are never installed silently.
    """
    lookup = path_lookup or shutil.which
    needed = required_tools(provider_id)
    missing = [tool for tool in needed if not lookup(tool)]
    return {
        "provider_id": provider_id,
        "requires_tools": needed,
        "missing_tools": missing,
        "available": not missing,
        "detect": ((providers_mod.capability(provider_id, control_ids=[])
                    .get("availability") or {}).get("detect")),
    }


def availability_report(path_lookup=None):
    """Availability of every external specialist provider."""
    return [tool_availability(provider_id, path_lookup)
            for provider_id in _TOOLS]


# ------------------------------------------------------------- run records

def run_record(command=None, exit_code=None, timed_out=False, cancelled=False,
               error=None, started_at=None, duration_seconds=None,
               version=None, scope_note=None):
    """How a tool run was invoked and how it ended.

    The exact argv is provenance: a Semgrep run with one ruleset and a Semgrep
    run with another produce the same JSON shape and cover different things, so
    the command travels with the evidence instead of being reconstructed later.
    """
    return {
        "command": list(command) if command else None,
        "exit_code": exit_code,
        "timed_out": bool(timed_out),
        "cancelled": bool(cancelled),
        "error": error,
        "started_at": started_at,
        "duration_seconds": duration_seconds,
        "version": version,
        "scope_note": scope_note,
    }


def _command_text(run):
    command = (run or {}).get("command")
    if not command:
        return "command not recorded"
    return " ".join(str(part) for part in command)


def _run_failure(run, parsed_error, parsed_ok):
    """(kind, detail) for a run that did not complete cleanly, or None.

    Order matters: cancellation and timeout are reported as themselves rather
    than as the non-zero exit they also produce, because what a reviewer has to
    do about them differs.

    A non-zero exit is deliberately *not* a failure on its own. Every tool here
    signals "I found something" that way — gitleaks 1, semgrep 1, `trivy
    --exit-code`, ZAP baseline 1 and 2 — so treating it as a crash would turn
    the tool's most useful runs into gaps. It only counts when the run also
    produced nothing this adapter could read.
    """
    run = run or {}
    if run.get("cancelled"):
        return ("cancelled", run.get("error"))
    if run.get("timed_out"):
        return ("timeout", run.get("error"))
    if run.get("error"):
        return ("error", str(run["error"]))
    if parsed_error:
        return ("error", str(parsed_error))
    exit_code = run.get("exit_code")
    if not parsed_ok and isinstance(exit_code, int) and exit_code != 0:
        return ("error", "the tool exited %d and produced no readable output"
                % exit_code)
    return None


# --------------------------------------------------------------- parsing

def _parse(data):
    """(parsed, parse_error) for one tool's stdout.

    ``data`` may be raw text or an already-parsed object, because a caller that
    read the tool's report file with json.load should not have to re-serialize
    it to hand it over.
    """
    if data is None:
        return (None, "no output was captured")
    if isinstance(data, (dict, list)):
        return (data, None)
    text = data.strip()
    if not text:
        return (None, "the tool produced no output")
    try:
        return (json.loads(text), None)
    except ValueError as exc:
        return (None, "output is not valid JSON: %s" % exc)


def _parse_jsonl(data):
    """(objects, parse_error) for a JSON-lines stream (TruffleHog)."""
    if isinstance(data, list):
        return (data, None)
    if isinstance(data, dict):
        return ([data], None)
    if data is None:
        return (None, "no output was captured")
    lines = [line.strip() for line in data.splitlines() if line.strip()]
    if not lines:
        return ([], None)
    objects, bad = [], 0
    for line in lines:
        try:
            obj = json.loads(line)
        except ValueError:
            bad += 1
            continue
        if isinstance(obj, list):
            objects.extend(obj)
        elif isinstance(obj, dict):
            objects.append(obj)
    if bad and not objects:
        return (None, "no line of the output parsed as JSON")
    if bad:
        return (objects, "%d line(s) of the output did not parse" % bad)
    return (objects, None)


def _embedded_error(parsed):
    """An error the tool reported inside its own successful-looking output."""
    if not isinstance(parsed, dict):
        return None
    if parsed.get("error"):
        return str(parsed["error"])
    if parsed.get("status") in ("failed", "timeout", "error"):
        return str(parsed.get("message") or parsed.get("status"))
    if parsed.get("errors"):
        errors = parsed["errors"]
        if isinstance(errors, list) and errors:
            first = errors[0]
            return str(first.get("message") if isinstance(first, dict)
                       else first)
    return None


def _redacted_finding(finding, extra_drop=()):
    """One finding as archivable text: secret-bearing fields removed first."""
    if isinstance(finding, dict):
        dropped = {key: value for key, value in finding.items()
                   if key not in _SECRET_FIELDS and key not in extra_drop}
        text = json.dumps(dropped, ensure_ascii=False, sort_keys=True)
    else:
        text = str(finding)
    return canonical.bound_raw(text)


# ---------------------------------------------------------------- claims

_CONTROL_NUMBERS = {control_id: number
                    for number, control_id in controls_mod.CONTROL_IDS.items()}


@functools.lru_cache(maxsize=None)
def declared_controls(provider_id):
    """Control IDs this provider's registry record says it can observe.

    Cached: the registry is static per process, and every finding in a run
    (hundreds, for a noisy Semgrep/Trivy pass) calls this via `_claim_within`.
    """
    record = providers_mod.capability(provider_id)
    if record is None:
        raise KeyError("no such provider: %r" % (provider_id,))
    return tuple(entry["control_id"] for entry in record.get("coverage") or [])


def _claim_within(provider_id, item_numbers):
    """A claim narrowed to what this provider actually declares.

    The structural half of "never turn a tool result into a control-wide
    conclusion": a keyword map that guesses a control the provider never
    declared produces nothing here, and the caller raises a triage Action
    instead of evidence with a claim nobody can check.
    """
    allowed = set(declared_controls(provider_id))
    numbers = [number for number in item_numbers
               if controls_mod.CONTROL_IDS.get(number) in allowed]
    if not numbers:
        return None
    return _claim(sorted(set(numbers)))


def _all_declared_claim(provider_id):
    numbers = sorted(_CONTROL_NUMBERS[control_id]
                     for control_id in set(declared_controls(provider_id))
                     if control_id in _CONTROL_NUMBERS)
    return _claim(numbers)


def _matches(text, keywords):
    lowered = text.lower()
    return any(keyword in lowered for keyword in keywords)


#: Rule-text → control keyword map for the two SAST providers and ZAP. Each
#: entry is (item numbers, keywords). First match wins, so the more specific
#: injection classes are listed before the general validation bucket.
_SAST_RULES = (
    ((29,), ("sql-injection", "sqli", "sql_injection", "sql injection",
             "unparameterized", "raw-query", "tainted-sql")),
    ((30,), ("xss", "cross-site-scripting", "cross site scripting",
             "innerhtml", "dangerouslysetinnerhtml", "html-escap",
             "autoescape", "output-encod", "template-injection")),
    ((32,), ("command-injection", "os-command", "command injection", "exec",
             "path-traversal", "path traversal", "ssrf", "xxe",
             "deserializ", "insecure-deserial", "zip-slip", "ldap-injection",
             "nosql-injection")),
    ((28,), ("validation", "mass-assignment", "open-redirect", "unvalidated",
             "user-controlled", "taint")),
    ((42,), ("debug", "verbose-error", "stacktrace", "stack-trace",
             "console-log", "detailed-error")),
    ((77,), ("llm", "prompt-injection", "openai", "anthropic",
             "model-output-exec")),
)

_ZAP_RULES = (
    ((44,), ("cors", "cross-domain", "access-control-allow-origin")),
    ((45,), ("strict-transport", "hsts", "ssl", "tls", "secure cookie",
             "cookie without secure", "mixed content", "https")),
    ((42,), ("debug", "stack trace", "error message", "information disclosure",
             "x-powered-by", "server leaks", "suspicious comments")),
    ((30,), ("cross site scripting", "xss", "header injection",
             "content-type-options", "content security policy", "anti-clickjack",
             "x-frame-options", "samesite")),
    ((28,), ("sql injection", "command injection", "path traversal",
             "remote file inclusion", "parameter tampering", "buffer overflow")),
    ((14,), ("directory browsing", "authentication", "session id",
             "private ip disclosure", "user agent fuzzer")),
)


def _rule_numbers(text, table):
    for numbers, keywords in table:
        if _matches(text, keywords):
            return numbers
    return ()


# ------------------------------------------------------- envelope assembly

def _new_envelope(provider_id, environment, observed_at, app_name,
                  description, assessment_id, target_scopes,
                  authorization_objects=None):
    slug = _TOOLS[provider_id][1]
    return _envelope(
        assessment_id or "va-%s-import" % slug,
        "ctx-%s-import" % slug,
        app_name or "unknown application",
        description,
        target_scopes or [{"environment": environment,
                           "intended_use": "prototype_demo"}],
        observed_at,
        authorization_objects)


def _signal(env, provider_id, check_id, subject, environment, observed_at,
            raw, seq, notes=None):
    slug = _TOOLS[provider_id][1]
    signal_id = "sig-%s-%04d" % (slug, seq)
    signal = {
        "signal_id": signal_id,
        "source": {"tool": _TOOLS[provider_id][0], "check_id": check_id,
                   "provider_ref": provider_id},
        "subject": subject,
        "environment": environment,
        "observed_at": observed_at,
        "raw_ref": {"kind": "inline",
                    "value": canonical.bound_raw(raw, canonical.MAX_RAW_SIGNAL)},
    }
    if notes:
        signal["notes"] = notes
    env["signals"].append(signal)
    return signal_id


def _evidence(env, provider_id, seq, subject, environment, operation, scope,
              claim, direction, strength, observed_at, valid_until, signal_id,
              raw_value, run=None, authorization=None, coverage=None,
              side_effects=None, redaction=None):
    slug = _TOOLS[provider_id][1]
    item = {
        "evidence_id": "ev-%s-%04d" % (slug, seq),
        "provider": providers_mod.evidence_provider_block(
            provider_id, (run or {}).get("version")),
        "subject": subject,
        "environment": environment,
        "operation": operation,
        "scope": scope,
        "claim": claim,
        "direction": direction,
        "strength": strength,
        "observed_at": observed_at,
        "valid_until": valid_until,
        "signal_refs": [signal_id],
        "raw_result_ref": {"kind": "inline",
                           "value": canonical.bound_raw(raw_value)},
        "redaction": redaction or (
            "secret-bearing fields dropped at import; the rest redacted and "
            "bounded at %d chars" % canonical.MAX_RAW_EVIDENCE),
        "side_effects": side_effects or {"writes": False, "destructive": False,
                                         "external_accounts": False,
                                         "data_egress": False},
    }
    if authorization:
        item["authorization"] = authorization
    if coverage:
        item["coverage"] = coverage
    env["evidence"].append(item)
    return item


def _action(env, provider_id, key, observed_at, outcome, reason,
            control_ids=None, priority="high", owner="developer",
            success_evidence=None, seq=1):
    slug = _TOOLS[provider_id][1]
    action = {
        "action_id": "act-%s-%04d" % (slug, seq),
        "action_key": "%s-%s" % (slug, key),
        "revision": 1,
        "created_at": observed_at,
        "kind": "verify",
        "outcome": outcome,
        "reason": reason,
        "priority": priority,
        "urgency": "planned",
        "deadline": {
            "kind": "unknown",
            "rationale": ("The deadline depends on the confirmed target "
                          "environment and intended use; set it during review."),
            "reassess_trigger": {"kind": "context_change"},
        },
        "blocking_scope": [],
        "owner": {"role": owner},
        "state": "open",
        "state_history": [{"state": "open", "at": observed_at,
                           "by": "vibecheck %s import adapter" % slug}],
        "success_evidence": success_evidence or (
            "A completed run of this tool whose output was imported, or an "
            "equivalent recorded observation. A disappeared warning is never "
            "sufficient."),
    }
    if control_ids:
        action["control_refs"] = list(control_ids)
        action["reassess_control_ids"] = list(control_ids)
    env["actions"].append(action)
    return action


def _failure_action(env, provider_id, kind, detail, run, observed_at,
                    control_ids, partial_count, seq=0):
    """The one Action a failed, timed-out, cancelled or partial run produces."""
    name = _TOOLS[provider_id][0]
    stopped_early = kind in ("timeout", "cancelled")
    said = " (%s)" % detail if detail else ""
    if kind == "timeout":
        reason = ("The %s run timed out%s. Whatever it had not reached when it "
                  "stopped is uncovered, and an unfinished scan says nothing "
                  "about the part it never read." % (name, said))
    elif kind == "cancelled":
        reason = ("The %s run was cancelled%s. Its coverage is partial by "
                  "construction." % (name, said))
    elif kind == "unavailable":
        reason = ("%s is not installed%s, so this review has no result from "
                  "it. vibecheck does not install tools on a user's machine; "
                  "the gap stays open until somebody runs it." % (name, said))
    else:
        reason = ("The %s run did not produce a usable result%s."
                  % (name, said))
    if partial_count:
        reason += (" %d finding(s) %s were imported and are evidence about "
                   "themselves only; the absence of others is not evidence."
                   % (partial_count,
                      "from before the run stopped" if stopped_early
                      else "that did parse"))
    if kind != "unavailable":
        reason = "%s Command: %s" % (reason, _command_text(run))
    return _action(
        env, provider_id, kind, observed_at,
        outcome=("A completed %s run whose output is imported, or a recorded "
                 "equivalent observation for the controls it would have "
                 "covered." % name),
        reason=reason, control_ids=control_ids, seq=seq)


def _scope_prefix(run):
    """The provenance sentence every evidence scope from a run starts with."""
    parts = ["Command: %s." % _command_text(run)]
    note = (run or {}).get("scope_note")
    if note:
        parts.append(note)
    return " ".join(parts)


# -------------------------------------------------------- the common shape

def _import(provider_id, data, *, environment, now, app_name, assessment_id,
            target_scopes, run, subject, operation, description,
            findings_fn, clean_claim_numbers, egress_destinations=None,
            authorization=None, authorization_objects=None, parser=_parse,
            data_egress=False):
    """The shape every external import shares.

    ``findings_fn(env, parsed, ctx)`` emits the per-finding signals, evidence
    and triage actions and returns how many findings it saw. Everything around
    it — parsing, the five failure outcomes, the neutral clean run, the
    capability stamp — is the same for every tool on purpose: a new adapter
    that forgets to keep a timeout visible is not a thing this can express.
    """
    now_dt = _parse_now(now)
    observed_at = _iso(now_dt)
    valid_until = _iso(now_dt + datetime.timedelta(days=EVIDENCE_VALIDITY_DAYS))
    env = _new_envelope(provider_id, environment, observed_at, app_name,
                        description, assessment_id, target_scopes,
                        authorization_objects)

    parsed, parse_error = parser(data)
    failure = _run_failure(run, _embedded_error(parsed), parsed is not None)
    if failure is None and parse_error:
        failure = ("parse_error", parse_error)

    ctx = {
        "provider_id": provider_id,
        "environment": environment,
        "observed_at": observed_at,
        "valid_until": valid_until,
        "subject": subject,
        "operation": operation,
        "run": run or {},
        "authorization": authorization,
        "scope_prefix": _scope_prefix(run),
    }

    count = 0
    if parsed is not None:
        count = findings_fn(env, parsed, ctx)

    if failure is not None:
        kind, detail = failure
        # A failed run that still parsed keeps what it found: partial results
        # are results. A failed run with nothing parsed produces no evidence at
        # all, which is not the same as a clean one.
        _failure_action(env, provider_id, kind, detail, run, observed_at,
                        _all_declared_claim(provider_id)["control_ids"], count)
    elif count == 0:
        claim = _claim(clean_claim_numbers)
        signal_id = _signal(env, provider_id, "clean_run", subject, environment,
                            observed_at, "no findings reported", 1)
        _evidence(env, provider_id, 1, subject, environment, operation,
                  scope=("%s No findings were reported for the rules and scope "
                         "this run covered. %s" % (ctx["scope_prefix"], _R3_NOTE)),
                  claim=claim, direction="neutral", strength="indicative",
                  observed_at=observed_at, valid_until=valid_until,
                  signal_id=signal_id, raw_value="no findings reported",
                  run=run, authorization=authorization,
                  side_effects={"writes": False, "destructive": False,
                                "external_accounts": False,
                                "data_egress": bool(data_egress)},
                  redaction="clean run; nothing to redact")

    _attach_capability(env, provider_id, (run or {}).get("version"),
                       egress_destinations=egress_destinations,
                       network_targets=egress_destinations)
    return env


def import_tool_unavailable(provider_id, environment="developer_only",
                            now=None, app_name=None, assessment_id=None,
                            target_scopes=None, missing_tools=None):
    """An envelope for a provider whose tool is not installed.

    An uninstalled specialist tool is a coverage gap with a name, not a silent
    absence: this records which controls nobody looked at and what would close
    that, and produces no evidence whatsoever.
    """
    now_dt = _parse_now(now)
    observed_at = _iso(now_dt)
    missing = missing_tools or tool_availability(provider_id)["missing_tools"]
    env = _new_envelope(
        provider_id, environment, observed_at, app_name,
        "Recorded gap: %s was not available for this review."
        % _TOOLS[provider_id][0],
        assessment_id, target_scopes)
    control_ids = _all_declared_claim(provider_id)["control_ids"]
    _failure_action(
        env, provider_id, "unavailable",
        "missing: %s" % ", ".join(missing or required_tools(provider_id)),
        run_record(), observed_at, control_ids, 0)
    # _attach_capability derives the controls from evidence, and there is none
    # here on purpose. The record still belongs in the envelope: it is what
    # says which controls the missing tool would have covered.
    env.setdefault("providers", []).append(
        providers_mod.instantiate(provider_id, control_ids=control_ids))
    return env


# --------------------------------------------------------------- Gitleaks

def _secret_scan_numbers(rule, file_path):
    """Which secrets controls one credential hit bears on.

    A history hit always refutes "no secrets in the repository history". It
    additionally refutes the client-bundle controls only when what was found
    says so — a provider key rule, or a file that ships to the browser —
    because "a secret exists somewhere in the history" and "a secret ships to
    every visitor" are different findings with different urgency.
    """
    numbers = [9]
    haystack = "%s %s" % (rule or "", file_path or "")
    if _matches(haystack, ("aws", "stripe", "openai", "anthropic", "google",
                           "supabase", "service-role", "service_role",
                           "sendgrid", "twilio", "slack", "github",
                           "api-key", "api_key", "apikey", "token")):
        numbers.append(8)
    if _matches(file_path or "", ("src/", "public/", "app/", "components/",
                                  "pages/", "static/", "client", "frontend",
                                  ".jsx", ".tsx", ".vue", ".svelte",
                                  ".env.local", "dist/", "build/")):
        numbers.append(7)
    return sorted(set(numbers))


def import_gitleaks_json(data, run=None, environment="developer_only",
                         now=None, app_name=None, assessment_id=None,
                         target_scopes=None, repo_locator="."):
    """Gitleaks `detect --report-format json` output → envelope.

    Gitleaks reports one object per match over the commits it was pointed at.
    Every match is indicative: the ruleset is regex plus entropy, so a hit is
    material a reviewer confirms and a miss is not an absence of secrets.
    """
    subject = {"kind": "repo", "locator": repo_locator}

    def findings(env, parsed, ctx):
        rows = parsed if isinstance(parsed, list) else (
            [] if _embedded_error(parsed) else [parsed])
        for seq, finding in enumerate(rows, 1):
            if not isinstance(finding, dict):
                continue
            rule = finding.get("RuleID") or finding.get("Description") or "secret"
            file_path = finding.get("File") or repo_locator
            commit = finding.get("Commit") or "working tree"
            line = finding.get("StartLine") or "?"
            raw = _redacted_finding(finding)
            file_subject = {"kind": "file", "locator": str(file_path)}
            signal_id = _signal(env, GITLEAKS_PROVIDER, str(rule), file_subject,
                                ctx["environment"], ctx["observed_at"], raw, seq)
            claim = _claim_within(GITLEAKS_PROVIDER,
                                  _secret_scan_numbers(rule, file_path))
            _evidence(
                env, GITLEAKS_PROVIDER, seq, file_subject, ctx["environment"],
                ctx["operation"],
                scope=("%s Gitleaks rule %s matched %s line %s in commit %s. "
                       "A pattern-and-entropy match is material for a reviewer: "
                       "it does not establish that the credential is live, and "
                       "rotating it is a separate step from removing it from "
                       "history."
                       % (ctx["scope_prefix"], rule, file_path, line, commit)),
                claim=claim, direction="refutes", strength="indicative",
                observed_at=ctx["observed_at"], valid_until=ctx["valid_until"],
                signal_id=signal_id,
                raw_value="rule %s at %s:%s" % (rule, file_path, line),
                run=ctx["run"])
        return len([row for row in rows if isinstance(row, dict)])

    return _import(GITLEAKS_PROVIDER, data, environment=environment, now=now,
                   app_name=app_name, assessment_id=assessment_id,
                   target_scopes=target_scopes, run=run, subject=subject,
                   operation="git_history_scan",
                   description="Imported from Gitleaks secret scanner output.",
                   findings_fn=findings, clean_claim_numbers=[7, 8, 9])


# ------------------------------------------------------------- TruffleHog

def import_trufflehog_json(data, run=None, environment="developer_only",
                           now=None, app_name=None, assessment_id=None,
                           target_scopes=None, repo_locator="."):
    """TruffleHog `git --json` output (JSON lines) → envelope.

    A verified TruffleHog hit means the credential was accepted by the provider
    it belongs to, which is a stronger statement than a pattern match — but it
    is still indicative here, because the registry caps this provider there and
    a live key is not by itself the control's whole question.
    """
    subject = {"kind": "repo", "locator": repo_locator}

    def findings(env, parsed, ctx):
        rows = [row for row in (parsed or []) if isinstance(row, dict)
                and not _embedded_error(row)]
        for seq, finding in enumerate(rows, 1):
            detector = (finding.get("DetectorName")
                        or finding.get("detector_name") or "credential")
            git = (((finding.get("SourceMetadata") or {}).get("Data") or {})
                   .get("Git") or {})
            file_path = git.get("file") or repo_locator
            commit = git.get("commit") or "working tree"
            verified = bool(finding.get("Verified"))
            raw = _redacted_finding(finding)
            file_subject = {"kind": "file", "locator": str(file_path)}
            signal_id = _signal(env, TRUFFLEHOG_PROVIDER, str(detector),
                                file_subject, ctx["environment"],
                                ctx["observed_at"], raw, seq)
            claim = _claim_within(TRUFFLEHOG_PROVIDER,
                                  _secret_scan_numbers(detector, file_path))
            _evidence(
                env, TRUFFLEHOG_PROVIDER, seq, file_subject, ctx["environment"],
                ctx["operation"],
                scope=("%s TruffleHog detector %s matched %s in commit %s "
                       "(verified against the provider: %s). %s"
                       % (ctx["scope_prefix"], detector, file_path, commit,
                          "yes" if verified else "no",
                          "A verified hit means the credential was live at scan "
                          "time and needs rotating, not only removing."
                          if verified else
                          "An unverified hit is a pattern match a reviewer "
                          "confirms.")),
                claim=claim, direction="refutes", strength="indicative",
                observed_at=ctx["observed_at"], valid_until=ctx["valid_until"],
                signal_id=signal_id,
                raw_value="detector %s in %s" % (detector, file_path),
                run=ctx["run"])
        return len(rows)

    return _import(TRUFFLEHOG_PROVIDER, data, environment=environment, now=now,
                   app_name=app_name, assessment_id=assessment_id,
                   target_scopes=target_scopes, run=run, subject=subject,
                   operation="git_history_scan",
                   description="Imported from TruffleHog credential scanner "
                               "output.",
                   findings_fn=findings, clean_claim_numbers=[7, 8, 9],
                   parser=_parse_jsonl)


# ------------------------------------------------------------ OSV-Scanner

def import_osv_scanner_json(data, run=None, environment="developer_only",
                            now=None, app_name=None, assessment_id=None,
                            target_scopes=None, repo_locator="."):
    """OSV-Scanner `--format json` output → envelope.

    One evidence per (package, advisory). An advisory is about a declared
    dependency version, not about whether the vulnerable path is reachable from
    this application, which is why the scope says so and the strength is
    indicative.
    """
    subject = {"kind": "repo", "locator": repo_locator}

    def findings(env, parsed, ctx):
        results = (parsed.get("results") if isinstance(parsed, dict)
                   else parsed) or []
        seq = 0
        for result in results:
            if not isinstance(result, dict):
                continue
            source = result.get("source") or {}
            source_path = (source.get("path") if isinstance(source, dict)
                           else str(source)) or repo_locator
            for entry in result.get("packages") or []:
                package = entry.get("package") or {}
                name = package.get("name") or "unknown package"
                version = package.get("version") or "unknown version"
                locator = "%s@%s" % (name, version)
                for vuln in entry.get("vulnerabilities") or []:
                    seq += 1
                    vuln_id = vuln.get("id") or "advisory"
                    summary = (vuln.get("summary") or vuln.get("details")
                               or "no summary supplied")
                    dep_subject = {"kind": "dependency", "locator": locator}
                    signal_id = _signal(
                        env, OSV_SCANNER_PROVIDER, str(vuln_id), dep_subject,
                        ctx["environment"], ctx["observed_at"],
                        _redacted_finding(vuln), seq)
                    _evidence(
                        env, OSV_SCANNER_PROVIDER, seq, dep_subject,
                        ctx["environment"], ctx["operation"],
                        scope=("%s OSV advisory %s affects %s as declared in "
                               "%s: %s. The advisory is about the declared "
                               "version; whether this application reaches the "
                               "vulnerable code is a separate question."
                               % (ctx["scope_prefix"], vuln_id, locator,
                                  source_path,
                                  canonical.bound_raw(str(summary), 300))),
                        claim=_claim_within(OSV_SCANNER_PROVIDER, [51]),
                        direction="refutes", strength="indicative",
                        observed_at=ctx["observed_at"],
                        valid_until=ctx["valid_until"], signal_id=signal_id,
                        raw_value="%s in %s" % (vuln_id, locator),
                        run=ctx["run"],
                        side_effects={"writes": False, "destructive": False,
                                      "external_accounts": False,
                                      "data_egress": True})
        return seq

    return _import(OSV_SCANNER_PROVIDER, data, environment=environment, now=now,
                   app_name=app_name, assessment_id=assessment_id,
                   target_scopes=target_scopes, run=run, subject=subject,
                   operation="dependency_audit",
                   description="Imported from OSV-Scanner dependency audit "
                               "output.",
                   findings_fn=findings, clean_claim_numbers=[51, 52],
                   egress_destinations=["osv.dev"], data_egress=True)


# ------------------------------------------------------------------ Trivy

def import_trivy_json(data, run=None, environment="developer_only", now=None,
                      app_name=None, assessment_id=None, target_scopes=None,
                      repo_locator="."):
    """Trivy `fs`/`image --format json` output → envelope.

    Vulnerability rows refute the dependency-vulnerability control; licence
    rows refute the licence-compatibility control. They are kept apart because
    a CVE says nothing about licensing and a GPL notice says nothing about
    exploitability.
    """
    subject = {"kind": "repo", "locator": repo_locator}

    def findings(env, parsed, ctx):
        results = (parsed.get("Results") if isinstance(parsed, dict)
                   else parsed) or []
        seq = 0
        for result in results:
            if not isinstance(result, dict):
                continue
            target = result.get("Target") or repo_locator
            for vuln in result.get("Vulnerabilities") or []:
                seq += 1
                vuln_id = vuln.get("VulnerabilityID") or "advisory"
                package = vuln.get("PkgName") or "unknown package"
                version = vuln.get("InstalledVersion") or "unknown version"
                severity = vuln.get("Severity") or "UNKNOWN"
                title = vuln.get("Title") or vuln.get("Description") or ""
                locator = "%s@%s" % (package, version)
                dep_subject = {"kind": "dependency", "locator": locator}
                signal_id = _signal(env, TRIVY_PROVIDER, str(vuln_id),
                                    dep_subject, ctx["environment"],
                                    ctx["observed_at"],
                                    _redacted_finding(vuln), seq)
                _evidence(
                    env, TRIVY_PROVIDER, seq, dep_subject, ctx["environment"],
                    ctx["operation"],
                    scope=("%s Trivy reports %s (%s) against %s in %s: %s. "
                           "Severity is the advisory's, not this application's: "
                           "exploitability here is unestablished."
                           % (ctx["scope_prefix"], vuln_id, severity, locator,
                              target, canonical.bound_raw(str(title), 300))),
                    claim=_claim_within(TRIVY_PROVIDER, [51]),
                    direction="refutes", strength="indicative",
                    observed_at=ctx["observed_at"],
                    valid_until=ctx["valid_until"], signal_id=signal_id,
                    raw_value="%s [%s] in %s" % (vuln_id, severity, locator),
                    run=ctx["run"],
                    side_effects={"writes": False, "destructive": False,
                                  "external_accounts": False,
                                  "data_egress": True})
            for licence in result.get("Licenses") or []:
                seq += 1
                name = licence.get("Name") or "unknown licence"
                package = licence.get("PkgName") or "unknown package"
                severity = licence.get("Severity") or "UNKNOWN"
                dep_subject = {"kind": "dependency", "locator": str(package)}
                signal_id = _signal(env, TRIVY_PROVIDER, str(name), dep_subject,
                                    ctx["environment"], ctx["observed_at"],
                                    _redacted_finding(licence), seq)
                _evidence(
                    env, TRIVY_PROVIDER, seq, dep_subject, ctx["environment"],
                    ctx["operation"],
                    scope=("%s Trivy flags licence %s on %s (%s) in %s. "
                           "Whether that licence is compatible with how this "
                           "application is distributed is a decision, not a "
                           "scan result."
                           % (ctx["scope_prefix"], name, package, severity,
                              target)),
                    claim=_claim_within(TRIVY_PROVIDER, [54]),
                    direction="refutes", strength="indicative",
                    observed_at=ctx["observed_at"],
                    valid_until=ctx["valid_until"], signal_id=signal_id,
                    raw_value="licence %s on %s" % (name, package),
                    run=ctx["run"],
                    side_effects={"writes": False, "destructive": False,
                                  "external_accounts": False,
                                  "data_egress": True})
        return seq

    return _import(TRIVY_PROVIDER, data, environment=environment, now=now,
                   app_name=app_name, assessment_id=assessment_id,
                   target_scopes=target_scopes, run=run, subject=subject,
                   operation="dependency_audit",
                   description="Imported from Trivy scanner output.",
                   findings_fn=findings, clean_claim_numbers=[51, 52, 54],
                   egress_destinations=["the Trivy vulnerability database"],
                   data_egress=True)


# ---------------------------------------------------------------- Semgrep

def _sast_finding(env, provider_id, seq, ctx, rule_id, file_path, message,
                  detail, table=_SAST_RULES):
    """One SAST alert: mapped evidence, or a triage Action when unmapped.

    The claim comes from the rule, intersected with what the provider declares.
    A rule this map does not recognize is not silently filed under "input
    validation": it becomes an open Action naming the rule, because a claim
    nobody can trace back to a control is worse than an admitted gap.
    """
    file_subject = {"kind": "file", "locator": str(file_path)}
    haystack = "%s %s" % (rule_id, message)
    signal_id = _signal(env, provider_id, str(rule_id), file_subject,
                        ctx["environment"], ctx["observed_at"], detail, seq)
    claim = _claim_within(provider_id, _rule_numbers(haystack, table))
    if claim is None:
        _action(env, provider_id, "triage-%04d" % seq, ctx["observed_at"],
                outcome=("A reviewer decides which control rule %s bears on, "
                         "and records the result." % rule_id),
                reason=("%s reported %s in %s, and vibecheck cannot map that "
                        "rule to a control this provider declares. It is "
                        "recorded as a signal and left for triage rather than "
                        "filed under a control it may not belong to."
                        % (_TOOLS[provider_id][0], rule_id, file_path)),
                priority="moderate", seq=seq)
        return
    _evidence(
        env, provider_id, seq, file_subject, ctx["environment"],
        ctx["operation"],
        scope=("%s %s rule %s matched %s: %s. Static analysis reads the source, "
               "not the deployment, so it fills no authorization coverage cell "
               "and a reviewer confirms the path before it is a finding."
               % (ctx["scope_prefix"], _TOOLS[provider_id][0], rule_id,
                  file_path, canonical.bound_raw(str(message), 300))),
        claim=claim, direction="refutes", strength="indicative",
        observed_at=ctx["observed_at"], valid_until=ctx["valid_until"],
        signal_id=signal_id,
        raw_value="%s in %s" % (rule_id, file_path), run=ctx["run"])


def import_semgrep_json(data, run=None, environment="developer_only", now=None,
                        app_name=None, assessment_id=None, target_scopes=None,
                        repo_locator="."):
    """Semgrep `scan --json` output → envelope."""
    subject = {"kind": "repo", "locator": repo_locator}

    def findings(env, parsed, ctx):
        results = (parsed.get("results") if isinstance(parsed, dict)
                   else parsed) or []
        seq = 0
        for result in results:
            if not isinstance(result, dict):
                continue
            seq += 1
            extra = result.get("extra") or {}
            _sast_finding(
                env, SEMGREP_PROVIDER, seq, ctx,
                rule_id=result.get("check_id") or "semgrep rule",
                file_path=result.get("path") or repo_locator,
                message=extra.get("message") or "",
                detail=_redacted_finding(result, extra_drop=("lines",)))
        return seq

    return _import(SEMGREP_PROVIDER, data, environment=environment, now=now,
                   app_name=app_name, assessment_id=assessment_id,
                   target_scopes=target_scopes, run=run, subject=subject,
                   operation="sast_code_scan",
                   description="Imported from Semgrep Community Edition "
                               "output.",
                   findings_fn=findings,
                   clean_claim_numbers=[28, 29, 30, 32, 42, 77])


# ----------------------------------------------------------------- CodeQL

def import_codeql_sarif(data, run=None, environment="developer_only", now=None,
                        app_name=None, assessment_id=None, target_scopes=None,
                        repo_locator="."):
    """CodeQL SARIF 2.1.0 output → envelope."""
    subject = {"kind": "repo", "locator": repo_locator}

    def findings(env, parsed, ctx):
        if not isinstance(parsed, dict):
            return 0
        seq = 0
        for sarif_run in parsed.get("runs") or []:
            if not isinstance(sarif_run, dict):
                continue
            for result in sarif_run.get("results") or []:
                seq += 1
                locations = result.get("locations") or []
                file_path = repo_locator
                if locations:
                    physical = (locations[0].get("physicalLocation") or {})
                    file_path = ((physical.get("artifactLocation") or {})
                                 .get("uri") or repo_locator)
                _sast_finding(
                    env, CODEQL_PROVIDER, seq, ctx,
                    rule_id=result.get("ruleId") or "codeql query",
                    file_path=file_path,
                    message=(result.get("message") or {}).get("text") or "",
                    detail=_redacted_finding(result))
        return seq

    return _import(CODEQL_PROVIDER, data, environment=environment, now=now,
                   app_name=app_name, assessment_id=assessment_id,
                   target_scopes=target_scopes, run=run, subject=subject,
                   operation="sast_code_scan",
                   description="Imported from CodeQL SARIF output.",
                   findings_fn=findings,
                   clean_claim_numbers=[28, 29, 30, 32])


# ----------------------------------------------------- Codex Security

def import_codex_security_sarif(data, run=None, environment="developer_only",
                                now=None, app_name=None, assessment_id=None,
                                target_scopes=None, repo_locator="."):
    """Codex Security SARIF output → envelope.

    Codex Security produces a findings.json with file/line locations and a
    confidence for each finding, and can also emit SARIF 2.1.0. When no SARIF
    runs are present the results stay attributable to the source reading and
    are imported neutrally rather than as a control-wide claim.
    """
    subject = {"kind": "repo", "locator": repo_locator}

    def findings(env, parsed, ctx):
        if not isinstance(parsed, dict):
            return 0
        seq = 0
        for sarif_run in parsed.get("runs") or []:
            if not isinstance(sarif_run, dict):
                continue
            for result in sarif_run.get("results") or []:
                seq += 1
                locations = result.get("locations") or []
                file_path = repo_locator
                if locations:
                    physical = (locations[0].get("physicalLocation") or {})
                    file_path = ((physical.get("artifactLocation") or {})
                                 .get("uri") or repo_locator)
                _sast_finding(
                    env, CODEX_SECURITY_PROVIDER, seq, ctx,
                    rule_id=result.get("ruleId") or "codex security finding",
                    file_path=file_path,
                    message=(result.get("message") or {}).get("text") or "",
                    detail=_redacted_finding(result))
        return seq

    return _import(CODEX_SECURITY_PROVIDER, data,
                   environment=environment, now=now,
                   app_name=app_name, assessment_id=assessment_id,
                   target_scopes=target_scopes, run=run, subject=subject,
                   operation="sast_code_scan",
                   description="Imported from Codex Security SARIF output.",
                   findings_fn=findings,
                   clean_claim_numbers=[28, 29, 30, 32])


# ------------------------------------------------------------- OWASP ZAP

def import_owasp_zap_json(data, target_url, authorized_by, run=None,
                          environment="private_test", now=None, app_name=None,
                          assessment_id=None, target_scopes=None,
                          authorization_scope=None, granted_at=None):
    """OWASP ZAP JSON report → envelope.

    ``target_url`` and ``authorized_by`` are positional on purpose. ZAP sends
    traffic at somebody's deployment; an import that cannot say which target
    was scanned or who authorized it has no business producing evidence, so
    this refuses rather than defaulting ("do not scan a network
    target without explicit authorization and resolved scope").
    """
    if not target_url:
        raise ValueError("target_url is required: DAST evidence has to name "
                         "the deployment it was observed against")
    if not authorized_by:
        raise ValueError("authorized_by is required: a DAST run against a "
                         "target nobody authorized is not importable evidence")
    now_dt = _parse_now(now)
    authorization = {
        "authorized_by": authorized_by,
        "granted_at": granted_at or _iso(now_dt),
        "scope": authorization_scope or (
            "explicitly authorized OWASP ZAP scan of %s in %s"
            % (target_url, environment)),
    }
    subject = {"kind": "deployment", "locator": target_url}

    def findings(env, parsed, ctx):
        alerts = []
        if isinstance(parsed, dict):
            for site in parsed.get("site") or []:
                if isinstance(site, dict):
                    alerts.extend(site.get("alerts") or [])
            if not alerts and isinstance(parsed.get("alerts"), list):
                alerts = parsed["alerts"]
        elif isinstance(parsed, list):
            alerts = parsed
        seq = 0
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            seq += 1
            plugin = str(alert.get("pluginid") or alert.get("pluginId")
                         or "alert")
            name = alert.get("alert") or alert.get("name") or "ZAP alert"
            risk = alert.get("riskdesc") or alert.get("risk") or "unknown risk"
            confidence = alert.get("confidence") or "unstated"
            endpoint = {"kind": "endpoint", "locator": target_url}
            signal_id = _signal(env, ZAP_PROVIDER, plugin, endpoint,
                                ctx["environment"], ctx["observed_at"],
                                _redacted_finding(alert, ("instances",)), seq)
            claim = _claim_within(ZAP_PROVIDER,
                                  _rule_numbers("%s %s" % (name, plugin),
                                                _ZAP_RULES))
            if claim is None:
                _action(env, ZAP_PROVIDER, "triage-%04d" % seq,
                        ctx["observed_at"],
                        outcome=("A reviewer decides which control ZAP alert "
                                 "%s (%s) bears on." % (plugin, name)),
                        reason=("ZAP reported %r against %s and vibecheck "
                                "cannot map that alert to a control this "
                                "provider declares." % (name, target_url)),
                        priority="moderate", seq=seq)
                continue
            _evidence(
                env, ZAP_PROVIDER, seq, endpoint, ctx["environment"],
                ctx["operation"],
                scope=("%s ZAP alert %s (%s, risk %s, ZAP confidence %s) "
                       "against %s. Observed on the deployment as it answered "
                       "this run; a baseline scan reaches the routes it "
                       "crawled and says nothing about the rest."
                       % (ctx["scope_prefix"], plugin, name, risk, confidence,
                          target_url)),
                claim=claim, direction="refutes", strength="indicative",
                observed_at=ctx["observed_at"], valid_until=ctx["valid_until"],
                signal_id=signal_id, raw_value="%s: %s" % (plugin, name),
                run=ctx["run"], authorization=ctx["authorization"],
                side_effects={"writes": False, "destructive": False,
                              "external_accounts": False, "data_egress": True})
        return seq

    return _import(ZAP_PROVIDER, data, environment=environment, now=now,
                   app_name=app_name or target_url,
                   assessment_id=assessment_id, target_scopes=target_scopes,
                   run=run, subject=subject, operation="dast_web_scan",
                   description="Imported from an authorized OWASP ZAP scan of "
                               "%s." % target_url,
                   findings_fn=findings,
                   clean_claim_numbers=[14, 28, 30, 42, 44, 45],
                   egress_destinations=[target_url],
                   authorization=authorization, data_egress=True)


# ------------------------------------------------------------- Playwright

#: Which control a two-account assertion is about, from the actor it used.
_ACTOR_CONTROL = {
    "anonymous": 14,
    "other_account": 13,
    "other_tenant_member": 15,
    "unprivileged_account": 16,
}

_CELL_OPERATIONS = ("read", "create", "update", "delete")

#: Playwright statuses that say nothing about the application: the run did not
#: get far enough to observe a decision, so the cell is inconclusive rather
#: than denied. A timed-out assertion is not a refused request.
_INDECISIVE_STATUSES = ("timedout", "timed_out", "interrupted", "skipped",
                        "flaky", "unknown")


def _playwright_cases(parsed):
    """Flat list of assertions from either a plain list or a Playwright report.

    The JSON reporter nests specs inside arbitrarily deep suites; a hand-written
    fixture is usually a flat list. Both are accepted because both are what
    people actually have.
    """
    if isinstance(parsed, list):
        return [case for case in parsed if isinstance(case, dict)]
    if not isinstance(parsed, dict):
        return []
    if isinstance(parsed.get("tests"), list):
        return [case for case in parsed["tests"] if isinstance(case, dict)]

    cases = []

    def walk(suite):
        for spec in suite.get("specs") or []:
            statuses = [test.get("status") for test in spec.get("tests") or []]
            if not statuses:
                statuses = [spec.get("status")
                            if spec.get("ok") is None
                            else ("passed" if spec.get("ok") else "failed")]
            case = {key: value for key, value in spec.items()
                    if key not in ("tests", "specs", "suites")}
            case["status"] = statuses[0]
            cases.append(case)
        for child in suite.get("suites") or []:
            walk(child)

    for suite in parsed.get("suites") or []:
        if isinstance(suite, dict):
            walk(suite)
    return cases


def _playwright_observation(case):
    """(observed, note) for one assertion.

    An assertion carries two separable things: what it expected and what
    happened. ``expects`` defaults to ``denied`` because that is what a
    two-account authorization flow asserts; a suite that asserts an *allowed*
    path says so and gets read the other way round. A failure of an
    expected-allowed assertion is deliberately inconclusive, not "denied": the
    request may equally have hit an application error.
    """
    stated = str(case.get("observed") or "").lower()
    if stated in ("denied", "allowed", "inconclusive"):
        return (stated, "the assertion recorded the outcome directly")
    status = str(case.get("status") or "passed").lower().replace("-", "_")
    if status in _INDECISIVE_STATUSES:
        return ("inconclusive",
                "the assertion ended %s, so no decision by the application was "
                "observed" % status)
    passed = status in ("passed", "expected", "ok")
    expects = str(case.get("expects") or "denied").lower()
    if expects == "allowed":
        return (("allowed", "the assertion expected access and got it")
                if passed else
                ("inconclusive",
                 "an expected-allowed assertion failed, which an authorization "
                 "refusal and an unrelated application error both produce"))
    return (("denied", "the assertion expected a refusal and got one")
            if passed else
            ("allowed", "the assertion expected a refusal and the request "
                        "succeeded"))


def import_playwright_json(data, target_url, authorized_by, run=None,
                           environment="private_test", now=None, app_name=None,
                           assessment_id=None, target_scopes=None,
                           authorization_objects=None,
                           authorization_scope=None, granted_at=None):
    """Playwright two-account flow results → envelope.

    Each assertion becomes one evidence about one route, one actor and one
    operation. It fills an authorization coverage cell only when the assertion
    names the object it touched (``object_ref``) and the run actually observed
    a decision — an assertion that says "cross-account access is refused"
    without saying refused *to what* observed something real and covers no cell
    (rule R20). Assertions with no authorization actor are read as core-flow
    tests instead.
    """
    if not target_url:
        raise ValueError("target_url is required: a browser flow's evidence "
                         "has to name the deployment it ran against")
    if not authorized_by:
        raise ValueError("authorized_by is required: driving somebody's "
                         "deployment with two test accounts needs an owner's "
                         "authorization on record")
    now_dt = _parse_now(now)
    authorization = {
        "authorized_by": authorized_by,
        "granted_at": granted_at or _iso(now_dt),
        "scope": authorization_scope or (
            "authorized two-account Playwright run against %s in %s"
            % (target_url, environment)),
    }
    subject = {"kind": "deployment", "locator": target_url}

    def findings(env, parsed, ctx):
        cases = _playwright_cases(parsed)
        for seq, case in enumerate(cases, 1):
            title = case.get("title") or "assertion %d" % seq
            actor = case.get("actor")
            operation = case.get("operation")
            object_ref = (case.get("object_ref") or case.get("object")
                          or case.get("route"))
            object_class = case.get("object_class") or "unclassified"
            observed, why = _playwright_observation(case)
            endpoint = {"kind": "endpoint",
                        "locator": str(object_ref or target_url)}
            signal_id = _signal(env, PLAYWRIGHT_PROVIDER, str(title), endpoint,
                                ctx["environment"], ctx["observed_at"],
                                _redacted_finding(case), seq)

            item_number = _ACTOR_CONTROL.get(actor)
            cell = None
            if (item_number is not None and operation in _CELL_OPERATIONS
                    and object_ref and observed != "inconclusive"):
                cell = {
                    "object_ref": str(object_ref),
                    "actor": actor,
                    "operation": operation,
                    "observed": observed,
                    "environment": ctx["environment"],
                    "note": "%s: %s" % (title, why),
                }
                if object_class:
                    cell["object_class"] = object_class
                if case.get("object_id"):
                    cell["object_id"] = str(case["object_id"])
                if case.get("instance"):
                    cell["instance"] = str(case["instance"])

            if item_number is None:
                # No authorization actor: a functional end-to-end assertion.
                numbers = [69]
                gap = ("The assertion names no authorization actor, so it is "
                       "read as a core-flow test and covers no authorization "
                       "cell.")
            else:
                numbers = [item_number, 70]
                gap = ("" if cell else
                       "It fills no authorization coverage cell: %s"
                       % ("the assertion does not name the object it touched"
                          if not object_ref else
                          "the observation was inconclusive"
                          if observed == "inconclusive" else
                          "the assertion does not name a read/create/update/"
                          "delete operation"))
            claim = _claim_within(PLAYWRIGHT_PROVIDER, numbers)
            if claim is None:
                _action(env, PLAYWRIGHT_PROVIDER, "triage-%04d" % seq,
                        ctx["observed_at"],
                        outcome=("A reviewer decides what assertion %r "
                                 "establishes." % title),
                        reason=("The assertion maps to no control this "
                                "provider declares."), priority="moderate",
                        seq=seq)
                continue

            direction = {"denied": "supports", "allowed": "refutes",
                         "inconclusive": "neutral"}[observed]
            # Decisive is for an observation that settles its own cell. Without
            # a cell there is nothing settled, and an inconclusive run settles
            # nothing by definition.
            strength = "decisive" if cell else "indicative"
            writes = operation in ("create", "update", "delete")
            _evidence(
                env, PLAYWRIGHT_PROVIDER, seq, endpoint, ctx["environment"],
                ctx["operation"],
                scope=("%s Assertion %r ran against %s as %s and the "
                       "application %s the %s. %s %s"
                       % (ctx["scope_prefix"], title, object_ref or target_url,
                          actor or "the signed-in test account", observed,
                          operation or "requested interaction", why, gap)).strip(),
                claim=claim, direction=direction, strength=strength,
                observed_at=ctx["observed_at"], valid_until=ctx["valid_until"],
                signal_id=signal_id,
                raw_value="%s: %s" % (title, case.get("status") or observed),
                run=ctx["run"], authorization=ctx["authorization"],
                coverage=[cell] if cell else None,
                side_effects={"writes": writes,
                              "destructive": operation == "delete",
                              "external_accounts": False, "data_egress": True})
        return len(cases)

    return _import(PLAYWRIGHT_PROVIDER, data, environment=environment, now=now,
                   app_name=app_name or target_url,
                   assessment_id=assessment_id, target_scopes=target_scopes,
                   run=run, subject=subject,
                   operation="browser_two_account_flow",
                   description="Imported from an authorized Playwright "
                               "two-account run against %s." % target_url,
                   findings_fn=findings, clean_claim_numbers=[69, 70],
                   egress_destinations=[target_url],
                   authorization=authorization,
                   authorization_objects=authorization_objects,
                   data_egress=True)


# -------------------------------------------------------------------- CLI

_IMPORTERS = {
    "gitleaks": import_gitleaks_json,
    "trufflehog": import_trufflehog_json,
    "osv-scanner": import_osv_scanner_json,
    "trivy": import_trivy_json,
    "semgrep": import_semgrep_json,
    "codeql": import_codeql_sarif,
    "codex-security": import_codex_security_sarif,
    "zap": import_owasp_zap_json,
    "playwright": import_playwright_json,
}

_USAGE = """usage:
  python3 scripts/external_adapters.py --availability [--json]
  python3 scripts/external_adapters.py --import TOOL FILE [options]

TOOL is one of: %s

options for --import:
  --environment ENV     environment the output was observed in
  --target-url URL      required for zap and playwright
  --authorized-by WHO   required for zap and playwright
  --command "CMD"       the exact command the output came from
  --timed-out           the run hit its timeout (partial results kept)
  --cancelled           the run was cancelled
  --exit-code N         the tool's exit status

Reads no network and runs no tool: it imports output you already have.
""" % ", ".join(sorted(_IMPORTERS))


def _cli(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        sys.stdout.write(_USAGE)
        return 0

    if argv[0] == "--availability":
        report = availability_report()
        if "--json" in argv:
            sys.stdout.write(json.dumps(report, indent=2) + "\n")
            return 0
        for entry in report:
            sys.stdout.write(
                "%-9s %-28s %s\n"
                % ("available" if entry["available"] else "MISSING",
                   entry["provider_id"],
                   ", ".join(entry["requires_tools"]) or "-"))
        sys.stdout.write(
            "\nNothing is installed by vibecheck. A missing tool is a recorded "
            "coverage gap, not an error.\n")
        return 0

    if argv[0] != "--import" or len(argv) < 3:
        sys.stderr.write(_USAGE)
        return 2

    tool, path = argv[1], argv[2]
    if tool not in _IMPORTERS:
        sys.stderr.write("unknown tool %r\n%s" % (tool, _USAGE))
        return 2

    options, rest = {}, argv[3:]
    flags = {"--timed-out": "timed_out", "--cancelled": "cancelled"}
    index = 0
    while index < len(rest):
        token = rest[index]
        if token in flags:
            options[flags[token]] = True
            index += 1
            continue
        if index + 1 >= len(rest):
            sys.stderr.write("missing value for %s\n" % token)
            return 2
        options[token.lstrip("-").replace("-", "_")] = rest[index + 1]
        index += 2

    with open(path, encoding="utf-8") as handle:
        data = handle.read()

    run = run_record(
        command=(options["command"].split() if options.get("command")
                 else None),
        exit_code=(int(options["exit_code"]) if options.get("exit_code")
                   else None),
        timed_out=options.get("timed_out", False),
        cancelled=options.get("cancelled", False))

    kwargs = {"run": run}
    if options.get("environment"):
        kwargs["environment"] = options["environment"]
    if tool in ("zap", "playwright"):
        kwargs["target_url"] = options.get("target_url")
        kwargs["authorized_by"] = options.get("authorized_by")

    try:
        env = _IMPORTERS[tool](data, **kwargs)
    except ValueError as exc:
        sys.stderr.write("%s\n" % exc)
        return 2
    sys.stdout.write(json.dumps(env, indent=2, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(_cli())
