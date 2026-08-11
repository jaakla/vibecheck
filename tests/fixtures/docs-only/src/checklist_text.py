# -*- coding: utf-8 -*-
"""Prose about security controls. Contains no code that does any of it.

Regression fixture: an earlier scanner FAILed on text like this, because it
grepped for bare words instead of for call syntax and route context.
"""

ITEMS = [
    ("Authentication is a proven provider or library; no hand-rolled password "
     "hashing, session tokens or JWT schemes. Home-made primitives (md5/sha1 "
     "password hashes, Math.random tokens) are a serious red flag."),
    ("No provider key prefixes shipped to client (sk-, AKIA, service_role, etc.). "
     "Search the deployed bundle for service_role and report any hit."),
    ("Inbound webhooks verify signatures and timestamp; the endpoint rejects "
     "unrelated event types. Ask the developer to show webhook signature "
     "verification, e.g. the Stripe signing secret."),
    ("Server-side validation on all inputs. Ask which validation library is "
     "used and whether it runs on the server, not only in the browser."),
    ("Error tracking on client AND server; structured logs with correlation "
     "IDs; secrets and PII redacted. PostHog or Sentry are common choices."),
    ("Could users mistake AI-generated text for real human content? Art. 50 "
     "requires disclosure."),
]
