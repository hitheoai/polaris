"""Verified fixes for the problems Polaris finds (`polaris fix`).

Candidate fixes come from generators (a rule's own suggested edit, deterministic codemods), and
every one passes the same checks before a person sees it: it stays near the problem, a fresh
in-memory review no longer finds the problem and finds nothing new, and it fits the bounded
proposal the engineering pipeline can apply after approval. Behavioral tests are never run.
"""

from polaris.refactor.models import FIX_PLAN_FORMAT, FixItem, FixPlan

__all__ = ["FIX_PLAN_FORMAT", "FixItem", "FixPlan"]
