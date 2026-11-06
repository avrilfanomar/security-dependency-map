"""Collector registry.

A collector is a module exposing::

    NAME = "apt"                    # unique, used by --only/--skip
    DESCRIPTION = "..."
    def applicable(ctx) -> (bool, reason)
    def collect(ctx, graph) -> Status

Collectors must never raise for missing tools or permissions; they return
``Status("skipped"|"partial", notes=[...])`` instead. Unexpected exceptions
are caught by the runner and recorded as ``error``.
"""

from __future__ import annotations

import importlib

# Order matters: later collectors may use ctx.shared data from earlier ones.
ORDER = [
    "host",
    "apt",
    "rpm",
    "snap",
    "flatpak",
    "lang",
    "unmanaged",
    "services",
    "firmware",
    "containers",
]


class Status:
    def __init__(self, status="ok", notes=None, stats=None):
        self.status = status
        self.notes = list(notes or [])
        self.stats = dict(stats or {})

    def partial(self, note):
        if self.status == "ok":
            self.status = "partial"
        self.notes.append(note)

    def note(self, note):
        self.notes.append(note)

    def to_dict(self):
        return {"status": self.status, "notes": self.notes, "stats": self.stats}


def load(name):
    return importlib.import_module("secdepmap.collectors." + name)


def all_collectors():
    return [load(n) for n in ORDER]
