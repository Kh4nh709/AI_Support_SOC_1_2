"""
infra/ - Database, job queue, worker loop, auth, configuration.

Named infra (not platform) because "platform" shadows a Python standard
library module. Named at all (not "shared") because a package called shared
becomes a dumping ground - the failure mode a tier-based layout is prone to.

Scope is deliberately narrow: things that talk to the outside world or manage
process lifecycle. Business logic does not belong here.

Import rule: infrastructure. MUST NOT import any tier package.
"""
