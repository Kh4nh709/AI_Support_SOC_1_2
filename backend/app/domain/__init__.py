"""
domain/ - Alert, Case and Incident: models, state constants, valid transitions.

The ONLY place a lifecycle state may change. Every transition validates that
it is legal and writes an audit event; an illegal transition raises rather
than silently passing.

Incident is modelled here but NOT implemented in this scope (Tier 3 is out of
scope - see design section 2), so the follow-on work does not have to redesign it.

Import rule: infrastructure. MUST NOT import any tier package.
"""
