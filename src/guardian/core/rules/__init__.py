"""Rule engine: data-defined rules (YAML) evaluated against a parsed config.

* ``model``  - what a loaded rule looks like (scope + check)
* ``loader`` - reads and validates rule files
* ``engine`` - evaluates rules and produces findings
* ``custom`` - registry for checks written in Python
"""
