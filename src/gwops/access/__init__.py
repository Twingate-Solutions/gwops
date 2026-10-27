"""Group / security-policy access for gwops-created Twingate resources.

:mod:`~gwops.access.precedence` decides what access a resource should have (its own
``access`` block over ``twingate.resource_defaults``); :mod:`~gwops.access.resolve`
turns the resulting name/id references into Twingate ids.
"""
