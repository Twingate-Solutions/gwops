"""Shipper test fixtures: reuse the supervisor suite's fake-gateway launcher."""

from tests.supervisor.conftest import fake_gateway

__all__ = ["fake_gateway"]
