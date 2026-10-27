"""The gwops PID-1 supervisor: owns the gateway child process and its lifecycle."""

from gwops.supervisor.childenv import child_env

__all__ = ["child_env"]
