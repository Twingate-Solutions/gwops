# Reference

Exact, exhaustive facts: every key, variable, route, event and limit. For how things work, see
[Architecture](../architecture/README.md); for complete deployments, see
[Recipes](../recipes/README.md); for one capability at a time, see [Guides](../guides/README.md);
for day-2 tasks, see [Operations](../operations/README.md).

| Page | Contents |
| --- | --- |
| [Seed reference](seed.md) | Every seed key: type, default, constraints, and whether an overlay may set it. |
| [Environment](environment.md) | Every environment variable: secrets, settings, what reaches the gateway and lego, what is ignored. |
| [Image](image.md) | Published image and tags, ports, mounts, `/data` layout, runtime user, healthcheck, build arguments, pinned binaries, network egress. |
| [Admin API](admin-api.md) | Every admin API route: authentication, request and response bodies, status codes, examples. |
| [Recording wire format](recording-wire-format.md) | The HTTP contract a recording receiver implements: request, response, delivery semantics, line types. |
| [Log events](log-events.md) | gwops log event names worth watching or alerting on, and what they mean. |
| [Known limitations](limitations.md) | What the image and the gateway binary do not do, and accepted risks. |
| [Development](development.md) | Development setup, lint, tests, pin checks and the rendered-config preflight. |
| [Glossary](glossary.md) | The terms used throughout the documentation. |
