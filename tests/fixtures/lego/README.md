# lego CLI fixtures

Recorded help output of the pinned lego binary, used by the argv contract test
(`tests/acme/test_lego_contract.py`). A lego bump must regenerate these files deliberately.

## Provenance

| Field | Value |
|---|---|
| Image | `goacme/lego:v5.5.2@sha256:1944e8c36055beec47c7de6f15202b41128be75eea0ffa257f0c14d93c5155fd` |
| Binary | `/lego` (image entrypoint), `lego version 5.5.2 linux/amd64` |
| Captured | 2026-10-20 |
| Source tag | `github.com/go-acme/lego` `v5.5.2` (commit `452dc82113609488fb680acf8fc72712b1794f8d`) |

## Commands

Run from a scratch container; the repo image is not involved. `IMG` is the image reference above.

```sh
docker run --rm "$IMG" --help                > v5.5.2-help.txt
docker run --rm "$IMG" run --help            > v5.5.2-run-help.txt
docker run --rm "$IMG" dnshelp -c cloudflare > v5.5.2-dnshelp-cloudflare.txt
```

## Files

| File | Content |
|---|---|
| `v5.5.2-help.txt` | Top-level help: commands and global options |
| `v5.5.2-run-help.txt` | `run` help: every flag and its `LEGO_*` environment variable |
| `v5.5.2-dnshelp-cloudflare.txt` | Cloudflare provider credential and tuning variables |

There is no `renew` fixture: lego v5 has no `renew` command. `lego run` obtains a certificate when
none exists under `--path` for the certificate name, and renews it otherwise
(`cmd/cmd_run.go` in the source tag). `docker run "$IMG" renew --help` prints
`No help topic for 'renew'` and exits 1.

## Line endings

The files are LF-terminated as captured. `.gitattributes` applies `* text=auto`, so a Windows
checkout may convert them to CRLF; the contract test should normalise line endings before
comparing.
