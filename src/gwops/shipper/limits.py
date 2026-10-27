"""Size limits shared by the stderr reader, the spool, the shipper and the seed schema."""

# Longest gateway line delivered whole, excluding the newline (the ingest frame cap).
LINE_MAX_BYTES = 16 * 1024 * 1024

# Largest POST body the shipper assembles; one line at the cap always ships alone.
BATCH_MAX_BYTES = LINE_MAX_BYTES
