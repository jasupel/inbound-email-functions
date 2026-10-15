# Inbound Email Functions

Google Cloud Functions for the inbound email processing pipeline. Each function is maintained and deployed independently from its own directory under `functions/`.

## Components

- `webhook-ingestor` — receives inbound email webhooks and publishes messages to Pub/Sub.
- `classifier-parser` — extracts text from email bodies and attachments.
- `extractor-engine` — extracts reported record data points.
- `deduplicator-linker` — detects duplicates, links related records, and persists new records.
