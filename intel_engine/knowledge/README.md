# Knowledge base — normalized, attributed OSINT store

Append-only, idempotent. Every fact carries provenance (source / collector /
observed_at / confidence / evidence_ref). Reports are generated FROM here, cited.

    entities/<type>/<value>.json     one record per entity, facts merged across sources
    relationships/edges.jsonl        one attributed edge per line
    evidence/<source>/<target>/<day>.json   raw cached payloads (attribution backing)

Populate:  python3 tools/kb/ingest_webpivot.py --kb knowledge cases/*/raw/*.json
Query:     python3 tools/kb/query.py --kb knowledge --shared
Stats:     python3 tools/kb/query.py --kb knowledge --stats
