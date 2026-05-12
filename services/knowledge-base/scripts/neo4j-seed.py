#!/usr/bin/env python3
"""Ledger → Neo4j projection seed script.

The S5 SQLite ledger is the source of truth.  Neo4j is a query projection derived
from ledger rows, not from Qdrant metadata.

Usage:
    cd services/knowledge-base
    source .venv/bin/activate
    python scripts/neo4j-seed.py [--ledger-url sqlite:///data/s5-ledger.sqlite] [--neo4j-uri bolt://localhost:7687]
"""

from __future__ import annotations

import argparse
import os
import sys
import time

_script_dir = os.path.dirname(os.path.abspath(__file__))
_service_root = os.path.dirname(_script_dir)
if _service_root not in sys.path:
    sys.path.insert(0, _service_root)

from app.ledger.repository import SQLiteLedgerRepository
from app.projections.ledger_projection import NEO4J_THREAT_PROJECTION, SCOPE_KEY, build_projection_bundle


def _resolve_ledger_url(ledger_url: str) -> str:
    prefix = "sqlite:///"
    if not ledger_url.startswith(prefix):
        return ledger_url
    raw_path = ledger_url[len(prefix):]
    if raw_path == ":memory:" or os.path.isabs(raw_path):
        return ledger_url
    return prefix + os.path.join(_service_root, raw_path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Ledger → Neo4j projection seed")
    parser.add_argument("--ledger-url", default="sqlite:///data/s5-ledger.sqlite", help="S5 SQLite ledger URL")
    parser.add_argument("--neo4j-uri", default="bolt://localhost:7687", help="Neo4j URI")
    parser.add_argument("--neo4j-user", default="neo4j")
    parser.add_argument("--neo4j-password", default="aegis-kb")
    parser.add_argument("--clear", action="store_true", help="기존 Neo4j threat projection 삭제 후 재적재")
    args = parser.parse_args()

    ledger_url = _resolve_ledger_url(args.ledger_url)
    print(f"[1/4] Ledger 연결: {ledger_url}", flush=True)
    repo = SQLiteLedgerRepository(ledger_url)
    repo.initialize()

    print("[2/4] Ledger-derived projection records 생성...", flush=True)
    t0 = time.time()
    bundle = build_projection_bundle(repo)
    t1 = time.time()
    print(
        f"  → Neo4j records={len(bundle.neo4j_records)} sourceHash={bundle.source_hash} ({t1 - t0:.1f}초)",
        flush=True,
    )

    print(f"[3/4] Neo4j 연결: {args.neo4j_uri}", flush=True)
    import neo4j
    driver = neo4j.GraphDatabase.driver(args.neo4j_uri, auth=(args.neo4j_user, args.neo4j_password))
    driver.verify_connectivity()

    if args.clear:
        print("  → 기존 위협 projection 노드 삭제...", flush=True)
        with driver.session() as session:
            for label in ["CWE", "CVE", "Attack", "CAPEC"]:
                session.run(f"MATCH (n:{label}) DETACH DELETE n")
        print("  → 삭제 완료", flush=True)

    print("[4/4] Neo4j projection 구축...", flush=True)
    from app.graphrag.neo4j_graph import Neo4jGraph

    graph = Neo4jGraph(driver)
    t2 = time.time()
    graph.load_from_records(bundle.neo4j_records)
    t3 = time.time()

    stats = graph.get_stats()
    repo.record_projection_job(
        projection_name=NEO4J_THREAT_PROJECTION,
        scope_key=SCOPE_KEY,
        state="completed",
        diagnostics=[],
        completed_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )
    repo.record_projection_state(
        projection_name=NEO4J_THREAT_PROJECTION,
        scope_key=SCOPE_KEY,
        state="ready",
        source_hash=bundle.source_hash,
        projection_version=bundle.projection_version,
        debt={},
        freshness={"status": "current", "recordCount": len(bundle.neo4j_records)},
    )

    print(f"\n  완료! ({t3 - t2:.1f}초)", flush=True)
    print(f"  Projection: {NEO4J_THREAT_PROJECTION}", flush=True)
    print(f"  Nodes: {stats['nodeCount']}", flush=True)
    print(f"  Edges: {stats['edgeCount']}", flush=True)
    print(f"  Source hash: {bundle.source_hash}", flush=True)
    driver.close()
    print("\n  Neo4j ledger-derived projection seed 완료.", flush=True)


if __name__ == "__main__":
    main()
