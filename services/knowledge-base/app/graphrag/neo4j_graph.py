"""Neo4jGraph — Neo4j 기반 위협 지식 관계 그래프. RelationGraph 대체."""

from __future__ import annotations

import logging
from collections import defaultdict

import neo4j

logger = logging.getLogger(__name__)

_THREAT_LABELS = ("CWE", "CVE", "Attack", "CAPEC")
_THREAT_NODE_FILTER = " OR ".join(f"n:{label}" for label in _THREAT_LABELS)
_THREAT_EDGE_FILTER = " AND ".join(
    f"({alias}:CWE OR {alias}:CVE OR {alias}:Attack OR {alias}:CAPEC)"
    for alias in ("a", "b")
)

# source 값 → Neo4j 노드 레이블 매핑
_SOURCE_TO_LABEL = {
    "CWE": "CWE",
    "CVE": "CVE",
    "ATT&CK": "Attack",
    "CAPEC": "CAPEC",
}

# related_* 필드 → 관계 타입 + 대상 레이블
_REL_FIELD_MAP = {
    "related_cwe": ("RELATED_CWE", "CWE"),
    "related_cve": ("RELATED_CVE", "CVE"),
    "related_attack": ("RELATED_ATTACK", "Attack"),
    "related_capec": ("RELATED_CAPEC", "CAPEC"),
}

# 관계 타입 → get_related() 반환 키
_REL_TYPE_TO_KEY = {
    "RELATED_CWE": "cwe",
    "RELATED_CVE": "cve",
    "RELATED_ATTACK": "attack",
    "RELATED_CAPEC": "capec",
    "MAPS_CWE": "cwe",
    "MAPS_ATTACK": "attack",
}


class Neo4jGraph:
    """Neo4j-backed 위협 지식 관계 그래프.

    RelationGraph와 동일한 인터페이스(duck typing)를 제공하여
    KnowledgeAssembler 코드 변경 없이 교체 가능.
    """

    def __init__(self, driver: neo4j.Driver) -> None:
        self._driver = driver

    def close(self) -> None:
        self._driver.close()

    # --- RelationGraph 호환 인터페이스 ---

    @property
    def node_count(self) -> int:
        with self._driver.session() as session:
            result = session.run(
                f"MATCH (n) WHERE {_THREAT_NODE_FILTER} "
                "RETURN count(n) AS cnt"
            )
            return result.single()["cnt"]

    @property
    def edge_count(self) -> int:
        with self._driver.session() as session:
            result = session.run(
                f"MATCH (a)-[r]->(b) WHERE {_THREAT_EDGE_FILTER} RETURN count(r) AS cnt"
            )
            return result.single()["cnt"]

    def load_from_records(self, records: list[dict]) -> None:
        """Ledger-derived threat projection records → Neo4j 노드/관계 배치 생성."""
        # 레이블별 분류
        by_label: dict[str, list[dict]] = defaultdict(list)
        for rec in records:
            source = rec.get("source", "")
            label = _SOURCE_TO_LABEL.get(source)
            if not label or not rec.get("id"):
                continue
            by_label[label].append(rec)

        with self._driver.session() as session:
            # 인덱스 생성 (이미 존재하면 무시)
            for label in ["CWE", "CVE", "Attack", "CAPEC"]:
                session.run(
                    f"CREATE INDEX IF NOT EXISTS FOR (n:{label}) ON (n.id)"
                )
            session.run(
                "CREATE INDEX IF NOT EXISTS FOR (n:Function) ON (n.project_id, n.name)"
            )

            # 노드 생성 (레이블별 배치)
            for label, recs in by_label.items():
                for batch_start in range(0, len(recs), 100):
                    batch = recs[batch_start:batch_start + 100]
                    params = []
                    for rec in batch:
                        props = {
                            "id": rec["id"],
                            "title": rec.get("title", ""),
                            "source": rec.get("source", ""),
                            "threat_category": rec.get("threat_category", ""),
                        }
                        if rec.get("severity") is not None:
                            props["severity"] = rec["severity"]
                        if rec.get("attack_vector"):
                            props["attack_vector"] = rec["attack_vector"]
                        if rec.get("kill_chain_phase"):
                            props["kill_chain_phase"] = rec["kill_chain_phase"]
                        if rec.get("attack_surfaces"):
                            props["attack_surfaces"] = rec["attack_surfaces"]
                        if rec.get("automotive_relevance") is not None:
                            props["automotive_relevance"] = rec["automotive_relevance"]
                        params.append(props)

                    session.run(
                        f"UNWIND $batch AS props "
                        f"MERGE (n:{label} {{id: props.id}}) "
                        f"SET n += props",
                        batch=params,
                    )

            # 관계 생성
            for rel_field, (rel_type, target_label) in _REL_FIELD_MAP.items():
                edges = []
                for rec in records:
                    src_id = rec.get("id", "")
                    if not src_id:
                        continue
                    for ref_id in rec.get(rel_field, []):
                        if ref_id:
                            edges.append({"src": src_id, "dst": ref_id})

                for batch_start in range(0, len(edges), 200):
                    batch = edges[batch_start:batch_start + 200]
                    # 소스 노드의 레이블을 모르므로 id 기반 MATCH
                    session.run(
                        f"UNWIND $batch AS e "
                        f"MATCH (a {{id: e.src}}) "
                        f"MERGE (b:{target_label} {{id: e.dst}}) "
                        f"MERGE (a)-[:{rel_type}]->(b)",
                        batch=batch,
                    )

        logger.info(
            "Neo4jGraph 구축 완료: %d nodes, %d edges",
            self.node_count, self.edge_count,
        )

    def neighbors(self, node_id: str, depth: int = 2) -> list[str]:
        """BFS로 depth까지 탐색하여 관련 노드 ID를 반환한다."""
        with self._driver.session() as session:
            result = session.run(
                f"MATCH (n {{id: $id}})-[*1..{depth}]-(m) "
                "WHERE m.id IS NOT NULL AND m.id <> $id "
                "RETURN DISTINCT m.id AS mid",
                id=node_id,
            )
            return [record["mid"] for record in result]

    def get_related(self, node_id: str) -> dict[str, list[str]]:
        """노드와 관련된 ID를 카테고리별로 반환한다."""
        categories: dict[str, list[str]] = defaultdict(list)

        with self._driver.session() as session:
            result = session.run(
                "MATCH (n {id: $id})-[r]-(m) "
                "WHERE m.id IS NOT NULL "
                "RETURN type(r) AS rel_type, m.id AS mid",
                id=node_id,
            )
            for record in result:
                rel_type = record["rel_type"]
                key = _REL_TYPE_TO_KEY.get(rel_type, rel_type.lower())
                mid = record["mid"]
                if mid not in categories[key]:
                    categories[key].append(mid)

        return dict(categories)

    def get_node_info(self, node_id: str) -> dict | None:
        """노드의 속성을 반환한다."""
        with self._driver.session() as session:
            result = session.run(
                "MATCH (n {id: $id}) RETURN n",
                id=node_id,
            )
            record = result.single()
            if record is None:
                return None
            node = record["n"]
            return dict(node)

    def get_kb_meta(self) -> dict | None:
        """KBMeta 노드에서 ontology 버전 정보를 반환한다."""
        with self._driver.session() as session:
            result = session.run(
                "MATCH (m:KBMeta {id: 'kb-meta'}) RETURN m"
            )
            record = result.single()
            if record is None:
                return None
            node = record["m"]
            meta = dict(node)
            meta.pop("id", None)
            # Neo4j DateTime → ISO 문자열 변환
            for key, val in meta.items():
                if hasattr(val, "iso_format"):
                    meta[key] = val.iso_format()
            return meta

    # --- 추가 메서드 (API용) ---

    def get_stats(self) -> dict:
        """그래프 통계: 노드/엣지 수, 소스별 분포, 관계 타입별 분포, 상위 연결 노드."""
        with self._driver.session() as session:
            # 소스별 카운트
            sources = {}
            for label in _THREAT_LABELS:
                result = session.run(f"MATCH (n:{label}) RETURN count(n) AS cnt")
                sources[label] = result.single()["cnt"]

            # 관계 타입별 카운트
            result = session.run(
                f"MATCH (a)-[r]->(b) WHERE {_THREAT_EDGE_FILTER} "
                "RETURN type(r) AS rel_type, count(r) AS cnt "
                "ORDER BY cnt DESC"
            )
            edge_types = {rec["rel_type"]: rec["cnt"] for rec in result}

            # 상위 연결 노드 (degree 기준)
            result = session.run(
                "MATCH (n)-[r]-() "
                "WHERE n:CWE OR n:CVE OR n:Attack OR n:CAPEC "
                "WITH n, count(r) AS degree "
                "ORDER BY degree DESC LIMIT 20 "
                "RETURN n.id AS id, n.title AS title, labels(n) AS labels, degree"
            )
            top_connected = [
                {
                    "id": rec["id"],
                    "title": rec["title"],
                    "label": rec["labels"][0] if rec["labels"] else "",
                    "degree": rec["degree"],
                }
                for rec in result
            ]

        return {
            "nodeCount": self.node_count,
            "edgeCount": self.edge_count,
            "sources": sources,
            "edgeTypes": edge_types,
            "topConnected": top_connected,
        }
