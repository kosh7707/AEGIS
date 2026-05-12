PRAGMA user_version = 1;

CREATE TABLE IF NOT EXISTS ledger_meta (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  schema_version INTEGER NOT NULL,
  initialized_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS knowledge_source (
  source_id TEXT PRIMARY KEY,
  source_kind TEXT NOT NULL,
  name TEXT NOT NULL,
  version TEXT,
  source_url TEXT,
  payload_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS raw_artifact (
  raw_artifact_id TEXT PRIMARY KEY,
  source_id TEXT,
  uri TEXT,
  content_hash TEXT NOT NULL,
  payload_json TEXT NOT NULL DEFAULT '{}',
  retrieved_at TEXT NOT NULL,
  FOREIGN KEY (source_id) REFERENCES knowledge_source(source_id)
);

CREATE TABLE IF NOT EXISTS normalized_record (
  normalized_record_id TEXT PRIMARY KEY,
  source_id TEXT,
  raw_artifact_id TEXT,
  record_type TEXT NOT NULL,
  external_id TEXT NOT NULL,
  payload_json TEXT NOT NULL DEFAULT '{}',
  provenance_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (source_id) REFERENCES knowledge_source(source_id),
  FOREIGN KEY (raw_artifact_id) REFERENCES raw_artifact(raw_artifact_id)
);

CREATE TABLE IF NOT EXISTS package_identity (
  package_identity_id TEXT PRIMARY KEY,
  canonical_name TEXT NOT NULL,
  ecosystem TEXT,
  purl TEXT,
  cpe TEXT,
  repo_url TEXT,
  aliases_json TEXT NOT NULL DEFAULT '[]',
  provenance_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vulnerability_advisory (
  advisory_id TEXT PRIMARY KEY,
  source_id TEXT,
  source_kind TEXT NOT NULL,
  external_id TEXT NOT NULL,
  payload_json TEXT NOT NULL DEFAULT '{}',
  freshness_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (source_id) REFERENCES knowledge_source(source_id)
);

CREATE TABLE IF NOT EXISTS affected_range (
  affected_range_id TEXT PRIMARY KEY,
  advisory_id TEXT NOT NULL,
  package_identity_id TEXT,
  introduced TEXT,
  fixed TEXT,
  range_json TEXT NOT NULL DEFAULT '{}',
  provenance_json TEXT NOT NULL DEFAULT '{}',
  FOREIGN KEY (advisory_id) REFERENCES vulnerability_advisory(advisory_id),
  FOREIGN KEY (package_identity_id) REFERENCES package_identity(package_identity_id)
);

CREATE TABLE IF NOT EXISTS weakness (
  weakness_id TEXT PRIMARY KEY,
  external_id TEXT NOT NULL UNIQUE,
  taxonomy_family TEXT,
  payload_json TEXT NOT NULL DEFAULT '{}',
  provenance_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attack_pattern (
  attack_pattern_id TEXT PRIMARY KEY,
  external_id TEXT NOT NULL UNIQUE,
  source_kind TEXT NOT NULL,
  payload_json TEXT NOT NULL DEFAULT '{}',
  provenance_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mitigation (
  mitigation_id TEXT PRIMARY KEY,
  external_id TEXT,
  payload_json TEXT NOT NULL DEFAULT '{}',
  provenance_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tool_rule (
  tool_rule_id TEXT PRIMARY KEY,
  tool_name TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  payload_json TEXT NOT NULL DEFAULT '{}',
  provenance_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (tool_name, rule_id)
);

CREATE TABLE IF NOT EXISTS domain_concept (
  domain_concept_id TEXT PRIMARY KEY,
  profile_id TEXT NOT NULL,
  concept_id TEXT NOT NULL,
  payload_json TEXT NOT NULL DEFAULT '{}',
  provenance_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (profile_id, concept_id)
);

CREATE TABLE IF NOT EXISTS relation_record (
  relation_record_id TEXT PRIMARY KEY,
  subject_id TEXT NOT NULL,
  predicate TEXT NOT NULL,
  object_id TEXT NOT NULL,
  method TEXT NOT NULL,
  consumer_policy TEXT NOT NULL,
  provenance_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS transform_decision (
  transform_decision_id TEXT PRIMARY KEY,
  input_id TEXT NOT NULL,
  output_id TEXT,
  method TEXT NOT NULL,
  decision_json TEXT NOT NULL DEFAULT '{}',
  diagnostics_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS target_context (
  target_knowledge_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  latest_version INTEGER NOT NULL DEFAULT 0,
  UNIQUE (project_id, target_id)
);

CREATE TABLE IF NOT EXISTS target_context_version (
  target_context_version_id TEXT PRIMARY KEY,
  target_knowledge_id TEXT NOT NULL,
  target_context_version INTEGER NOT NULL,
  target_context_ingest_id TEXT NOT NULL,
  target_context_input_hash TEXT NOT NULL,
  build_snapshot_id TEXT,
  build_snapshot_key TEXT NOT NULL DEFAULT '',
  build_unit_id TEXT,
  snapshot_schema_version TEXT,
  source_build_attempt_id TEXT,
  bundle_json TEXT NOT NULL,
  identity_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_ingested_at TEXT NOT NULL,
  supersedes_target_context_version INTEGER,
  FOREIGN KEY (target_knowledge_id) REFERENCES target_context(target_knowledge_id) ON DELETE CASCADE,
  UNIQUE (target_knowledge_id, target_context_version),
  UNIQUE (target_knowledge_id, target_context_input_hash, build_snapshot_key)
);

CREATE TABLE IF NOT EXISTS acquisition_run (
  acquisition_id TEXT PRIMARY KEY,
  target_knowledge_id TEXT,
  target_context_version INTEGER,
  surface TEXT NOT NULL,
  acquisition_status TEXT NOT NULL,
  acquisition_quality_gate TEXT NOT NULL,
  consumer_policy TEXT NOT NULL,
  scope_json TEXT NOT NULL DEFAULT '{}',
  provenance_json TEXT NOT NULL DEFAULT '{}',
  results_json TEXT NOT NULL DEFAULT '{}',
  started_at TEXT NOT NULL,
  completed_at TEXT,
  FOREIGN KEY (target_knowledge_id) REFERENCES target_context(target_knowledge_id)
);

CREATE TABLE IF NOT EXISTS acquisition_item (
  item_id TEXT PRIMARY KEY,
  acquisition_id TEXT NOT NULL,
  item_key TEXT NOT NULL,
  item_type TEXT NOT NULL,
  acquisition_status TEXT NOT NULL,
  acquisition_quality_gate TEXT NOT NULL,
  consumer_policy TEXT NOT NULL,
  scope_json TEXT NOT NULL DEFAULT '{}',
  diagnostics_json TEXT NOT NULL DEFAULT '[]',
  results_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  FOREIGN KEY (acquisition_id) REFERENCES acquisition_run(acquisition_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS provider_observation (
  observation_id TEXT PRIMARY KEY,
  acquisition_id TEXT,
  provider TEXT NOT NULL,
  subject_key TEXT NOT NULL,
  status TEXT NOT NULL,
  freshness_json TEXT NOT NULL DEFAULT '{}',
  cache_json TEXT NOT NULL DEFAULT '{}',
  payload_json TEXT NOT NULL DEFAULT '{}',
  observed_at TEXT NOT NULL,
  FOREIGN KEY (acquisition_id) REFERENCES acquisition_run(acquisition_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS projection_state (
  projection_state_id TEXT PRIMARY KEY,
  projection_name TEXT NOT NULL,
  scope_key TEXT NOT NULL,
  state TEXT NOT NULL,
  source_hash TEXT,
  projection_version TEXT,
  debt_json TEXT NOT NULL DEFAULT '{}',
  freshness_json TEXT NOT NULL DEFAULT '{}',
  updated_at TEXT NOT NULL,
  UNIQUE (projection_name, scope_key)
);

CREATE TABLE IF NOT EXISTS projection_job (
  projection_job_id TEXT PRIMARY KEY,
  projection_name TEXT NOT NULL,
  scope_key TEXT NOT NULL,
  state TEXT NOT NULL,
  diagnostics_json TEXT NOT NULL DEFAULT '[]',
  started_at TEXT NOT NULL,
  completed_at TEXT
);
