PRAGMA user_version = 4;

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

CREATE TABLE IF NOT EXISTS source_artifact (
  source_artifact_id TEXT PRIMARY KEY,
  source_id TEXT,
  source_family TEXT NOT NULL,
  source_name TEXT NOT NULL,
  artifact_uri TEXT NOT NULL,
  media_type TEXT NOT NULL,
  source_version TEXT,
  schema_version TEXT,
  retrieved_at TEXT NOT NULL,
  published_at TEXT,
  modified_at TEXT,
  checksum_sha256 TEXT NOT NULL,
  parser_version TEXT NOT NULL,
  normalizer_version TEXT NOT NULL,
  record_count INTEGER,
  required_files_json TEXT NOT NULL DEFAULT '[]',
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
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

CREATE TABLE IF NOT EXISTS product_identity (
  product_identity_id TEXT PRIMARY KEY,
  vendor TEXT,
  product TEXT,
  version TEXT,
  cpe TEXT,
  match_criteria_id TEXT,
  qualifiers_json TEXT NOT NULL DEFAULT '{}',
  provenance_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS source_component_identity (
  source_component_identity_id TEXT PRIMARY KEY,
  repo_url TEXT,
  commit_id TEXT,
  source_path TEXT,
  fingerprint TEXT,
  qualifiers_json TEXT NOT NULL DEFAULT '{}',
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

CREATE TABLE IF NOT EXISTS affectedness_record (
  affectedness_id TEXT PRIMARY KEY,
  advisory_id TEXT NOT NULL,
  subject_kind TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  affectedness_status TEXT NOT NULL,
  introduced TEXT,
  fixed TEXT,
  range_json TEXT NOT NULL DEFAULT '{}',
  qualifiers_json TEXT NOT NULL DEFAULT '{}',
  evidence_json TEXT NOT NULL DEFAULT '{}',
  confidence REAL NOT NULL DEFAULT 1.0,
  decision_state TEXT NOT NULL DEFAULT 'accepted',
  provenance_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (advisory_id) REFERENCES vulnerability_advisory(advisory_id)
);

CREATE TABLE IF NOT EXISTS risk_signal (
  risk_signal_id TEXT PRIMARY KEY,
  advisory_id TEXT,
  signal_kind TEXT NOT NULL,
  signal_date TEXT,
  signal_value REAL,
  source_kind TEXT NOT NULL,
  payload_json TEXT NOT NULL DEFAULT '{}',
  provenance_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (advisory_id) REFERENCES vulnerability_advisory(advisory_id)
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

CREATE TABLE IF NOT EXISTS identity_alias (
  identity_alias_id TEXT PRIMARY KEY,
  subject_kind TEXT NOT NULL,
  subject_namespace TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  alias_kind TEXT NOT NULL,
  alias_namespace TEXT NOT NULL,
  alias_id TEXT NOT NULL,
  relation_semantics TEXT NOT NULL,
  confidence REAL NOT NULL DEFAULT 1.0,
  source_artifact_id TEXT,
  normalized_record_id TEXT,
  provenance_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (source_artifact_id) REFERENCES source_artifact(source_artifact_id),
  FOREIGN KEY (normalized_record_id) REFERENCES normalized_record(normalized_record_id)
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

CREATE TABLE IF NOT EXISTS unresolved_reference (
  unresolved_reference_id TEXT PRIMARY KEY,
  source_artifact_id TEXT,
  normalized_record_id TEXT,
  relation_record_id TEXT,
  owner_record_id TEXT NOT NULL,
  reference_role TEXT NOT NULL,
  reference_kind TEXT NOT NULL,
  target_raw TEXT NOT NULL,
  status TEXT NOT NULL,
  reason TEXT NOT NULL,
  evidence_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (source_artifact_id) REFERENCES source_artifact(source_artifact_id),
  FOREIGN KEY (normalized_record_id) REFERENCES normalized_record(normalized_record_id),
  FOREIGN KEY (relation_record_id) REFERENCES relation_record(relation_record_id)
);

CREATE TABLE IF NOT EXISTS conflict_record (
  conflict_record_id TEXT PRIMARY KEY,
  conflict_kind TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  conflicting_values_json TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL,
  evidence_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
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

CREATE TABLE IF NOT EXISTS source_repository_snapshot (
  repository_snapshot_id TEXT PRIMARY KEY,
  repository_url TEXT,
  repository_id TEXT,
  commit_hash TEXT NOT NULL,
  tree_hash TEXT,
  submodule_hashes_json TEXT NOT NULL DEFAULT '{}',
  metadata_json TEXT NOT NULL DEFAULT '{}',
  provenance_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (repository_url, repository_id, commit_hash, tree_hash)
);

CREATE TABLE IF NOT EXISTS source_repository_artifact (
  source_repository_artifact_id TEXT PRIMARY KEY,
  repository_snapshot_id TEXT NOT NULL,
  artifact_uri TEXT NOT NULL,
  media_type TEXT NOT NULL,
  checksum_sha256 TEXT NOT NULL,
  storage_mode TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  provenance_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (repository_snapshot_id) REFERENCES source_repository_snapshot(repository_snapshot_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS source_build_context (
  build_context_id TEXT PRIMARY KEY,
  repository_snapshot_id TEXT NOT NULL,
  project_id TEXT,
  target_id TEXT,
  build_target TEXT,
  toolchain_json TEXT NOT NULL DEFAULT '{}',
  compile_commands_artifact_id TEXT,
  dependency_graph_json TEXT NOT NULL DEFAULT '{}',
  build_metadata_json TEXT NOT NULL DEFAULT '{}',
  provenance_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (repository_snapshot_id) REFERENCES source_repository_snapshot(repository_snapshot_id) ON DELETE CASCADE,
  FOREIGN KEY (compile_commands_artifact_id) REFERENCES source_repository_artifact(source_repository_artifact_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS source_analysis_artifact_set (
  analysis_artifact_set_id TEXT PRIMARY KEY,
  build_context_id TEXT NOT NULL,
  analyzer_name TEXT NOT NULL,
  analyzer_version TEXT,
  analysis_config_json TEXT NOT NULL DEFAULT '{}',
  artifact_hashes_json TEXT NOT NULL DEFAULT '{}',
  produced_at TEXT,
  provenance_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (build_context_id) REFERENCES source_build_context(build_context_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS source_evidence_snippet (
  evidence_snippet_id TEXT PRIMARY KEY,
  repository_snapshot_id TEXT NOT NULL,
  file_path TEXT NOT NULL,
  line_start INTEGER,
  line_end INTEGER,
  language TEXT,
  snippet_text TEXT NOT NULL,
  checksum_sha256 TEXT NOT NULL,
  provenance_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (repository_snapshot_id) REFERENCES source_repository_snapshot(repository_snapshot_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS source_graph_node (
  source_graph_node_id TEXT PRIMARY KEY,
  analysis_artifact_set_id TEXT NOT NULL,
  node_kind TEXT NOT NULL,
  stable_id TEXT NOT NULL,
  display_name TEXT,
  file_path TEXT,
  line_start INTEGER,
  line_end INTEGER,
  symbol_json TEXT NOT NULL DEFAULT '{}',
  metadata_json TEXT NOT NULL DEFAULT '{}',
  evidence_snippet_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (analysis_artifact_set_id) REFERENCES source_analysis_artifact_set(analysis_artifact_set_id) ON DELETE CASCADE,
  FOREIGN KEY (evidence_snippet_id) REFERENCES source_evidence_snippet(evidence_snippet_id) ON DELETE SET NULL,
  UNIQUE (analysis_artifact_set_id, stable_id)
);

CREATE TABLE IF NOT EXISTS source_graph_edge (
  source_graph_edge_id TEXT PRIMARY KEY,
  analysis_artifact_set_id TEXT NOT NULL,
  edge_kind TEXT NOT NULL,
  source_graph_node_id TEXT NOT NULL,
  target_graph_node_id TEXT NOT NULL,
  evidence_json TEXT NOT NULL DEFAULT '{}',
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (analysis_artifact_set_id) REFERENCES source_analysis_artifact_set(analysis_artifact_set_id) ON DELETE CASCADE,
  FOREIGN KEY (source_graph_node_id) REFERENCES source_graph_node(source_graph_node_id) ON DELETE CASCADE,
  FOREIGN KEY (target_graph_node_id) REFERENCES source_graph_node(source_graph_node_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS source_rich_ir_artifact (
  rich_ir_artifact_id TEXT PRIMARY KEY,
  analysis_artifact_set_id TEXT NOT NULL,
  artifact_kind TEXT NOT NULL,
  media_type TEXT NOT NULL,
  uri TEXT,
  checksum_sha256 TEXT NOT NULL,
  payload_json TEXT NOT NULL DEFAULT '{}',
  provenance_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (analysis_artifact_set_id) REFERENCES source_analysis_artifact_set(analysis_artifact_set_id) ON DELETE CASCADE
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

CREATE TABLE IF NOT EXISTS projection_bundle_manifest (
  projection_bundle_id TEXT PRIMARY KEY,
  scope_key TEXT NOT NULL,
  projection_version TEXT NOT NULL,
  source_hash TEXT NOT NULL,
  manifest_json TEXT NOT NULL DEFAULT '{}',
  qa_report_json TEXT NOT NULL DEFAULT '{}',
  node_count INTEGER NOT NULL,
  edge_count INTEGER NOT NULL,
  text_chunk_count INTEGER NOT NULL,
  checksums_json TEXT NOT NULL DEFAULT '{}',
  production_write_enabled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS serving_query_run (
  serving_run_id TEXT PRIMARY KEY,
  canonical_query_id TEXT NOT NULL,
  decision_fragment_key TEXT NOT NULL,
  answer_schema_version TEXT NOT NULL,
  verdict TEXT NOT NULL,
  status TEXT NOT NULL,
  quality_gate TEXT NOT NULL,
  component_json TEXT NOT NULL DEFAULT '{}',
  source_context_json TEXT NOT NULL DEFAULT '{}',
  request_json TEXT NOT NULL DEFAULT '{}',
  canonical_query_json TEXT NOT NULL DEFAULT '{}',
  answer_json TEXT NOT NULL DEFAULT '{}',
  applied_controls_json TEXT NOT NULL DEFAULT '{}',
  control_effects_json TEXT NOT NULL DEFAULT '[]',
  fallback_trace_json TEXT NOT NULL DEFAULT '[]',
  cache_trace_json TEXT NOT NULL DEFAULT '{}',
  score_vector_json TEXT NOT NULL DEFAULT '{}',
  score_policy_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_serving_query_run_canonical_query
  ON serving_query_run (canonical_query_id);

CREATE INDEX IF NOT EXISTS idx_serving_query_run_decision_fragment
  ON serving_query_run (decision_fragment_key);

CREATE INDEX IF NOT EXISTS idx_serving_query_run_verdict_status
  ON serving_query_run (verdict, status);

CREATE INDEX IF NOT EXISTS idx_serving_query_run_created_at
  ON serving_query_run (created_at);
