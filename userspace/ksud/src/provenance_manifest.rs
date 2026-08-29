use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::fmt::Write as FmtWrite;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const MANIFEST_SIZE: usize = 192;
pub const SIGNATURE_SIZE: usize = 384;
pub const SIDECAR_SIZE: usize = MANIFEST_SIZE + SIGNATURE_SIZE;
pub const MAX_IMAGE_SIZE: u64 = 64 * 1024 * 1024;
pub const UAPI_VERSION: u32 = 1;
pub const ROLE_SUPERVISOR: u32 = 1 << 0;
pub const ROLE_INIT_PROXY: u32 = 1 << 1;
pub const ROLE_MASK_V1: u32 = ROLE_SUPERVISOR | ROLE_INIT_PROXY;

const MANIFEST_MAGIC: &[u8; 8] = b"KSUIMV1\0";
const MANIFEST_DOMAIN: &[u8; 24] = b"KSU-PROVENANCE-IMAGE-V1\0";
#[allow(dead_code)]
const EVENT_DOMAIN: &[u8; 24] = b"KSU-PROVENANCE-EVENT-V1\0";
const KERNEL_SELFTEST_IMAGE: &[u8] = b"KSU-PROVENANCE-KERNEL-SELFTEST-V1\0";
const KERNEL_SELFTEST_BUILD_DOMAIN: &[u8] = b"KSU-PROVENANCE-SELFTEST-BUILD-V1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageManifestV1 {
    pub roles: u32,
    pub image_size: u64,
    pub image_sha256: [u8; 32],
    pub build_id: [u8; 32],
    pub uapi_min: u32,
    pub uapi_max: u32,
    pub security_epoch: u64,
    pub signing_key_id: [u8; 32],
}

impl ImageManifestV1 {
    pub fn encode(&self) -> Result<[u8; MANIFEST_SIZE]> {
        ensure!(self.roles != 0, "manifest roles must not be empty");
        ensure!(
            self.roles & !ROLE_MASK_V1 == 0,
            "manifest contains unknown role bits"
        );
        ensure!(
            self.image_size != 0 && self.image_size <= MAX_IMAGE_SIZE,
            "image size is outside the version 1 limit"
        );
        ensure!(
            self.uapi_min != 0 && self.uapi_min <= self.uapi_max,
            "invalid provenance UAPI interval"
        );
        ensure!(self.build_id != [0; 32], "build identity must not be zero");
        ensure!(
            self.signing_key_id != [0; 32],
            "signing key id must not be zero"
        );

        let mut output = [0_u8; MANIFEST_SIZE];
        output[0..8].copy_from_slice(MANIFEST_MAGIC);
        output[8..10].copy_from_slice(&1_u16.to_le_bytes());
        output[10..12].copy_from_slice(&(MANIFEST_SIZE as u16).to_le_bytes());
        output[16..20].copy_from_slice(&self.roles.to_le_bytes());
        output[24..32].copy_from_slice(&self.image_size.to_le_bytes());
        output[32..64].copy_from_slice(&self.image_sha256);
        output[64..96].copy_from_slice(&self.build_id);
        output[96..100].copy_from_slice(&self.uapi_min.to_le_bytes());
        output[100..104].copy_from_slice(&self.uapi_max.to_le_bytes());
        output[104..112].copy_from_slice(&self.security_epoch.to_le_bytes());
        output[112..144].copy_from_slice(&self.signing_key_id);
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        ensure!(input.len() == MANIFEST_SIZE, "wrong manifest length");
        ensure!(&input[0..8] == MANIFEST_MAGIC, "wrong manifest magic");
        ensure!(read_u16(input, 8) == 1, "unsupported manifest format");
        ensure!(
            usize::from(read_u16(input, 10)) == MANIFEST_SIZE,
            "wrong encoded manifest length"
        );
        ensure!(read_u32(input, 12) == 0, "unknown manifest flags");
        ensure!(read_u32(input, 20) == 0, "reserved field is not zero");
        ensure!(
            input[144..192].iter().all(|byte| *byte == 0),
            "reserved tail is not zero"
        );

        let manifest = Self {
            roles: read_u32(input, 16),
            image_size: read_u64(input, 24),
            image_sha256: array_at(input, 32),
            build_id: array_at(input, 64),
            uapi_min: read_u32(input, 96),
            uapi_max: read_u32(input, 100),
            security_epoch: read_u64(input, 104),
            signing_key_id: array_at(input, 112),
        };
        manifest.encode()?;
        Ok(manifest)
    }
}

#[derive(Clone, Debug)]
pub struct SignOptions {
    pub image: PathBuf,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub output: PathBuf,
    pub build_id: [u8; 32],
    pub roles: u32,
    pub security_epoch: u64,
    pub uapi_min: u32,
    pub uapi_max: u32,
}

#[derive(Clone, Debug)]
pub struct VerifyOptions {
    pub image: PathBuf,
    pub certificate: PathBuf,
    pub sidecar: PathBuf,
    pub required_role: u32,
    pub minimum_security_epoch: u64,
}

#[derive(Clone, Debug)]
pub struct KernelKeyHeaderOptions {
    pub current_certificate: PathBuf,
    pub current_private_key: PathBuf,
    pub current_minimum_epoch: u64,
    pub next_certificate: Option<PathBuf>,
    pub next_private_key: Option<PathBuf>,
    pub next_minimum_epoch: Option<u64>,
    pub output: PathBuf,
}

#[derive(Clone, Debug)]
pub struct GenerateCertificateOptions {
    pub private_key: PathBuf,
    pub certificate: PathBuf,
    pub common_name: String,
    pub validity_days: u32,
}

pub fn parse_digest_hex(value: &str, field: &str) -> Result<[u8; 32]> {
    ensure!(
        value.len() == 64,
        "{field} must contain 64 hexadecimal characters"
    );
    let mut digest = [0_u8; 32];
    base16ct::mixed::decode(value.as_bytes(), &mut digest)
        .map_err(|error| anyhow::anyhow!("invalid {field}: {error}"))?;
    Ok(digest)
}

#[allow(dead_code)]
pub fn manifest_digest(manifest: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(MANIFEST_DOMAIN);
    hasher.update(manifest);
    hasher.finalize().into()
}

#[allow(dead_code)]
pub fn event_digest(previous: &[u8; 32], frame: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(EVENT_DOMAIN);
    hasher.update(previous);
    hasher.update(frame);
    hasher.finalize().into()
}

pub fn sign(options: &SignOptions) -> Result<ImageManifestV1> {
    let image = read_bounded_image(&options.image)?;
    let certificate_der = certificate_der(&options.certificate)?;
    validate_rsa3072_certificate(&options.certificate)?;
    let signing_key_id: [u8; 32] = Sha256::digest(&certificate_der).into();
    let manifest = ImageManifestV1 {
        roles: options.roles,
        image_size: image.len() as u64,
        image_sha256: Sha256::digest(&image).into(),
        build_id: options.build_id,
        uapi_min: options.uapi_min,
        uapi_max: options.uapi_max,
        security_epoch: options.security_epoch,
        signing_key_id,
    };
    let encoded = manifest.encode()?;
    ensure!(
        options.uapi_min <= UAPI_VERSION && options.uapi_max >= UAPI_VERSION,
        "manifest UAPI interval does not include version {UAPI_VERSION}"
    );

    let signature = sign_manifest(&options.private_key, &encoded)?;
    verify_signature(&options.certificate, &encoded, &signature)?;

    let mut sidecar = Vec::with_capacity(SIDECAR_SIZE);
    sidecar.extend_from_slice(&encoded);
    sidecar.extend_from_slice(&signature);
    write_atomic(&options.output, &sidecar)?;
    Ok(manifest)
}

pub fn verify(options: &VerifyOptions) -> Result<ImageManifestV1> {
    let image = read_bounded_image(&options.image)?;
    let certificate_der = certificate_der(&options.certificate)?;
    validate_rsa3072_certificate(&options.certificate)?;
    let sidecar = fs::read(&options.sidecar).context("read provenance sidecar")?;
    ensure!(
        sidecar.len() == SIDECAR_SIZE,
        "sidecar is {} bytes, expected {SIDECAR_SIZE}",
        sidecar.len()
    );
    let manifest = ImageManifestV1::decode(&sidecar[..MANIFEST_SIZE])?;
    ensure!(
        manifest.roles & options.required_role != 0,
        "manifest does not contain the required role"
    );
    ensure!(
        manifest.uapi_min <= UAPI_VERSION && manifest.uapi_max >= UAPI_VERSION,
        "manifest UAPI interval does not include version {UAPI_VERSION}"
    );
    ensure!(
        manifest.security_epoch >= options.minimum_security_epoch,
        "manifest security epoch is below the configured minimum"
    );
    let certificate_key_id: [u8; 32] = Sha256::digest(certificate_der).into();
    ensure!(
        manifest.signing_key_id == certificate_key_id,
        "manifest key id does not match the certificate"
    );
    ensure!(
        manifest.image_size == image.len() as u64,
        "image size mismatch"
    );
    let image_digest: [u8; 32] = Sha256::digest(image).into();
    ensure!(
        manifest.image_sha256 == image_digest,
        "image digest mismatch"
    );
    verify_signature(
        &options.certificate,
        &sidecar[..MANIFEST_SIZE],
        &sidecar[MANIFEST_SIZE..],
    )?;
    Ok(manifest)
}

pub fn emit_kernel_key_header(options: &KernelKeyHeaderOptions) -> Result<()> {
    ensure!(
        options.current_minimum_epoch != 0,
        "current minimum security epoch must be positive"
    );
    ensure!(
        options.next_certificate.is_some() == options.next_private_key.is_some()
            && options.next_certificate.is_some() == options.next_minimum_epoch.is_some(),
        "next certificate, private key, and minimum epoch must be supplied together"
    );
    let mut certificates = vec![(
        options.current_certificate.as_path(),
        options.current_private_key.as_path(),
        options.current_minimum_epoch,
    )];
    if let (Some(certificate), Some(private_key), Some(epoch)) = (
        options.next_certificate.as_deref(),
        options.next_private_key.as_deref(),
        options.next_minimum_epoch,
    ) {
        ensure!(epoch != 0, "next minimum security epoch must be positive");
        certificates.push((certificate, private_key, epoch));
    }

    let mut output = String::from(
        "#ifndef __KSU_PROVENANCE_GENERATED_KEY_H\n#define __KSU_PROVENANCE_GENERATED_KEY_H\n\n#define KSU_PROVENANCE_KEY_HEADER_FORMAT 2\n\n",
    );
    let mut entries = Vec::new();
    for (index, (certificate, private_key, epoch)) in certificates.iter().enumerate() {
        validate_rsa3072_certificate(certificate)?;
        let der = certificate_der(certificate)?;
        let key_id: [u8; 32] = Sha256::digest(&der).into();
        let build_id: [u8; 32] = Sha256::new()
            .chain_update(KERNEL_SELFTEST_BUILD_DOMAIN)
            .chain_update(key_id)
            .finalize()
            .into();
        let selftest_manifest = ImageManifestV1 {
            roles: ROLE_SUPERVISOR,
            image_size: KERNEL_SELFTEST_IMAGE.len() as u64,
            image_sha256: Sha256::digest(KERNEL_SELFTEST_IMAGE).into(),
            build_id,
            uapi_min: UAPI_VERSION,
            uapi_max: UAPI_VERSION,
            security_epoch: *epoch,
            signing_key_id: key_id,
        }
        .encode()?;
        let selftest_signature = sign_manifest(private_key, &selftest_manifest)?;
        verify_signature(certificate, &selftest_manifest, &selftest_signature)?;
        let mut selftest_sidecar = Vec::with_capacity(SIDECAR_SIZE);
        selftest_sidecar.extend_from_slice(&selftest_manifest);
        selftest_sidecar.extend_from_slice(&selftest_signature);
        write!(
            output,
            "static const u8 ksu_provenance_certificate_{index}[] = {{\n{}\n}};\n\nstatic const u8 ksu_provenance_selftest_image_{index}[] = {{\n{}\n}};\n\nstatic const u8 ksu_provenance_selftest_sidecar_{index}[] = {{\n{}\n}};\n\n",
            c_byte_lines(&der),
            c_byte_lines(KERNEL_SELFTEST_IMAGE),
            c_byte_lines(&selftest_sidecar),
        )
        .expect("writing to a String cannot fail");
        entries.push((index, *epoch, key_id));
    }
    if entries.len() == 2 {
        ensure!(
            entries[0].2 != entries[1].2,
            "current and next certificate are identical"
        );
    }
    output.push_str(
        "static const struct ksu_provenance_embedded_key ksu_provenance_embedded_keys[] = {\n",
    );
    for (index, epoch, key_id) in &entries {
        write!(
            output,
            "    {{ .certificate_der = ksu_provenance_certificate_{index}, .certificate_size = sizeof(ksu_provenance_certificate_{index}),\n      .key_id = {{ {} }}, .minimum_security_epoch = {epoch}ULL,\n      .selftest_image = ksu_provenance_selftest_image_{index}, .selftest_image_size = sizeof(ksu_provenance_selftest_image_{index}),\n      .selftest_sidecar = ksu_provenance_selftest_sidecar_{index}, .selftest_sidecar_size = sizeof(ksu_provenance_selftest_sidecar_{index}) }},\n",
            c_byte_list(key_id)
        )
        .expect("writing to a String cannot fail");
    }
    output.push_str("};\n#define KSU_PROVENANCE_EMBEDDED_KEY_COUNT ");
    output.push_str(&entries.len().to_string());
    output.push_str("\n#define KSU_PROVENANCE_EMBEDDED_KEY_IDS_HEX \"");
    output.push_str(
        &entries
            .iter()
            .map(|(_, _, key_id)| base16ct::lower::encode_string(key_id))
            .collect::<Vec<_>>()
            .join(","),
    );
    output.push_str("\"\n#define KSU_PROVENANCE_EMBEDDED_MINIMUM_EPOCHS \"");
    output.push_str(
        &entries
            .iter()
            .map(|(_, epoch, _)| epoch.to_string())
            .collect::<Vec<_>>()
            .join(","),
    );
    output.push('"');
    output.push_str("\n\n#endif /* __KSU_PROVENANCE_GENERATED_KEY_H */\n");
    write_atomic(&options.output, output.as_bytes())
}

pub fn generate_certificate(options: &GenerateCertificateOptions) -> Result<()> {
    ensure!(
        !options.common_name.is_empty(),
        "certificate common name is empty"
    );
    ensure!(
        options.validity_days != 0,
        "certificate validity must not be zero"
    );
    ensure!(
        !options.private_key.exists() && !options.certificate.exists(),
        "refusing to overwrite an existing key or certificate"
    );

    let temporary_directory =
        tempfile::tempdir().context("create certificate temporary directory")?;
    let private_key = temporary_directory.path().join("private-key.pem");
    let certificate = temporary_directory.path().join("certificate.pem");
    let subject = format!("/CN={}", options.common_name.replace('/', "_"));
    let validity_days = options.validity_days.to_string();
    run_openssl([
        "req",
        "-x509",
        "-newkey",
        "rsa:3072",
        "-sha256",
        "-nodes",
        "-keyout",
        path_text(&private_key)?,
        "-out",
        path_text(&certificate)?,
        "-days",
        &validity_days,
        "-subj",
        &subject,
    ])?;
    validate_rsa3072_certificate(&certificate)?;
    write_new_atomic(&options.private_key, &fs::read(&private_key)?)?;
    write_new_atomic(&options.certificate, &fs::read(&certificate)?)
}

fn read_bounded_image(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    ensure!(metadata.is_file(), "image is not a regular file");
    ensure!(
        metadata.len() != 0 && metadata.len() <= MAX_IMAGE_SIZE,
        "image size is outside the version 1 limit"
    );
    let image = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    ensure!(
        image.len() as u64 == metadata.len(),
        "image changed while it was being read"
    );
    Ok(image)
}

fn certificate_der(path: &Path) -> Result<Vec<u8>> {
    let path = path_text(path)?;
    for format in ["PEM", "DER"] {
        let output = Command::new("openssl")
            .env("LC_ALL", "C")
            .args(["x509", "-inform", format, "-in", path, "-outform", "DER"])
            .output()
            .context("execute openssl x509")?;
        if output.status.success() {
            ensure!(!output.stdout.is_empty(), "certificate DER is empty");
            return Ok(output.stdout);
        }
    }
    bail!("openssl could not parse {path} as a PEM or DER certificate")
}

fn validate_rsa3072_certificate(path: &Path) -> Result<()> {
    let path = path_text(path)?;
    for format in ["PEM", "DER"] {
        let output = Command::new("openssl")
            .env("LC_ALL", "C")
            .args(["x509", "-inform", format, "-in", path, "-noout", "-text"])
            .output()
            .context("execute openssl certificate inspection")?;
        if output.status.success() {
            let text = String::from_utf8(output.stdout).context("openssl output is not UTF-8")?;
            ensure!(
                text.contains("Public Key Algorithm: rsaEncryption")
                    && text.contains("Public-Key: (3072 bit)"),
                "certificate must contain an exact RSA-3072 public key"
            );
            return Ok(());
        }
    }
    bail!("openssl could not inspect {path} as a PEM or DER certificate")
}

fn sign_manifest(private_key: &Path, manifest: &[u8]) -> Result<Vec<u8>> {
    let temporary_directory = tempfile::tempdir().context("create signing temporary directory")?;
    let input_path = temporary_directory.path().join("manifest.input");
    let signature_path = temporary_directory.path().join("manifest.signature");
    fs::write(&input_path, signed_manifest_input(manifest)).context("write signing input")?;
    run_openssl([
        "dgst",
        "-sha256",
        "-sign",
        path_text(private_key)?,
        "-out",
        path_text(&signature_path)?,
        path_text(&input_path)?,
    ])?;
    let signature = fs::read(&signature_path).context("read generated signature")?;
    ensure!(
        signature.len() == SIGNATURE_SIZE,
        "RSA signature is {} bytes, expected {SIGNATURE_SIZE}",
        signature.len()
    );
    Ok(signature)
}

fn verify_signature(certificate: &Path, manifest: &[u8], signature: &[u8]) -> Result<()> {
    ensure!(signature.len() == SIGNATURE_SIZE, "wrong signature length");
    let temporary_directory = tempfile::tempdir().context("create verification temp directory")?;
    let public_key = temporary_directory.path().join("public.pem");
    let input = temporary_directory.path().join("manifest.input");
    let signature_path = temporary_directory.path().join("manifest.signature");

    let certificate_text = path_text(certificate)?;
    let mut extracted = false;
    for format in ["PEM", "DER"] {
        let output = Command::new("openssl")
            .env("LC_ALL", "C")
            .args([
                "x509",
                "-inform",
                format,
                "-in",
                certificate_text,
                "-pubkey",
                "-noout",
            ])
            .output()
            .context("extract certificate public key")?;
        if output.status.success() {
            fs::write(&public_key, output.stdout).context("write public key")?;
            extracted = true;
            break;
        }
    }
    ensure!(extracted, "could not extract certificate public key");
    fs::write(&input, signed_manifest_input(manifest)).context("write verification input")?;
    fs::write(&signature_path, signature).context("write verification signature")?;
    run_openssl([
        "dgst",
        "-sha256",
        "-verify",
        path_text(&public_key)?,
        "-signature",
        path_text(&signature_path)?,
        path_text(&input)?,
    ])
}

fn signed_manifest_input(manifest: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(MANIFEST_DOMAIN.len() + manifest.len());
    input.extend_from_slice(MANIFEST_DOMAIN);
    input.extend_from_slice(manifest);
    input
}

fn run_openssl<const N: usize>(arguments: [&str; N]) -> Result<()> {
    let output = Command::new("openssl")
        .env("LC_ALL", "C")
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .context("execute openssl")?;
    if output.status.success() {
        return Ok(());
    }
    let details = if output.stderr.is_empty() {
        &output.stdout
    } else {
        &output.stderr
    };
    bail!(
        "openssl failed: {}",
        String::from_utf8_lossy(details).trim()
    )
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("create temporary file in {}", parent.display()))?;
    temporary
        .write_all(data)
        .context("write temporary output")?;
    temporary
        .as_file()
        .sync_all()
        .context("sync temporary output")?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("replace {}", path.display()))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("sync {}", parent.display()))?;
    Ok(())
}

fn write_new_atomic(path: &Path, data: &[u8]) -> Result<()> {
    ensure!(!path.exists(), "refusing to overwrite {}", path.display());
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("create temporary file in {}", parent.display()))?;
    temporary
        .write_all(data)
        .context("write temporary output")?;
    temporary
        .as_file()
        .sync_all()
        .context("sync temporary output")?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| error.error)
        .with_context(|| format!("create {}", path.display()))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("sync {}", parent.display()))?;
    Ok(())
}

fn c_byte_lines(bytes: &[u8]) -> String {
    bytes
        .chunks(12)
        .map(|chunk| format!("    {},", c_byte_list(chunk)))
        .collect::<Vec<_>>()
        .join("\n")
}

fn c_byte_list(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("0x{byte:02x}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("path is not valid UTF-8: {}", path.display()))
}

fn read_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        input[offset..offset + 2]
            .try_into()
            .expect("checked manifest range"),
    )
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        input[offset..offset + 4]
            .try_into()
            .expect("checked manifest range"),
    )
}

fn read_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        input[offset..offset + 8]
            .try_into()
            .expect("checked manifest range"),
    )
}

fn array_at(input: &[u8], offset: usize) -> [u8; 32] {
    input[offset..offset + 32]
        .try_into()
        .expect("checked manifest range")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_manifest() -> ImageManifestV1 {
        ImageManifestV1 {
            roles: ROLE_MASK_V1,
            image_size: 0x0102_0304,
            image_sha256: [0x11; 32],
            build_id: [0x22; 32],
            uapi_min: 1,
            uapi_max: 1,
            security_epoch: 0x1112_1314_1516_1718,
            signing_key_id: [0x33; 32],
        }
    }

    #[test]
    fn manifest_golden_layout_and_digest() {
        let encoded = fixture_manifest().encode().unwrap();
        assert_eq!(encoded.len(), MANIFEST_SIZE);
        assert_eq!(&encoded[0..8], b"KSUIMV1\0");
        assert_eq!(&encoded[8..12], &[1, 0, 192, 0]);
        assert_eq!(&encoded[16..20], &[3, 0, 0, 0]);
        assert_eq!(&encoded[24..32], &[4, 3, 2, 1, 0, 0, 0, 0]);
        assert_eq!(
            base16ct::lower::encode_string(&manifest_digest(&encoded)),
            "4a95491f769934120dd5cccabf1f9b2e2b86905dca45631ead21ad9ac816df5f"
        );
        assert_eq!(
            ImageManifestV1::decode(&encoded).unwrap(),
            fixture_manifest()
        );
    }

    #[test]
    fn event_hash_golden_vector() {
        assert_eq!(
            base16ct::lower::encode_string(&event_digest(&[0x44; 32], &[0x55; 128])),
            "b18737ddb8a84651c6fb878cf739239f3e7c75b9a91afbda20376b257dae2abe"
        );
    }

    #[test]
    fn manifest_matches_shared_c_fixture() {
        let fixture = include_str!("../../../uapi/provenance_golden.h");
        let manifest_hex = c_define_string(fixture, "KSU_PROVENANCE_GOLDEN_MANIFEST_HEX");
        let expected_digest = c_define_string(fixture, "KSU_PROVENANCE_GOLDEN_MANIFEST_DIGEST_HEX");
        let bytes = base16ct::mixed::decode_vec(&manifest_hex).unwrap();
        assert_eq!(bytes, fixture_manifest().encode().unwrap());
        assert_eq!(
            base16ct::lower::encode_string(&manifest_digest(&bytes)),
            expected_digest
        );
    }

    #[test]
    fn manifest_rejects_noncanonical_data() {
        let mut encoded = fixture_manifest().encode().unwrap();
        encoded[12] = 1;
        assert!(ImageManifestV1::decode(&encoded).is_err());
        encoded[12] = 0;
        encoded[20] = 1;
        assert!(ImageManifestV1::decode(&encoded).is_err());
        encoded[20] = 0;
        encoded[191] = 1;
        assert!(ImageManifestV1::decode(&encoded).is_err());
        assert!(ImageManifestV1::decode(&encoded[..191]).is_err());
        let mut trailing = encoded.to_vec();
        trailing[191] = 0;
        trailing.push(0);
        assert!(ImageManifestV1::decode(&trailing).is_err());
    }

    #[test]
    fn signed_artifacts_reject_phase_one_negative_matrix() {
        let directory = tempfile::tempdir().unwrap();
        let image_path = directory.path().join("ksud");
        let key_path = directory.path().join("key.pem");
        let certificate_path = directory.path().join("certificate.pem");
        let sidecar_path = directory.path().join("ksud.provenance");
        let original_image = b"phase-one-test-image";
        fs::write(&image_path, original_image).unwrap();
        generate_certificate(&GenerateCertificateOptions {
            private_key: key_path.clone(),
            certificate: certificate_path.clone(),
            common_name: "KernelSU test".to_owned(),
            validity_days: 1,
        })
        .unwrap();
        let header_path = directory.path().join("provenance-public-key.h");
        emit_kernel_key_header(&KernelKeyHeaderOptions {
            current_certificate: certificate_path.clone(),
            current_private_key: key_path.clone(),
            current_minimum_epoch: 7,
            next_certificate: None,
            next_private_key: None,
            next_minimum_epoch: None,
            output: header_path.clone(),
        })
        .unwrap();
        let header = fs::read_to_string(header_path).unwrap();
        assert!(header.contains("#define KSU_PROVENANCE_KEY_HEADER_FORMAT 2"));
        assert!(header.contains("ksu_provenance_selftest_sidecar_0"));
        assert!(header.contains("KSU_PROVENANCE_EMBEDDED_KEY_IDS_HEX"));
        assert!(!header.contains("BEGIN PRIVATE KEY"));
        let sign_options = SignOptions {
            image: image_path.clone(),
            certificate: certificate_path.clone(),
            private_key: key_path.clone(),
            output: sidecar_path.clone(),
            build_id: [0x66; 32],
            roles: ROLE_SUPERVISOR,
            security_epoch: 7,
            uapi_min: 1,
            uapi_max: 1,
        };
        sign(&sign_options).unwrap();
        let verify_options = VerifyOptions {
            image: image_path.clone(),
            certificate: certificate_path.clone(),
            sidecar: sidecar_path.clone(),
            required_role: ROLE_SUPERVISOR,
            minimum_security_epoch: 7,
        };
        verify(&verify_options).unwrap();
        let valid_sidecar = fs::read(&sidecar_path).unwrap();

        fs::write(&image_path, b"phase-one-test-imagf").unwrap();
        assert!(verify(&verify_options).is_err());
        fs::write(&image_path, [original_image.as_slice(), b"x"].concat()).unwrap();
        assert!(verify(&verify_options).is_err());
        fs::write(&image_path, original_image).unwrap();

        let mut corrupted = valid_sidecar.clone();
        corrupted[MANIFEST_SIZE] ^= 1;
        fs::write(&sidecar_path, &corrupted).unwrap();
        assert!(verify(&verify_options).is_err());
        fs::write(&sidecar_path, &valid_sidecar[..SIDECAR_SIZE - 1]).unwrap();
        assert!(verify(&verify_options).is_err());
        fs::write(&sidecar_path, [valid_sidecar.as_slice(), &[0]].concat()).unwrap();
        assert!(verify(&verify_options).is_err());
        fs::write(&sidecar_path, &valid_sidecar).unwrap();

        let mut wrong_role = verify_options.clone();
        wrong_role.required_role = ROLE_INIT_PROXY;
        assert!(verify(&wrong_role).is_err());
        let mut wrong_epoch = verify_options.clone();
        wrong_epoch.minimum_security_epoch = 8;
        assert!(verify(&wrong_epoch).is_err());
        let mut wrong_uapi = valid_sidecar.clone();
        wrong_uapi[96..100].copy_from_slice(&2_u32.to_le_bytes());
        wrong_uapi[100..104].copy_from_slice(&2_u32.to_le_bytes());
        fs::write(&sidecar_path, &wrong_uapi).unwrap();
        assert!(verify(&verify_options).is_err());
        fs::write(&sidecar_path, &valid_sidecar).unwrap();

        let second_key = directory.path().join("second-key.pem");
        let second_certificate = directory.path().join("second-certificate.pem");
        generate_certificate(&GenerateCertificateOptions {
            private_key: second_key,
            certificate: second_certificate.clone(),
            common_name: "KernelSU wrong test key".to_owned(),
            validity_days: 1,
        })
        .unwrap();
        let mut wrong_key = verify_options.clone();
        wrong_key.certificate = second_certificate;
        assert!(verify(&wrong_key).is_err());

        assert_rejects_alternate_signature(
            &key_path,
            &sidecar_path,
            &valid_sidecar,
            &verify_options,
            true,
        );
        assert_rejects_alternate_signature(
            &key_path,
            &sidecar_path,
            &valid_sidecar,
            &verify_options,
            false,
        );

        let rsa2048 = directory.path().join("rsa2048.pem");
        generate_test_certificate(&rsa2048, "rsa:2048", &[]);
        assert!(validate_rsa3072_certificate(&rsa2048).is_err());
        let ec = directory.path().join("ec.pem");
        generate_test_certificate(&ec, "ec", &["-pkeyopt", "ec_paramgen_curve:P-256"]);
        assert!(validate_rsa3072_certificate(&ec).is_err());
    }

    fn assert_rejects_alternate_signature(
        key: &Path,
        sidecar_path: &Path,
        valid_sidecar: &[u8],
        verify_options: &VerifyOptions,
        pss: bool,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input");
        let signature = directory.path().join("signature");
        if pss {
            fs::write(
                &input,
                signed_manifest_input(&valid_sidecar[..MANIFEST_SIZE]),
            )
            .unwrap();
            run_openssl([
                "dgst",
                "-sha256",
                "-sign",
                path_text(key).unwrap(),
                "-sigopt",
                "rsa_padding_mode:pss",
                "-out",
                path_text(&signature).unwrap(),
                path_text(&input).unwrap(),
            ])
            .unwrap();
        } else {
            fs::write(&input, manifest_digest(&valid_sidecar[..MANIFEST_SIZE])).unwrap();
            run_openssl([
                "pkeyutl",
                "-sign",
                "-inkey",
                path_text(key).unwrap(),
                "-in",
                path_text(&input).unwrap(),
                "-out",
                path_text(&signature).unwrap(),
                "-pkeyopt",
                "rsa_padding_mode:pkcs1",
            ])
            .unwrap();
        }
        let alternate_signature = fs::read(signature).unwrap();
        assert_eq!(alternate_signature.len(), SIGNATURE_SIZE);
        let mut sidecar = valid_sidecar[..MANIFEST_SIZE].to_vec();
        sidecar.extend_from_slice(&alternate_signature);
        fs::write(sidecar_path, sidecar).unwrap();
        assert!(verify(verify_options).is_err());
        fs::write(sidecar_path, valid_sidecar).unwrap();
    }

    fn generate_test_certificate(certificate: &Path, key_type: &str, extra: &[&str]) {
        let directory = certificate.parent().unwrap();
        let key = directory.join(format!(
            "{}.key",
            certificate.file_name().unwrap().to_string_lossy()
        ));
        let mut command = Command::new("openssl");
        command.env("LC_ALL", "C").args([
            "req",
            "-x509",
            "-newkey",
            key_type,
            "-nodes",
            "-keyout",
            path_text(&key).unwrap(),
            "-out",
            path_text(certificate).unwrap(),
            "-days",
            "1",
            "-subj",
            "/CN=KernelSU negative test",
        ]);
        command.args(extra);
        assert!(command.status().unwrap().success());
    }

    fn c_define_string(source: &str, name: &str) -> String {
        let marker = format!("#define {name}");
        let start = source.find(&marker).unwrap();
        source[start + marker.len()..]
            .lines()
            .take_while(|line| line.trim_end().ends_with('\\') || line.contains('"'))
            .flat_map(|line| {
                line.split('"')
                    .enumerate()
                    .filter_map(|(index, part)| (index % 2 == 1).then_some(part))
            })
            .collect()
    }
}
