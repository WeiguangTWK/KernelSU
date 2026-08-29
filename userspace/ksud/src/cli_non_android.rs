use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

use crate::boot_patch::{BootPatchArgs, BootRestoreArgs};
use crate::lkm_image::BootPatchV2Args;
use crate::provenance_manifest::{
    GenerateCertificateOptions, KernelKeyHeaderOptions, SignOptions, VerifyOptions,
};
use crate::{apk_sign, defs};

/// KernelSU cli for non-android
#[derive(Parser, Debug)]
#[command(author, version = defs::VERSION_NAME, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Patch boot or init_boot images to apply KernelSU
    BootPatch(BootPatchArgs),

    /// Restore boot or init_boot images patched by KernelSU
    BootRestore(BootRestoreArgs),

    /// Patch KernelSU into a boot image
    ///
    /// Always operates on a boot image; never selects init_boot or vendor_boot.
    BootPatchV2(BootPatchV2Args),

    /// Get apk size and hash
    GetSign {
        /// apk path
        apk: String,
    },

    /// show supported kmi versions
    SupportedKmis,

    /// Audit a KernelSU module ZIP without installing it
    ModuleAudit {
        /// module zip file path
        zip: String,
        /// print the structured JSON report
        #[arg(long)]
        json: bool,
    },

    /// Verify a development module audit history store
    ModuleAuditHistory {
        /// audit history root
        root: String,
        /// limit verification to one module id
        #[arg(long)]
        id: Option<String>,
        /// repair corrupt event suffixes
        #[arg(long)]
        repair: bool,
    },

    /// Export a development Manager-checkpoint payload
    ModuleAuditCheckpoint {
        /// audit history root
        root: String,
    },

    /// Build and inspect signed audit provenance artifacts
    ProvenanceManifest {
        #[command(subcommand)]
        command: ProvenanceManifestCommand,
    },
}

#[derive(clap::Subcommand, Debug)]
enum ProvenanceManifestCommand {
    /// Generate a new RSA-3072 private key and self-signed X.509 certificate
    GenerateCertificate {
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        certificate: PathBuf,
        #[arg(long, default_value = "KernelSU provenance build")]
        common_name: String,
        #[arg(long, default_value_t = 3650)]
        validity_days: u32,
    },
    /// Create a canonical detached manifest and RSA-3072 signature sidecar
    Sign {
        #[arg(long)]
        image: PathBuf,
        #[arg(long)]
        certificate: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// 32-byte build identity encoded as 64 hexadecimal characters
        #[arg(long)]
        build_id: String,
        /// Role bitmap: supervisor=1, init-proxy=2
        #[arg(long, default_value_t = 1)]
        roles: u32,
        #[arg(long)]
        security_epoch: u64,
        #[arg(long, default_value_t = 1)]
        uapi_min: u32,
        #[arg(long, default_value_t = 1)]
        uapi_max: u32,
    },
    /// Verify a detached manifest and image using the kernel-equivalent rules
    Verify {
        #[arg(long)]
        image: PathBuf,
        #[arg(long)]
        certificate: PathBuf,
        #[arg(long)]
        sidecar: PathBuf,
        /// Required role bitmap: supervisor=1, init-proxy=2
        #[arg(long, default_value_t = 1)]
        required_role: u32,
        #[arg(long, default_value_t = 0)]
        minimum_security_epoch: u64,
    },
    /// Emit the public-only header consumed by built-in and LKM builds
    EmitKernelKeyHeader {
        #[arg(long)]
        current_certificate: PathBuf,
        #[arg(long)]
        current_private_key: PathBuf,
        #[arg(long)]
        current_minimum_epoch: u64,
        #[arg(long)]
        next_certificate: Option<PathBuf>,
        #[arg(long)]
        next_private_key: Option<PathBuf>,
        #[arg(long)]
        next_minimum_epoch: Option<u64>,
        #[arg(long)]
        output: PathBuf,
    },
}

pub fn run() -> Result<()> {
    env_logger::init();

    let cli = Args::parse();

    log::info!("command: {:?}", cli.command);

    let result = match cli.command {
        Commands::GetSign { apk } => {
            let sign = apk_sign::get_apk_signature(&apk)?;
            println!("size: {:#x}, hash: {}", sign.0, sign.1);
            Ok(())
        }

        Commands::BootPatch(boot_patch) => crate::boot_patch::patch(boot_patch),

        Commands::BootRestore(boot_restore) => crate::boot_patch::restore(boot_restore),

        Commands::BootPatchV2(patch) => crate::lkm_image::patch_boot(&patch),

        Commands::SupportedKmis => {
            let kmi = crate::assets::list_supported_kmi();
            for kmi in &kmi {
                println!("{kmi}");
            }
            Ok(())
        }

        Commands::ModuleAudit { zip, json } => crate::module_audit::print_zip_report(&zip, json),
        Commands::ModuleAuditHistory { root, id, repair } => {
            let root = std::path::Path::new(&root);
            let histories = if let Some(id) = id {
                vec![crate::module_audit_log::read_module_history(
                    root, &id, repair,
                )?]
            } else {
                crate::module_audit_log::list_histories(root, repair)?
            };
            println!("{}", serde_json::to_string_pretty(&histories)?);
            Ok(())
        }
        Commands::ModuleAuditCheckpoint { root } => {
            let payload = crate::module_audit_log::checkpoint_payload(std::path::Path::new(&root))?;
            println!("{}", serde_json::to_string_pretty(&payload)?);
            Ok(())
        }
        Commands::ProvenanceManifest { command } => match command {
            ProvenanceManifestCommand::GenerateCertificate {
                private_key,
                certificate,
                common_name,
                validity_days,
            } => crate::provenance_manifest::generate_certificate(&GenerateCertificateOptions {
                private_key,
                certificate,
                common_name,
                validity_days,
            }),
            ProvenanceManifestCommand::Sign {
                image,
                certificate,
                private_key,
                output,
                build_id,
                roles,
                security_epoch,
                uapi_min,
                uapi_max,
            } => {
                let manifest = crate::provenance_manifest::sign(&SignOptions {
                    image,
                    certificate,
                    private_key,
                    output,
                    build_id: crate::provenance_manifest::parse_digest_hex(&build_id, "build id")?,
                    roles,
                    security_epoch,
                    uapi_min,
                    uapi_max,
                })?;
                print_manifest(&manifest);
                Ok(())
            }
            ProvenanceManifestCommand::Verify {
                image,
                certificate,
                sidecar,
                required_role,
                minimum_security_epoch,
            } => {
                let manifest = crate::provenance_manifest::verify(&VerifyOptions {
                    image,
                    certificate,
                    sidecar,
                    required_role,
                    minimum_security_epoch,
                })?;
                print_manifest(&manifest);
                Ok(())
            }
            ProvenanceManifestCommand::EmitKernelKeyHeader {
                current_certificate,
                current_private_key,
                current_minimum_epoch,
                next_certificate,
                next_private_key,
                next_minimum_epoch,
                output,
            } => crate::provenance_manifest::emit_kernel_key_header(&KernelKeyHeaderOptions {
                current_certificate,
                current_private_key,
                current_minimum_epoch,
                next_certificate,
                next_private_key,
                next_minimum_epoch,
                output,
            }),
        },
    };

    if let Err(e) = &result {
        log::error!("Error: {e:?}");
    }
    result
}

fn print_manifest(manifest: &crate::provenance_manifest::ImageManifestV1) {
    println!("roles: 0x{:x}", manifest.roles);
    println!("image_size: {}", manifest.image_size);
    println!(
        "image_sha256: {}",
        base16ct::lower::encode_string(&manifest.image_sha256)
    );
    println!(
        "build_id: {}",
        base16ct::lower::encode_string(&manifest.build_id)
    );
    println!("uapi: {}..={}", manifest.uapi_min, manifest.uapi_max);
    println!("security_epoch: {}", manifest.security_epoch);
    println!(
        "signing_key_id: {}",
        base16ct::lower::encode_string(&manifest.signing_key_id)
    );
}
