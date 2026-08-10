use anyhow::Result;
use clap::Parser;

use crate::boot_patch::{BootPatchArgs, BootRestoreArgs};
use crate::lkm_image::BootPatchV2Args;
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
    };

    if let Err(e) = &result {
        log::error!("Error: {e:?}");
    }
    result
}
