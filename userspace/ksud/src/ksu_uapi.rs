#![allow(nonstandard_style, unused, unsafe_op_in_unsafe_fn)]
#![allow(clippy::all, clippy::pedantic, clippy::nursery)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

const _: [(); 128] = [(); std::mem::size_of::<ksu_provenance_event_header_v1>()];
const _: [(); 224] = [(); std::mem::size_of::<ksu_provenance_context_descriptor_v1>()];
const _: [(); 96] = [(); std::mem::size_of::<ksu_provenance_barrier_result_v1>()];
const _: [(); 64] = [(); std::mem::size_of::<ksu_provenance_control_cmd_v1>()];
const _: [(); 64] = [(); std::mem::size_of::<ksu_provenance_claim_supervisor_v1>()];
const _: [(); 32] = [(); std::mem::size_of::<ksu_provenance_claim_result_v1>()];
const _: [(); 256] = [(); std::mem::size_of::<ksu_provenance_create_launch_v1>()];
const _: [(); 32] = [(); std::mem::size_of::<ksu_provenance_create_launch_result_v1>()];
const _: [(); 32] = [(); std::mem::size_of::<ksu_provenance_activate_v1>()];
const _: [(); 32] = [(); std::mem::size_of::<ksu_provenance_activate_result_v1>()];
const _: [(); 32] = [(); std::mem::size_of::<ksu_provenance_close_context_v1>()];
const _: [(); 32] = [(); std::mem::size_of::<ksu_provenance_supervisor_ready_v1>()];
const _: [(); 64] = [(); std::mem::size_of::<ksu_provenance_current_context_v1>()];
const _: [(); 128] = [(); std::mem::size_of::<ksu_provenance_context_status_v1>()];
const _: [(); 192] = [(); std::mem::size_of::<ksu_provenance_eligibility_info_v1>()];
const _: [(); 192] = [(); std::mem::size_of::<ksu_provenance_info_v1>()];
const _: [(); 192] = [(); std::mem::size_of::<ksu_provenance_image_manifest_v1>()];
