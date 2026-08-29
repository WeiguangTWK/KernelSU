#![allow(nonstandard_style, unused, unsafe_op_in_unsafe_fn)]
#![allow(clippy::all, clippy::pedantic, clippy::nursery)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

const _: [(); 128] = [(); std::mem::size_of::<ksu_provenance_event_header_v1>()];
const _: [(); 224] = [(); std::mem::size_of::<ksu_provenance_context_descriptor_v1>()];
const _: [(); 96] = [(); std::mem::size_of::<ksu_provenance_barrier_result_v1>()];
const _: [(); 64] = [(); std::mem::size_of::<ksu_provenance_control_cmd_v1>()];
const _: [(); 64] = [(); std::mem::size_of::<ksu_provenance_claim_supervisor_v1>()];
const _: [(); 32] = [(); std::mem::size_of::<ksu_provenance_claim_result_v1>()];
const _: [(); 192] = [(); std::mem::size_of::<ksu_provenance_eligibility_info_v1>()];
const _: [(); 192] = [(); std::mem::size_of::<ksu_provenance_info_v1>()];
const _: [(); 192] = [(); std::mem::size_of::<ksu_provenance_image_manifest_v1>()];
