use crate::{ksu_uapi, ksucalls};
use anyhow::{Context, Result, bail, ensure};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

const RING_ENTRIES: u32 = 8;
const COMPLETION_TIMEOUT: Duration = Duration::from_secs(2);
const COMPLETION_POLL_INTERVAL: Duration = Duration::from_millis(1);

const IORING_SETUP_SQPOLL: u32 = 1 << 1;
const IORING_FEAT_SINGLE_MMAP: u32 = 1 << 0;
const IORING_SQ_NEED_WAKEUP: u32 = 1 << 0;

const IORING_REGISTER_FILES: u32 = 2;
const IORING_REGISTER_PERSONALITY: u32 = 9;
const IORING_UNREGISTER_PERSONALITY: u32 = 10;

const IORING_OFF_SQ_RING: libc::off_t = 0;
const IORING_OFF_CQ_RING: libc::off_t = 0x0800_0000;
const IORING_OFF_SQES: libc::off_t = 0x1000_0000;

const IORING_OP_READ: u8 = 22;
const IOSQE_FIXED_FILE: u8 = 1 << 0;
const IOSQE_ASYNC: u8 = 1 << 4;
const PROBE_USER_DATA: u64 = 0x4b53_5550_524f_5633;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct IoSqringOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    flags: u32,
    dropped: u32,
    array: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct IoCqringOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    overflow: u32,
    cqes: u32,
    flags: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct IoUringParams {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: u32,
    wq_fd: u32,
    resv: [u32; 3],
    sq_off: IoSqringOffsets,
    cq_off: IoCqringOffsets,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct IoUringSqe {
    opcode: u8,
    flags: u8,
    ioprio: u16,
    fd: i32,
    off: u64,
    addr: u64,
    len: u32,
    rw_flags: u32,
    user_data: u64,
    buf_index: u16,
    personality: u16,
    splice_fd_in: i32,
    addr3: u64,
    pad2: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct IoUringCqe {
    user_data: u64,
    res: i32,
    flags: u32,
}

const _: [(); 40] = [(); std::mem::size_of::<IoSqringOffsets>()];
const _: [(); 40] = [(); std::mem::size_of::<IoCqringOffsets>()];
const _: [(); 120] = [(); std::mem::size_of::<IoUringParams>()];
const _: [(); 64] = [(); std::mem::size_of::<IoUringSqe>()];
const _: [(); 16] = [(); std::mem::size_of::<IoUringCqe>()];

struct Mapping {
    address: *mut u8,
    length: usize,
}

impl Mapping {
    fn new(fd: RawFd, length: usize, offset: libc::off_t) -> io::Result<Self> {
        let address = unsafe {
            libc::mmap(
                ptr::null_mut(),
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd,
                offset,
            )
        };
        if address == libc::MAP_FAILED {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self {
                address: address.cast(),
                length,
            })
        }
    }

    const fn at<T>(&self, offset: u32) -> *mut T {
        unsafe { self.address.add(offset as usize).cast() }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.address.cast(), self.length);
        }
    }
}

struct Ring {
    fd: OwnedFd,
    parameters: IoUringParams,
    sq_mapping: Mapping,
    cq_mapping: Option<Mapping>,
    sqes: Mapping,
    sqpoll: bool,
}

impl Ring {
    fn new(sqpoll: bool) -> io::Result<Self> {
        let mut parameters = IoUringParams::default();
        if sqpoll {
            parameters.flags = IORING_SETUP_SQPOLL;
            parameters.sq_thread_idle = 1_000;
        }
        let fd = unsafe {
            libc::syscall(
                libc::SYS_io_uring_setup,
                RING_ENTRIES,
                ptr::from_mut(&mut parameters),
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };

        let sq_ring_length = parameters.sq_off.array as usize
            + parameters.sq_entries as usize * std::mem::size_of::<u32>();
        let cq_ring_length = parameters.cq_off.cqes as usize
            + parameters.cq_entries as usize * std::mem::size_of::<IoUringCqe>();
        let single_mapping = parameters.features & IORING_FEAT_SINGLE_MMAP != 0;
        let sq_mapping = Mapping::new(
            fd.as_raw_fd(),
            if single_mapping {
                sq_ring_length.max(cq_ring_length)
            } else {
                sq_ring_length
            },
            IORING_OFF_SQ_RING,
        )?;
        let cq_mapping = if single_mapping {
            None
        } else {
            Some(Mapping::new(
                fd.as_raw_fd(),
                cq_ring_length,
                IORING_OFF_CQ_RING,
            )?)
        };
        let sqes = Mapping::new(
            fd.as_raw_fd(),
            parameters.sq_entries as usize * std::mem::size_of::<IoUringSqe>(),
            IORING_OFF_SQES,
        )?;
        Ok(Self {
            fd,
            parameters,
            sq_mapping,
            cq_mapping,
            sqes,
            sqpoll,
        })
    }

    fn cq_mapping(&self) -> &Mapping {
        self.cq_mapping.as_ref().unwrap_or(&self.sq_mapping)
    }

    fn register_files(&self, driver_fd: RawFd) -> io::Result<()> {
        let file = driver_fd;
        let result = unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                self.fd.as_raw_fd(),
                IORING_REGISTER_FILES,
                ptr::from_ref(&file),
                1_u32,
            )
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn register_personality(&self) -> io::Result<u16> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                self.fd.as_raw_fd(),
                IORING_REGISTER_PERSONALITY,
                ptr::null::<libc::c_void>(),
                0_u32,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        u16::try_from(result).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "io_uring returned an invalid personality identifier",
            )
        })
    }

    fn unregister_personality(&self, personality: u16) -> io::Result<()> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                self.fd.as_raw_fd(),
                IORING_UNREGISTER_PERSONALITY,
                ptr::null::<libc::c_void>(),
                u32::from(personality),
            )
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn submit_probe(
        &self,
        driver_fd: RawFd,
        sqe_flags: u8,
        personality: u16,
    ) -> Result<ksu_uapi::ksu_provenance_current_context_v1> {
        let sq_head = unsafe { &*self.sq_mapping.at::<AtomicU32>(self.parameters.sq_off.head) };
        let sq_tail = unsafe { &*self.sq_mapping.at::<AtomicU32>(self.parameters.sq_off.tail) };
        let head = sq_head.load(Ordering::Acquire);
        let tail = sq_tail.load(Ordering::Relaxed);
        ensure!(
            tail.wrapping_sub(head) < self.parameters.sq_entries,
            "io_uring submission queue is full"
        );
        let mask = unsafe {
            ptr::read_volatile(self.sq_mapping.at::<u32>(self.parameters.sq_off.ring_mask))
        };
        let index = tail & mask;
        let mut current =
            Box::new(unsafe { std::mem::zeroed::<ksu_uapi::ksu_provenance_current_context_v1>() });
        let sqe = IoUringSqe {
            opcode: IORING_OP_READ,
            flags: sqe_flags,
            fd: if sqe_flags & IOSQE_FIXED_FILE != 0 {
                0
            } else {
                driver_fd
            },
            off: u64::MAX,
            addr: ptr::from_mut(current.as_mut()) as u64,
            len: std::mem::size_of_val(current.as_ref()) as u32,
            user_data: PROBE_USER_DATA,
            personality,
            ..IoUringSqe::default()
        };
        unsafe {
            ptr::write(self.sqes.at::<IoUringSqe>(index * 64), sqe);
            ptr::write_volatile(
                self.sq_mapping
                    .at::<u32>(self.parameters.sq_off.array)
                    .add(index as usize),
                index,
            );
        }
        sq_tail.store(tail.wrapping_add(1), Ordering::Release);

        let completion = (|| -> Result<()> {
            if self.sqpoll {
                let poll_flags = unsafe {
                    &*self
                        .sq_mapping
                        .at::<AtomicU32>(self.parameters.sq_off.flags)
                };
                if poll_flags.load(Ordering::Acquire) & IORING_SQ_NEED_WAKEUP != 0 {
                    self.enter(0, 1 << 1)
                        .context("wake io_uring SQPOLL thread")?;
                }
            } else {
                let submitted = self
                    .enter(1, 0)
                    .context("submit io_uring provenance probe")?;
                ensure!(
                    submitted == 1,
                    "io_uring accepted {submitted} probes, expected 1"
                );
            }
            self.wait_completion()
        })();

        if let Err(error) = completion {
            Box::leak(current);
            return Err(error);
        }
        Ok(*current)
    }

    fn enter(&self, to_submit: u32, flags: u32) -> io::Result<i64> {
        loop {
            let result = unsafe {
                libc::syscall(
                    libc::SYS_io_uring_enter,
                    self.fd.as_raw_fd(),
                    to_submit,
                    0_u32,
                    flags,
                    ptr::null::<libc::sigset_t>(),
                    0_usize,
                )
            };
            if result >= 0 {
                return Ok(result);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    fn wait_completion(&self) -> Result<()> {
        let cq_mapping = self.cq_mapping();
        let cq_head = unsafe { &*cq_mapping.at::<AtomicU32>(self.parameters.cq_off.head) };
        let cq_tail = unsafe { &*cq_mapping.at::<AtomicU32>(self.parameters.cq_off.tail) };
        let deadline = Instant::now() + COMPLETION_TIMEOUT;
        loop {
            let head = cq_head.load(Ordering::Relaxed);
            if head != cq_tail.load(Ordering::Acquire) {
                let mask = unsafe {
                    ptr::read_volatile(cq_mapping.at::<u32>(self.parameters.cq_off.ring_mask))
                };
                let cqe = unsafe {
                    ptr::read(
                        cq_mapping
                            .at::<IoUringCqe>(self.parameters.cq_off.cqes)
                            .add((head & mask) as usize),
                    )
                };
                cq_head.store(head.wrapping_add(1), Ordering::Release);
                ensure!(
                    cqe.user_data == PROBE_USER_DATA,
                    "io_uring returned an unexpected completion"
                );
                if cqe.res < 0 {
                    return Err(io::Error::from_raw_os_error(-cqe.res))
                        .context("io_uring provenance probe completion");
                }
                ensure!(
                    cqe.res as usize
                        == std::mem::size_of::<ksu_uapi::ksu_provenance_current_context_v1>(),
                    "io_uring provenance probe returned {} bytes",
                    cqe.res
                );
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!("io_uring provenance probe timed out");
            }
            std::thread::sleep(COMPLETION_POLL_INTERVAL);
        }
    }
}

fn verify_context(
    label: &str,
    current: &ksu_uapi::ksu_provenance_current_context_v1,
    generation: u64,
    cookie: u64,
) -> Result<()> {
    ensure!(
        usize::from(current.size) == std::mem::size_of_val(current)
            && current.version == ksu_uapi::KSU_PROVENANCE_UAPI_VERSION,
        "{label} returned an invalid provenance response"
    );
    ensure!(
        current.supervisor_generation == generation,
        "{label} lost supervisor generation: expected {generation}, got {}",
        current.supervisor_generation
    );
    ensure!(
        current.context_cookie == cookie,
        "{label} lost context cookie: expected {cookie:#x}, got {:#x}",
        current.context_cookie
    );
    ensure!(
        current.gap_reason == ksu_uapi::ksu_provenance_gap_reason_KSU_PROVENANCE_GAP_NONE,
        "{label} acquired provenance gap {}",
        current.gap_reason
    );
    Ok(())
}

pub fn run_all(generation: u64, cookie: u64) -> Result<()> {
    let driver_fd = ksucalls::provenance_probe_fd().context("open io_uring provenance probe")?;
    let ring = Ring::new(false).context("create direct/worker io_uring")?;

    let direct = ring
        .submit_probe(driver_fd, 0, 0)
        .context("direct io_uring attribution")?;
    verify_context("direct io_uring", &direct, generation, cookie)?;

    let worker = ring
        .submit_probe(driver_fd, IOSQE_ASYNC, 0)
        .context("io_uring worker attribution")?;
    verify_context("io_uring worker", &worker, generation, cookie)?;

    let personality = ring
        .register_personality()
        .context("register io_uring personality")?;
    let personality_result = ring
        .submit_probe(driver_fd, IOSQE_ASYNC, personality)
        .context("registered-personality io_uring attribution")
        .and_then(|current| {
            verify_context(
                "registered-personality io_uring",
                &current,
                generation,
                cookie,
            )
        });
    let unregister_result = ring.unregister_personality(personality);
    personality_result?;
    unregister_result.context("unregister io_uring personality")?;

    let sqpoll_ring = Ring::new(true).context("create SQPOLL io_uring")?;
    sqpoll_ring
        .register_files(driver_fd)
        .context("register SQPOLL provenance probe descriptor")?;
    let sqpoll = sqpoll_ring
        .submit_probe(driver_fd, IOSQE_FIXED_FILE, 0)
        .context("SQPOLL io_uring attribution")?;
    verify_context("SQPOLL io_uring", &sqpoll, generation, cookie)?;
    Ok(())
}
