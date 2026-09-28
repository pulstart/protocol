//! Scheduling priority for latency-critical media threads.
//!
//! A streaming host is usually also running the game being streamed. Without
//! elevation, capture/encode/send compete with it as equals and the stream
//! stutters exactly when the machine is busiest. Each media thread calls
//! [`promote_current_thread`] once when it starts.
//!
//! Linux: `SCHED_RR | SCHED_RESET_ON_FORK` (needs `CAP_SYS_NICE` or
//! `RLIMIT_RTPRIO`) → negative nice → RealtimeKit (feature `rtkit`). Reset-on-fork
//! keeps FFmpeg/driver worker threads spawned by a promoted thread out of the RT
//! class. Windows: thread priority + MMCSS. macOS: QoS class.
//! `ST_THREAD_PRIO=nice` skips realtime; `0`/`off` disables elevation.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadRole {
    /// Input injection / input send.
    Input,
    /// Media send (server) or receive + reassembly (client).
    Network,
    AudioCapture,
    /// Audio encode / decode / playback feed.
    Audio,
    /// Frame capture.
    Capture,
    /// Video encode / decode.
    Video,
}

impl ThreadRole {
    fn name(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Network => "network",
            Self::AudioCapture => "audio-capture",
            Self::Audio => "audio",
            Self::Capture => "capture",
            Self::Video => "video",
        }
    }

    fn bit(self) -> u32 {
        1 << self as u32
    }

    // Kept below kernel IRQ threads (50) and PipeWire's data loop (88). Video
    // stays nice-only: software codecs can saturate a core, and their worker
    // threads inherit nice but not a reset-on-fork RT class.
    #[cfg(target_os = "linux")]
    fn rt_priority(self) -> Option<i32> {
        match self {
            Self::Input => Some(24),
            Self::Network => Some(22),
            Self::AudioCapture => Some(20),
            Self::Audio => Some(18),
            Self::Capture => Some(16),
            Self::Video => None,
        }
    }

    // -15 is RealtimeKit's default floor.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn nice(self) -> i32 {
        match self {
            Self::Input | Self::Network | Self::AudioCapture | Self::Capture => -15,
            Self::Audio | Self::Video => -10,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Elevation {
    Realtime(i32),
    Nice(i32),
    /// Windows/macOS platform priority applied.
    Platform,
    Unchanged,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Auto,
    NiceOnly,
    Off,
}

fn mode() -> Mode {
    static MODE: OnceLock<Mode> = OnceLock::new();
    *MODE.get_or_init(|| {
        match std::env::var("ST_THREAD_PRIO")
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref()
        {
            Ok("0") | Ok("off") | Ok("false") | Ok("no") => Mode::Off,
            Ok("nice") => Mode::NiceOnly,
            _ => Mode::Auto,
        }
    })
}

/// Raise the calling thread's scheduling priority for `role`. Never fails hard;
/// logs the outcome once per role per process.
pub fn promote_current_thread(role: ThreadRole) -> Elevation {
    let elevation = if mode() == Mode::Off {
        Elevation::Unchanged
    } else {
        platform::promote(role)
    };
    static LOGGED: AtomicU32 = AtomicU32::new(0);
    if LOGGED.fetch_or(role.bit(), Ordering::Relaxed) & role.bit() == 0 {
        match elevation {
            Elevation::Realtime(p) => eprintln!("[prio] {}: SCHED_RR {p}", role.name()),
            Elevation::Nice(n) => eprintln!("[prio] {}: nice {n}", role.name()),
            Elevation::Platform => eprintln!("[prio] {}: elevated", role.name()),
            Elevation::Unchanged if mode() == Mode::Off => {}
            Elevation::Unchanged => eprintln!(
                "[prio] {}: not elevated (grant CAP_SYS_NICE or run RealtimeKit); media may stutter under host load",
                role.name()
            ),
        }
    }
    elevation
}

/// Process-wide scheduling setup; call once at startup before spawning threads.
/// `host` selects the streaming-host policy (higher process class on Windows).
pub fn init_process(host: bool) {
    if mode() == Mode::Off {
        return;
    }
    platform::init_process(host);
}

#[cfg(target_os = "linux")]
const SCHED_RESET_ON_FORK: libc::c_int = 0x4000_0000;

#[cfg(any(target_os = "linux", target_os = "android"))]
mod platform {
    use super::{Elevation, ThreadRole};

    pub(super) fn promote(role: ThreadRole) -> Elevation {
        // Nice-level fallback threads would otherwise oversleep every pacing
        // wait by the default 50µs slack; RT threads ignore slack.
        unsafe {
            libc::prctl(libc::PR_SET_TIMERSLACK, 1 as libc::c_ulong, 0, 0, 0);
        }
        #[cfg(target_os = "linux")]
        if let Some(priority) = role
            .rt_priority()
            .filter(|_| super::mode() == super::Mode::Auto)
        {
            let param = libc::sched_param {
                sched_priority: priority,
            };
            if unsafe {
                libc::sched_setscheduler(0, libc::SCHED_RR | super::SCHED_RESET_ON_FORK, &param)
            } == 0
            {
                return Elevation::Realtime(priority);
            }
        }
        let tid = unsafe { libc::syscall(libc::SYS_gettid) } as libc::id_t;
        if unsafe { libc::setpriority(libc::PRIO_PROCESS, tid, role.nice()) } == 0 {
            return Elevation::Nice(role.nice());
        }
        #[cfg(all(target_os = "linux", feature = "rtkit"))]
        if let Some(nice) = super::rtkit::make_thread_high_priority(tid as u64, role.nice()) {
            return Elevation::Nice(nice);
        }
        Elevation::Unchanged
    }

    pub(super) fn init_process(_host: bool) {}
}

#[cfg(all(target_os = "linux", feature = "rtkit"))]
mod rtkit {
    use std::sync::OnceLock;
    use zbus::blocking::{Connection, Proxy};

    pub(super) fn make_thread_high_priority(tid: u64, nice: i32) -> Option<i32> {
        static CONN: OnceLock<Option<Connection>> = OnceLock::new();
        let conn = CONN.get_or_init(|| Connection::system().ok()).as_ref()?;
        let proxy = Proxy::new(
            conn,
            "org.freedesktop.RealtimeKit1",
            "/org/freedesktop/RealtimeKit1",
            "org.freedesktop.RealtimeKit1",
        )
        .ok()?;
        let floor: i32 = proxy.get_property("MinNiceLevel").unwrap_or(-15);
        let nice = nice.max(floor);
        proxy
            .call::<_, _, ()>("MakeThreadHighPriority", &(tid, nice))
            .ok()
            .map(|()| nice)
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::{Elevation, ThreadRole};

    const THREAD_PRIORITY_HIGHEST: i32 = 2;
    const THREAD_PRIORITY_TIME_CRITICAL: i32 = 15;
    const HIGH_PRIORITY_CLASS: u32 = 0x80;
    const ABOVE_NORMAL_PRIORITY_CLASS: u32 = 0x8000;
    const PROCESS_POWER_THROTTLING: i32 = 4;
    const POWER_THROTTLING_CURRENT_VERSION: u32 = 1;
    const POWER_THROTTLING_EXECUTION_SPEED: u32 = 0x1;
    const POWER_THROTTLING_IGNORE_TIMER_RESOLUTION: u32 = 0x4;

    #[repr(C)]
    struct PowerThrottlingState {
        version: u32,
        control_mask: u32,
        state_mask: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentThread() -> isize;
        fn GetCurrentProcess() -> isize;
        fn SetThreadPriority(thread: isize, priority: i32) -> i32;
        fn SetPriorityClass(process: isize, class: u32) -> i32;
        fn SetProcessInformation(
            process: isize,
            class: i32,
            info: *const core::ffi::c_void,
            size: u32,
        ) -> i32;
    }

    #[link(name = "avrt")]
    extern "system" {
        fn AvSetMmThreadCharacteristicsW(task: *const u16, index: *mut u32) -> isize;
    }

    #[link(name = "winmm")]
    extern "system" {
        fn timeBeginPeriod(period: u32) -> u32;
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub(super) fn promote(role: ThreadRole) -> Elevation {
        let (priority, task) = match role {
            ThreadRole::AudioCapture | ThreadRole::Audio => {
                (THREAD_PRIORITY_TIME_CRITICAL, "Pro Audio")
            }
            ThreadRole::Input | ThreadRole::Network | ThreadRole::Capture => {
                (THREAD_PRIORITY_TIME_CRITICAL, "Games")
            }
            ThreadRole::Video => (THREAD_PRIORITY_HIGHEST, "Games"),
        };
        let task = wide(task);
        let mut index = 0u32;
        // The MMCSS registration lives until the thread exits.
        let mmcss = unsafe { AvSetMmThreadCharacteristicsW(task.as_ptr(), &mut index) } != 0;
        let prio = unsafe { SetThreadPriority(GetCurrentThread(), priority) } != 0;
        if mmcss || prio {
            Elevation::Platform
        } else {
            Elevation::Unchanged
        }
    }

    pub(super) fn init_process(host: bool) {
        let class = if host {
            HIGH_PRIORITY_CLASS
        } else {
            ABOVE_NORMAL_PRIORITY_CLASS
        };
        // EcoQoS would park a windowless host on E-cores at reduced clocks and
        // ignore its timer-resolution request.
        let state = PowerThrottlingState {
            version: POWER_THROTTLING_CURRENT_VERSION,
            control_mask: POWER_THROTTLING_EXECUTION_SPEED
                | POWER_THROTTLING_IGNORE_TIMER_RESOLUTION,
            state_mask: 0,
        };
        unsafe {
            SetPriorityClass(GetCurrentProcess(), class);
            SetProcessInformation(
                GetCurrentProcess(),
                PROCESS_POWER_THROTTLING,
                &state as *const PowerThrottlingState as *const core::ffi::c_void,
                std::mem::size_of::<PowerThrottlingState>() as u32,
            );
            // Channel waits otherwise round up to the 15.6ms scheduler tick.
            timeBeginPeriod(1);
        }
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::{Elevation, ThreadRole};

    pub(super) fn promote(_role: ThreadRole) -> Elevation {
        let ok = unsafe {
            libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_USER_INTERACTIVE, 0)
        } == 0;
        if ok {
            Elevation::Platform
        } else {
            Elevation::Unchanged
        }
    }

    pub(super) fn init_process(_host: bool) {}
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "windows",
    target_os = "macos"
)))]
mod platform {
    use super::{Elevation, ThreadRole};

    pub(super) fn promote(_role: ThreadRole) -> Elevation {
        Elevation::Unchanged
    }

    pub(super) fn init_process(_host: bool) {}
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// Promoted threads must not leak the RT class into threads they spawn
    /// (FFmpeg/x264 workers, driver threads).
    #[test]
    fn realtime_promotion_does_not_propagate_to_children() {
        std::thread::spawn(|| {
            let elevation = promote_current_thread(ThreadRole::Capture);
            let child_policy = std::thread::spawn(|| unsafe { libc::sched_getscheduler(0) })
                .join()
                .unwrap();
            if let Elevation::Realtime(_) = elevation {
                let own = unsafe { libc::sched_getscheduler(0) };
                assert_eq!(own & !SCHED_RESET_ON_FORK, libc::SCHED_RR);
                assert_eq!(child_policy, libc::SCHED_OTHER);
            }
        })
        .join()
        .unwrap();
    }

    /// Codec threads get nice, which their worker threads inherit.
    #[test]
    fn video_role_is_nice_and_inherited() {
        std::thread::spawn(|| {
            if let Elevation::Nice(nice) = promote_current_thread(ThreadRole::Video) {
                assert_eq!(unsafe { libc::sched_getscheduler(0) }, libc::SCHED_OTHER);
                let child_nice = std::thread::spawn(|| unsafe {
                    libc::getpriority(
                        libc::PRIO_PROCESS,
                        libc::syscall(libc::SYS_gettid) as libc::id_t,
                    )
                })
                .join()
                .unwrap();
                assert_eq!(child_nice, nice);
            }
        })
        .join()
        .unwrap();
    }
}
