use std::time::Duration;

/// Maximum chunk data size for TCP (direct) transport.
pub const TCP_CHUNK_DATA_SIZE: usize = 60_000;

/// Maximum chunk data size for reliable UDP (punched) transport.
pub const PUNCHED_CHUNK_DATA_SIZE: usize = 1_100;

/// Default maximum file size (2 GB).
pub const MAX_FILE_SIZE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Maximum file size over punched (NAT traversal) transport (200 MB).
pub const MAX_PUNCHED_FILE_SIZE_BYTES: u64 = 200 * 1024 * 1024;

/// Number of chunks the sender can send ahead of the last acknowledged chunk.
pub const FLOW_CONTROL_WINDOW: u32 = 64;

/// Chunks to send per control-loop tick (prevents starving cursor/input).
pub const CHUNKS_PER_TICK: usize = 8;

/// How often the receiver sends FileProgress ACKs (every N chunks).
pub const PROGRESS_ACK_INTERVAL: u32 = 16;

/// Timeout for stalled transfers (no chunk or ACK received).
pub const TRANSFER_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum filename length in bytes.
pub const MAX_FILENAME_BYTES: usize = 255;

/// File receive directory name inside ~/Downloads.
pub const DEFAULT_RECEIVE_DIR: &str = "st-transfers";

/// Transport mode determines chunk sizing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    Direct,
    Punched,
}

impl TransportMode {
    pub fn chunk_size(self) -> usize {
        match self {
            TransportMode::Direct => TCP_CHUNK_DATA_SIZE,
            TransportMode::Punched => PUNCHED_CHUNK_DATA_SIZE,
        }
    }

    pub fn max_file_size(self) -> u64 {
        match self {
            TransportMode::Direct => max_file_size_configured(),
            TransportMode::Punched => MAX_PUNCHED_FILE_SIZE_BYTES.min(max_file_size_configured()),
        }
    }
}

/// Read configured max file size from `ST_MAX_FILE_SIZE_MB`, falling back to default.
fn max_file_size_configured() -> u64 {
    std::env::var("ST_MAX_FILE_SIZE_MB")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(|mb| mb * 1024 * 1024)
        .unwrap_or(MAX_FILE_SIZE_BYTES)
}

/// Transfer direction from the perspective of the local side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    Sending,
    Receiving,
}

/// Current state of a file transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferStatus {
    /// Sender has sent FileOffer, waiting for FileAccept.
    AwaitingAccept,
    /// Actively transferring chunks.
    Active,
    /// All chunks sent/received, verifying integrity.
    Verifying,
    /// Transfer completed successfully.
    Completed,
    /// Transfer was cancelled.
    Cancelled,
    /// Transfer failed.
    Failed,
}

/// Metadata for an in-progress transfer (shared between sender and receiver).
#[derive(Debug, Clone)]
pub struct TransferInfo {
    pub transfer_id: u32,
    pub direction: TransferDirection,
    pub file_name: String,
    pub file_size: u64,
    pub status: TransferStatus,
    pub chunks_total: u32,
    pub chunks_done: u32,
    pub chunk_size: usize,
}

impl TransferInfo {
    pub fn new_send(transfer_id: u32, file_name: String, file_size: u64, mode: TransportMode) -> Self {
        let chunk_size = mode.chunk_size();
        let chunks_total = ((file_size + chunk_size as u64 - 1) / chunk_size as u64) as u32;
        Self {
            transfer_id,
            direction: TransferDirection::Sending,
            file_name,
            file_size,
            status: TransferStatus::AwaitingAccept,
            chunks_total,
            chunks_done: 0,
            chunk_size,
        }
    }

    pub fn new_receive(
        transfer_id: u32,
        file_name: String,
        file_size: u64,
        mode: TransportMode,
    ) -> Self {
        let chunk_size = mode.chunk_size();
        let chunks_total = ((file_size + chunk_size as u64 - 1) / chunk_size as u64) as u32;
        Self {
            transfer_id,
            direction: TransferDirection::Receiving,
            file_name,
            file_size,
            status: TransferStatus::Active,
            chunks_total,
            chunks_done: 0,
            chunk_size,
        }
    }

    pub fn progress_fraction(&self) -> f32 {
        if self.chunks_total == 0 {
            return 1.0;
        }
        self.chunks_done as f32 / self.chunks_total as f32
    }

    pub fn bytes_transferred(&self) -> u64 {
        (self.chunks_done as u64) * (self.chunk_size as u64)
    }
}

/// Sanitize a filename received from a remote peer.
///
/// Strips path components, rejects dangerous patterns, and clamps length.
/// Returns `None` if the filename is empty or entirely invalid.
pub fn sanitize_filename(raw: &str) -> Option<String> {
    // Take only the final path component (handle both / and \).
    let name = raw
        .rsplit(|c| c == '/' || c == '\\')
        .next()
        .unwrap_or("");

    // Reject empty, dot-only, null bytes, or ".." traversal.
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('\0')
    {
        return None;
    }

    // Clamp to max length at a UTF-8 boundary.
    let clamped = if name.len() > MAX_FILENAME_BYTES {
        let mut end = MAX_FILENAME_BYTES;
        while end > 0 && !name.is_char_boundary(end) {
            end -= 1;
        }
        &name[..end]
    } else {
        name
    };

    if clamped.is_empty() {
        return None;
    }

    Some(clamped.to_string())
}

/// Format bytes into a human-readable string.
pub fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_path() {
        assert_eq!(sanitize_filename("/etc/passwd"), Some("passwd".into()));
        assert_eq!(sanitize_filename("C:\\Users\\foo\\doc.txt"), Some("doc.txt".into()));
    }

    #[test]
    fn sanitize_rejects_bad() {
        assert_eq!(sanitize_filename(".."), None);
        assert_eq!(sanitize_filename("."), None);
        assert_eq!(sanitize_filename(""), None);
        assert_eq!(sanitize_filename("foo\0bar"), None);
    }

    #[test]
    fn sanitize_clamps_length() {
        let long = "a".repeat(300);
        let result = sanitize_filename(&long).unwrap();
        assert!(result.len() <= MAX_FILENAME_BYTES);
    }

    #[test]
    fn transfer_info_progress() {
        let info = TransferInfo::new_send(1, "test.bin".into(), 120_000, TransportMode::Direct);
        assert_eq!(info.chunks_total, 2); // 120_000 / 60_000
        assert_eq!(info.progress_fraction(), 0.0);
    }

    #[test]
    fn format_bytes_ranges() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(2048), "2.0 KB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 MB");
    }
}
