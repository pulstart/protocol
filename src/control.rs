/// Simple TCP control messages between server and client.
///
/// Wire format: [type: u8][len: u16 BE][payload: len bytes]

/// Maximum payload size for a control message.
pub const MAX_CONTROL_PAYLOAD: usize = u16::MAX as usize;

/// Control message header size: 1 byte type + 2 bytes length.
pub const CONTROL_HEADER_SIZE: usize = 3;

/// Fixed-size payload for stream configuration.
const STREAM_CONFIG_PAYLOAD_SIZE: usize = 17;
/// Fixed-size payload for client display refresh hints, client UDP receive
/// port, and advertised video codec support.
const CLIENT_DISPLAY_INFO_PAYLOAD_SIZE: usize = 8;
/// Fixed-size payload for client clock-sync pings.
const CLOCK_SYNC_PING_PAYLOAD_SIZE: usize = 8;
/// Fixed-size payload for server clock-sync pongs.
const CLOCK_SYNC_PONG_PAYLOAD_SIZE: usize = 28;
/// Fixed-size payload for periodic client transport feedback.
const TRANSPORT_FEEDBACK_PAYLOAD_SIZE: usize = 24;
/// Fixed-size payload for per-client input session ids.
const INPUT_SESSION_PAYLOAD_SIZE: usize = 4;
/// Fixed-size payload for controller ownership state.
const CONTROLLER_STATE_PAYLOAD_SIZE: usize = 1;
/// Fixed-size payload for advertised input capabilities.
const INPUT_CAPABILITIES_PAYLOAD_SIZE: usize = 1;
/// Fixed-size payload for cursor state updates.
const CURSOR_STATE_PAYLOAD_SIZE: usize = 17;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoCodec {
    H264,
    Hevc,
    Av1,
}

impl VideoCodec {
    const fn bit(self) -> u8 {
        match self {
            Self::H264 => 1 << 0,
            Self::Hevc => 1 << 1,
            Self::Av1 => 1 << 2,
        }
    }

    fn to_u8(self) -> u8 {
        match self {
            Self::H264 => 0,
            Self::Hevc => 1,
            Self::Av1 => 2,
        }
    }

    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::H264),
            1 => Some(Self::Hevc),
            2 => Some(Self::Av1),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VideoCodecSupport {
    bits: u8,
}

impl VideoCodecSupport {
    const KNOWN_BITS: u8 = VideoCodec::H264.bit() | VideoCodec::Hevc.bit() | VideoCodec::Av1.bit();

    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    pub const fn h264_only() -> Self {
        Self {
            bits: 1 << 0,
        }
    }

    pub const fn all() -> Self {
        Self {
            bits: Self::KNOWN_BITS,
        }
    }

    pub fn supports(self, codec: VideoCodec) -> bool {
        self.bits & codec.bit() != 0
    }

    pub fn insert(&mut self, codec: VideoCodec) {
        self.bits |= codec.bit();
    }

    pub fn subtract(self, other: Self) -> Self {
        Self {
            bits: self.bits & !other.bits,
        }
    }

    pub fn is_empty(self) -> bool {
        self.bits == 0
    }

    fn serialize(self) -> u8 {
        self.bits & Self::KNOWN_BITS
    }

    fn deserialize(bits: u8) -> Self {
        Self {
            bits: bits & Self::KNOWN_BITS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamConfig {
    pub codec: VideoCodec,
    pub width: u32,
    pub height: u32,
    pub framerate: u16,
    pub audio_sample_rate: u32,
    pub audio_channels: u8,
    pub hdr: bool,
}

impl StreamConfig {
    fn serialize(&self) -> [u8; STREAM_CONFIG_PAYLOAD_SIZE] {
        let mut buf = [0u8; STREAM_CONFIG_PAYLOAD_SIZE];
        buf[0] = self.codec.to_u8();
        buf[1] = u8::from(self.hdr);
        buf[2..6].copy_from_slice(&self.width.to_be_bytes());
        buf[6..10].copy_from_slice(&self.height.to_be_bytes());
        buf[10..12].copy_from_slice(&self.framerate.to_be_bytes());
        buf[12..16].copy_from_slice(&self.audio_sample_rate.to_be_bytes());
        buf[16] = self.audio_channels;
        buf
    }

    fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() != STREAM_CONFIG_PAYLOAD_SIZE {
            return None;
        }

        Some(Self {
            codec: VideoCodec::from_u8(buf[0])?,
            hdr: buf[1] != 0,
            width: u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]),
            height: u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]),
            framerate: u16::from_be_bytes([buf[10], buf[11]]),
            audio_sample_rate: u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]),
            audio_channels: buf[16],
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClientDisplayInfo {
    pub max_refresh_millihz: u32,
    pub udp_port: u16,
    pub supported_video_codecs: VideoCodecSupport,
    pub hardware_video_codecs: VideoCodecSupport,
}

impl ClientDisplayInfo {
    fn serialize(&self) -> [u8; CLIENT_DISPLAY_INFO_PAYLOAD_SIZE] {
        let mut buf = [0u8; CLIENT_DISPLAY_INFO_PAYLOAD_SIZE];
        buf[0..4].copy_from_slice(&self.max_refresh_millihz.to_be_bytes());
        buf[4..6].copy_from_slice(&self.udp_port.to_be_bytes());
        buf[6] = self.supported_video_codecs.serialize();
        buf[7] = self.hardware_video_codecs.serialize();
        buf
    }

    fn deserialize(buf: &[u8]) -> Option<Self> {
        let legacy_supported = VideoCodecSupport::h264_only();
        match buf.len() {
            4 => Some(Self {
                max_refresh_millihz: u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
                udp_port: 0,
                supported_video_codecs: legacy_supported,
                hardware_video_codecs: VideoCodecSupport::empty(),
            }),
            CLIENT_DISPLAY_INFO_PAYLOAD_SIZE => Some(Self {
                max_refresh_millihz: u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
                udp_port: u16::from_be_bytes([buf[4], buf[5]]),
                supported_video_codecs: VideoCodecSupport::deserialize(buf[6]),
                hardware_video_codecs: VideoCodecSupport::deserialize(buf[7]),
            }),
            6 => Some(Self {
                max_refresh_millihz: u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
                udp_port: u16::from_be_bytes([buf[4], buf[5]]),
                supported_video_codecs: legacy_supported,
                hardware_video_codecs: VideoCodecSupport::empty(),
            }),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClockSyncPing {
    pub client_send_micros: u64,
}

impl ClockSyncPing {
    fn serialize(&self) -> [u8; CLOCK_SYNC_PING_PAYLOAD_SIZE] {
        self.client_send_micros.to_be_bytes()
    }

    fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() != CLOCK_SYNC_PING_PAYLOAD_SIZE {
            return None;
        }

        Some(Self {
            client_send_micros: u64::from_be_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]),
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClockSyncPong {
    pub client_send_micros: u64,
    pub server_recv_micros: u64,
    pub server_send_micros: u64,
    pub bitrate_kbps: u32,
}

impl ClockSyncPong {
    fn serialize(&self) -> [u8; CLOCK_SYNC_PONG_PAYLOAD_SIZE] {
        let mut buf = [0u8; CLOCK_SYNC_PONG_PAYLOAD_SIZE];
        buf[0..8].copy_from_slice(&self.client_send_micros.to_be_bytes());
        buf[8..16].copy_from_slice(&self.server_recv_micros.to_be_bytes());
        buf[16..24].copy_from_slice(&self.server_send_micros.to_be_bytes());
        buf[24..28].copy_from_slice(&self.bitrate_kbps.to_be_bytes());
        buf
    }

    fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() != CLOCK_SYNC_PONG_PAYLOAD_SIZE {
            return None;
        }

        Some(Self {
            client_send_micros: u64::from_be_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]),
            server_recv_micros: u64::from_be_bytes([
                buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
            ]),
            server_send_micros: u64::from_be_bytes([
                buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
            ]),
            bitrate_kbps: u32::from_be_bytes([buf[24], buf[25], buf[26], buf[27]]),
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionDebugInfo {
    pub encoder_name: String,
    pub capture_backend: String,
    pub input_backend: String,
    pub target_bitrate_kbps: u32,
    pub quality_preset: String,
}

impl SessionDebugInfo {
    fn serialize(&self) -> Vec<u8> {
        let encoder = self.encoder_name.as_bytes();
        let capture = self.capture_backend.as_bytes();
        let input = self.input_backend.as_bytes();
        let quality = self.quality_preset.as_bytes();
        let encoder_len = encoder.len().min(u8::MAX as usize);
        let capture_len = capture.len().min(u8::MAX as usize);
        let input_len = input.len().min(u8::MAX as usize);
        let quality_len = quality.len().min(u8::MAX as usize);
        let mut buf = Vec::with_capacity(8 + encoder_len + capture_len + input_len + quality_len);
        buf.extend_from_slice(&self.target_bitrate_kbps.to_be_bytes());
        buf.push(encoder_len as u8);
        buf.push(capture_len as u8);
        buf.push(input_len as u8);
        buf.push(quality_len as u8);
        buf.extend_from_slice(&encoder[..encoder_len]);
        buf.extend_from_slice(&capture[..capture_len]);
        buf.extend_from_slice(&input[..input_len]);
        buf.extend_from_slice(&quality[..quality_len]);
        buf
    }

    fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < 8 {
            return None;
        }
        let target_bitrate_kbps = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let encoder_len = buf[4] as usize;
        let capture_len = buf[5] as usize;
        let input_len = buf[6] as usize;
        let quality_len = buf[7] as usize;
        if buf.len() != 8 + encoder_len + capture_len + input_len + quality_len {
            return None;
        }
        let encoder_start = 8;
        let capture_start = encoder_start + encoder_len;
        let input_start = capture_start + capture_len;
        let quality_start = input_start + input_len;
        Some(Self {
            encoder_name: String::from_utf8_lossy(&buf[encoder_start..capture_start]).to_string(),
            capture_backend: String::from_utf8_lossy(&buf[capture_start..input_start]).to_string(),
            input_backend: String::from_utf8_lossy(&buf[input_start..quality_start]).to_string(),
            target_bitrate_kbps,
            quality_preset: String::from_utf8_lossy(&buf[quality_start..]).to_string(),
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransportFeedback {
    pub interval_ms: u32,
    pub received_packets: u32,
    pub lost_packets: u32,
    pub late_packets: u32,
    pub completed_frames: u32,
    pub dropped_frames: u32,
}

impl TransportFeedback {
    fn serialize(&self) -> [u8; TRANSPORT_FEEDBACK_PAYLOAD_SIZE] {
        let mut buf = [0u8; TRANSPORT_FEEDBACK_PAYLOAD_SIZE];
        buf[0..4].copy_from_slice(&self.interval_ms.to_be_bytes());
        buf[4..8].copy_from_slice(&self.received_packets.to_be_bytes());
        buf[8..12].copy_from_slice(&self.lost_packets.to_be_bytes());
        buf[12..16].copy_from_slice(&self.late_packets.to_be_bytes());
        buf[16..20].copy_from_slice(&self.completed_frames.to_be_bytes());
        buf[20..24].copy_from_slice(&self.dropped_frames.to_be_bytes());
        buf
    }

    fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() != TRANSPORT_FEEDBACK_PAYLOAD_SIZE {
            return None;
        }

        Some(Self {
            interval_ms: u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
            received_packets: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            lost_packets: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
            late_packets: u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]),
            completed_frames: u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]),
            dropped_frames: u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]),
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InputCapabilities {
    pub mouse_absolute: bool,
    pub mouse_relative: bool,
    pub keyboard: bool,
    pub separate_cursor: bool,
    pub hover_capture: bool,
}

impl InputCapabilities {
    const MOUSE_ABSOLUTE_BIT: u8 = 1 << 0;
    const MOUSE_RELATIVE_BIT: u8 = 1 << 1;
    const KEYBOARD_BIT: u8 = 1 << 2;
    const SEPARATE_CURSOR_BIT: u8 = 1 << 3;
    const HOVER_CAPTURE_BIT: u8 = 1 << 4;

    fn serialize(&self) -> [u8; INPUT_CAPABILITIES_PAYLOAD_SIZE] {
        let mut flags = 0u8;
        if self.mouse_absolute {
            flags |= Self::MOUSE_ABSOLUTE_BIT;
        }
        if self.mouse_relative {
            flags |= Self::MOUSE_RELATIVE_BIT;
        }
        if self.keyboard {
            flags |= Self::KEYBOARD_BIT;
        }
        if self.separate_cursor {
            flags |= Self::SEPARATE_CURSOR_BIT;
        }
        if self.hover_capture {
            flags |= Self::HOVER_CAPTURE_BIT;
        }
        [flags]
    }

    fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() != INPUT_CAPABILITIES_PAYLOAD_SIZE {
            return None;
        }

        let flags = buf[0];
        Some(Self {
            mouse_absolute: flags & Self::MOUSE_ABSOLUTE_BIT != 0,
            mouse_relative: flags & Self::MOUSE_RELATIVE_BIT != 0,
            keyboard: flags & Self::KEYBOARD_BIT != 0,
            separate_cursor: flags & Self::SEPARATE_CURSOR_BIT != 0,
            hover_capture: flags & Self::HOVER_CAPTURE_BIT != 0,
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InputSession {
    pub client_id: u32,
}

impl InputSession {
    fn serialize(&self) -> [u8; INPUT_SESSION_PAYLOAD_SIZE] {
        self.client_id.to_be_bytes()
    }

    fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() != INPUT_SESSION_PAYLOAD_SIZE {
            return None;
        }

        Some(Self {
            client_id: u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ControllerState {
    #[default]
    Unavailable,
    Available,
    OwnedByYou,
    OwnedByOther,
}

impl ControllerState {
    fn to_u8(self) -> u8 {
        match self {
            Self::Unavailable => 0,
            Self::Available => 1,
            Self::OwnedByYou => 2,
            Self::OwnedByOther => 3,
        }
    }

    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Unavailable),
            1 => Some(Self::Available),
            2 => Some(Self::OwnedByYou),
            3 => Some(Self::OwnedByOther),
            _ => None,
        }
    }

    fn serialize(&self) -> [u8; CONTROLLER_STATE_PAYLOAD_SIZE] {
        [self.to_u8()]
    }

    fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() != CONTROLLER_STATE_PAYLOAD_SIZE {
            return None;
        }
        Self::from_u8(buf[0])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorShape {
    pub serial: u64,
    pub width: u16,
    pub height: u16,
    pub hotspot_x: u16,
    pub hotspot_y: u16,
    pub rgba: Vec<u8>,
}

impl CursorShape {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16 + self.rgba.len());
        buf.extend_from_slice(&self.serial.to_be_bytes());
        buf.extend_from_slice(&self.width.to_be_bytes());
        buf.extend_from_slice(&self.height.to_be_bytes());
        buf.extend_from_slice(&self.hotspot_x.to_be_bytes());
        buf.extend_from_slice(&self.hotspot_y.to_be_bytes());
        buf.extend_from_slice(&self.rgba);
        buf
    }

    fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() < 16 {
            return None;
        }
        let serial = u64::from_be_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]);
        let width = u16::from_be_bytes([buf[8], buf[9]]);
        let height = u16::from_be_bytes([buf[10], buf[11]]);
        let hotspot_x = u16::from_be_bytes([buf[12], buf[13]]);
        let hotspot_y = u16::from_be_bytes([buf[14], buf[15]]);
        let rgba = buf[16..].to_vec();
        let expected_len = width as usize * height as usize * 4;
        if rgba.len() != expected_len {
            return None;
        }
        Some(Self {
            serial,
            width,
            height,
            hotspot_x,
            hotspot_y,
            rgba,
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CursorState {
    pub serial: u64,
    pub x: i32,
    pub y: i32,
    pub visible: bool,
}

impl CursorState {
    fn serialize(&self) -> [u8; CURSOR_STATE_PAYLOAD_SIZE] {
        let mut buf = [0u8; CURSOR_STATE_PAYLOAD_SIZE];
        buf[0..8].copy_from_slice(&self.serial.to_be_bytes());
        buf[8..12].copy_from_slice(&self.x.to_be_bytes());
        buf[12..16].copy_from_slice(&self.y.to_be_bytes());
        buf[16] = u8::from(self.visible);
        buf
    }

    fn deserialize(buf: &[u8]) -> Option<Self> {
        if buf.len() != CURSOR_STATE_PAYLOAD_SIZE {
            return None;
        }
        Some(Self {
            serial: u64::from_be_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]),
            x: i32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
            y: i32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]),
            visible: buf[16] != 0,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    /// Server-selected stream parameters.
    StreamConfig(StreamConfig),
    /// Client has started its UDP media receive path and is ready for packets.
    ClientReadyForMedia,
    /// Server is ready and streaming has started.
    StreamStarted,
    /// Server encountered a fatal error — payload is a UTF-8 error string.
    Error(String),
    /// Server is shutting down gracefully.
    Shutdown,
    /// Client → server: enable/disable audio for this client.
    SetAudio(bool),
    /// Client → server: display refresh hint for stream FPS negotiation.
    ClientDisplayInfo(ClientDisplayInfo),
    /// Client → server: timestamp for clock-sync.
    ClockSyncPing(ClockSyncPing),
    /// Server → client: timestamp echo plus bitrate snapshot.
    ClockSyncPong(ClockSyncPong),
    /// Server → client: encoder/capture session info for debug UI.
    SessionDebugInfo(SessionDebugInfo),
    /// Client → server: periodic UDP transport health snapshot.
    TransportFeedback(TransportFeedback),
    /// Server → client: per-connection input session id.
    InputSession(InputSession),
    /// Client → server: request exclusive control ownership.
    AcquireControl,
    /// Client → server: release exclusive control ownership.
    ReleaseControl,
    /// Client → server: request a fresh video keyframe for decoder recovery.
    RequestKeyframe,
    /// Server → client: current controller ownership status.
    ControllerState(ControllerState),
    /// Server → client: available input features for this session/backend.
    InputCapabilities(InputCapabilities),
    /// Server → client: remote cursor image, sent on cursor shape changes.
    CursorShape(CursorShape),
    /// Server → client: remote cursor position and visibility.
    CursorState(CursorState),
    /// Client → server: authentication token.
    Authenticate(String),
    /// Server → client: authentication result (true = accepted).
    AuthResult(bool),
}

impl ControlMessage {
    const TYPE_STREAM_CONFIG: u8 = 0;
    const TYPE_CLIENT_READY_FOR_MEDIA: u8 = 1;
    const TYPE_STREAM_STARTED: u8 = 2;
    const TYPE_ERROR: u8 = 3;
    const TYPE_SHUTDOWN: u8 = 4;
    const TYPE_SET_AUDIO: u8 = 5;
    const TYPE_CLIENT_DISPLAY_INFO: u8 = 6;
    const TYPE_CLOCK_SYNC_PING: u8 = 7;
    const TYPE_CLOCK_SYNC_PONG: u8 = 8;
    const TYPE_SESSION_DEBUG_INFO: u8 = 9;
    const TYPE_TRANSPORT_FEEDBACK: u8 = 10;
    const TYPE_INPUT_SESSION: u8 = 11;
    const TYPE_ACQUIRE_CONTROL: u8 = 12;
    const TYPE_RELEASE_CONTROL: u8 = 13;
    const TYPE_REQUEST_KEYFRAME: u8 = 14;
    const TYPE_CONTROLLER_STATE: u8 = 15;
    const TYPE_INPUT_CAPABILITIES: u8 = 16;
    const TYPE_CURSOR_SHAPE: u8 = 17;
    const TYPE_CURSOR_STATE: u8 = 18;
    const TYPE_AUTHENTICATE: u8 = 19;
    const TYPE_AUTH_RESULT: u8 = 20;

    /// Serialize this message into a byte vector (header + payload).
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            ControlMessage::StreamConfig(config) => {
                let payload = config.serialize();
                let mut buf = vec![0u8; CONTROL_HEADER_SIZE + STREAM_CONFIG_PAYLOAD_SIZE];
                buf[0] = Self::TYPE_STREAM_CONFIG;
                buf[1..3].copy_from_slice(&(STREAM_CONFIG_PAYLOAD_SIZE as u16).to_be_bytes());
                buf[CONTROL_HEADER_SIZE..].copy_from_slice(&payload);
                buf
            }
            ControlMessage::ClientReadyForMedia => {
                let mut buf = vec![0u8; CONTROL_HEADER_SIZE];
                buf[0] = Self::TYPE_CLIENT_READY_FOR_MEDIA;
                buf[1..3].copy_from_slice(&0u16.to_be_bytes());
                buf
            }
            ControlMessage::StreamStarted => {
                let mut buf = vec![0u8; CONTROL_HEADER_SIZE];
                buf[0] = Self::TYPE_STREAM_STARTED;
                buf[1..3].copy_from_slice(&0u16.to_be_bytes());
                buf
            }
            ControlMessage::Error(msg) => {
                let payload = msg.as_bytes();
                let len = payload.len().min(MAX_CONTROL_PAYLOAD);
                let mut buf = vec![0u8; CONTROL_HEADER_SIZE + len];
                buf[0] = Self::TYPE_ERROR;
                buf[1..3].copy_from_slice(&(len as u16).to_be_bytes());
                buf[CONTROL_HEADER_SIZE..CONTROL_HEADER_SIZE + len]
                    .copy_from_slice(&payload[..len]);
                buf
            }
            ControlMessage::Shutdown => {
                let mut buf = vec![0u8; CONTROL_HEADER_SIZE];
                buf[0] = Self::TYPE_SHUTDOWN;
                buf[1..3].copy_from_slice(&0u16.to_be_bytes());
                buf
            }
            ControlMessage::SetAudio(enabled) => {
                let mut buf = vec![0u8; CONTROL_HEADER_SIZE + 1];
                buf[0] = Self::TYPE_SET_AUDIO;
                buf[1..3].copy_from_slice(&1u16.to_be_bytes());
                buf[CONTROL_HEADER_SIZE] = if *enabled { 1 } else { 0 };
                buf
            }
            ControlMessage::ClientDisplayInfo(info) => {
                let payload = info.serialize();
                let mut buf = vec![0u8; CONTROL_HEADER_SIZE + CLIENT_DISPLAY_INFO_PAYLOAD_SIZE];
                buf[0] = Self::TYPE_CLIENT_DISPLAY_INFO;
                buf[1..3].copy_from_slice(&(CLIENT_DISPLAY_INFO_PAYLOAD_SIZE as u16).to_be_bytes());
                buf[CONTROL_HEADER_SIZE..].copy_from_slice(&payload);
                buf
            }
            ControlMessage::ClockSyncPing(ping) => {
                let payload = ping.serialize();
                let mut buf = vec![0u8; CONTROL_HEADER_SIZE + CLOCK_SYNC_PING_PAYLOAD_SIZE];
                buf[0] = Self::TYPE_CLOCK_SYNC_PING;
                buf[1..3].copy_from_slice(&(CLOCK_SYNC_PING_PAYLOAD_SIZE as u16).to_be_bytes());
                buf[CONTROL_HEADER_SIZE..].copy_from_slice(&payload);
                buf
            }
            ControlMessage::ClockSyncPong(pong) => {
                let payload = pong.serialize();
                let mut buf = vec![0u8; CONTROL_HEADER_SIZE + CLOCK_SYNC_PONG_PAYLOAD_SIZE];
                buf[0] = Self::TYPE_CLOCK_SYNC_PONG;
                buf[1..3].copy_from_slice(&(CLOCK_SYNC_PONG_PAYLOAD_SIZE as u16).to_be_bytes());
                buf[CONTROL_HEADER_SIZE..].copy_from_slice(&payload);
                buf
            }
            ControlMessage::SessionDebugInfo(info) => {
                let payload = info.serialize();
                let len = payload.len().min(MAX_CONTROL_PAYLOAD);
                let mut buf = vec![0u8; CONTROL_HEADER_SIZE + len];
                buf[0] = Self::TYPE_SESSION_DEBUG_INFO;
                buf[1..3].copy_from_slice(&(len as u16).to_be_bytes());
                buf[CONTROL_HEADER_SIZE..CONTROL_HEADER_SIZE + len]
                    .copy_from_slice(&payload[..len]);
                buf
            }
            ControlMessage::TransportFeedback(feedback) => {
                let payload = feedback.serialize();
                let mut buf = vec![0u8; CONTROL_HEADER_SIZE + TRANSPORT_FEEDBACK_PAYLOAD_SIZE];
                buf[0] = Self::TYPE_TRANSPORT_FEEDBACK;
                buf[1..3].copy_from_slice(&(TRANSPORT_FEEDBACK_PAYLOAD_SIZE as u16).to_be_bytes());
                buf[CONTROL_HEADER_SIZE..].copy_from_slice(&payload);
                buf
            }
            ControlMessage::InputSession(session) => {
                let payload = session.serialize();
                let mut buf = vec![0u8; CONTROL_HEADER_SIZE + INPUT_SESSION_PAYLOAD_SIZE];
                buf[0] = Self::TYPE_INPUT_SESSION;
                buf[1..3].copy_from_slice(&(INPUT_SESSION_PAYLOAD_SIZE as u16).to_be_bytes());
                buf[CONTROL_HEADER_SIZE..].copy_from_slice(&payload);
                buf
            }
            ControlMessage::AcquireControl => {
                let mut buf = vec![0u8; CONTROL_HEADER_SIZE];
                buf[0] = Self::TYPE_ACQUIRE_CONTROL;
                buf[1..3].copy_from_slice(&0u16.to_be_bytes());
                buf
            }
            ControlMessage::ReleaseControl => {
                let mut buf = vec![0u8; CONTROL_HEADER_SIZE];
                buf[0] = Self::TYPE_RELEASE_CONTROL;
                buf[1..3].copy_from_slice(&0u16.to_be_bytes());
                buf
            }
            ControlMessage::RequestKeyframe => {
                let mut buf = vec![0u8; CONTROL_HEADER_SIZE];
                buf[0] = Self::TYPE_REQUEST_KEYFRAME;
                buf[1..3].copy_from_slice(&0u16.to_be_bytes());
                buf
            }
            ControlMessage::ControllerState(state) => {
                let payload = state.serialize();
                let mut buf = vec![0u8; CONTROL_HEADER_SIZE + CONTROLLER_STATE_PAYLOAD_SIZE];
                buf[0] = Self::TYPE_CONTROLLER_STATE;
                buf[1..3].copy_from_slice(&(CONTROLLER_STATE_PAYLOAD_SIZE as u16).to_be_bytes());
                buf[CONTROL_HEADER_SIZE..].copy_from_slice(&payload);
                buf
            }
            ControlMessage::InputCapabilities(caps) => {
                let payload = caps.serialize();
                let mut buf = vec![0u8; CONTROL_HEADER_SIZE + INPUT_CAPABILITIES_PAYLOAD_SIZE];
                buf[0] = Self::TYPE_INPUT_CAPABILITIES;
                buf[1..3].copy_from_slice(&(INPUT_CAPABILITIES_PAYLOAD_SIZE as u16).to_be_bytes());
                buf[CONTROL_HEADER_SIZE..].copy_from_slice(&payload);
                buf
            }
            ControlMessage::CursorShape(shape) => {
                let payload = shape.serialize();
                let len = payload.len().min(MAX_CONTROL_PAYLOAD);
                let mut buf = vec![0u8; CONTROL_HEADER_SIZE + len];
                buf[0] = Self::TYPE_CURSOR_SHAPE;
                buf[1..3].copy_from_slice(&(len as u16).to_be_bytes());
                buf[CONTROL_HEADER_SIZE..CONTROL_HEADER_SIZE + len]
                    .copy_from_slice(&payload[..len]);
                buf
            }
            ControlMessage::CursorState(state) => {
                let payload = state.serialize();
                let mut buf = vec![0u8; CONTROL_HEADER_SIZE + CURSOR_STATE_PAYLOAD_SIZE];
                buf[0] = Self::TYPE_CURSOR_STATE;
                buf[1..3].copy_from_slice(&(CURSOR_STATE_PAYLOAD_SIZE as u16).to_be_bytes());
                buf[CONTROL_HEADER_SIZE..].copy_from_slice(&payload);
                buf
            }
            ControlMessage::Authenticate(token) => {
                let payload = token.as_bytes();
                let len = payload.len().min(MAX_CONTROL_PAYLOAD);
                let mut buf = vec![0u8; CONTROL_HEADER_SIZE + len];
                buf[0] = Self::TYPE_AUTHENTICATE;
                buf[1..3].copy_from_slice(&(len as u16).to_be_bytes());
                buf[CONTROL_HEADER_SIZE..CONTROL_HEADER_SIZE + len]
                    .copy_from_slice(&payload[..len]);
                buf
            }
            ControlMessage::AuthResult(ok) => {
                let mut buf = vec![0u8; CONTROL_HEADER_SIZE + 1];
                buf[0] = Self::TYPE_AUTH_RESULT;
                buf[1..3].copy_from_slice(&1u16.to_be_bytes());
                buf[CONTROL_HEADER_SIZE] = if *ok { 1 } else { 0 };
                buf
            }
        }
    }

    /// Deserialize a control message from a buffer.
    /// Returns `(message, bytes_consumed)` or `None` if the buffer is incomplete.
    pub fn deserialize(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < CONTROL_HEADER_SIZE {
            return None;
        }

        let msg_type = buf[0];
        let payload_len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
        let total_len = CONTROL_HEADER_SIZE + payload_len;

        if buf.len() < total_len {
            return None;
        }

        let payload = &buf[CONTROL_HEADER_SIZE..total_len];

        let msg = match msg_type {
            Self::TYPE_STREAM_CONFIG => {
                ControlMessage::StreamConfig(StreamConfig::deserialize(payload)?)
            }
            Self::TYPE_CLIENT_READY_FOR_MEDIA => ControlMessage::ClientReadyForMedia,
            Self::TYPE_STREAM_STARTED => ControlMessage::StreamStarted,
            Self::TYPE_ERROR => {
                let text = String::from_utf8_lossy(payload).to_string();
                ControlMessage::Error(text)
            }
            Self::TYPE_SHUTDOWN => ControlMessage::Shutdown,
            Self::TYPE_SET_AUDIO => {
                let enabled = payload.first().copied().unwrap_or(0) != 0;
                ControlMessage::SetAudio(enabled)
            }
            Self::TYPE_CLIENT_DISPLAY_INFO => {
                ControlMessage::ClientDisplayInfo(ClientDisplayInfo::deserialize(payload)?)
            }
            Self::TYPE_CLOCK_SYNC_PING => {
                ControlMessage::ClockSyncPing(ClockSyncPing::deserialize(payload)?)
            }
            Self::TYPE_CLOCK_SYNC_PONG => {
                ControlMessage::ClockSyncPong(ClockSyncPong::deserialize(payload)?)
            }
            Self::TYPE_SESSION_DEBUG_INFO => {
                ControlMessage::SessionDebugInfo(SessionDebugInfo::deserialize(payload)?)
            }
            Self::TYPE_TRANSPORT_FEEDBACK => {
                ControlMessage::TransportFeedback(TransportFeedback::deserialize(payload)?)
            }
            Self::TYPE_INPUT_SESSION => {
                ControlMessage::InputSession(InputSession::deserialize(payload)?)
            }
            Self::TYPE_ACQUIRE_CONTROL => ControlMessage::AcquireControl,
            Self::TYPE_RELEASE_CONTROL => ControlMessage::ReleaseControl,
            Self::TYPE_REQUEST_KEYFRAME => ControlMessage::RequestKeyframe,
            Self::TYPE_CONTROLLER_STATE => {
                ControlMessage::ControllerState(ControllerState::deserialize(payload)?)
            }
            Self::TYPE_INPUT_CAPABILITIES => {
                ControlMessage::InputCapabilities(InputCapabilities::deserialize(payload)?)
            }
            Self::TYPE_CURSOR_SHAPE => {
                ControlMessage::CursorShape(CursorShape::deserialize(payload)?)
            }
            Self::TYPE_CURSOR_STATE => {
                ControlMessage::CursorState(CursorState::deserialize(payload)?)
            }
            Self::TYPE_AUTHENTICATE => {
                let text = String::from_utf8_lossy(payload).to_string();
                ControlMessage::Authenticate(text)
            }
            Self::TYPE_AUTH_RESULT => {
                let ok = payload.first().copied().unwrap_or(0) != 0;
                ControlMessage::AuthResult(ok)
            }
            _ => return None,
        };

        Some((msg, total_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_stream_config() {
        let msg = ControlMessage::StreamConfig(StreamConfig {
            codec: VideoCodec::Av1,
            width: 2560,
            height: 1440,
            framerate: 120,
            audio_sample_rate: 48_000,
            audio_channels: 2,
            hdr: true,
        });
        let buf = msg.serialize();
        let (decoded, consumed) = ControlMessage::deserialize(&buf).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn roundtrip_stream_started() {
        let msg = ControlMessage::StreamStarted;
        let buf = msg.serialize();
        let (decoded, consumed) = ControlMessage::deserialize(&buf).unwrap();
        assert_eq!(decoded, ControlMessage::StreamStarted);
        assert_eq!(consumed, CONTROL_HEADER_SIZE);
    }

    #[test]
    fn roundtrip_error() {
        let msg = ControlMessage::Error("capture failed: NVFBC_ERR_X".to_string());
        let buf = msg.serialize();
        let (decoded, consumed) = ControlMessage::deserialize(&buf).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn roundtrip_shutdown() {
        let msg = ControlMessage::Shutdown;
        let buf = msg.serialize();
        let (decoded, consumed) = ControlMessage::deserialize(&buf).unwrap();
        assert_eq!(decoded, ControlMessage::Shutdown);
        assert_eq!(consumed, CONTROL_HEADER_SIZE);
    }

    #[test]
    fn roundtrip_client_display_info() {
        let msg = ControlMessage::ClientDisplayInfo(ClientDisplayInfo {
            max_refresh_millihz: 143_856,
            udp_port: 45_000,
            supported_video_codecs: VideoCodecSupport::all(),
            hardware_video_codecs: VideoCodecSupport::h264_only(),
        });
        let buf = msg.serialize();
        let (decoded, consumed) = ControlMessage::deserialize(&buf).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn deserialize_legacy_client_display_info() {
        let mut buf = vec![0u8; CONTROL_HEADER_SIZE + 4];
        buf[0] = ControlMessage::TYPE_CLIENT_DISPLAY_INFO;
        buf[1..3].copy_from_slice(&(4u16).to_be_bytes());
        buf[3..7].copy_from_slice(&143_856u32.to_be_bytes());

        let (decoded, consumed) = ControlMessage::deserialize(&buf).unwrap();
        assert_eq!(
            decoded,
            ControlMessage::ClientDisplayInfo(ClientDisplayInfo {
                max_refresh_millihz: 143_856,
                udp_port: 0,
                supported_video_codecs: VideoCodecSupport::h264_only(),
                hardware_video_codecs: VideoCodecSupport::empty(),
            })
        );
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn deserialize_legacy_six_byte_client_display_info() {
        let mut buf = vec![0u8; CONTROL_HEADER_SIZE + 6];
        buf[0] = ControlMessage::TYPE_CLIENT_DISPLAY_INFO;
        buf[1..3].copy_from_slice(&(6u16).to_be_bytes());
        buf[3..7].copy_from_slice(&143_856u32.to_be_bytes());
        buf[7..9].copy_from_slice(&45_000u16.to_be_bytes());

        let (decoded, consumed) = ControlMessage::deserialize(&buf).unwrap();
        assert_eq!(
            decoded,
            ControlMessage::ClientDisplayInfo(ClientDisplayInfo {
                max_refresh_millihz: 143_856,
                udp_port: 45_000,
                supported_video_codecs: VideoCodecSupport::h264_only(),
                hardware_video_codecs: VideoCodecSupport::empty(),
            })
        );
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn roundtrip_clock_sync_ping() {
        let msg = ControlMessage::ClockSyncPing(ClockSyncPing {
            client_send_micros: 123_456,
        });
        let buf = msg.serialize();
        let (decoded, consumed) = ControlMessage::deserialize(&buf).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn roundtrip_clock_sync_pong() {
        let msg = ControlMessage::ClockSyncPong(ClockSyncPong {
            client_send_micros: 11,
            server_recv_micros: 22,
            server_send_micros: 33,
            bitrate_kbps: 44_000,
        });
        let buf = msg.serialize();
        let (decoded, consumed) = ControlMessage::deserialize(&buf).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn roundtrip_session_debug_info() {
        let msg = ControlMessage::SessionDebugInfo(SessionDebugInfo {
            encoder_name: "vaapi-h264".to_string(),
            capture_backend: "pipewire".to_string(),
            input_backend: "uinput".to_string(),
            target_bitrate_kbps: 50_000,
            quality_preset: "Balanced".to_string(),
        });
        let buf = msg.serialize();
        let (decoded, consumed) = ControlMessage::deserialize(&buf).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn incomplete_buffer() {
        let msg = ControlMessage::Error("test".to_string());
        let buf = msg.serialize();
        // Only give partial buffer
        assert!(ControlMessage::deserialize(&buf[..2]).is_none());
    }

    #[test]
    fn roundtrip_transport_feedback() {
        let msg = ControlMessage::TransportFeedback(TransportFeedback {
            interval_ms: 500,
            received_packets: 320,
            lost_packets: 12,
            late_packets: 3,
            completed_frames: 58,
            dropped_frames: 2,
        });
        let buf = msg.serialize();
        let (decoded, consumed) = ControlMessage::deserialize(&buf).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn roundtrip_input_session() {
        let msg = ControlMessage::InputSession(InputSession { client_id: 77 });
        let buf = msg.serialize();
        let (decoded, consumed) = ControlMessage::deserialize(&buf).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn roundtrip_controller_state() {
        let msg = ControlMessage::ControllerState(ControllerState::OwnedByYou);
        let buf = msg.serialize();
        let (decoded, consumed) = ControlMessage::deserialize(&buf).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn roundtrip_input_capabilities() {
        let msg = ControlMessage::InputCapabilities(InputCapabilities {
            mouse_absolute: true,
            mouse_relative: true,
            keyboard: true,
            separate_cursor: false,
            hover_capture: true,
        });
        let buf = msg.serialize();
        let (decoded, consumed) = ControlMessage::deserialize(&buf).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn roundtrip_cursor_shape() {
        let msg = ControlMessage::CursorShape(CursorShape {
            serial: 19,
            width: 2,
            height: 2,
            hotspot_x: 1,
            hotspot_y: 1,
            rgba: vec![
                255, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, 255, 255, 255, 255,
            ],
        });
        let buf = msg.serialize();
        let (decoded, consumed) = ControlMessage::deserialize(&buf).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn roundtrip_cursor_state() {
        let msg = ControlMessage::CursorState(CursorState {
            serial: 12,
            x: -40,
            y: 80,
            visible: true,
        });
        let buf = msg.serialize();
        let (decoded, consumed) = ControlMessage::deserialize(&buf).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(consumed, buf.len());
    }
}
