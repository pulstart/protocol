use crate::packet::{PacketHeader, PayloadType, HEADER_SIZE};

pub const MOUSE_BUTTON_PRIMARY: u8 = 1 << 0;
pub const MOUSE_BUTTON_SECONDARY: u8 = 1 << 1;
pub const MOUSE_BUTTON_MIDDLE: u8 = 1 << 2;
pub const MOUSE_BUTTON_EXTRA1: u8 = 1 << 3;
pub const MOUSE_BUTTON_EXTRA2: u8 = 1 << 4;
/// High-resolution wheel units per traditional mouse-wheel notch.
pub const MOUSE_WHEEL_STEP_UNITS: i16 = 120;
pub const KEYBOARD_STATE_BYTES: usize = 16;
pub const INPUT_CREDENTIAL_BYTES: usize = 16;

/// Per-session secret that authenticates UDP input datagrams.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct InputCredential([u8; INPUT_CREDENTIAL_BYTES]);

impl InputCredential {
    pub const fn from_bytes(bytes: [u8; INPUT_CREDENTIAL_BYTES]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; INPUT_CREDENTIAL_BYTES] {
        &self.0
    }
}

impl std::fmt::Debug for InputCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("InputCredential([REDACTED])")
    }
}

const MOUSE_ABSOLUTE_PAYLOAD_SIZE: usize = 9;
const MOUSE_RELATIVE_PAYLOAD_SIZE: usize = 9;
const MOUSE_BUTTONS_PAYLOAD_SIZE: usize = 5;
const MOUSE_WHEEL_PAYLOAD_SIZE: usize = 9;
const KEYBOARD_STATE_PAYLOAD_SIZE: usize = 4 + KEYBOARD_STATE_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyboardKey {
    Escape = 0,
    Tab = 1,
    Backspace = 2,
    Enter = 3,
    Space = 4,
    Insert = 5,
    Delete = 6,
    Home = 7,
    End = 8,
    PageUp = 9,
    PageDown = 10,
    ArrowUp = 11,
    ArrowDown = 12,
    ArrowLeft = 13,
    ArrowRight = 14,
    Minus = 15,
    Equals = 16,
    OpenBracket = 17,
    CloseBracket = 18,
    Backslash = 19,
    Semicolon = 20,
    Quote = 21,
    Backtick = 22,
    Comma = 23,
    Period = 24,
    Slash = 25,
    Num0 = 26,
    Num1 = 27,
    Num2 = 28,
    Num3 = 29,
    Num4 = 30,
    Num5 = 31,
    Num6 = 32,
    Num7 = 33,
    Num8 = 34,
    Num9 = 35,
    A = 36,
    B = 37,
    C = 38,
    D = 39,
    E = 40,
    F = 41,
    G = 42,
    H = 43,
    I = 44,
    J = 45,
    K = 46,
    L = 47,
    M = 48,
    N = 49,
    O = 50,
    P = 51,
    Q = 52,
    R = 53,
    S = 54,
    T = 55,
    U = 56,
    V = 57,
    W = 58,
    X = 59,
    Y = 60,
    Z = 61,
    F1 = 62,
    F2 = 63,
    F3 = 64,
    F4 = 65,
    F5 = 66,
    F6 = 67,
    F7 = 68,
    F8 = 69,
    F9 = 70,
    F10 = 71,
    F11 = 72,
    F12 = 73,
    LeftShift = 74,
    LeftCtrl = 75,
    LeftAlt = 76,
    LeftMeta = 77,
    RightShift = 78,
    RightCtrl = 79,
    RightAlt = 80,
    RightMeta = 81,
    CapsLock = 82,
    NumLock = 83,
    ScrollLock = 84,
    PrintScreen = 85,
    Pause = 86,
    Application = 87,
    Numpad0 = 88,
    Numpad1 = 89,
    Numpad2 = 90,
    Numpad3 = 91,
    Numpad4 = 92,
    Numpad5 = 93,
    Numpad6 = 94,
    Numpad7 = 95,
    Numpad8 = 96,
    Numpad9 = 97,
    NumpadDecimal = 98,
    NumpadDivide = 99,
    NumpadMultiply = 100,
    NumpadSubtract = 101,
    NumpadAdd = 102,
    NumpadEnter = 103,
    NumpadEquals = 104,
    NumpadComma = 105,
    F13 = 106,
    F14 = 107,
    F15 = 108,
    F16 = 109,
    F17 = 110,
    F18 = 111,
    F19 = 112,
    F20 = 113,
    F21 = 114,
    F22 = 115,
    F23 = 116,
    F24 = 117,
    VolumeMute = 118,
    VolumeDown = 119,
    VolumeUp = 120,
    MediaPrevious = 121,
    MediaNext = 122,
    MediaPlayPause = 123,
    MediaStop = 124,
    IntlBackslash = 125,
}

impl KeyboardKey {
    pub const COUNT: usize = Self::IntlBackslash as usize + 1;

    pub fn bit(self) -> (usize, u8) {
        let index = self as usize;
        (index / 8, 1 << (index % 8))
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        if value <= Self::IntlBackslash as u8 {
            // SAFETY: KeyboardKey is a repr(u8) enum with contiguous discriminants from 0
            // through IntlBackslash.
            Some(unsafe { std::mem::transmute::<u8, Self>(value) })
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
/// Absolute motion is always meaningful mouse activity and makes this client
/// the current mouse owner. Periodic state repair should use `MouseButtonsInput`
/// instead so an idle heartbeat cannot reclaim ownership.
pub struct MouseAbsoluteInput {
    pub client_id: u32,
    pub x: u16,
    pub y: u16,
    pub buttons: u8,
}

impl MouseAbsoluteInput {
    fn serialize_payload(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.client_id.to_be_bytes());
        buf.extend_from_slice(&self.x.to_be_bytes());
        buf.extend_from_slice(&self.y.to_be_bytes());
        buf.push(self.buttons);
    }

    fn deserialize_payload(buf: &[u8]) -> Option<Self> {
        if buf.len() != MOUSE_ABSOLUTE_PAYLOAD_SIZE {
            return None;
        }

        Some(Self {
            client_id: u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
            x: u16::from_be_bytes([buf[4], buf[5]]),
            y: u16::from_be_bytes([buf[6], buf[7]]),
            buttons: buf[8],
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
/// Nonzero motion or a newly pressed button is meaningful mouse activity.
pub struct MouseRelativeInput {
    pub client_id: u32,
    pub dx: i16,
    pub dy: i16,
    pub buttons: u8,
}

impl MouseRelativeInput {
    fn serialize_payload(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.client_id.to_be_bytes());
        buf.extend_from_slice(&self.dx.to_be_bytes());
        buf.extend_from_slice(&self.dy.to_be_bytes());
        buf.push(self.buttons);
    }

    fn deserialize_payload(buf: &[u8]) -> Option<Self> {
        if buf.len() != MOUSE_RELATIVE_PAYLOAD_SIZE {
            return None;
        }

        Some(Self {
            client_id: u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
            dx: i16::from_be_bytes([buf[4], buf[5]]),
            dy: i16::from_be_bytes([buf[6], buf[7]]),
            buttons: buf[8],
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
/// Full mouse-button snapshot. Newly pressed bits are meaningful mouse activity;
/// unchanged and falling-only snapshots repair state without taking ownership.
pub struct MouseButtonsInput {
    pub client_id: u32,
    pub buttons: u8,
}

impl MouseButtonsInput {
    fn serialize_payload(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.client_id.to_be_bytes());
        buf.push(self.buttons);
    }

    fn deserialize_payload(buf: &[u8]) -> Option<Self> {
        if buf.len() != MOUSE_BUTTONS_PAYLOAD_SIZE {
            return None;
        }

        Some(Self {
            client_id: u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
            buttons: buf[4],
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
/// Nonzero wheel motion or a newly pressed button is meaningful mouse activity.
pub struct MouseWheelInput {
    pub client_id: u32,
    /// High-resolution wheel units. `MOUSE_WHEEL_STEP_UNITS` equals one line/notch.
    pub delta_x: i16,
    /// High-resolution wheel units. `MOUSE_WHEEL_STEP_UNITS` equals one line/notch.
    pub delta_y: i16,
    pub buttons: u8,
}

impl MouseWheelInput {
    fn serialize_payload(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.client_id.to_be_bytes());
        buf.extend_from_slice(&self.delta_x.to_be_bytes());
        buf.extend_from_slice(&self.delta_y.to_be_bytes());
        buf.push(self.buttons);
    }

    fn deserialize_payload(buf: &[u8]) -> Option<Self> {
        if buf.len() != MOUSE_WHEEL_PAYLOAD_SIZE {
            return None;
        }

        Some(Self {
            client_id: u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
            delta_x: i16::from_be_bytes([buf[4], buf[5]]),
            delta_y: i16::from_be_bytes([buf[6], buf[7]]),
            buttons: buf[8],
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Per-client full keyboard snapshot. The server ORs all registered clients'
/// snapshots, so a key remains injected until every client releases it.
pub struct KeyboardStateInput {
    pub client_id: u32,
    pub pressed: [u8; KEYBOARD_STATE_BYTES],
}

impl Default for KeyboardStateInput {
    fn default() -> Self {
        Self {
            client_id: 0,
            pressed: [0u8; KEYBOARD_STATE_BYTES],
        }
    }
}

impl KeyboardStateInput {
    fn serialize_payload(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.client_id.to_be_bytes());
        buf.extend_from_slice(&self.pressed);
    }

    fn deserialize_payload(buf: &[u8]) -> Option<Self> {
        if buf.len() != KEYBOARD_STATE_PAYLOAD_SIZE {
            return None;
        }

        let mut pressed = [0u8; KEYBOARD_STATE_BYTES];
        pressed.copy_from_slice(&buf[4..]);
        Some(Self {
            client_id: u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
            pressed,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputPacket {
    MouseAbsolute(MouseAbsoluteInput),
    MouseRelative(MouseRelativeInput),
    MouseButtons(MouseButtonsInput),
    MouseWheel(MouseWheelInput),
    KeyboardState(KeyboardStateInput),
}

impl InputPacket {
    pub fn serialize(&self, seq: u16, credential: InputCredential) -> Vec<u8> {
        let payload_len = match self {
            Self::MouseAbsolute(_) => MOUSE_ABSOLUTE_PAYLOAD_SIZE,
            Self::MouseRelative(_) => MOUSE_RELATIVE_PAYLOAD_SIZE,
            Self::MouseButtons(_) => MOUSE_BUTTONS_PAYLOAD_SIZE,
            Self::MouseWheel(_) => MOUSE_WHEEL_PAYLOAD_SIZE,
            Self::KeyboardState(_) => KEYBOARD_STATE_PAYLOAD_SIZE,
        };

        let mut buf = Vec::with_capacity(HEADER_SIZE + INPUT_CREDENTIAL_BYTES + payload_len);
        buf.resize(HEADER_SIZE, 0);
        let header = PacketHeader {
            seq,
            frame_id: 0,
            payload_type: self.payload_type(),
        };
        header.serialize(&mut buf[..HEADER_SIZE]);
        buf.extend_from_slice(credential.as_bytes());
        match self {
            Self::MouseAbsolute(packet) => packet.serialize_payload(&mut buf),
            Self::MouseRelative(packet) => packet.serialize_payload(&mut buf),
            Self::MouseButtons(packet) => packet.serialize_payload(&mut buf),
            Self::MouseWheel(packet) => packet.serialize_payload(&mut buf),
            Self::KeyboardState(packet) => packet.serialize_payload(&mut buf),
        }
        buf
    }

    pub fn deserialize(raw: &[u8]) -> Option<(PacketHeader, InputCredential, Self)> {
        let header = PacketHeader::deserialize(raw)?;
        let credential_bytes: [u8; INPUT_CREDENTIAL_BYTES] = raw
            .get(HEADER_SIZE..HEADER_SIZE + INPUT_CREDENTIAL_BYTES)?
            .try_into()
            .ok()?;
        let credential = InputCredential::from_bytes(credential_bytes);
        let payload = &raw[HEADER_SIZE + INPUT_CREDENTIAL_BYTES..];
        let packet = match header.payload_type {
            PayloadType::MouseAbsolute => {
                Self::MouseAbsolute(MouseAbsoluteInput::deserialize_payload(payload)?)
            }
            PayloadType::MouseRelative => {
                Self::MouseRelative(MouseRelativeInput::deserialize_payload(payload)?)
            }
            PayloadType::MouseButtons => {
                Self::MouseButtons(MouseButtonsInput::deserialize_payload(payload)?)
            }
            PayloadType::MouseWheel => {
                Self::MouseWheel(MouseWheelInput::deserialize_payload(payload)?)
            }
            PayloadType::KeyboardState => {
                Self::KeyboardState(KeyboardStateInput::deserialize_payload(payload)?)
            }
            _ => return None,
        };
        Some((header, credential, packet))
    }

    fn payload_type(&self) -> PayloadType {
        match self {
            Self::MouseAbsolute(_) => PayloadType::MouseAbsolute,
            Self::MouseRelative(_) => PayloadType::MouseRelative,
            Self::MouseButtons(_) => PayloadType::MouseButtons,
            Self::MouseWheel(_) => PayloadType::MouseWheel,
            Self::KeyboardState(_) => PayloadType::KeyboardState,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CREDENTIAL: InputCredential = InputCredential::from_bytes([0xA5; 16]);

    #[test]
    fn roundtrip_mouse_absolute() {
        let packet = InputPacket::MouseAbsolute(MouseAbsoluteInput {
            client_id: 7,
            x: 1234,
            y: 4321,
            buttons: MOUSE_BUTTON_PRIMARY | MOUSE_BUTTON_SECONDARY,
        });
        let raw = packet.serialize(99, CREDENTIAL);
        let (header, credential, decoded) = InputPacket::deserialize(&raw).unwrap();
        assert_eq!(header.seq, 99);
        assert_eq!(credential, CREDENTIAL);
        assert_eq!(decoded, packet);
    }

    #[test]
    fn roundtrip_mouse_relative() {
        let packet = InputPacket::MouseRelative(MouseRelativeInput {
            client_id: 3,
            dx: -18,
            dy: 42,
            buttons: MOUSE_BUTTON_MIDDLE,
        });
        let raw = packet.serialize(11, CREDENTIAL);
        let (_, credential, decoded) = InputPacket::deserialize(&raw).unwrap();
        assert_eq!(credential, CREDENTIAL);
        assert_eq!(decoded, packet);
    }

    #[test]
    fn roundtrip_mouse_buttons() {
        let packet = InputPacket::MouseButtons(MouseButtonsInput {
            client_id: 9,
            buttons: MOUSE_BUTTON_EXTRA1 | MOUSE_BUTTON_EXTRA2,
        });
        let raw = packet.serialize(27, CREDENTIAL);
        let (_, credential, decoded) = InputPacket::deserialize(&raw).unwrap();
        assert_eq!(credential, CREDENTIAL);
        assert_eq!(decoded, packet);
    }

    #[test]
    fn roundtrip_mouse_wheel() {
        let packet = InputPacket::MouseWheel(MouseWheelInput {
            client_id: 5,
            delta_x: -1,
            delta_y: 3,
            buttons: MOUSE_BUTTON_PRIMARY,
        });
        let raw = packet.serialize(51, CREDENTIAL);
        let (_, credential, decoded) = InputPacket::deserialize(&raw).unwrap();
        assert_eq!(credential, CREDENTIAL);
        assert_eq!(decoded, packet);
    }

    #[test]
    fn roundtrip_keyboard_state() {
        let mut pressed = [0u8; KEYBOARD_STATE_BYTES];
        let (byte, bit) = KeyboardKey::W.bit();
        pressed[byte] |= bit;
        let (byte, bit) = KeyboardKey::LeftShift.bit();
        pressed[byte] |= bit;
        let packet = InputPacket::KeyboardState(KeyboardStateInput {
            client_id: 21,
            pressed,
        });
        let raw = packet.serialize(88, CREDENTIAL);
        let (header, credential, decoded) = InputPacket::deserialize(&raw).unwrap();
        assert_eq!(header.seq, 88);
        assert_eq!(credential, CREDENTIAL);
        assert_eq!(decoded, packet);
    }

    #[test]
    fn keyboard_wire_ids_are_stable() {
        assert_eq!(KeyboardKey::Escape as u8, 0);
        assert_eq!(KeyboardKey::Enter as u8, 3);
        assert_eq!(KeyboardKey::A as u8, 36);
        assert_eq!(KeyboardKey::F12 as u8, 73);
        assert_eq!(KeyboardKey::RightMeta as u8, 81);

        let appended = [
            KeyboardKey::CapsLock,
            KeyboardKey::NumLock,
            KeyboardKey::ScrollLock,
            KeyboardKey::PrintScreen,
            KeyboardKey::Pause,
            KeyboardKey::Application,
            KeyboardKey::Numpad0,
            KeyboardKey::Numpad1,
            KeyboardKey::Numpad2,
            KeyboardKey::Numpad3,
            KeyboardKey::Numpad4,
            KeyboardKey::Numpad5,
            KeyboardKey::Numpad6,
            KeyboardKey::Numpad7,
            KeyboardKey::Numpad8,
            KeyboardKey::Numpad9,
            KeyboardKey::NumpadDecimal,
            KeyboardKey::NumpadDivide,
            KeyboardKey::NumpadMultiply,
            KeyboardKey::NumpadSubtract,
            KeyboardKey::NumpadAdd,
            KeyboardKey::NumpadEnter,
            KeyboardKey::NumpadEquals,
            KeyboardKey::NumpadComma,
            KeyboardKey::F13,
            KeyboardKey::F14,
            KeyboardKey::F15,
            KeyboardKey::F16,
            KeyboardKey::F17,
            KeyboardKey::F18,
            KeyboardKey::F19,
            KeyboardKey::F20,
            KeyboardKey::F21,
            KeyboardKey::F22,
            KeyboardKey::F23,
            KeyboardKey::F24,
            KeyboardKey::VolumeMute,
            KeyboardKey::VolumeDown,
            KeyboardKey::VolumeUp,
            KeyboardKey::MediaPrevious,
            KeyboardKey::MediaNext,
            KeyboardKey::MediaPlayPause,
            KeyboardKey::MediaStop,
            KeyboardKey::IntlBackslash,
        ];
        for (offset, key) in appended.into_iter().enumerate() {
            assert_eq!(key as usize, 82 + offset);
            assert_eq!(KeyboardKey::from_u8(key as u8), Some(key));
        }
        assert_eq!(KeyboardKey::COUNT, 126);
        assert_eq!(KeyboardKey::from_u8(126), None);
    }

    #[test]
    fn expanded_keyboard_state_has_stable_golden_bytes() {
        let mut pressed = [0u8; KEYBOARD_STATE_BYTES];
        for key in [
            KeyboardKey::CapsLock,
            KeyboardKey::Numpad0,
            KeyboardKey::F24,
            KeyboardKey::IntlBackslash,
        ] {
            let (byte, bit) = key.bit();
            pressed[byte] |= bit;
        }
        let raw = InputPacket::KeyboardState(KeyboardStateInput {
            client_id: 0x0102_0304,
            pressed,
        })
        .serialize(0x1234, CREDENTIAL);
        assert_eq!(
            raw,
            vec![
                0x12, 0x34, 0, 0, 0, 0, 7, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
                0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0x04, 0x01, 0, 0, 0x20, 0x20,
            ]
        );
    }

    #[test]
    fn input_rejects_missing_or_truncated_credential() {
        let packet = InputPacket::MouseButtons(MouseButtonsInput {
            client_id: 1,
            buttons: 0,
        });
        let raw = packet.serialize(1, CREDENTIAL);
        assert!(InputPacket::deserialize(&raw[..HEADER_SIZE]).is_none());
        assert!(
            InputPacket::deserialize(&raw[..HEADER_SIZE + INPUT_CREDENTIAL_BYTES - 1]).is_none()
        );
    }
}
