use crate::packet::{PacketHeader, PayloadType, HEADER_SIZE};

pub const MOUSE_BUTTON_PRIMARY: u8 = 1 << 0;
pub const MOUSE_BUTTON_SECONDARY: u8 = 1 << 1;
pub const MOUSE_BUTTON_MIDDLE: u8 = 1 << 2;
pub const MOUSE_BUTTON_EXTRA1: u8 = 1 << 3;
pub const MOUSE_BUTTON_EXTRA2: u8 = 1 << 4;
/// High-resolution wheel units per traditional mouse-wheel notch.
pub const MOUSE_WHEEL_STEP_UNITS: i16 = 120;
pub const KEYBOARD_STATE_BYTES: usize = 16;

const MOUSE_ABSOLUTE_PAYLOAD_SIZE: usize = 9;
const MOUSE_RELATIVE_PAYLOAD_SIZE: usize = 9;
const MOUSE_BUTTONS_PAYLOAD_SIZE: usize = 5;
const MOUSE_WHEEL_PAYLOAD_SIZE: usize = 9;
const KEYBOARD_STATE_PAYLOAD_SIZE: usize = 4 + KEYBOARD_STATE_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyboardKey {
    Escape = 0,
    Tab,
    Backspace,
    Enter,
    Space,
    Insert,
    Delete,
    Home,
    End,
    PageUp,
    PageDown,
    ArrowUp,
    ArrowDown,
    ArrowLeft,
    ArrowRight,
    Minus,
    Equals,
    OpenBracket,
    CloseBracket,
    Backslash,
    Semicolon,
    Quote,
    Backtick,
    Comma,
    Period,
    Slash,
    Num0,
    Num1,
    Num2,
    Num3,
    Num4,
    Num5,
    Num6,
    Num7,
    Num8,
    Num9,
    A,
    B,
    C,
    D,
    E,
    F,
    G,
    H,
    I,
    J,
    K,
    L,
    M,
    N,
    O,
    P,
    Q,
    R,
    S,
    T,
    U,
    V,
    W,
    X,
    Y,
    Z,
    F1,
    F2,
    F3,
    F4,
    F5,
    F6,
    F7,
    F8,
    F9,
    F10,
    F11,
    F12,
    LeftShift,
    LeftCtrl,
    LeftAlt,
    LeftMeta,
    RightShift,
    RightCtrl,
    RightAlt,
    RightMeta,
}

impl KeyboardKey {
    pub const COUNT: usize = Self::RightMeta as usize + 1;

    pub fn bit(self) -> (usize, u8) {
        let index = self as usize;
        (index / 8, 1 << (index % 8))
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        if value <= Self::RightMeta as u8 {
            // SAFETY: KeyboardKey is a repr(u8) enum with contiguous discriminants from 0
            // through RightMeta.
            Some(unsafe { std::mem::transmute::<u8, Self>(value) })
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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
    pub fn serialize(&self, seq: u16) -> Vec<u8> {
        let payload_len = match self {
            Self::MouseAbsolute(_) => MOUSE_ABSOLUTE_PAYLOAD_SIZE,
            Self::MouseRelative(_) => MOUSE_RELATIVE_PAYLOAD_SIZE,
            Self::MouseButtons(_) => MOUSE_BUTTONS_PAYLOAD_SIZE,
            Self::MouseWheel(_) => MOUSE_WHEEL_PAYLOAD_SIZE,
            Self::KeyboardState(_) => KEYBOARD_STATE_PAYLOAD_SIZE,
        };

        let mut buf = Vec::with_capacity(HEADER_SIZE + payload_len);
        buf.resize(HEADER_SIZE, 0);
        let header = PacketHeader {
            seq,
            frame_id: 0,
            payload_type: self.payload_type(),
        };
        header.serialize(&mut buf[..HEADER_SIZE]);
        match self {
            Self::MouseAbsolute(packet) => packet.serialize_payload(&mut buf),
            Self::MouseRelative(packet) => packet.serialize_payload(&mut buf),
            Self::MouseButtons(packet) => packet.serialize_payload(&mut buf),
            Self::MouseWheel(packet) => packet.serialize_payload(&mut buf),
            Self::KeyboardState(packet) => packet.serialize_payload(&mut buf),
        }
        buf
    }

    pub fn deserialize(raw: &[u8]) -> Option<(PacketHeader, Self)> {
        let header = PacketHeader::deserialize(raw)?;
        let payload = &raw[HEADER_SIZE..];
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
        Some((header, packet))
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

    #[test]
    fn roundtrip_mouse_absolute() {
        let packet = InputPacket::MouseAbsolute(MouseAbsoluteInput {
            client_id: 7,
            x: 1234,
            y: 4321,
            buttons: MOUSE_BUTTON_PRIMARY | MOUSE_BUTTON_SECONDARY,
        });
        let raw = packet.serialize(99);
        let (header, decoded) = InputPacket::deserialize(&raw).unwrap();
        assert_eq!(header.seq, 99);
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
        let raw = packet.serialize(11);
        let (_, decoded) = InputPacket::deserialize(&raw).unwrap();
        assert_eq!(decoded, packet);
    }

    #[test]
    fn roundtrip_mouse_buttons() {
        let packet = InputPacket::MouseButtons(MouseButtonsInput {
            client_id: 9,
            buttons: MOUSE_BUTTON_EXTRA1 | MOUSE_BUTTON_EXTRA2,
        });
        let raw = packet.serialize(27);
        let (_, decoded) = InputPacket::deserialize(&raw).unwrap();
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
        let raw = packet.serialize(51);
        let (_, decoded) = InputPacket::deserialize(&raw).unwrap();
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
        let raw = packet.serialize(88);
        let (header, decoded) = InputPacket::deserialize(&raw).unwrap();
        assert_eq!(header.seq, 88);
        assert_eq!(decoded, packet);
    }
}
