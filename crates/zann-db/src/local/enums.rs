use zann_core::EnumParseError;

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyWrapType {
    Master = 1,
    RemoteServer = 2,
    RemoteStrict = 3,
}

impl KeyWrapType {
    pub const MASTER: i32 = Self::Master as i32;
    pub const REMOTE_SERVER: i32 = Self::RemoteServer as i32;
    pub const REMOTE_STRICT: i32 = Self::RemoteStrict as i32;

    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

impl From<KeyWrapType> for i32 {
    fn from(value: KeyWrapType) -> Self {
        value as i32
    }
}

impl TryFrom<i32> for KeyWrapType {
    type Error = EnumParseError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Master),
            2 => Ok(Self::RemoteServer),
            3 => Ok(Self::RemoteStrict),
            _ => Err(EnumParseError::new("key_wrap_type", value.to_string())),
        }
    }
}
