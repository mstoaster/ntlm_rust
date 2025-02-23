
#[macro_export]
macro_rules! try_read_u16 {
    ($buffer:expr, $pos:expr) => {{
        let val = u16::from_le_bytes($buffer[$pos..$pos+2].try_into().ok()?);
        $pos += 2;
        val
    }};
}

#[macro_export]
macro_rules! try_read_u32 {
    ($buffer:expr, $pos:expr) => {{
        let val = u32::from_le_bytes($buffer[$pos..$pos+4].try_into().ok()?);
        $pos += 4;
        val
    }};
}

#[macro_export]
macro_rules! try_read_u64 {
    ($buffer:expr, $pos:expr) => {{
        let val = u64::from_le_bytes($buffer[$pos..$pos+8].try_into().ok()?);
        $pos += 8;
        val
    }};
}