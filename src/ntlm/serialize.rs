
#[macro_use]
macro_rules! read_u16 {
    ($val:expr) => {
        &($val as u16).to_le_bytes()
    };
    ($buffer:expr, $pos:expr) => {
        let val = $buffer[pos..pos+2].to_le_bytes();
        pos += 2
        val
    }
}

#[macro_use]
macro_rules! read_u32 {
    ($val:expr) => {
        &($val as u32).to_le_bytes()
    };
    ($buffer:expr, $pos:expr) => {
        let val = $buffer[pos..pos+4].to_le_bytes();
        pos += 4
        val
    }
}
#[macro_use]
macro_rules! write_u16 {
    ($val:expr) => {
        .chain(read_u16!($val))
    };
}
#[macro_use]
macro_rules! write_u32 {
    ($val:expr) => {
        .chain(read_u32!($val))
    };
}