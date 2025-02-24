    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/99d90ff4-957f-4c8a-80e4-5bfe5a9a9832
// Adding mod hack for the "enum class" concept from c++
#[allow(dead_code)]
pub mod NegotiateFlags {
    pub const NTLMSSP_NEGOTIATE_56: u32 = 1 << 0;
    pub const NTLMSSP_NEGOTIATE_KEY_EXCH: u32 = 1 << 1;
    pub const NTLMSSP_NEGOTIATE_128: u32 = 1 << 2;
    pub const R1: u32 = 1 << 3;
    pub const R2: u32 = 1 << 4;
    pub const R3: u32 = 1 << 5;
    pub const NTLMSSP_NEGOTIATE_VERSION: u32 = 1 << 6;
    pub const R4: u32 = 1 << 7;
    pub const NTLMSSP_NEGOTIATE_TARGET_INFO: u32 = 1 << 8;
    pub const NTLMSSP_REQUEST_NON_NT_SESSION_KEY: u32 = 1 << 9;
    pub const R5: u32 = 1 << 10;
    pub const NTLMSSP_NEGOTIATE_IDENTIFY: u32 = 1 << 11;
    pub const NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 1 << 12;
    pub const R6: u32 = 1 << 13;
    pub const NTLMSSP_TARGET_TYPE_SERVER: u32 = 1 << 14;
    pub const NTLMSSP_TARGET_TYPE_DOMAIN: u32 = 1 << 15;
    pub const NTLMSSP_NEGOTIATE_ALWAYS_SIGN: u32 = 1 << 16;
    pub const R7: u32 = 1 << 17;
    pub const NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED: u32 = 1 << 18;
    pub const NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED: u32 = 1 << 19;
    pub const NTLMSSP_NEGOTIATE_ANONYMOUS: u32 = 1 << 20;
    pub const R8: u32 = 1 << 21;
    pub const NTLMSSP_NEGOTIATE_NTLM: u32 = 1 << 22;
    pub const R9: u32 = 1 << 23;
    pub const NTLMSSP_NEGOTIATE_LM_KEY: u32 = 1 << 24;
    pub const NTLMSSP_NEGOTIATE_DATAGRAM: u32 = 1 << 25;
    pub const NTLMSSP_NEGOTIATE_SEAL: u32 = 1 << 26;
    pub const NTLMSSP_NEGOTIATE_SIGN: u32 = 1 << 27;
    pub const R10: u32 = 1 << 28;
    pub const NTLMSSP_REQUEST_TARGET: u32 = 1 << 29;
    pub const NTLM_NEGOTIATE_OEM: u32 = 1 << 30;
    pub const NTLMSSP_NEGOTIATE_UNICODE: u32 = 1 << 31;
}

pub const DEFAULT_NEGOTIATE_FLAGS: u32 = NTLMSSP_NEGOTIATE_128 
                                        | NTLMSSP_NEGOTIATE_KEY_EXCH 
                                        | NTLMSSP_NEGOTIATE_ALWAYS_SIGN 
                                        | NTLMSSP_NEGOTIATE_SEAL 
                                        | NTLMSSP_NEGOTIATE_SIGN 
                                        | NTLMSSP_NEGOTIATE_UNICODE;

// The NEGOTIATE message contains more fields, but many are hard-coded and they're not needed
// to be stored. They just have to be added for serialization purposes.
pub struct NegotiateMessage {
    pub nego_flags: u32,
    domain_name: String,
    workstation: String,
}
use NegotiateFlags::*;
use crate::{try_read_u16, try_read_u32, try_read_u64};

use super::credential::Credential;

impl From<&Credential> for NegotiateMessage {
    fn from(cred: &Credential) -> Self {
        NegotiateMessage {
            nego_flags: DEFAULT_NEGOTIATE_FLAGS,
            domain_name: String::from(cred.domain()),
            workstation: String::from(cred.domain())
        }
    }
}
impl NegotiateMessage {

    pub fn new() -> NegotiateMessage{
        NegotiateMessage {
            nego_flags: DEFAULT_NEGOTIATE_FLAGS,
            domain_name: String::new(),
            workstation: String::new()
        }
    }

    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b34032e5-3aae-4bc6-84c3-c6d80eadf7f2
    //  Signature (8 bytes): An 8-byte character array that MUST contain the ASCII string ('N', 'T', 'L', 'M', 'S', 'S', 'P', '\0').
    //  MessageType (4 bytes): A 32-bit unsigned integer that indicates the message type. This field MUST be set to 0x00000001.  
    //  NegotiateFlags (4 bytes): A NEGOTIATE structure that contains a set of flags, as defined in section 2.2.2.5. The client sets flags to indicate options it supports.
    //  DomainNameFields (8 bytes): A field containing DomainName information. The field diagram for DomainNameFields is as follows.
    //      § DomainNameLen (2 bytes): A 16-bit unsigned integer that defines the size, in bytes, of DomainName in the Payload.
    //      § DomainNameMaxLen (2 bytes): A 16-bit unsigned integer that SHOULD be set to the value of DomainNameLen, and MUST be ignored on receipt.
    //      § DomainNameBufferOffset (4 bytes): A 32-bit unsigned integer that defines the offset, in bytes, from the beginning of the NEGOTIATE_MESSAGE to DomainName in Payloadn
    //  WorkstationFields (8 bytes): A field containing WorkstationName information. The field diagram for WorkstationFields is as follow
    //      § WorkstationLen (2 bytes): A 16-bit unsigned integer that defines the size, in bytes, of WorkStationName in the Payload.
    //      § WorkstationMaxLen (2 bytes): A 16-bit unsigned integer that SHOULD be set to the value of WorkstationLen and MUST be ignored on receipt.
    //      § WorkstationBufferOffset (4 bytes): A 32-bit unsigned integer that defines the offset, in bytes, from the beginning of the NEGOTIATE_MESSAGE to WorkstationName in the Payload.
    //  Version (8 bytes): A VERSION structure (as defined in section 2.2.2.10) that is populated only when the NTLMSSP_NEGOTIATE_VERSION flag is set in the NegotiateFlags field; 
    //      otherwise, it MUST be set to all zero. This structure SHOULD<6> be used for debugging purposes only. 
    //  Payload (variable)

    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        
        // Add the NTLMSSP data.
        buffer.extend_from_slice("NTLMSSP\0".as_bytes());

        // Add the MessageType, which must be 0x00000001.
        buffer.extend_from_slice(&(1 as u32).to_le_bytes());

        // Add the negotiated flags.
        buffer.extend_from_slice(&self.nego_flags.to_le_bytes());

        // Add the domain fields.
        buffer.extend_from_slice(&(self.domain_name.len() as u16).to_le_bytes()); // Len
        buffer.extend_from_slice(&(self.domain_name.len() as u16).to_le_bytes()); // MaxLen
        buffer.extend_from_slice(&(0 as u32).to_le_bytes()); // offset of the payload. As this is the first item, it's 0.

        // Add the workstation fields.
        buffer.extend_from_slice(&(self.workstation.len() as u16).to_le_bytes()); // Len
        buffer.extend_from_slice(&(self.workstation.len() as u16).to_le_bytes()); // MaxLen = Len
        buffer.extend_from_slice(&(self.domain_name.len() as u32).to_le_bytes()); // offset of the payload. We put this after the domain_name field

        // Add the version information.
        buffer.extend_from_slice(&(0 as u64).to_le_bytes());

        // Add the buffers.
        buffer.extend_from_slice(self.domain_name.as_bytes());
        buffer.extend_from_slice(self.workstation.as_bytes());

        buffer
    }

    pub fn deserialize(buffer: &Vec<u8>) -> Option<NegotiateMessage> {
        let min_size: usize = 10 * 4; // minimum size of the NEGOTIATE_MESSAGE
        if buffer.len() < min_size { 
            return None;
        }

        // check if the first 8 bytes are "NTLMSSP\0".
        let mut pos: usize = 0;
        if &buffer[0..8] != b"NTLMSSP\0" {
            return None;
        }
        pos += 8;

        // The next 4 bytes are the Message Field. It must be 1.
        let message: u32 = try_read_u32!(buffer,pos);
        if message != 1 {
            return None;
        }

        // The next 4 bytes are the negotiated flags.
        let negotiated_flags: u32 = try_read_u32!(buffer,pos);

        // The next 8 bytes are as follows:
        // 1. Domain len     - 2 bytes
        // 2. Domain max len - 2 bytes (ignored)
        // 3. Domain offset  - 4 bytes
        let domain_len = try_read_u16!(buffer,pos);
        let _ = try_read_u16!(buffer,pos);
        let domain_offset = try_read_u32!(buffer,pos);

        // The next 8 bytes are as follows:
        // 1. Workstation len     - 2 bytes
        // 2. Workstation max len - 2 bytes (ignored)
        // 3. Workstation offset  - 4 bytes
        let workstation_len: u16 = try_read_u16!(buffer,pos);
        let _ = try_read_u16!(buffer,pos);
        let workstaiton_offset: u32 = try_read_u32!(buffer,pos);

        // we have both domain len and workstation len. The buffer must be large enought to hold them:
        if ((domain_len as usize) + (workstation_len as usize) + min_size) > buffer.len() {
            return None;
        }

        // The next 8 bytes are for version, ignored.
        let _ = try_read_u64!(buffer,pos);

        // Now, we copy the strings. They're OEM strings.
        let domain_slice: &[u8] = {
            let start: usize = min_size + domain_offset as usize;
            let end: usize = start + domain_len as usize;
            &buffer[start..end]
        };
        let domain_str = String::from_utf8(domain_slice.to_vec()).ok()?;

        let workstation_slice: &[u8] = {
            let start: usize = min_size + workstaiton_offset as usize;
            let end: usize = start + workstation_len as usize;
            &buffer[start..end]
        };
        let workstation_str = String::from_utf8(workstation_slice.to_vec()).ok()?;

        return Some(NegotiateMessage {
            nego_flags: negotiated_flags,
            domain_name: domain_str,
            workstation: workstation_str
        });
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn serialize_and_deserialize() {
        let helper = | original: &NegotiateMessage |  {
            let new_message = NegotiateMessage::deserialize(&original.serialize()).expect("serialize -> deserialize failed");

            assert_eq!(new_message.nego_flags, original.nego_flags);
            assert_eq!(new_message.domain_name, original.domain_name);
            assert_eq!(new_message.workstation, original.workstation);
        };

        let reg_cred = Credential::acquire_credentials("toast", "kitchen", "machine1", "IMakeToast1!").unwrap();
        let original_message = NegotiateMessage::from(&reg_cred);
        helper(&original_message);

        let empty_cred = Credential::acquire_credentials("", "", "", "").unwrap();
        let empty_message = NegotiateMessage::from(&empty_cred);
        helper(&empty_message);
    }
}
