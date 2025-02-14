
struct Field {
    len: u16,
    max_len: u16,
    offset: u32
}

// The NEGOTIATE message contains more fields, but many are hard-coded and they're not needed
// to be stored. They just have to be added for serialization purposes.
pub struct NegotiateMessage {
    nego_flags: u32,
    domain_name: String,
    workstation: String,
}

impl NegotiateMessage {

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
        
        // first, add the NTLMSSP data
        let ntlm_str: &str = "NTLMSSP";
        buffer.extend_from_slice(&mut ntlm_str.as_bytes());

        // Add the MessageType, which must be 0x00000001
        let message_type: u32 = 1;
        buffer.extend_from_slice(&message_type.to_be_bytes());

        // add the negotiated flags
        buffer.extend_from_slice(&self.nego_flags.to_be_bytes());

        // add the domain fields.
        // We already checked that the string is of the right lenght;
        let domain_len: u16 = self.domain_name.len() as u16;
        let domain_max_len = domain_len;
        buffer.extend_from_slice(&domain_len.to_be_bytes());

        buffer
    }
}