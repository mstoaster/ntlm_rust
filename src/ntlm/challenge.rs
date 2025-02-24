use super::credential::Credential;
use super::negotiate::{NegotiateFlags, NegotiateMessage, DEFAULT_NEGOTIATE_FLAGS};
use super::av_pair::*;
use rand::Rng;
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/801a4681-8809-4be9-ab0d-61dcfe762786
pub struct ChallengeMessage {
    nego_flags: u32,
    target_info: AvPairVec,
    server_challenge: [u8; 8],
    server_realm: String,
}

impl From<&Credential> for ChallengeMessage {
    fn from(cred: &Credential) -> Self {
        let mut avpairs = AvPairVec::new();

        // Add the domain info. If we have a '.', then it's an DNS name
        let domain_id = if cred.domain().contains(".") { AvId::MsvAvDnsDomainName } else { AvId::MsvAvnbDomainName };
        avpairs.add(&Pair{ id: domain_id, data: cred.domain().as_bytes().to_vec()});

        // Add the server info. If we have a '.', then it's a DNS name
        let server_id = if cred.computer().contains(".") { AvId::MsvAvDnsDomainName } else { AvId::MsvAvNbComputerName };
        avpairs.add(&Pair{id: server_id, data: cred.computer().as_bytes().to_vec()});

        // We have all the info, build the challenge message
        ChallengeMessage {
            nego_flags: DEFAULT_NEGOTIATE_FLAGS,
            target_info: avpairs,
            server_challenge: rand::rng().random::<u64>().to_le_bytes(),
            server_realm: String::from(cred.domain())
        }
    }
}

impl ChallengeMessage {
    pub fn new() -> ChallengeMessage {
        ChallengeMessage {
            nego_flags: DEFAULT_NEGOTIATE_FLAGS,
            target_info: AvPairVec::new(),
            server_challenge: [0; 8],
            server_realm: String::new()
        }
    }

    pub fn process_negotiate(&mut self, nego_msg: &Vec<u8>) {
        let nego = match NegotiateMessage::deserialize(nego_msg) {
            Some(x) => {x}
            None => { return; }
        };

        self.nego_flags |= nego.nego_flags;
    }

    // CHALLENGE_MESSAGE Structure - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/801a4681-8809-4be9-ab0d-61dcfe762786
    //  Signature (8 bytes): An 8-byte character array that MUST contain the ASCII string ('N', 'T', 'L', 'M', 'S', 'S', 'P', '\0').
    //  MessageType (4 bytes): A 32-bit unsigned integer that indicates the message type. This field MUST be set to 0x00000002.  
    //  TargetNameFields  meFields (8 bytes): A field containing TargetName  information. The field diagram for TargetName  is as follows.
    //      § TargetNameLen (2 bytes): A 16-bit unsigned integer that defines the size, in bytes, of TargetNameFields in the Payload.
    //      § TargetNameMaxLen (2 bytes): A 16-bit unsigned integer that SHOULD be set to the value of TargetNameLen, and MUST be ignored on receipt.
    //      § TargetNameBufferOffset (4 bytes): A 32-bit unsigned integer that defines the offset, in bytes, from the beginning of the CHALLENGE_MESSAGE to TargetNameFields in Payload.
    //  NegotiateFlags (4 bytes): A NEGOTIATE structure that contains a set of flags, as defined in section 2.2.2.5. The client sets flags to indicate options it supports.
    //  ServerChallenge (8 bytes): A 64-bit value that contains the NTLM challenge. The challenge is a 64-bit nonce.
    //  Reserved (8 bytes): An 8-byte array whose elements MUST be zero when sent and MUST be ignored on receipt.
    //  TargetInfoFields (8 bytes): A field containing TargetInfo  information. The field diagram for TargetInfo  is as follows.
    //      § TargetInfoLen (2 bytes): A 16-bit unsigned integer that defines the size, in bytes, of TargetInfo in the Payload.
    //      § TargetInfoMaxLen (2 bytes): A 16-bit unsigned integer that SHOULD be set to the value of TargetInfoLen, and MUST be ignored on receipt.
    //      § TargetInfoBufferOffset (4 bytes): A 32-bit unsigned integer that defines the offset, in bytes, from the beginning of the CHALLENGE_MESSAGE to TargetInfo in Payload.
    //  Version (8 bytes): A VERSION structure (as defined in section 2.2.2.10) that is populated only when the NTLMSSP_NEGOTIATE_VERSION flag is set in the NegotiateFlags field; 
    //      otherwise, it MUST be set to all zero. This structure SHOULD<6> be used for debugging purposes only. 
    //  Payload (variable)
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        
        // Add the NTLMSSP data.
        buffer.extend_from_slice("NTLMSSP\0".as_bytes());

        // Add the MessageType, which must be 0x00000002.
        buffer.extend_from_slice(&(2 as u32).to_le_bytes());

        // Add the TargetName fields, which is the server realm
        buffer.extend_from_slice(&(self.server_realm.len() as u16).to_le_bytes()); // Len
        buffer.extend_from_slice(&(self.server_realm.len() as u16).to_le_bytes()); // MaxLen
        buffer.extend_from_slice(&(0 as u32).to_le_bytes()); // offset of the payload. As this is the first item, it's 0.

        // Add the negotiated flags.
        buffer.extend_from_slice(&self.nego_flags.to_le_bytes());

        // Add the server challenge
        buffer.extend_from_slice(&self.server_challenge);

        // Add the 'reserved' section
        buffer.extend_from_slice(&(0 as u64).to_le_bytes());

        // Add the TargetInfo fields, which is the AvPairs. We add the len fields here, then append the buffer at the end.
        let mut serialized_avpairs = self.target_info.serialize();
        buffer.extend_from_slice(&(serialized_avpairs.len() as u16).to_le_bytes());
        buffer.extend_from_slice(&(serialized_avpairs.len() as u16).to_le_bytes());
        buffer.extend_from_slice(&(self.server_realm.len() as u32).to_le_bytes()); // offset of the payload, comes after targetname data.

        // Add the version information.
        buffer.extend_from_slice(&(0 as u64).to_le_bytes());

        // Add the buffers.
        buffer.extend_from_slice(self.server_realm.as_bytes());
        buffer.append(&mut serialized_avpairs);

        buffer
    }

    pub fn deserialize(buffer: Vec<u8>) -> Option<ChallengeMessage> {
        None
    }
}