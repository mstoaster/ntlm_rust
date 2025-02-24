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
}