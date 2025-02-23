use super::negotiate::{NegotiateFlags, NegotiateMessage};
use super::av_pair::PairVec;

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/801a4681-8809-4be9-ab0d-61dcfe762786
pub struct ChallengeMessage {
    pub nego_flags: u32,
    pub target_info: PairVec,
    server_challenge: [u8; 8],
    target_name: String,
}

impl ChallengeMessage {
    pub fn process_negotiate(&mut self, nego_msg: &Vec<u8>) {
        
    }
}