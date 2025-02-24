use crate::{try_read_u16,try_read_u32};

#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(u16)]
pub enum AvId {
    MsvAvEOL = 0,
    MsvAvNbComputerName = 1,
    MsvAvnbDomainName = 2,
    MsvAvDnsComputerName = 3,
    MsvAvDnsDomainName = 4,
    MsvAvDnsTreeName = 5,
    MsvAvFlags = 6,
    MsvAvTimestamp = 7,
    MsvAvSingleHost = 8,
    MsvAvTargetName = 9,
    MsvAvChannelBindings = 0xA
}

impl AvId {
    pub fn from_u16(id: u16) -> Option<AvId> {
        match id {
            0 => Some(AvId::MsvAvEOL),
            1 => Some(AvId::MsvAvNbComputerName),
            2 => Some(AvId::MsvAvnbDomainName),
            3 => Some(AvId::MsvAvDnsComputerName),
            4 => Some(AvId::MsvAvDnsDomainName),
            5 => Some(AvId::MsvAvDnsTreeName),
            6 => Some(AvId::MsvAvFlags),
            7 => Some(AvId::MsvAvTimestamp),
            8 => Some(AvId::MsvAvSingleHost),
            9 => Some(AvId::MsvAvTargetName),
            0xA => Some(AvId::MsvAvChannelBindings),
            _ => None
        }
    }
}

pub struct Pair {
    pub id : AvId, 
    pub data : Vec<u8>
}  

pub struct AvPairVec {
    m_pairs : Vec<Pair>
}

impl AvPairVec {
    pub fn new() -> AvPairVec { 
        AvPairVec { 
            m_pairs: Vec::new()
        }
    }
    pub fn add(&mut self, pair : &Pair) {
        if !self.query(pair.id) // don't add duplicates
            && pair.data.len() <= u16::MAX as usize
        {
            let local_pair = Pair{id : pair.id,  data: pair.data.clone()};
            self.m_pairs.push(local_pair);
        }
    }

    pub fn query(&self, id: AvId) -> bool {
        if id == AvId::MsvAvEOL { // we don't store EoL, but return true since we'll always add it to the serialized verison.
            return true;
        }
        self.m_pairs.iter().any(|pair| pair.id == id)
    }

    pub fn deserialize(buffer: &Vec<u8>) -> Option<AvPairVec>{
        // the data must at least be some type of size of 4 u16 values.
        let min_size:usize = size_of::<i64>();
        if buffer.len() < min_size { 
            return None;
        }
        // we have <something>, clear our current data.
        let mut pos = 0;
        let mut avpairs = AvPairVec::new();
        let mut eol_found = false;

        // Loop through the vector. We will always need to read 4 bytes.
        while pos + 4 < buffer.len() {
            let id = AvId::from_u16(try_read_u16!(buffer, pos));
            let len = try_read_u16!(buffer,pos) as usize;
            
            // If we do not recognize an AvPair, drop it.
            if let Some(avid) = id {
                if avid == AvId::MsvAvEOL && len == 0 {
                    eol_found = true;
                    break;
                }
                let pair = Pair {id: avid, data: buffer[pos..pos+len].to_vec()};
                avpairs.add(&pair);
            }
            pos += len;
        }

        if !eol_found {
            return None
        }

        return Some(avpairs);
    }

    // Serialize the information that we have. If this is empty, it'll just be EoL.
    pub fn serialize(&self) -> Vec<u8>  {
        let mut local_vec: Vec<u8> = Vec::new();
        for pair in self.m_pairs.iter() {
            // first, add the id;
            local_vec.extend_from_slice(&(pair.id as u16).to_le_bytes());

            // then, add the size.
            local_vec.extend_from_slice(&pair.data.len().to_le_bytes());
        
            // then, copy the data.
            local_vec.extend(&pair.data);
        }
        // finally, add the EoL.
        local_vec.extend_from_slice(&(AvId::MsvAvEOL as u32).to_le_bytes());
        
        local_vec   
    }
}
