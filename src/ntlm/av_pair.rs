#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(u16)]
pub enum Id {
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

pub struct Pair {
    pub id : Id, 
    pub data : Vec<u8>
}  

pub struct PairVec {
    pub m_pairs : Vec<Pair>
}

impl PairVec {
    pub fn add(&mut self, pair : &Pair) {
        if !self.query(pair.id) // don't add duplicates
            && pair.data.len() <= u16::MAX as usize
        {
            let local_pair = Pair{id : pair.id,  data: pair.data.clone()};
            self.m_pairs.push(local_pair);
        }
    }

    pub fn query(&self, id: Id) -> bool {
        if id == Id::MsvAvEOL { // we don't keep id EoL, but return true since we'll always add it to the serialized verison.
            return true;
        }
        self.m_pairs.iter().any(|pair| pair.id == id)
    }

    pub fn deserialize(&mut self, data: &Vec<u8>) -> Result<(), u32>{
        // the data must at least be some type of size of 4 u16 values.
        let min_size:usize = size_of::<i64>();
        if data.len() < min_size { 
            return Err(0);
        }

        // we have <something>, clear our current data.
        self.m_pairs.clear();
        return Ok(());
    }

    // Serialize the information that we have. If this is empty, it'll just be EoL.
    pub fn serialize(&self) -> Vec<u8>  {
        let mut local_vec: Vec<u8> = Vec::new();
        for pair in self.m_pairs.iter() {
            // first, add the id;
            let local_id = pair.id as u16;
            local_vec.push(((local_id >> 8) & 0xFF) as u8);
            local_vec.push((local_id & 0xFF) as u8);

            // then, add the size.
            local_vec.push(((pair.data.len() >> 8) & 0xFF) as u8);
            local_vec.push((pair.data.len() & 0xFF) as u8);

            // then, copy the data.
            local_vec.append(&mut pair.data.clone());
        }
        // at the end, add the EoL pair
        for _i in 0..4 {
            local_vec.push(0);
        }
        local_vec   
    }
}
