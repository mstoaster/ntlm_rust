
mod ntlm;
use ntlm::av_pair;

fn main() {
    println!("Hello, world!");
    let vec1 = vec!{1, 2, 3, 4};
    let vec2: Vec<u8> = vec![5, 6, 7, 8];

    let avpair1:av_pair::Pair = av_pair::Pair{id: av_pair::Id::MsvAvNbComputerName, data: vec1};
    let avpair2:av_pair::Pair = av_pair::Pair{id: av_pair::Id::MsvAvDnsComputerName, data: vec2};

    let mut av_pairs : av_pair::PairVec = av_pair::PairVec{ m_pairs: Vec::new() };
    av_pairs.add(&avpair1);
    av_pairs.add(&avpair2);

    println!("Do we have id 0? {0}", av_pairs.query(av_pair::Id::MsvAvEOL));
    println!("Do we have id 1? {0}", av_pairs.query(av_pair::Id::MsvAvNbComputerName));
    println!("Do we have id 3? {0}", av_pairs.query(av_pair::Id::MsvAvDnsDomainName));

    let v = av_pairs.serialize();
    println!("Serialize result: {:?}", v);
}
