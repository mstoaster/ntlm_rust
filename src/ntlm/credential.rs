use md5::{Digest, Md5};
use hmac::{Hmac, Mac};
use md4::Md4;

#[derive(Debug)]
pub struct Credential {
    pub user_name: String,
    pub domain_name: String,
    pub password: Vec<u8>
}

// Passes-in a cleartext password, returns an NTOWF hash of the password.
// NTOWFv2(Passwd, User, UserDom) as 
//      HMAC_MD5( MD4(UNICODE(Passwd)), UNICODE(ConcatenationOf( Uppercase(User), UserDom ) ) )
fn ntowf(username: &String, domainname: &String, password: &String) -> Vec<u8> {

    // Calculate the password hash, which will act as our key   
    // Step 1: Convert the UTF-8 str to UTF-16 as required by the protocol
    let pwd: Vec<u16> = password.encode_utf16().collect();

    // collect it as a vector of u8
    let pwd_bytes: Vec<u8> = pwd.iter().copied().flat_map(|x| x.to_le_bytes()).collect();

    // Hash it
    let mut md4_hasher = Md4::new();
    md4_hasher.update(pwd_bytes);
    let pwd_hash = md4_hasher.finalize();

    // Step 2: concat the data
    // Combined the upser-cased username and domain name
    let mut combined: Vec<u16> = username.to_uppercase().encode_utf16().collect(); 
    combined.extend(domainname.encode_utf16());

    // now, conver it to u8
    let combined_bytes: Vec<u8> = combined.iter().copied().flat_map(|x| x.to_le_bytes()).collect();

    // Step 3: calcualte the NTOWF by doing the HMAC_MD5
    type HmacMd5 = Hmac<Md5>;
    let mut hmac_md5: HmacMd5 = HmacMd5::new_from_slice(&pwd_hash).expect("unexpected error converting key for NTOWF");
    hmac_md5.update(&combined_bytes);

    let result = hmac_md5.finalize().into_bytes().to_vec();
    result
}

// Outside, of OOM, this function cannot fail.
pub fn acquire_credentials(username: &String, domainname: &String, password: &String) -> Option<Credential> {
    let cred: Credential = Credential { 
        user_name: String::from(username), 
        domain_name: String::from(domainname), 
        password: ntowf(&username, &domainname, &password)
    };
    Some(cred)
}