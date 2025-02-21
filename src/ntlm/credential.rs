use md5::{Digest, Md5};
use hmac::{Hmac, Mac};
use md4::Md4;

pub struct Credential {
    user_name: String,
    domain_name: String,
    password: Vec<u8>
}

impl Credential {
    pub fn new() -> Self {
        Self { user_name: String::new(), domain_name: String::new(), password: Vec::new()}
    }

    pub fn from(user: &String, domain: &String, password: &String) -> Self {
        Credential {
            user_name: String::from(user),
            domain_name: String::from(domain),
            password: Self::ntowf(user, domain, password)
        }
    }

    fn generate_hmac_md5_signature(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut algo: Hmac<Md5> = Hmac::new_from_slice(&key)
                                    .expect("unexpected failure generating hmac-md5 signature");
        algo.update(&data);
        algo.finalize().into_bytes().to_vec()
    }

    // Passes-in a cleartext password, returns an NTOWF hash of the password.
    // NTOWFv2(Passwd, User, UserDom) as 
    //      HMAC_MD5( MD4(UNICODE(Passwd)), UNICODE(ConcatenationOf( Uppercase(User), UserDom ) ) )
    fn ntowf(username: &String, domainname: &String, password: &String) -> Vec<u8> {

        // Calculate the password hash, which will act as our key   
        // Step 1: Convert the UTF-8 str to UTF-16 as required by the protocol
        let pwd: Vec<u16> = password.encode_utf16().collect();

        // collect it as a vector of u8
        let pwd_bytes: Vec<u8> = pwd.iter().flat_map(|x| x.to_le_bytes()).collect();

        // Hash it
        let mut md4_hasher = Md4::new();
        md4_hasher.update(pwd_bytes);
        let pwd_hash = md4_hasher.finalize();

        // Step 2: concat the data
        // Combined the upser-cased username and domain name
        let mut combined: Vec<u16> = username.to_uppercase().encode_utf16().collect(); 
        combined.extend(domainname.encode_utf16());

        // now, conver it to u8
        let combined_bytes: Vec<u8> = combined.iter().flat_map(|x| x.to_le_bytes()).collect();

        // Step 3: calcualte the NTOWF by doing the HMAC_MD5
        Self::generate_hmac_md5_signature(&pwd_hash, &combined_bytes)
    }

    // Set SessionBaseKey to HMAC_MD5(ResponseKeyNT, NTProofStr)
    pub fn create_session_key(&self, proof_str: &Vec<u8>) -> Vec<u8> {
        Self::generate_hmac_md5_signature(&self.password, &proof_str)
    }

    pub fn user(&self) -> &String { &self.user_name }
    pub fn domain(&self) -> &String {&self.domain_name }
}
    

pub fn acquire_credentials(username: &String, domainname: &String, password: &String) -> Option<Credential> {
    Some(Credential::from(username, domainname, password))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test] // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/7795bd0e-fd5e-43ec-bd9c-994704d8ee26
    fn test_ntowf() {
        let username = String::from("User");
        let domainname: String = String::from("Domain");
        let password: String = String::from("Password");

        let expected_ntowf: [u8; 16] = [0x0c, 0x86, 0x8a, 0x40, 0x3b, 0xfd, 0x7a, 0x93, 0xa3, 0x00, 0x1e, 0xf2, 0x2e, 0xf0, 0x2e, 0x3f];
        let actual_ntowf = Credential::ntowf(&username, &domainname, &password);

        assert_eq!(actual_ntowf.len(), 16);

        // count how many bytes are the same between the expected and actual NTOWF buffers.
        let num_of_same_bytes = expected_ntowf
                                        .iter()
                                        .zip(actual_ntowf.iter())
                                        .filter(|&(x, y) | x == y)
                                        .count();
        assert_eq!(num_of_same_bytes, expected_ntowf.len());
    }
}