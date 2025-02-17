pub struct Credential {
    pub user_name: String,
    pub domain_name: String,
    pub password: Vec<u8>
}

// Passes-in a cleartext password, returns an NTOWF hash of the password.
// NTOWFv2(Passwd, User, UserDom) as 
//      HMAC_MD5( MD4(UNICODE(Passwd)), UNICODE(ConcatenationOf( Uppercase(User), UserDom ) ) )
fn ntwof(username: &String, domainname: &String, password: &String) -> Vec<u8> {
    let user_bytes: Vec<u8> = username.to_uppercase().encode_utf16().collect();
    let domain_bytes: Vec<u8> = domainname.encode_utf16().collect();
    let password_bytes: Vec<u8> = password.encode_utf16().collect();

    
}

// Outside, of OOM, this function cannot fail.
pub fn acquire_credentials(username: &String, domainname: &String, password: &String) -> Option<Credential> {
    let mut cred: Credential = Credential { user_name: (), domain_name: (), password: () };
}