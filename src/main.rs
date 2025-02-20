
mod ntlm;
use ntlm::credential;

fn main() {
    let username = String::from("toaster");
    let domain = String::from("earth");
    let pwd = String::from("imaketoast");

    let cred = credential::acquire_credentials(&username, &domain, &pwd)
        .expect("this shouldn't fail");
}
