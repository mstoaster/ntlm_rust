
mod ntlm;
use ntlm::{credential, negotiate::NegotiateMessage};

fn main() {
    let username = String::from("toaster");
    let domain = String::from("kitchen");
    let pwd = String::from("imaketoast");
    let machine = String::from("machine");

    let negomsg = NegotiateMessage::new_from_names(&domain, &machine);
    println!("Negotiate Message: {:?}", &negomsg.unwrap().serialize());
}
