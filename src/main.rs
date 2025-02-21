
mod ntlm;
use ntlm::{credential, negotiate::NegotiateMessage};

fn main() {
    let username = String::from("toaster");
    let domain = String::from("earth");
    let pwd = String::from("imaketoast");
    let machine = String::from("machine");

    let negomsg = NegotiateMessage::from(&domain, &machine);
    println!("Negotiate Message: {:?}", &negomsg.serialize());
}
