fn main() {
    let t = socket2::Type::RAW;
    let d = socket2::Domain::IPV4;
    let p = socket2::Protocol::ICMPV4;
    println!("{:?} {:?} {:?}", t, d, p);
}
