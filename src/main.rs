use rayon::prelude::*;
use structopt::StructOpt;
use tsproto::crypto::{EccKeyPrivP256, EccKeyPubP256};
use byteorder::{BigEndian, ByteOrder, ReadBytesExt};

#[derive(StructOpt, Debug)]
#[structopt(about, author)]
struct Opts {
	#[structopt()]
	pattern: Vec<String>,
}

#[derive(Debug)]
struct FindPattern{
	text: u64,
	mask: u64,
}

fn main() {
	let opts: Opts = Opts::from_args();

	if opts.pattern.is_empty() {
		println!("No patters given, please call with wanted uid strings");
		return;
	}

	let mut patterns = vec![];
	for inp in opts.pattern {
		let mut pattern_padded = inp.clone();
		pattern_padded.push_str(&"A".repeat(inp.len() % 4));
		let mut target_bytes = base64::decode(&pattern_padded).unwrap();
		for _ in (target_bytes.len())..8 { target_bytes.push(0); }
		let mut text = BigEndian::read_u64(&target_bytes[0..8]);

		let mut mask = 0u64;
		for i in 0..std::cmp::min(inp.len(), 10) {
			mask |= 0x3F << 58 - (6 * i);
		}
		text &= mask;
		patterns.push(FindPattern { text, mask });
		println!{"Patterns: {:X} {:X}", text, mask};
	}
	//return;

	//let patt = opts.pattern.into_iter().map(|p| p.into_bytes()).collect::<Vec<_>>();
	gen_bench_para(&patterns);
}

fn gen_single(patt: &[FindPattern]) -> bool {
	let (priv_key, pub_key) = ring::signature::EcdsaKeyPair::generate_key_pair(
		&ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
		&ring::rand::SystemRandom::new(),
	).unwrap();

	// Compute uid
	let pub_key = EccKeyPubP256::from_short(pub_key);
	let hash = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
		pub_key.to_ts().unwrap().as_bytes());
	let uid = hash.as_ref();

	for p in patt {
		if BigEndian::read_u64(&uid[0..8]) & p.mask == p.text {
			let tp_priv = EccKeyPrivP256::from_short(priv_key).unwrap();
			let export = tp_priv.to_ts().unwrap();
			println!("UID: {} KEY: {}", pub_key.get_uid().unwrap(), export);
			return true;
		}
	}
	false
}

fn gen_bench_para(patt: &[FindPattern]) {
	//rayon::ThreadPoolBuilder::new().num_threads(12).build_global().unwrap();
	let mut found_any = false;
	while !found_any {
		found_any = (0..500_000).into_par_iter().any(|_| {
			gen_single(patt)
		});
	}
	println!("Done");
}
