use rayon::prelude::*;
use structopt::StructOpt;
use tsproto::crypto::{EccKeyPrivP256, EccKeyPubP256};
use byteorder::{BigEndian, ByteOrder};
use std::time::{Instant, Duration};

#[derive(StructOpt, Debug)]
#[structopt(about, author)]
struct Opts {
	#[structopt(short, long)]
	exit_when_found: bool,

	#[structopt(short, long)]
	threads: Option<usize>,

	#[structopt()]
	patterns: Vec<String>,

	#[structopt(short, long)]
	bench: bool,
}

struct RunData {
	patterns: Vec<FindPattern>,
	exit_when_found: bool,
	print_matches: bool,
}

#[derive(Debug)]
struct FindPattern {
	text: u64,
	mask: u64,
}

fn main() {
	let opts: Opts = Opts::from_args();

	if opts.patterns.is_empty() {
		println!("No patters given, please call with wanted uid strings");
		return;
	}

	if let Some(t) = opts.threads {
		rayon::ThreadPoolBuilder::new().num_threads(t).build_global().unwrap();
	}

	let time_per_bit = if opts.bench {
		println!("Benching...");
		Some(bench())
	} else { None };

	let mut patterns = vec![];
	for inp in &opts.patterns {
		let mut mask_builder = [0u8; 28]; // The max number of chars in a UID including the '=' at the end
		let mut char_builder = String::with_capacity(28);
		let mut i = 0;
		for c in inp.chars() {
			if c == '+' || c == '/' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
				mask_builder[i] = 0b0011_1111;
				char_builder.push(c);
				i += 1;
			} else if c == '_' || c == '?' {
				mask_builder[i] = 0x0;
				char_builder.push('A');
				i += 1;
			} else {
				panic!("Invalid pattern input");
			}
			if i >= mask_builder.len() - 1 { break; }
		}
		for _ in i..27 {
			char_builder.push('A');
		}
		char_builder.push('=');

		let mut mask = 0u64;
		for i in 0..10 {
			mask |= (mask_builder[i] as u64) << 58 - (6 * i);
		}

		let target_bytes = base64::decode(&char_builder).unwrap();
		let mut text = BigEndian::read_u64(&target_bytes[0..8]);

		text &= mask;
		patterns.push(FindPattern { text, mask });
		print!("Patterns: {} {:#010b} {:#010b}", char_builder, text, mask);
		if let Some(t) = time_per_bit {
			print!(" {}", expect_time(t, mask.count_ones()));
		}
		println!();
	}

	let data = RunData {
		patterns,
		exit_when_found: opts.exit_when_found,
		print_matches: true
	};
	gen_bench_para(&data);
	println!("Done");
}

fn bench() -> Duration {
	let data = RunData {
		exit_when_found: true,
		print_matches: false,
		patterns: vec! [
			FindPattern {
				text: 0,
				mask: 0b111111_111111_000000_000000_0000000000000000000000000000000000000000
			}
		]
	};

	let now = Instant::now();
	let iters = 100;
	for _ in 0..iters {
		gen_bench_para(&data);
	}
	let elap = now.elapsed();
	let time_per_run = elap.div_f64(iters as f64);
	println!("Avg Run {:?}", time_per_run);
	let time_per_bit = time_per_run.div_f64(2u32.pow(data.patterns[0].mask.count_ones()) as f64);
	println!("Time per bit {:?}", time_per_bit);
	time_per_bit
}

fn expect_time(dur: Duration, bits: u32) -> String {
	let mut t = dur.as_secs_f64() * 2u64.pow(bits) as f64;
	let mut u = "second(s)";
	if t > 60.0 {
		t /= 60.0;
		u = "minute(s)";

		if t > 60.0 {
			t /= 60.0;
			u = "hours(s)";

			if t > 24.0 {
				t /= 24.0;
				u = "day(s)";
			}
		}
	}
	format!("Expected time: ~ {:.2} {}", t, u)
}

fn gen_single(data: &RunData) -> bool {
	let (priv_key, pub_key) = ring::signature::EcdsaKeyPair::generate_key_pair(
		&ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
		&ring::rand::SystemRandom::new(),
	).unwrap();

	// Compute uid
	let pub_key = EccKeyPubP256::from_short(pub_key);
	let hash = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
		pub_key.to_ts().unwrap().as_bytes());
	let uid = hash.as_ref();

	for p in &data.patterns {
		if BigEndian::read_u64(&uid[0..8]) & p.mask == p.text {
			if data.print_matches {
				let tp_priv = EccKeyPrivP256::from_short(priv_key).unwrap();
				let export = tp_priv.to_ts().unwrap();
				println!("UID: {} KEY: {}", pub_key.get_uid().unwrap(), export);
			}
			return data.exit_when_found;
		}
	}
	false
}

fn gen_bench_para(data: &RunData) {
	let mut found_any = false;
	while !found_any {
		found_any = (0..500_000).into_par_iter().any(|_| {
			gen_single(data)
		});
	}
}
