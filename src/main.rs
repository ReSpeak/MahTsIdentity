use rayon::prelude::*;
use structopt::StructOpt;
use tsproto::crypto::{EccKeyPrivP256, EccKeyPubP256};
use tsproto::algorithms::get_hash_cash_level;
use byteorder::{BigEndian, ByteOrder};
use std::time::{Instant, Duration};

type Result = std::result::Result<(), String>;

#[derive(StructOpt, Debug)]
#[structopt(about, author)]
struct Opts {
	#[structopt(short, long)]
	/// Stops searching after the first match.
	exit_when_found: bool,

	#[structopt(short, long)]
	/// Specifies how many threads should be used for the task. By default this will match the cpu cores/hyperthreads
	threads: Option<usize>,

	#[structopt()]
	/// All patterns to seatch for. Use an '_' as a wildcard.
	patterns: Vec<String>,

	#[structopt(short, long)]
	/// Run a small bench before starting the real search to add time estimates for all patterns.
	bench: bool,

	#[structopt(short, long)]
	identity: Option<String>,

	#[structopt(short="x", long)]
	/// Converts a private key to a ts-like obfucasted key which can be imported in the ts3 ui.
	export: bool,

	#[structopt(short="l", long)]
	/// Improves the security level of an identity
	level: Option<u64>,
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

struct Level {
	offset: u64,
	level: u8,
}

fn main() {
	let opts: Opts = Opts::from_args();
	
	if let Some(t) = opts.threads {
		rayon::ThreadPoolBuilder::new().num_threads(t).build_global().unwrap();
	}

	let result = (||{
		if opts.export {
			tool_export(opts)
		} else if !opts.patterns.is_empty() {
			tool_find_pattern(opts)
		} else if opts.level.is_some() {
			tool_improve_sec_level(opts)
		} else {
			Err("No patters given, please call with wanted uid strings".to_string())
		}
	})();

	std::process::exit(match result {
		Ok(_) => 0,
		Err(err) => {
			eprintln!("Error: {}", err);
			1
		}
	});
}

// Tool: export

fn tool_export(opts: Opts) -> Result {
	let identity = opts.identity.ok_or_else(|| "Requires an identity (-i) to export")?;
	let tp_priv = EccKeyPrivP256::import_str(&identity).map_err(|_| "Failed to read identity")?;
	let export = tp_priv.to_ts_obfuscated().map_err(|_| "Failed to export identity")?;
	println!("KEY: {}", export);
	Ok(())
}

// Tool: Find pattern

fn tool_find_pattern(opts: Opts) -> Result {
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
				return Err("Invalid pattern input".to_string());
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
	find_pattern_parallel(&data);
	println!("Done");
	Ok(())
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
		find_pattern_parallel(&data);
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

fn find_pattern_sync(data: &RunData) -> bool {
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

fn find_pattern_parallel(data: &RunData) {
	let mut found_any = false;
	while !found_any {
		found_any = (0..500_000).into_par_iter().any(|_| {
			find_pattern_sync(data)
		});
	}
}

// Tool: Increase security level

fn tool_improve_sec_level(opts: Opts) -> Result {
	let identity = opts.identity.ok_or_else(|| "Requires an identity (-i) to export")?;
	let tp_priv = EccKeyPrivP256::import_str(&identity).map_err(|_| "Failed to read identity")?;
	let omega = tp_priv.to_pub().to_ts().map_err(|_| "Failed to convert identity")?;

	let mut start_off = opts.level.unwrap();
	let mut best = Level { level: get_hash_cash_level(&omega, start_off), offset: start_off };
	const BATCH_SIZE: u64 = 500_000;

	let found_any = false;
	while !found_any {
		let max_res = (start_off..(start_off + BATCH_SIZE)).into_par_iter()
		.map(|i| Level { level: get_hash_cash_level(&omega, i), offset: i})
		.max_by(|x, y| x.level.cmp(&y.level))
		.expect("No elements in max");
		if max_res.level > best.level {
			best = max_res;
			println!("LEVEL: {} OFFSET: {}", best.level, best.offset);
		}
		start_off += BATCH_SIZE;

		if start_off % 100_000_000 < BATCH_SIZE {
			println!("STEP: {}", (start_off / BATCH_SIZE) * BATCH_SIZE);
		}
	}
	Ok(())
}
