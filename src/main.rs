//#[macro_use] extern crate failure;
//extern crate ring;
extern crate tsproto;
extern crate rayon;
use structopt::StructOpt;

use tsproto::crypto::{EccKeyPrivP256, EccKeyPubP256};
use rayon::prelude::*;
use std::thread;

#[derive(StructOpt, Debug)]
struct Opts {
    /// Sets a custom config file. Could have been an Option<T> with no default too
    #[structopt(short = "p", long = "pattern")]
    pattern: Vec<String>,
}

fn main() {
	let opts: Opts = Opts::from_args();

	let patt = opts.pattern.into_iter().map(|p| p.into_bytes()).collect();
	gen_bench_para(&patt);
}

fn gen_single(patt: &Vec<Vec<u8>>) -> bool {
	let tp_priv = EccKeyPrivP256::create().unwrap();
	let tp_pub: EccKeyPubP256 = (&tp_priv).into();
	let uid = tp_pub.get_uid_no_base64().unwrap();
	for p in patt {
		if uid.starts_with(p) {
			let export = tp_priv.to_ts().unwrap();
			println!("MATCH {} KEY: {}", String::from_utf8(p.to_vec()).unwrap(), export);
			return true;
		}
	}
	false
}

// fn _gen_bench() {
// 	//let mut cnt = 0usize;

// 	for _ in 0..50000 {
// 		gen_single();
// 		//cnt += 1;
// 		//if cnt % 10000 == 0 {
// 		//	println!("STEP: {}", cnt);
// 		//}
// 	}
// }

fn gen_bench_para(patt: &Vec<Vec<u8>>) {
	//rayon::ThreadPoolBuilder::new().num_threads(12).build_global().unwrap();
	let mut found_any = false;
	while !found_any {
		found_any = (0..500000).into_par_iter().any(|_|{
			gen_single(patt)
		});
	}
	println!("done");
}

// fn gen_bench_para_man(patt: Vec<String>) {
// 	let mut handlers = vec![];
// 	for _ in 0..12 {
// 		let pattc = patt.clone();
// 		handlers.push(thread::spawn(move || {
// 			loop {
// 				gen_single(&pattc);
// 			}
// 		}));
// 	}
// 	let any = handlers.pop().unwrap();
// 	any.join().unwrap();
// }
