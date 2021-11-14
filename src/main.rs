use md5::{Md5, Digest};
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};

use std::{io, env, fs};
use pdf::file::File;
use zip::ZipArchive;

use colored::Colorize;
use indicatif::ProgressBar;

// For ZIP files
fn ettuz(filename: &str, pass_list: &str) -> () {
    let zip_file = fs::File::open(filename).unwrap();
    let mut archive = ZipArchive::new(&zip_file).unwrap();

    let pass_file = fs::read_to_string(pass_list).unwrap();
    let pass_list: Vec<&str> = pass_file.split('\n').collect();
    let bar = ProgressBar::new(pass_list.len() as u64);

    let mut got_pass: bool = false;
    let mut possible_passes: Vec<&str> = vec![];

    for pass in pass_list {
        bar.inc(1);
        if got_pass {
            bar.finish();
            break;
        }

        for idx in 0..archive.len() {
            let mut file = match archive.by_index_decrypt(idx, String::from(pass).as_bytes()) {
                Ok(zip) => match zip {
                    Ok(og_file) => {
                        // println!("\nGot Password: {}", pass.bright_green());
                        got_pass = true;
                        og_file
                    },
                    Err(_) => {
                        // println!("trying: {}", pass.red());
                        break
                    }
                },
                Err(_) => {
                    println!("Couldnt get the file correctly!");
                    continue
                }
            };

            // Taken directly from: https://github.com/zip-rs/zip/blob/master/examples/extract.rs
            let outpath = match file.enclosed_name() {
                Some(path) => path.to_owned(),
                None => continue
            };

            // Starts extraction
            if (&*file.name()).ends_with("/") {
                println!("Folder");
                fs::create_dir_all(&outpath).unwrap();
            } else {
                if let Some(p) = outpath.parent() {
                    if !p.exists() {
                        fs::create_dir_all(&p).unwrap();
                    }
                }
                let mut outfile = fs::File::create(&outpath).unwrap();
                match io::copy(&mut file, &mut outfile) {
                    Ok(_) => {
                        possible_passes.push(pass);
                    },
                    Err(_) => {
                        got_pass = false;
                        continue
                    }
                }
            }
        }
    }
    println!("Possible Passwords: {}", possible_passes.join("\n").bright_green());
}

// for PDF files
fn ettup(filename: &str, pass_file_name: &str) -> () {
    let pass_file = fs::read_to_string(pass_file_name).unwrap();
    let pass_list: Vec<&str> = pass_file.split('\n').collect();
    let bar = ProgressBar::new(pass_list.len() as u64);

    for pass in pass_list.iter() {
        bar.inc(1);
        let f = File::open_password(filename, pass.as_bytes());

        match &f {
            Ok(_) => {
                bar.finish();
                println!("\nFound Password: {}", pass.bright_green());
                return ();
            },
            Err(_) => {}
        }
    }
    bar.finish();
    println!("Coundnt find password! :(");

    // TODO: pdf extraction
}

// For hashes
fn ettuh(query: &str, pass_list: &str) -> () {
    let pass_file = fs::read_to_string(pass_list).unwrap();
    let pass_list: Vec<&str> = pass_file.split('\n').collect();
    let bar = ProgressBar::new(pass_list.len() as u64);

    for pass in pass_list.iter() {
        bar.inc(1);
        // More hashes
        let pass_hash = match query.len() {
            32 => format!("{:x}", Md5::digest(pass.as_bytes())),
            40 => format!("{:x}", Sha1::digest(pass.as_bytes())),
            56 => format!("{:x}", Sha224::digest(pass.as_bytes())),
            64 => format!("{:x}", Sha256::digest(pass.as_bytes())),
            96 => format!("{:x}", Sha384::digest(pass.as_bytes())),
            128 => format!("{:x}", Sha512::digest(pass.as_bytes())),
            _ => "NULL".to_string()
        };

        if pass_hash == query[..] {
            bar.finish();
            println!("\nGot matching hash: {}", pass.bright_green());
            return ();
        } else if pass_hash == "NULL" {
            println!("{}", "No compatible hash found! :(".red());
            break
        } else {
            // bar.println(format!("trying: {}", pass.red()));
        }
    }
    bar.finish();
    println!("\nCouldnt find a match! :(");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        println!("{}", "Usage: bruttle <filename> <password_list>".bright_green());
        return ();
    }

    let file_or_hash = &args[1];
    let pass_list = &args[2];

    if file_or_hash.ends_with(".pdf") {
        ettup(file_or_hash, &pass_list);
    } else if file_or_hash.ends_with(".zip") {
        ettuz(file_or_hash, &pass_list);
    } else {
        ettuh(file_or_hash, &pass_list);
    }
}

