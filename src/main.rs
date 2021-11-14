use md5::{Md5, Digest};
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};

use std::{env, fs, io};
use pdf::file::File;
use colored::Colorize;
use zip::ZipArchive;

// For ZIP files
fn ettuz(filename: &str, pass_list: &str) -> () {
    let zip_file = fs::File::open(filename).unwrap();
    let mut archive = ZipArchive::new(&zip_file).unwrap();

    let pass_file = fs::read_to_string(pass_list).unwrap();
    let pass_list: Vec<&str> = pass_file.split('\n').collect();
    let mut got_pass: bool = false;

    for pass in pass_list {
        if got_pass { break }

        for idx in 0..archive.len() {
            let mut file = match archive.by_index_decrypt(idx, pass.as_bytes()) {
                Ok(zip) => match zip {
                    Ok(og_file) => {
                        println!("Got Password: {}", pass.bright_green());
                        got_pass = true;
                        og_file
                        // break
                    },
                    Err(_) => {
                        println!("trying: {}", pass.red());
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
                io::copy(&mut file, &mut outfile).unwrap();
            }
        }
    }
}

// for PDF files
fn ettup(filename: &str, pass_file_name: &str) -> () {
    let pass_file = fs::read_to_string(pass_file_name).unwrap();
    let pass_list: Vec<&str> = pass_file.split('\n').collect();

    for pass in pass_list.iter() {
        let f = File::open_password(filename, pass.as_bytes());

        match &f {
            Ok(_) => {
                println!("Found Password: {}", pass.bright_green());
                break
            },
            Err(_) => println!("trying: {}", pass.red())
        }
    }

    // TODO: pdf extraction
}

// For hashes
fn ettuh(query: &str, pass_list: &str) -> () {
    let pass_file = fs::read_to_string(pass_list).unwrap();
    let pass_list: Vec<&str> = pass_file.split('\n').collect();

    for pass in pass_list.iter() {
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

        if pass_hash == query {
            println!("Got matching hash: {}", pass.bright_green());
            break
        } else if pass_hash == "NULL" {
            println!("{}", "No compatible hash found! :(".red());
            break
        } else {
            println!("trying: {}", pass.red());
        }
    }
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

