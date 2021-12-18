//! # Zip bruteforcing module
//!
//! For bruteforcing encrypted zip files.
use indicatif::ProgressBar;
use std::{fs, io};
use zip::ZipArchive;

// For ZIP files
/// Bruteforces the password for a zip file.
///
/// # Examples
///
/// ```
/// use veldora::ettuz;
///
/// ... rest of your code.
/// match ettuz(filename, password_list) {
///     Some(pass) => println!("Possible password: {}", pass),
///     None => println!("Couldn't get password!")
/// };
/// ```
pub fn ettuz(filename: &str, pass_list: &str) -> Option<String> {
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
                        got_pass = true;
                        og_file
                    }
                    Err(_) => break,
                },
                Err(_) => {
                    println!("Couldnt get the file correctly!");
                    continue;
                }
            };

            // Taken directly from: https://github.com/zip-rs/zip/blob/master/examples/extract.rs
            let outpath = match file.enclosed_name() {
                Some(path) => path.to_owned(),
                None => continue,
            };

            // Starts extraction
            if (&*file.name()).ends_with("/") {
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
                    }
                    Err(_) => {
                        got_pass = false;
                        continue;
                    }
                }
            }
        }
    }

    if possible_passes.len() > 0 {
        Some(possible_passes.join("\n"))
    } else {
        None
    }
}
