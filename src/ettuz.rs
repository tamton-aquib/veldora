//! # Zip bruteforcing module
//!
//! For bruteforcing encrypted zip files.
use indicatif::{ProgressBar, ProgressStyle};
use std::fs;
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
    let zip_file = fs::File::open(filename).expect("Could not open the zip file.");
    let mut archive = ZipArchive::new(&zip_file).expect("Error Reading the zip file.");

    let pass_file = fs::read_to_string(pass_list).expect("Error on reading password file.");
    let pass_list: Vec<&str> = pass_file.split('\n').collect();
    // let bar = ProgressBar::new(pass_list.len() as u64);
    // bar.set_style(
    // ProgressStyle::default_bar().template(
    // "{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] ({eta})",
    // ),
    // );

    let mut got_pass: bool = false;
    let mut possible_passes: Vec<&str> = Vec::new();

    for pass in pass_list {
        // bar.inc(1);
        if got_pass {
            // bar.finish();
            break;
        }

        match archive.by_index_decrypt(0, pass.as_bytes()) {
            Ok(zip) => {
                match zip {
                    Ok(_) => {
                        // got_pass = true;
                        // TODO: add check for sanity
                        possible_passes.push(pass);
                    }
                    Err(_) => continue,
                };
            }
            Err(_) => continue,
        };

        // TODO: extraction logic
        // Taken directly from: https://github.com/zip-rs/zip/blob/master/examples/extract.rs
        // let outpath = match file.enclosed_name() {
        // Some(path) => path.to_owned(),
        // None => continue,
        // };

        // Starts extraction
        // if (&*file.name()).ends_with("/") {
        // fs::create_dir_all(&outpath).unwrap();
        // } else {
        // if let Some(p) = outpath.parent() {
        // if !p.exists() {
        // fs::create_dir_all(&p).unwrap();
        // }
        // }
        // let mut outfile = fs::File::create(&outpath).unwrap();
        // match io::copy(&mut file, &mut outfile) {
        // Ok(_) => {
        // possible_passes.push(pass);
        // }
        // Err(_) => {
        // got_pass = false;
        // continue;
        // }
        // }
        // }
        // }
    }

    if possible_passes.len() > 0 {
        Some(possible_passes.join("\n"))
    } else {
        None
    }
}
