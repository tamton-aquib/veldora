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
/// match ettuz(filename, password_list) {
///     Some(pass) => println!("Possible password: {}", pass),
///     None => println!("Couldn't get password!")
/// };
/// ```
pub fn ettuz(filename: &str, pass_list: &str) -> Option<String> {
    let zip_file = fs::File::open(filename).expect("Could not open the zip file.");
    let mut archive = ZipArchive::new(&zip_file).expect("Error Reading the zip file.");

    let pass_file = fs::read_to_string(pass_list).expect("Error on reading password file.");
    let pass_list: Vec<&str> = pass_file.lines().collect();

    let mut possible_passes: Vec<&str> = Vec::new();

    let bar = ProgressBar::new(pass_list.len() as u64);
    bar.set_style(
        ProgressStyle::default_bar().template(
            "{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] ({eta})",
        ),
    );

    for pass in pass_list {
        bar.inc(1);
        match archive.by_index_decrypt(0, pass.as_bytes()) {
            Ok(file) => match file {
                Ok(_) => {
                    possible_passes.push(pass);
                }
                Err(_) => continue,
            },
            Err(_) => panic!("Error reading zipfile"),
        };

        // // TODO: add check for sanity
        // possible_passes.push(pass);
        // }
        // Err(_) => continue,
        // };
        // }
        // Err(_) => continue,
        // };
    }
    // None

    bar.finish();
    if possible_passes.len() > 0 {
        Some(possible_passes.join("\n"))
    } else {
        None
    }
}
