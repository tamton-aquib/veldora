use pdf::file::File;
use indicatif::ProgressBar;
use std::fs;

// for PDF files
pub fn ettup(filename: &str, pass_file_name: &str) -> Option<String> {
    let pass_file = fs::read_to_string(pass_file_name)
        .expect("COULDN'T OPEN PASSWORD FILE");
    let pass_list: Vec<&str> = pass_file.split('\n').collect();
    let bar = ProgressBar::new(pass_list.len() as u64);

    for pass in pass_list.iter() {
        bar.inc(1);
        let f = File::open_password(filename, pass.as_bytes());

        match &f {
            Ok(_) => {
                bar.finish();
                return Some(
                    format!("\nFound Password: {}", pass)
                );
            },
            Err(_) => {}
        };
    }
    bar.finish();
    None
}
