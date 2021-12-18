# Veldora

A command-line program to bruteforce zips, pdfs and some popular hashes.<br />
This is basically a rust version of [bruttle](https://github.com/tamton-aquib/bruttle), but a lot faster.

### Installation:
```sh
git clone https://github.com/tamton-aquib/veldora.git
cd veldora
cargo build
```

### Usage:
```
cargo run <file/hash> <password_list>

# Examples:
cargo run "5f4dcc3b5aa765d61d8327deb882cf99" ./password_list.txt
# OR
cargo run secure.zip ~/Downloads/password_list.txt
# OR
cargo run secure.pdf ~/Downloads/password_list.txt
```

### Notes:
* You could move the binary from `target/debug/veldora` to your `$PATH`. <br />
This will allow us to use binary name anywhere instead of `cargo run`.
* Get password lists from [here](https://github.com/kkrypt0nn/Wordlists)
* To create custom passlist, try: [cupp.py](https://github.com/Mebus/cupp)
* As always, not to be used for illegal purposes  : )

### TODOS:
- [ ] Code cleaning.
- [ ] Add support for other filetypes like rar.
- [ ] hash mode breaking for zip and pdf.
- [ ] Make error messages pretty.
