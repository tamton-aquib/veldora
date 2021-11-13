# Veldora

A program to bruteforce zips, pdf and some popular hashes. 

### Installation:
```sh
git clone https://github.com/tamton-aquib/veldora.git
cd veldora
cargo build
```

### Usage:
```
cargo run <filename> <password_list>

# Example:
cargo run "5f4dcc3b5aa765d61d8327deb882cf99" ./password_list.txt
# OR
cargo run secure.zip ~/Downloads/password_list.txt
# OR
cargo run secure.pdf ~/Downloads/password_list.txt
```
or the same with binaries inside `target/debug/`

### TODOS:
- [ ] Code cleaning.
- [ ] Add support for other filetypes like rar, etc.

