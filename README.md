# Veldora

A command-line program to bruteforce zips, pdfs and some popular hashes.<br />
This is basically a rust version of [bruttle](https://github.com/tamton-aquib/bruttle), but a lot faster.

### Installation:
```sh
cargo install veldora
```

### Usage:
```
veldora <file/hash> <password_list>

# Examples:
veldora "5f4dcc3b5aa765d61d8327deb882cf99" ./password_list.txt
# OR
veldora secure.zip ~/Downloads/password_list.txt
# OR
veldora secure.pdf ~/Downloads/password_list.txt
```
> Make sure to add `$HOME/.cargo/` to path

### Notes:
* Get password lists from [here](https://github.com/kkrypt0nn/Wordlists)
* To create custom passlist, try: [cupp.py](https://github.com/Mebus/cupp)
* As always, not to be used for illegal purposes  : )

### TODOS:
- [x] Add to crates.io
- [x] Code cleaning.
- [x] Make error messages pretty.
- [ ] Add support for other filetypes like rar.
- [ ] hash mode breaking for zip and pdf. (super fast)
- [ ] Solve unicode error when reading some passowrd lists.
