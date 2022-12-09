# Veldora

A command-line program to bruteforce zips, pdfs and some popular hashes.<br />
This is basically a rust version of [bruttle](https://github.com/tamton-aquib/bruttle), but a lot faster.

### Installation:
> From AUR
```bash
yay -S veldora
```
> From source
```bash
cargo install veldora
```

### Usage:
```
veldora <file/hash> <password_list>
```

### Examples:
```sh
veldora "5f4dcc3b5aa765d61d8327deb882cf99" ./password_list.txt

veldora secure.zip ~/Downloads/password_list.txt

veldora secure.pdf ~/Downloads/password_list.txt
```
> Make sure `$HOME/.cargo/` is in path.

![veldora](https://user-images.githubusercontent.com/77913442/206756044-17d50402-7c5b-49e1-8047-acbc2c7dd288.gif)

### Notes:
* Get password lists from [here](https://github.com/kkrypt0nn/Wordlists)
* To create custom passlist, try: [cupp.py](https://github.com/Mebus/cupp)
* As always, not to be used for illegal purposes  : )

### TODOS:
- [x] Code cleaning and pretty error messages.
- [x] Add to crates.io
- [ ] Add support for other filetypes like rar.
- [ ] Add more hashtypes (bcrypt, whirpool, etc)
- [ ] Add tests for each.
- [ ] hash mode breaking for zip and pdf. (would get super fast)
- [ ] Solve unicode error when reading some password lists.
