# npmcheck
checks node module versions oder modules installed in `./node_modules` against list provided in `compromised.txt`

### Building

1) check out the repository
2) build using

   `GOOS=<os> GOARCH=<arch> go build`
   
   with
   
   `os` being either `DARWIN` or `LINUX`
   `arch` being either `amd64` or `arm64`
   
### Running

1) Make sure you have a populated `compromised.txt`
2) Execute

   `./npmcheck <target dir>``

If you omit `<target dir>` the programm will use the current directory.