## DES

*DES algorithm implementation.*

for now we are just generating des encryption keys. we will add encryption and
decryption algorithm in the future.


### Quick Start

```console
$ go build
$ ./des -msg <your message here> 
```

providing a hex encryption key is optional, because the program can already
generate encryption key and it will be logged in the stdout.

```console
$ go build
$ ./des -msg <message here> -key <hex decimal key here>
```



### References

- https://paginas.fe.up.pt/~ei10109/ca/des.html



### Todo

- [X] encryption

- [ ] decryption
