macaroon-shop
====

Macaroons are a form of bearer credential with the special property that the
holder of the credential can _attenuate_ the macaroon by adding contextual
restrictions.  For more details on the macaroon construction, see [this paper][1].


## Compatibility

Our implemention is compatible with the Go package [go-macaroons][2] using the
same cryptographic primitives, serialization format, and validity test.


[1]: http://theory.stanford.edu/~ataly/Papers/macaroons.pdf
[2]: https://github.com/go-macaroon/macaroon
