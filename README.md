# hyperdav-server [![](http://meritbadge.herokuapp.com/hyperdav-server)](https://crates.io/crates/hyperdav-server) [![](https://docs.rs/hyperdav-server/badge.svg)](https://docs.rs/hyperdav-server)
Basic WebDAV server as a hyper server handler.

Important: This makes no attempt at security and is not suitable for running
directly on a machine containing any sensitive resources. The server will
follow symlinks and can serve paths outside of the specified root directory.
There are also no access controls and the server supports write operations like
truncating PUT and DELETE.

The current intended use case is to add file access Rust to projects that are
already running a hyper server, such as embedded devices. As this would be a
debug-only feature, access controls are non-existent.

Adding configurability and supporting more of [RFC 4918](https://tools.ietf.org/html/rfc4918)
could be done. Patches welcome.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
