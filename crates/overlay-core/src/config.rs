//! The `config.yaml` model. Every tunable the sidecar has lives here as a typed field with an
//! Appendix A default, so the rest of the code reads a struct and never a key name. The file is
//! pushed to every host by configuration management, so an unknown or removed key fails loudly
//! at startup instead of silently taking a default.
