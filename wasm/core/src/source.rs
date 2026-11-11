// The passport carrier for the included gateway render modules (see
// lib.rs). The gateway's own source.rs is the loopback/issuer HTTP
// client — on the estate the passport and the profile layer ride the
// issuer and registry Durable Objects, so this module carries only
// the shape the render modules read. Same field names, same meaning;
// the transport stays on the TS side.

use std::collections::HashMap;

use unidpp_cli::passport::Passport;
use unidpp_model::Timestamp;

use crate::verdict::PublicKeyMaterial;

/// Where the rendered passport came from (the triad's `source`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Fixture,
    Issuer,
}

impl Origin {
    pub fn as_str(self) -> &'static str {
        match self {
            Origin::Fixture => "fixture",
            Origin::Issuer => "issuer",
        }
    }
}

/// A profile bound to the passport: id + version + effective window.
#[derive(Debug, Clone, PartialEq)]
pub struct ProfileRef {
    pub id: String,
    pub version: String,
    pub effective_from: Option<Timestamp>,
}

/// A passport ready to render: the document plus the profile layer
/// and (issuer mode) the pinned anchors.
#[derive(Debug, Clone)]
pub struct GatewayPassport {
    pub document: Passport,
    pub profiles: Vec<ProfileRef>,
    pub origin: Origin,
    /// Trust anchors by key id (issuer keyring; empty for fixtures,
    /// whose documents carry no event signatures).
    pub anchors: HashMap<String, PublicKeyMaterial>,
}
