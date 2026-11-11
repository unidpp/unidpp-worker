//! UniDPP on Cloudflare Workers (REARCH R12): the union surface of
//! the one deployment, native to the edge. The module goldens are
//! embedded verbatim and served byte-identically behind their
//! prefixes; the estate's core crates compile into this Worker as
//! libraries, so the algorithms — and the golden vectors that pin
//! them — are the same bytes the native binaries carry.

pub mod contract;

use worker::*;

fn yaml_headers() -> Headers {
    let headers = Headers::new();
    headers.set("content-type", "application/yaml").ok();
    headers
}

fn yaml_response(body: String) -> Result<Response> {
    Ok(Response::from_bytes(body.into_bytes())?.with_headers(yaml_headers()))
}

#[event(fetch)]
async fn fetch(req: Request, _env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();
    route(&req).await
}

async fn route(req: &Request) -> Result<Response> {
    let path = req.path().to_string();
    match path.as_str() {
        "/healthz" => Response::from_json(&serde_json::json!({"status": "ok"})),
        "/version" => Response::from_json(&serde_json::json!({
            "service": "unidpp",
            "version": env!("CARGO_PKG_VERSION"),
            "runtime": "cloudflare-workers",
        })),
        "/" => Response::from_json(
            &serde_json::to_value(contract::discovery_document())
                .expect("the discovery document serializes"),
        ),
        "/openapi.yaml" => yaml_response(contract::contract_yaml()),
        "/openapi.json" => Response::from_json(
            &serde_json::to_value(contract::union_contract())
                .expect("the union serializes"),
        ),
        _ => {
            for (name, _source, golden) in contract::MODULES {
                if let Some(rest) = path.strip_prefix(&format!("/{name}/")) {
                    match rest {
                        "healthz" => {
                            return Response::from_json(&serde_json::json!({"status": "ok"}))
                        }
                        "openapi.yaml" => return yaml_response(golden.to_string()),
                        _ => {}
                    }
                    break;
                }
            }
            Ok(Response::from_json(&serde_json::json!({"error": "no such path"}))?
                .with_status(404))
        }
    }
}

/// The estate's core, compiled into the Worker: a smoke of the same
/// algorithms the native binaries carry (the vector corpus replays
/// against these in CI as S1 completes).
pub fn core_is_loaded() -> bool {
    !unidpp_model::sha256(&[b"unidpp"]).hex().is_empty()
}
