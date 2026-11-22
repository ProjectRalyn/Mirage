# web-mirage

**Embeddable zero-copy HTTP deception & tarpit Tower middleware for Rust (Axum / Hyper / Tower).**

Part of the [Mirage](https://github.com/ProjectRalyn/Mirage) project.

`web-mirage` turns any Rust HTTP service into an asymmetric deception honeypot with a single `.layer(MirageHttpLayer::new(engine))`:
- **Near-zero overhead on benign traffic**: Powered by [`sigil-filter`](https://crates.io/crates/sigil-filter) (~85 ns benign fast-path) and pre-baked `bytes::Bytes` snapshots.
- **Scheduled persona rotation**: Automatically rotates fake `.env`, WordPress (`/wp-login.php`, `/wp-json/wp/v2/users`, `/wp-config.php.bak`), GraphQL/OpenAPI schemas, SQLMap blind-injection targets, AWS IMDSv1 SSRF responses, and 256 MiB slow-drip `/actuator/heapdump` tarpits.
- **Multiple topologies**: Embed in-process via `MirageHttpLayer`, run as a `FrontlineProxy`, or deploy as a `BehindProxySink` behind Nginx/Caddy/WAF.

## Quick Start

```toml
[dependencies]
web-mirage = "0.1"
```

```rust
use axum::{routing::get, Router};
use web_mirage::{MirageConfig, MirageEngine, MirageHttpLayer};

#[tokio::main]
async fn main() {
    let engine = MirageEngine::new(MirageConfig::default());
    engine.spawn_rotation_task();

    let app = Router::new()
        .route("/api/health", get(|| async { "OK" }))
        .layer(MirageHttpLayer::new(engine));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```
