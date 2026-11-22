use axum::{routing::get, Router};
use web_mirage::{MirageConfig, MirageEngine, MirageHttpLayer};

#[tokio::main]
async fn main() {
    let engine = MirageEngine::new(MirageConfig::default());
    // Spawn scheduled background payload rotation
    engine.spawn_rotation_task();

    let app = Router::new()
        .route("/api/health", get(|| async { "OK" }))
        .route(
            "/api/v1/items",
            get(|| async { r#"[{"id":1,"name":"real-item"}]"# }),
        )
        // One-line integration: attack probes get trapped, benign routes reach Axum handlers
        .layer(MirageHttpLayer::new(engine));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("Embedded Mirage + Axum listening on http://127.0.0.1:3000");
    axum::serve(listener, app).await.unwrap();
}
