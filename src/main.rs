//! Thin process entry point for Reproit Cloud.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    reproit_cloud::run().await
}
