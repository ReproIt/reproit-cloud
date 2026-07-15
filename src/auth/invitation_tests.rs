use crate::db::ControlStore;
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;

fn admin_url() -> String {
    std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://reproit:reproit@localhost:5433/postgres".into())
}
fn with_db(url: &str, db: &str) -> String {
    let (base, q) = url
        .split_once('?')
        .map_or((url, None), |(b, q)| (b, Some(q)));
    let idx = base.rfind('/').unwrap_or(base.len());
    let out = format!("{}/{}", &base[..idx], db);
    q.map_or(out.clone(), |q| format!("{out}?{q}"))
}
async fn drop_db(admin: &sqlx::PgPool, name: &str) {
    let _ = sqlx::query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1")
        .bind(name)
        .execute(admin)
        .await;
    let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS \"{name}\""))
        .execute(admin)
        .await;
}

#[tokio::test]
async fn active_org_and_invitation_lifecycle_are_exact() {
    let admin = match PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(3))
        .connect(&admin_url())
        .await
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("SKIP active_org_and_invitation_lifecycle_are_exact: {e}");
            return;
        }
    };
    let db = format!("reproit_selfhost_invites_{}", std::process::id());
    drop_db(&admin, &db).await;
    sqlx::query(&format!("CREATE DATABASE \"{db}\""))
        .execute(&admin)
        .await
        .unwrap();
    let result = async {
        let s = ControlStore::connect(&with_db(&admin_url(), &db)).await?;
        let owner = s.create_user("owner@example.test", "x").await?;
        let personal = s.create_org("Personal", true).await?;
        let org = s.create_org("Acme", false).await?;
        s.add_member(personal, owner, "owner").await?;
        s.add_member(org, owner, "owner").await?;
        s.create_session("owner-session", owner, 3600).await?;
        anyhow::ensure!(
            s.user_and_org_for_session("owner-session")
                .await?
                .unwrap()
                .1
                .id
                == personal
        );
        anyhow::ensure!(!s.set_session_org("owner-session", owner, org + 99).await?);
        anyhow::ensure!(s.set_session_org("owner-session", owner, org).await?);
        anyhow::ensure!(
            s.user_and_org_for_session("owner-session")
                .await?
                .unwrap()
                .1
                .id
                == org
        );
        let dev = s.create_user("dev@example.test", "x").await?;
        s.create_session("dev-session", dev, 3600).await?;
        let t1 = "1111111111111111111111111111111111111111111111111111111111111111";
        let id = s
            .upsert_org_invitation(
                org,
                "dev@example.test",
                "member",
                true,
                owner,
                t1,
                3600,
                None,
            )
            .await?
            .unwrap();
        anyhow::ensure!(s.list_org_invitations(org).await?.len() == 1);
        let t2 = "2222222222222222222222222222222222222222222222222222222222222222";
        s.refresh_org_invitation(org, id, t2, 3600).await?.unwrap();
        anyhow::ensure!(s.org_invitation_by_token(t1).await?.is_none());
        anyhow::ensure!(s
            .accept_org_invitation(t2, dev, "wrong@example.test")
            .await?
            .is_none());
        anyhow::ensure!(s.accept_org_invitation(t2, dev, "dev@example.test").await? == Some(org));
        anyhow::ensure!(s.has_seat(org, dev).await?);
        anyhow::ensure!(s.set_session_org("dev-session", dev, org).await?);
        anyhow::ensure!(
            s.user_and_org_for_session("dev-session")
                .await?
                .unwrap()
                .1
                .id
                == org
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    drop_db(&admin, &db).await;
    result.unwrap();
}
