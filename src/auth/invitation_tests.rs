//! Postgres-backed organization, session selection, and invitation contract.

use crate::db::ControlStore;
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;

fn admin_url() -> String {
    std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://reproit:reproit@localhost:5433/postgres".to_string())
}

fn with_db(url: &str, db: &str) -> String {
    let (base, query) = url
        .split_once('?')
        .map_or((url, None), |(b, q)| (b, Some(q)));
    let idx = base.rfind('/').unwrap_or(base.len());
    let out = format!("{}/{}", &base[..idx], db);
    query.map_or(out.clone(), |q| format!("{out}?{q}"))
}

async fn drop_db(admin: &sqlx::PgPool, name: &str) {
    let _ =
        sqlx::query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1")
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
        Ok(pool) => pool,
        Err(e) => {
            eprintln!("SKIP active_org_and_invitation_lifecycle_are_exact: {e}");
            return;
        }
    };
    let db_name = format!("reproit_it_invites_{}", std::process::id());
    drop_db(&admin, &db_name).await;
    sqlx::query(&format!("CREATE DATABASE \"{db_name}\""))
        .execute(&admin)
        .await
        .expect("create test db");

    let result = async {
        let store = ControlStore::connect(&with_db(&admin_url(), &db_name)).await?;
        let owner = store.create_user("owner@example.test", "x").await?;
        let personal = store.create_org("Personal", true).await?;
        let acme = store.create_org("Acme", false).await?;
        store.add_member(personal, owner, "owner").await?;
        store.add_member(acme, owner, "owner").await?;
        store.create_session("owner-session", owner, 3600).await?;

        let (_, initial) = store
            .user_and_org_for_session("owner-session")
            .await?
            .expect("live session");
        anyhow::ensure!(initial.id == personal, "a new session starts in Personal");
        anyhow::ensure!(
            !store
                .set_session_org("owner-session", owner, acme + 100)
                .await?,
            "a non-member org must be rejected"
        );
        anyhow::ensure!(store.set_session_org("owner-session", owner, acme).await?);
        let (_, active) = store
            .user_and_org_for_session("owner-session")
            .await?
            .expect("active org");
        anyhow::ensure!(active.id == acme, "the selected organization must resolve");
        anyhow::ensure!(store.list_user_orgs(owner).await?.len() == 2);

        let invitee = store.create_user("dev@example.test", "x").await?;
        store
            .create_session("invitee-session", invitee, 3600)
            .await?;
        anyhow::ensure!(
            store
                .user_and_org_for_session("invitee-session")
                .await?
                .is_none(),
            "a user with no membership has no accidental tenant"
        );

        let token1 = "1111111111111111111111111111111111111111111111111111111111111111";
        let id = store
            .upsert_org_invitation(
                acme,
                "dev@example.test",
                "member",
                true,
                owner,
                token1,
                3600,
                Some(2),
            )
            .await?
            .expect("owner plus one reserved seat fits");
        anyhow::ensure!(store.list_org_invitations(acme).await?.len() == 1);
        let blocked = store
            .upsert_org_invitation(
                acme,
                "second@example.test",
                "member",
                true,
                owner,
                "2222222222222222222222222222222222222222222222222222222222222222",
                3600,
                Some(2),
            )
            .await?;
        anyhow::ensure!(blocked.is_none(), "pending seats must enforce the cap");

        let token2 = "3333333333333333333333333333333333333333333333333333333333333333";
        store
            .refresh_org_invitation(acme, id, token2, 3600)
            .await?
            .expect("refresh");
        anyhow::ensure!(store.org_invitation_by_token(token1).await?.is_none());
        anyhow::ensure!(store.org_invitation_by_token(token2).await?.is_some());
        anyhow::ensure!(
            store
                .accept_org_invitation(token2, invitee, "wrong@example.test")
                .await?
                .is_none(),
            "the verified email must match"
        );
        anyhow::ensure!(store.org_invitation_by_token(token2).await?.is_some());
        anyhow::ensure!(
            store
                .accept_org_invitation(token2, invitee, "dev@example.test")
                .await?
                == Some(acme)
        );
        anyhow::ensure!(
            store.has_seat(acme, invitee).await?,
            "reserved seat transfers"
        );
        anyhow::ensure!(
            store.org_invitation_by_token(token2).await?.is_none(),
            "single use"
        );
        anyhow::ensure!(
            store
                .set_session_org("invitee-session", invitee, acme)
                .await?
        );
        let (_, joined) = store
            .user_and_org_for_session("invitee-session")
            .await?
            .expect("joined org");
        anyhow::ensure!(joined.id == acme);

        let expired = "4444444444444444444444444444444444444444444444444444444444444444";
        store
            .upsert_org_invitation(
                acme,
                "expired@example.test",
                "member",
                false,
                owner,
                expired,
                -1,
                None,
            )
            .await?
            .expect("write expired fixture");
        anyhow::ensure!(store.org_invitation_by_token(expired).await?.is_none());
        anyhow::ensure!(store.prune_org_invitations().await? >= 1);
        Ok::<_, anyhow::Error>(())
    }
    .await;

    drop_db(&admin, &db_name).await;
    result.expect("organization invitation contract");
}
