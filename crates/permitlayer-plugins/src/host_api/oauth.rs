//! `agentsso.oauth.*` — OAuth scoped-token issuance and service
//! enumeration.
//!
//! - `agentsso.oauth.getToken(service, scope) -> Promise<ScopedTokenHandle>`
//!   Returns a Promise that resolves to a `{bearer, scope, resource,
//!   expiresAt}` object — the bearer is a 60-second HS256 scoped
//!   token the plugin then attaches to `agentsso.http.fetch` calls.
//!   The plugin **never** sees the raw upstream OAuth token — that's
//!   the load-bearing AR29 invariant tested at
//!   `tests/host_api_surface.rs::oauth_get_token_does_not_leak_raw_oauth_material_anywhere`.
//! - `agentsso.oauth.listConnectedServices() -> Promise<string[]>`
//!   Read-only enumeration of services with vault credentials.
//!
//! **AD2 (Story 6.2 course-correction 2026-04-17 — uniform Promise-shape
//! model):** both methods return real Promises (via `wrap_in_promise`),
//! not plain Objects. `result instanceof Promise === true`; `.then()`
//! and `.catch()` chain idiomatically; `Promise.all([...])` works.

use rquickjs::function::{Func, MutFn, Opt};
use rquickjs::{Ctx, Object, Value};

use crate::PluginError;
use crate::host_api::services::{HostApiErrorCode, HostCode};
use crate::host_api::{HostApiError, HostServices, wrap_in_promise};

/// Install the `agentsso.oauth.*` namespace.
pub fn register<'js>(
    ctx: &Ctx<'js>,
    agentsso: &Object<'js>,
    services: std::sync::Arc<dyn HostServices>,
) -> Result<(), PluginError> {
    let oauth = Object::new(ctx.clone())?;

    install_get_token(ctx, &oauth, std::sync::Arc::clone(&services))?;
    install_list_connected_services(ctx, &oauth, services)?;

    agentsso.set("oauth", oauth)?;
    Ok(())
}

fn install_get_token<'js>(
    _ctx: &Ctx<'js>,
    oauth: &Object<'js>,
    services: std::sync::Arc<dyn HostServices>,
) -> Result<(), PluginError> {
    let closure = move |ctx: Ctx<'js>,
                        service: Opt<String>,
                        scope: Opt<String>|
          -> rquickjs::Result<Value<'js>> {
        // Validate `service` argument early — undefined / empty
        // string rejects via the Promise.
        let service_str = match service.0 {
            Some(s) if !s.is_empty() => s,
            _ => {
                return wrap_in_promise(
                    &ctx,
                    Err(HostApiError::new(
                        HostApiErrorCode::Host(HostCode::OauthUnknownService),
                        false,
                        "agentsso.oauth.getToken requires a non-empty `service` argument",
                    )),
                );
            }
        };
        let scope_str = match scope.0 {
            Some(s) if !s.is_empty() => s,
            _ => {
                return wrap_in_promise(
                    &ctx,
                    Err(HostApiError::new(
                        HostApiErrorCode::Host(HostCode::OauthScopeRequired),
                        false,
                        "agentsso.oauth.getToken requires a non-empty `scope` argument (1.0 \
                         requires explicit scope)",
                    )),
                );
            }
        };

        let result = match services.issue_scoped_token(&service_str, &scope_str) {
            Ok(token) => {
                let obj = Object::new(ctx.clone())?;
                obj.set("bearer", token.bearer)?;
                obj.set("scope", token.scope)?;
                obj.set("resource", token.resource)?;
                // JS represents large integers as f64 — epoch
                // seconds fits comfortably in 53 bits until year
                // 285_428_751 AD, so the cast is lossless for any
                // realistic timestamp.
                obj.set("expiresAt", token.expires_at_epoch_secs as f64)?;
                Ok(obj.into_value())
            }
            Err(host_err) => Err(host_err),
        };
        wrap_in_promise(&ctx, result)
    };
    oauth.set("getToken", Func::from(MutFn::new(closure)))?;
    Ok(())
}

fn install_list_connected_services<'js>(
    _ctx: &Ctx<'js>,
    oauth: &Object<'js>,
    services: std::sync::Arc<dyn HostServices>,
) -> Result<(), PluginError> {
    let closure = move |ctx: Ctx<'js>| -> rquickjs::Result<Value<'js>> {
        let result = match services.list_connected_services() {
            Ok(list) => {
                let arr = rquickjs::Array::new(ctx.clone())?;
                for (i, name) in list.into_iter().enumerate() {
                    arr.set(i, name)?;
                }
                Ok(arr.into_value())
            }
            Err(host_err) => Err(host_err),
        };
        wrap_in_promise(&ctx, result)
    };
    oauth.set("listConnectedServices", Func::from(MutFn::new(closure)))?;
    Ok(())
}
