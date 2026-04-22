//! `agentsso.policy.enforce(request) -> Promise<Decision>`.
//!
//! Plugin pattern-matches on `result.decision`:
//!
//! - `{decision: "allow"}` — allowed
//! - `{decision: "prompt", policyName, ruleId}` — operator approval needed
//! - `{decision: "deny", policyName, ruleId, deniedScope?, deniedResource?}` — denied
//!
//! `policyName` in the request defaults to the calling agent's bound
//! policy ([`HostServices::current_agent_policy_name`]). Plugins
//! pass it explicitly only when running speculative checks (e.g. a
//! scaffolder's "what would policy X say about request Y?" preview).
//!
//! Never throws on a Deny outcome — Deny is a returned VALUE, not a
//! thrown error. Only structural failures (policy engine missing,
//! invalid request shape) produce an `AgentssoError`.

use rquickjs::function::{Func, MutFn};
use rquickjs::{Ctx, Object, Value};

use crate::PluginError;
use crate::host_api::services::{DecisionDesc, HostApiErrorCode, HostCode, PolicyEvalReq};
use crate::host_api::{HostApiError, HostServices, wrap_in_promise};

/// Install `agentsso.policy.enforce` on the provided namespace.
///
/// **AD2 (Story 6.2 course-correction 2026-04-17):** the method
/// returns a real Promise via `wrap_in_promise`. Deny outcomes
/// resolve (Deny is a value, not a rejection); structural failures
/// reject with `AgentssoError`.
pub fn register<'js>(
    ctx: &Ctx<'js>,
    agentsso: &Object<'js>,
    services: std::sync::Arc<dyn HostServices>,
) -> Result<(), PluginError> {
    let policy = Object::new(ctx.clone())?;

    let closure = move |ctx: Ctx<'js>, request: Value<'js>| -> rquickjs::Result<Value<'js>> {
        // Convert the JS request object into a `PolicyEvalReq`. The
        // expected shape is `{scope: string, resource?: string,
        // policyName?: string}`. Anything else rejects via Promise.
        let request_obj = match request.into_object() {
            Some(obj) => obj,
            None => {
                return wrap_in_promise(
                    &ctx,
                    Err(HostApiError::new(
                        HostApiErrorCode::Host(HostCode::PolicyEvalFailed),
                        false,
                        "agentsso.policy.enforce requires an object argument",
                    )),
                );
            }
        };

        let scope: String = match request_obj.get::<_, Option<String>>("scope") {
            Ok(Some(s)) if !s.is_empty() => s,
            _ => {
                return wrap_in_promise(
                    &ctx,
                    Err(HostApiError::new(
                        HostApiErrorCode::Host(HostCode::PolicyEvalFailed),
                        false,
                        "agentsso.policy.enforce request must have a non-empty `scope` field",
                    )),
                );
            }
        };
        let resource: Option<String> =
            request_obj.get::<_, Option<String>>("resource").unwrap_or(None);
        let policy_name_opt: Option<String> =
            request_obj.get::<_, Option<String>>("policyName").unwrap_or(None);

        let policy_name = policy_name_opt
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| services.current_agent_policy_name());

        let req = PolicyEvalReq { policy_name, scope, resource };
        let result: Result<Value<'js>, HostApiError> = match services.evaluate_policy(req) {
            Ok(decision) => match decision_to_js(&ctx, decision) {
                Ok(value) => Ok(value),
                Err(rquickjs_err) => Err(HostApiError::new(
                    HostApiErrorCode::Host(HostCode::PolicyEvalFailed),
                    false,
                    format!("policy decision marshalling failed: {rquickjs_err}"),
                )),
            },
            Err(host_err) => Err(host_err),
        };
        wrap_in_promise(&ctx, result)
    };
    policy.set("enforce", Func::from(MutFn::new(closure)))?;
    agentsso.set("policy", policy)?;
    Ok(())
}

/// Marshal a `DecisionDesc` into a JS object matching the shape
/// documented at the top of this file.
fn decision_to_js<'js>(ctx: &Ctx<'js>, decision: DecisionDesc) -> rquickjs::Result<Value<'js>> {
    let obj = Object::new(ctx.clone())?;
    match decision {
        DecisionDesc::Allow => {
            obj.set("decision", "allow")?;
        }
        DecisionDesc::Prompt { policy_name, rule_id } => {
            obj.set("decision", "prompt")?;
            obj.set("policyName", policy_name)?;
            obj.set("ruleId", rule_id)?;
        }
        DecisionDesc::Deny { policy_name, rule_id, denied_scope, denied_resource } => {
            obj.set("decision", "deny")?;
            obj.set("policyName", policy_name)?;
            obj.set("ruleId", rule_id)?;
            // Always set the optional fields (even when None) so
            // `JSON.stringify` produces a deterministic output the
            // plugin can build on (AC #31). `null` is the JS-side
            // representation of `Option::None`.
            match denied_scope {
                Some(s) => obj.set("deniedScope", s)?,
                None => obj.set("deniedScope", Value::new_null(ctx.clone()))?,
            }
            match denied_resource {
                Some(r) => obj.set("deniedResource", r)?,
                None => obj.set("deniedResource", Value::new_null(ctx.clone()))?,
            }
        }
    }
    Ok(obj.into_value())
}
