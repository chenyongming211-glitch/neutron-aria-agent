use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};

use super::common::{err_response, AppState};
use crate::control_plane::ControlPlaneError;

pub async fn list_chains(State(cp): State<AppState>) -> impl IntoResponse {
    let chains = cp.list_chains().await;
    Json(aria_api::ServiceChainListResponse {
        chains: chains
            .into_iter()
            .map(|c| aria_api::ServiceChainEntry {
                name: c.name,
                description: c.description,
                hops: c
                    .hops
                    .into_iter()
                    .map(|h| aria_api::ServiceHopEntry {
                        name: h.name,
                        hop_type: format!("{:?}", h.hop_type).to_lowercase(),
                        taps: h
                            .taps
                            .into_iter()
                            .map(|t| aria_api::TapBindingEntry {
                                tap: t.tap,
                                role: format!("{:?}", t.role).to_lowercase(),
                            })
                            .collect(),
                    })
                    .collect(),
            })
            .collect(),
    })
}

pub async fn create_chain(
    State(cp): State<AppState>,
    Json(req): Json<aria_api::CreateServiceChainRequest>,
) -> impl IntoResponse {
    use crate::service_chain::{HopType, ServiceChain, ServiceHop, TapBinding, TapRole};

    let hops: Result<Vec<ServiceHop>, String> = req
        .hops
        .into_iter()
        .map(|h| {
            let hop_type = match h.hop_type.to_lowercase().as_str() {
                "bridge" => Ok(HopType::Bridge),
                "proxy" => Ok(HopType::Proxy),
                other => Err(format!(
                    "Invalid hop_type '{}': must be 'bridge' or 'proxy'",
                    other
                )),
            }?;
            let taps: Result<Vec<TapBinding>, String> = h
                .taps
                .into_iter()
                .map(|t| {
                    let role = match t.role.to_lowercase().as_str() {
                        "in" => Ok(TapRole::In),
                        "out" => Ok(TapRole::Out),
                        "bidirectional" | "bidi" => Ok(TapRole::Bidirectional),
                        other => Err(format!(
                            "Invalid tap role '{}': must be 'in', 'out', or 'bidirectional'",
                            other
                        )),
                    }?;
                    Ok(TapBinding { tap: t.tap, role })
                })
                .collect();
            Ok(ServiceHop {
                name: h.name,
                hop_type,
                taps: taps?,
            })
        })
        .collect();

    let hops = match hops {
        Ok(h) => h,
        Err(e) => return Err(err_response(ControlPlaneError::ValidationError(e))),
    };

    let chain = ServiceChain {
        name: req.name.clone(),
        description: req.description,
        hops,
    };

    match cp.create_chain(chain).await {
        Ok(()) => Ok((
            StatusCode::CREATED,
            Json(aria_api::MessageResponse {
                message: format!("Service chain '{}' created", req.name),
            }),
        )),
        Err(e) => Err(err_response(e)),
    }
}

pub async fn get_chain(State(cp): State<AppState>, Path(name): Path<String>) -> impl IntoResponse {
    match cp.get_chain(&name).await {
        Ok(c) => Ok(Json(aria_api::ServiceChainEntry {
            name: c.name,
            description: c.description,
            hops: c
                .hops
                .into_iter()
                .map(|h| aria_api::ServiceHopEntry {
                    name: h.name,
                    hop_type: format!("{:?}", h.hop_type).to_lowercase(),
                    taps: h
                        .taps
                        .into_iter()
                        .map(|t| aria_api::TapBindingEntry {
                            tap: t.tap,
                            role: format!("{:?}", t.role).to_lowercase(),
                        })
                        .collect(),
                })
                .collect(),
        })),
        Err(e) => Err(err_response(e)),
    }
}

pub async fn delete_chain(
    State(cp): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    match cp.delete_chain(&name).await {
        Ok(()) => Ok(Json(aria_api::MessageResponse {
            message: format!("Deleted service chain '{}'", name),
        })),
        Err(e) => Err(err_response(e)),
    }
}
