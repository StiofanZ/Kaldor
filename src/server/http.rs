use super::*;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::Incoming,
    header::{CONNECTION, HOST, HeaderMap, HeaderValue},
};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::convert::Infallible;
type Body = UnsyncBoxBody<Bytes, hyper::Error>;
fn error(code: StatusCode, msg: &'static str) -> Response<Body> {
    let mut r = Response::new(
        Full::new(Bytes::from_static(msg.as_bytes()))
            .map_err(|never| match never {})
            .boxed_unsync(),
    );
    *r.status_mut() = code;
    r
}
fn strip(headers: &mut HeaderMap) {
    let extra: Vec<_> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|s| s.trim().to_owned())
        .collect();
    for name in extra {
        headers.remove(name);
    }
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}
async fn handle(mut req: Request<Incoming>, src: SocketAddr, s: Service) -> Result<Response<Body>> {
    let connect = req.method() == Method::CONNECT;
    let Some(auth) = req.uri().authority() else {
        return Ok(error(StatusCode::BAD_REQUEST, "missing authority"));
    };
    if !connect && req.uri().scheme_str() != Some("http") {
        return Ok(error(StatusCode::BAD_REQUEST, "absolute HTTP URL required"));
    }
    if auth.as_str().contains('@') || connect && auth.port_u16().is_none() {
        return Ok(error(StatusCode::BAD_REQUEST, "invalid authority"));
    }
    let host = auth.host().trim_matches(['[', ']']).to_string();
    let t = Target {
        host,
        port: auth.port_u16().unwrap_or(80),
    };
    let (mut up, session) = s.engine.tcp(src, &t, &t.host, "HTTP", None).await?;
    if connect {
        let upgrade = hyper::upgrade::on(&mut req);
        tokio::spawn(async move {
            let _session = session;
            if let Ok(c) = upgrade.await {
                let _ = tokio::io::copy_bidirectional(&mut TokioIo::new(c), &mut up).await;
            }
        });
        return Ok(error(StatusCode::OK, ""));
    }
    let host = HeaderValue::from_str(auth.as_str())?;
    let uri = req
        .uri()
        .path_and_query()
        .map_or("/", |v| v.as_str())
        .parse()?;
    *req.uri_mut() = uri;
    strip(req.headers_mut());
    req.headers_mut().insert(HOST, host);
    let (mut tx, conn) = hyper::client::conn::http1::handshake(TokioIo::new(up)).await?;
    tokio::spawn(async move {
        let _session = session;
        conn.await
    });
    let resp = timeout(Duration::from_secs(30), tx.send_request(req)).await??;
    let (mut parts, body) = resp.into_parts();
    strip(&mut parts.headers);
    Ok(Response::from_parts(parts, body.boxed_unsync()))
}
pub(super) async fn serve(c: TcpStream, src: SocketAddr, s: Service) -> Result<()> {
    let handler = hyper::service::service_fn(move |req| {
        let s = s.clone();
        async move {
            Ok::<_, Infallible>(
                handle(req, src, s)
                    .await
                    .unwrap_or_else(|_| error(StatusCode::BAD_GATEWAY, "upstream unavailable")),
            )
        }
    });
    hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
        .max_buf_size(32768)
        .serve_connection(TokioIo::new(c), handler)
        .with_upgrades()
        .await?;
    Ok(())
}
