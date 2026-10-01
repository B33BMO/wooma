//! The http tab: request a URL, following redirects, timing every hop.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::runtime::Handle;

use super::http::{self, Request, Response, Url};

const MAX_REDIRECTS: usize = 8;

#[derive(Debug)]
pub struct HttpCheck {
    pub input: String,
    pub finished: Option<Instant>,
    /// Each request in the redirect chain.
    pub hops: Vec<(Url, Result<Response, String>)>,
}

impl HttpCheck {
    pub fn last_ok(&self) -> Option<(&Url, &Response)> {
        self.hops.iter().rev().find_map(|(u, r)| r.as_ref().ok().map(|r| (u, r)))
    }
}

pub fn start(rt: &Handle, input: &str) -> Arc<Mutex<HttpCheck>> {
    let state = Arc::new(Mutex::new(HttpCheck {
        input: input.trim().to_string(),
        finished: None,
        hops: vec![],
    }));
    let st = state.clone();
    let input = input.trim().to_string();
    rt.spawn(async move {
        let mut url = match Url::parse(&input) {
            Ok(u) => u,
            Err(e) => {
                let mut s = st.lock().unwrap();
                s.hops.push((Url { https: true, host: input.clone(), port: 443, path: "/".into() }, Err(e.to_string())));
                s.finished = Some(Instant::now());
                return;
            }
        };
        for _ in 0..=MAX_REDIRECTS {
            let mut req = Request::get(url.clone());
            req.lenient = true;
            req.keep_body = 256 * 1024;
            let result = http::send(req).await.map_err(|e| format!("{e:#}"));
            let next = result.as_ref().ok().and_then(|r| {
                (300..400).contains(&r.status).then(|| r.header("location")).flatten().and_then(|l| url.join(l).ok())
            });
            st.lock().unwrap().hops.push((url.clone(), result));
            match next {
                Some(n) => url = n,
                None => break,
            }
        }
        st.lock().unwrap().finished = Some(Instant::now());
    });
    state
}
