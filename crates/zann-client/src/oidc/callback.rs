use super::*;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

/// The caller chooses a platform transport explicitly, before preparation.
pub enum OidcCallback {
    Loopback,
    Application { redirect_uri: String },
}

pub(super) struct CallbackTransport {
    uri: Url,
    listener: Option<TcpListener>,
}

impl CallbackTransport {
    pub(super) fn new(callback: OidcCallback) -> Result<Self, OidcBrowserError> {
        match callback {
            OidcCallback::Loopback => {
                let listener = TcpListener::bind("127.0.0.1:0").map_err(transport)?;
                listener.set_nonblocking(true).map_err(transport)?;
                let port = listener.local_addr().map_err(transport)?.port();
                let uri = Url::parse(&format!("http://127.0.0.1:{port}/oidc/callback"))
                    .map_err(protocol)?;
                Ok(Self {
                    uri,
                    listener: Some(listener),
                })
            }
            OidcCallback::Application { redirect_uri } => {
                let uri = application_redirect(&redirect_uri)?;
                Ok(Self {
                    uri,
                    listener: None,
                })
            }
        }
    }

    pub(super) fn redirect_uri(&self) -> &Url {
        &self.uri
    }

    pub(super) async fn receive(
        &self,
        operation: &SessionOperation,
        state: &str,
    ) -> Result<Callback, OidcBrowserError> {
        let listener = self
            .listener
            .as_ref()
            .ok_or_else(|| OidcBrowserError::new(OidcBrowserErrorKind::Configuration))?
            .try_clone()
            .map_err(transport)?;
        let expected = self.uri.clone();
        let state = Zeroizing::new(state.to_owned());
        let operation = operation.detached_copy();
        tokio::task::spawn_blocking(move || {
            wait_for_callback(listener, &expected, &state, &operation)
        })
        .await
        .map_err(transport)?
    }

    pub(super) fn application_callback(&self, uri: String) -> Result<Callback, OidcBrowserError> {
        if self.listener.is_some() {
            return Err(OidcBrowserError::new(OidcBrowserErrorKind::Configuration));
        }
        let uri = Zeroizing::new(uri);
        parse_uri(&uri, &self.uri)
    }
}

pub(super) struct Callback {
    pub(super) code: Option<Zeroizing<String>>,
    pub(super) state: Zeroizing<String>,
    pub(super) rejected: bool,
}

impl Callback {
    pub(super) fn authorization_code(
        self,
        expected_state: &str,
    ) -> Result<Zeroizing<String>, OidcBrowserError> {
        if self.state.as_str() != expected_state {
            return Err(invalid());
        }
        if self.rejected {
            return Err(OidcBrowserError::new(
                OidcBrowserErrorKind::AuthorizationRejected,
            ));
        }
        self.code.ok_or_else(invalid)
    }
}

fn application_redirect(value: &str) -> Result<Url, OidcBrowserError> {
    if value.len() > MAX_CALLBACK_BYTES {
        return Err(invalid());
    }
    let uri = Url::parse(value).map_err(protocol)?;
    if !uri.scheme().contains('.')
        || uri.cannot_be_a_base()
        || uri.has_host()
        || uri.path().is_empty()
        || uri.path() == "/"
        || uri.query().is_some()
        || uri.fragment().is_some()
    {
        return Err(invalid());
    }
    Ok(uri)
}

fn parse_uri(value: &str, expected: &Url) -> Result<Callback, OidcBrowserError> {
    if value.len() > MAX_CALLBACK_BYTES {
        return Err(invalid());
    }
    let mut uri = Url::parse(value).map_err(protocol)?;
    if uri.fragment().is_some() {
        return Err(invalid());
    }
    let mut code = None;
    let mut state = None;
    let mut error = None;
    for (index, (key, value)) in uri.query_pairs().enumerate() {
        if index >= 32 {
            return Err(invalid());
        }
        let slot = match key.as_ref() {
            "code" => &mut code,
            "state" => &mut state,
            "error" => &mut error,
            _ => continue,
        };
        if value.is_empty() || slot.replace(Zeroizing::new(value.into_owned())).is_some() {
            return Err(invalid());
        }
    }
    uri.set_query(None);
    if &uri != expected || code.is_some() == error.is_some() {
        return Err(invalid());
    }
    Ok(Callback {
        code,
        state: state.ok_or_else(invalid)?,
        rejected: error.is_some(),
    })
}

fn wait_for_callback(
    listener: TcpListener,
    expected: &Url,
    state: &str,
    operation: &SessionOperation,
) -> Result<Callback, OidcBrowserError> {
    loop {
        check_operation(operation)?;
        match listener.accept() {
            Ok((mut stream, _)) => match parse_request(&mut stream, expected) {
                Ok(callback) if callback.state.as_str() == state => {
                    let _ = respond(&mut stream, 200, "You can return to Zann.");
                    return Ok(callback);
                }
                _ => {
                    let _ = respond(&mut stream, 404, "Not found");
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50))
            }
            Err(error) => return Err(transport(error)),
        }
    }
}

fn parse_request(stream: &mut TcpStream, expected: &Url) -> Result<Callback, OidcBrowserError> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(transport)?;
    let mut buffer = [0_u8; MAX_CALLBACK_BYTES];
    let size = stream.read(&mut buffer).map_err(protocol)?;
    let request = std::str::from_utf8(&buffer[..size]).map_err(protocol)?;
    let mut parts = request
        .lines()
        .next()
        .ok_or_else(invalid)?
        .split_whitespace();
    if parts.next() != Some("GET") {
        return Err(invalid());
    }
    let path = parts.next().ok_or_else(invalid)?;
    if !path.starts_with('/') || path.starts_with("//") {
        return Err(invalid());
    }
    let mut base = expected.clone();
    base.set_path("");
    parse_uri(
        &format!("{}{path}", base.as_str().trim_end_matches('/')),
        expected,
    )
}

fn respond(stream: &mut TcpStream, status: u16, body: &str) -> std::io::Result<()> {
    write!(stream, "HTTP/1.1 {status} OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
}
fn invalid() -> OidcBrowserError {
    OidcBrowserError::new(OidcBrowserErrorKind::Protocol)
}
fn protocol(error: impl std::error::Error + Send + Sync + 'static) -> OidcBrowserError {
    OidcBrowserError::caused_by(OidcBrowserErrorKind::Protocol, error)
}
fn transport(error: impl std::error::Error + Send + Sync + 'static) -> OidcBrowserError {
    OidcBrowserError::caused_by(OidcBrowserErrorKind::Transport, error)
}

#[cfg(test)]
mod tests;
