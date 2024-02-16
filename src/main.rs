use actix_web::{cookie::Cookie, get, web, web::Data, App, HttpServer, Responder};
use actix_web::{HttpRequest, HttpResponse};
use color_eyre::eyre::{Report, Result};
use compact_jwt::jws::JwsBuilder;
use compact_jwt::{
    crypto::JwsEs256Signer,
    jwt::Jwt,
    traits::{JwsSignerToVerifier, JwsVerifier},
    JwsSigner,
};
use compact_jwt::{JwsCompact, JwsEs256Verifier, JwtUnverified};
use config::Config;
use mini_moka::sync::Cache;
use openidconnect::EmptyAdditionalProviderMetadata;
use openidconnect::{
    core::{
        CoreAuthDisplay, CoreAuthenticationFlow, CoreClaimName, CoreClaimType, CoreClient,
        CoreClientAuthMethod, CoreGrantType, CoreJsonWebKey, CoreJsonWebKeyType, CoreJsonWebKeyUse,
        CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm, CoreJwsSigningAlgorithm,
        CoreResponseMode, CoreResponseType, CoreSubjectIdentifierType,
    },
    reqwest::async_http_client,
    AccessTokenHash, Audience, AuthorizationCode, ClientId, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, ProviderMetadata, RedirectUrl, Scope,
    TokenResponse,
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::{
    env,
    fs::read,
    net::SocketAddr,
    process::exit,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

extern crate pretty_env_logger;
#[macro_use]
extern crate log;

type AnnotatedProviderMetadata = ProviderMetadata<
    EmptyAdditionalProviderMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

#[derive(Debug, Deserialize)]
struct OidcConfig {
    client_id: ClientId,
    issuer_url: IssuerUrl,
    callback_url: RedirectUrl,
    verify_audience: bool,
    trusted_audiences: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
struct CookieConfig {
    name: String,
    domain: Option<String>,
    path: String,
}

#[derive(Debug, Deserialize)]
struct JwtConfig {
    key_path: String,
    duration: u64,
    compress: bool,
    kid: bool,
}

#[derive(Debug, Deserialize)]
struct Configuration {
    host: String,
    port: String,
    error_message: String,
    auth_time: u64,
    verify_redirect: bool,
    allowed_redirects: Vec<String>,
    jwt: JwtConfig,
    oidc: OidcConfig,
    cookie: CookieConfig,
}

#[derive(Debug, Deserialize, Serialize)]
struct Payload {
    exp: i64,
    sub: String,
}

type Sessions = Cache<String, Arc<OidcData>>;
type Verifier = Box<dyn Fn(&Audience, Vec<String>) -> bool + Send + Sync + 'static>;

#[derive(Deserialize, Debug)]
struct LoginQuery {
    redirect: String,
}
#[derive(Deserialize, Debug)]
struct CallbackQuery {
    code: String,
    state: String,
}

struct OidcData {
    nonce: Nonce,
    verifier: PkceCodeVerifier,
    redirect: String,
}

#[derive(Clone)]
struct ConfiguredConfig {
    cookie_config: CookieConfig,
    audience_verifier: Arc<Verifier>,
    trusted_audiences: Vec<String>,
    error_message: String,
    verify_redirect: bool,
    allowed_redirects: Vec<String>,
    signer: JwsEs256Signer,
    verifier: JwsEs256Verifier,
    jwt_expiry: Duration,
    compress: bool,
}

#[actix_web::main]
async fn main() -> Result<(), Report> {
    color_eyre::install()?;

    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "warn");
    }

    pretty_env_logger::init();

    let config_path = env::var("CONFIG").unwrap_or(String::from("./config.toml"));

    let configuration: Configuration = Config::builder()
        .add_source(config::File::with_name(config_path.as_str()))
        .add_source(config::Environment::default())
        .set_default("host", "127.0.0.1")?
        .set_default("port", "8080")?
        .set_default("oidc.verify_audience", true)?
        .set_default(
            "error_message",
            "There was an issue verifying your identity. Please try again or ask an administrator.",
        )?
        .set_default("verify_redirect", true)?
        .set_default("allowed_redirects", Vec::<String>::with_capacity(0))?
        .set_default("auth_time", 120)?
        .set_default("jwt_duration", 10080)?
        .set_default("jwt.compress", false)?
        .set_default("jwt.kid", false)?
        .set_default("key_path", "./private.der")?
        .set_default("cookie.path", "/")?
        .set_default("cookie.name", "vouch")?
        .build()?
        .try_deserialize()?;

    let do_verify: Verifier = Box::new(|aud, trusted| trusted.contains(aud));
    let no_verify: Verifier = Box::new(|_, _| true);

    let verifier: Verifier = if configuration.oidc.verify_audience {
        let trusted = &configuration.oidc.trusted_audiences;
        match trusted {
            Some(a) => {
                if a.is_empty() {
                    error!("trusted_audiences has to contain at least one string, otherwise the audience check will always fail.");
                    exit(1);
                };
                do_verify
            }
            None => {
                error!("trusted_audiences is missing in config.toml. Set trusted_audiences or disable audience verification.");
                exit(1);
            }
        }
    } else {
        no_verify
    };

    let key = match read(configuration.jwt.key_path.clone()) {
        Ok(t) => t,
        Err(e) => {
            error!(
                "Cant read private key '{}': {}",
                configuration.jwt.key_path, e
            );
            exit(1);
        }
    };

    let jwt_signer =
        JwsEs256Signer::from_es256_der(&key)?.set_sign_option_embed_kid(configuration.jwt.kid);
    let jwt_verifier = jwt_signer.get_verifier()?;

    let config: ConfiguredConfig = ConfiguredConfig {
        cookie_config: configuration.cookie,
        audience_verifier: Arc::new(verifier),
        trusted_audiences: configuration.oidc.trusted_audiences.unwrap_or_default(),
        error_message: configuration.error_message,
        verify_redirect: configuration.verify_redirect,
        allowed_redirects: configuration.allowed_redirects,
        jwt_expiry: Duration::from_secs(60 * configuration.jwt.duration),
        compress: configuration.jwt.compress,
        signer: jwt_signer,
        verifier: jwt_verifier,
    };

    let provider_metadata =
        AnnotatedProviderMetadata::discover_async(configuration.oidc.issuer_url, async_http_client)
            .await?;

    let client = Data::new(
        CoreClient::from_provider_metadata(provider_metadata, configuration.oidc.client_id, None)
            .set_redirect_uri(configuration.oidc.callback_url.clone()),
    );

    let sessions: Data<Sessions> = Data::new(
        Cache::builder()
            .time_to_live(Duration::from_secs(configuration.auth_time))
            .build(),
    );

    let configured_config = Data::new(config);

    let addr: SocketAddr = format!("{}:{}", configuration.host, configuration.port).parse()?;

    HttpServer::new(move || {
        App::new()
            .app_data(client.clone())
            .app_data(sessions.clone())
            .app_data(configured_config.clone())
            .service(verify)
            .service(login)
            .service(callback)
    })
    .bind(addr)
    .unwrap_or_else(|e| {
        error!("Cant bind to '{}': {}", addr, e);
        exit(1);
    })
    .run()
    .await?;
    Ok(())
}

fn verify_expiry(exp: i64) -> bool {
    exp > SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as i64
}

fn verify_jwt(jwt_string: &str, verifier: &JwsEs256Verifier) -> bool {
    let jwt = match JwtUnverified::from_str(jwt_string) {
        Ok(t) => t,
        Err(e) => {
            info!("Error while trying to parse JWT: {}", e.to_string());
            return false;
        }
    };

    match verifier.verify::<JwtUnverified<()>>(&jwt) {
        Ok(verified) => {
            if verified.exp.is_some_and(verify_expiry) {
                return true;
            }
            false
        }
        Err(e) => {
            info!("Error while validating JWT: {}", e.to_string());
            false
        }
    }
}

fn verify_jws(jws_string: &str, verifier: &JwsEs256Verifier) -> bool {
    let jws = match JwsCompact::from_str(jws_string) {
        Ok(t) => t,
        Err(e) => {
            info!("Error while trying to parse JWS: {}", e.to_string());
            return false;
        }
    };

    match verifier.verify::<JwsCompact>(&jws) {
        Ok(verified) => {
            let decompressed = match zstd::decode_all(verified.payload()) {
                Ok(t) => t,
                Err(e) => {
                    warn!(
                        "Error while trying to decompress JWS payload: {}",
                        e.to_string()
                    );
                    return false;
                }
            };
            let payload: Payload = match bincode::deserialize(decompressed.as_slice()) {
                Ok(t) => t,
                Err(e) => {
                    warn!("Error while trying to parse JWS payload: {}", e.to_string());
                    return false;
                }
            };
            verify_expiry(payload.exp)
        }
        Err(e) => {
            info!("Error while validating JWS: {}", e.to_string());
            false
        }
    }
}

#[get("/oidc/verify")]
async fn verify(request: HttpRequest, config: Data<ConfiguredConfig>) -> impl Responder {
    let Some(cookie) = request.cookie(&config.cookie_config.name) else {
        return HttpResponse::Unauthorized();
    };

    let is_valid = if config.compress {
        verify_jws(cookie.value(), &config.verifier)
    } else {
        verify_jwt(cookie.value(), &config.verifier)
    };

    if is_valid {
        HttpResponse::Ok()
    } else {
        HttpResponse::Unauthorized()
    }
}

#[get("/oidc/login")]
async fn login(
    login_query: web::Query<LoginQuery>,
    sessions: Data<Sessions>,
    oidc_client: Data<CoreClient>,
    config: Data<ConfiguredConfig>,
) -> impl Responder {
    if config.verify_redirect && !is_url_allowed(&login_query.redirect, &config.allowed_redirects) {
        info!(
            "Rejecting '{}' because it is not in allowed_redirects.",
            login_query.redirect
        );
        return HttpResponse::Unauthorized().body("Redirect not allowed.");
    }
    let id = Uuid::new_v4().simple().to_string();
    let token = CsrfToken::new(id.clone());
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (authorize_url, _csrf_state, nonce) = oidc_client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            || token,
            Nonce::new_random,
        )
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("openid".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    {
        sessions.insert(
            id.clone(),
            Arc::new(OidcData {
                nonce,
                verifier: pkce_verifier,
                redirect: login_query.redirect.clone(),
            }),
        );
    }
    debug!(
        "Received login request for url '{}'. Assigned Id: '{}'",
        login_query.redirect, id
    );

    HttpResponse::Found()
        .insert_header(("LOCATION", authorize_url.as_str()))
        .finish()
}

#[get("/oidc/callback")]
async fn callback(
    callback_query: web::Query<CallbackQuery>,
    sessions: Data<Sessions>,
    oidc_client: Data<CoreClient>,
    config: Data<ConfiguredConfig>,
) -> impl Responder {
    let id = &callback_query.state;
    debug!("Received callback with id: {}", id);
    let Some(session) = sessions.get(id) else {
        info!("Received callback with invalid id.");
        return HttpResponse::Unauthorized().body(config.error_message.clone());
    };
    sessions.invalidate(id);

    let verifier = PkceCodeVerifier::new(session.verifier.secret().to_owned());

    let token_response = match oidc_client
        .exchange_code(AuthorizationCode::new(callback_query.code.clone()))
        .set_pkce_verifier(verifier)
        .request_async(async_http_client)
        .await
    {
        Ok(t) => t,
        Err(e) => {
            return respond_unauthorized(
                "Error while requesting access token".into(),
                e.to_string(),
                config.error_message.clone(),
            );
        }
    };

    let Some(id_token) = token_response.id_token() else {
        return respond_unauthorized(
            "Error while parsing Id token".into(),
            "The authorization server didn't send an Id token".into(),
            config.error_message.clone(),
        );
    };

    let claims = match id_token.claims(
        &oidc_client
            .id_token_verifier()
            .set_other_audience_verifier_fn(|aud| {
                Arc::clone(&config.audience_verifier).as_ref()(
                    aud,
                    config.trusted_audiences.clone(),
                )
            }),
        &session.nonce,
    ) {
        Ok(t) => t,
        Err(e) => {
            return respond_unauthorized(
                "Error while verifying Id Token".into(),
                e.to_string(),
                config.error_message.clone(),
            );
        }
    };

    //TODO: clean this up
    if let Some(expected_access_token_hash) = claims.access_token_hash() {
        let actual_access_token_hash = AccessTokenHash::from_token(
            token_response.access_token(),
            &id_token.signing_alg().expect("Cant get signing alg"),
        )
        .expect("Cant get access token");
        if actual_access_token_hash != *expected_access_token_hash
            || claims.nonce() != Some(&session.nonce)
        {
            return HttpResponse::Unauthorized().finish();
        }
    } else {
        return respond_unauthorized(
            "Can't verify access token hash".into(),
            "Access Token hash not found in Id Token".into(),
            config.error_message.clone(),
        );
    }

    let time = SystemTime::now()
        .checked_add(config.jwt_expiry)
        .expect("Jwt expiry overflows data type")
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");

    let payload = Payload {
        exp: (time.as_secs() as i64),
        sub: claims.subject().to_string(),
    };

    let token = if config.compress {
        let Ok(encoded) = bincode::serialize(&payload) else {
            warn!("Couldn't serialize payload");
            return HttpResponse::Unauthorized().finish();
        };

        let Ok(compressed) = zstd::encode_all(&encoded[..], 0) else {
            warn!("Couldn't compress payload");
            return HttpResponse::Unauthorized().finish();
        };

        let jws = JwsBuilder::from(compressed).build();

        config.signer.sign(&jws).expect("openssl error").to_string()
    } else {
        let jwt = Jwt::<()> {
            exp: Some(payload.exp),
            sub: Some(payload.sub),
            ..Default::default()
        };
        config.signer.sign(&jwt).expect("openssl error").to_string()
    };

    //TODO: Consider setting max-age or expires?
    let authorization_cookie = Cookie::build(&config.cookie_config.name, token)
        .domain(config.cookie_config.domain.clone().unwrap_or_default())
        .same_site(actix_web::cookie::SameSite::Lax)
        .path(&config.cookie_config.path)
        .secure(true)
        .http_only(true)
        .finish();

    HttpResponse::Found()
        .insert_header(("LOCATION", session.redirect.clone()))
        .cookie(authorization_cookie)
        .finish()
}

fn is_url_allowed(url: &str, allowed_urls: &[String]) -> bool {
    allowed_urls.iter().any(|allowed| {
        if let Some(wildcard) = allowed.strip_suffix('*') {
            return url.starts_with(wildcard);
        }
        url == allowed
    })
}

fn respond_unauthorized(log: String, error: String, error_response: String) -> HttpResponse {
    warn!("{}: {}", log, error);
    HttpResponse::Unauthorized().body(error_response)
}
