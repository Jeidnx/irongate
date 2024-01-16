use actix_web::HttpResponse;
use actix_web::{cookie::Cookie, get, web, web::Data, App, HttpServer, Responder};
use color_eyre::eyre::{Report, Result};
use compact_jwt::{crypto::JwsEs256Signer, jwt::Jwt, JwsSigner};
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
use serde::Deserialize;
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
struct Configuration {
    host: String,
    port: String,
    error_message: String,
    auth_time: u64,
    verify_redirect: bool,
    allowed_redirects: Vec<String>,
    key_path: String,
    jwt_duration: u64,
    oidc: OidcConfig,
    cookie: CookieConfig,
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
    jwt_expiry: Duration,
}

#[actix_web::main]
async fn main() -> Result<(), Report> {
    color_eyre::install()?;

    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "warn")
    }

    pretty_env_logger::init();

    let config_path = env::var("CONFIG").unwrap_or("./config.toml".to_owned());

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
                } else {
                    do_verify
                }
            }
            None => {
                error!("trusted_audiences is missing in config.toml. Set trusted_audiences or disable audience verification.");
                exit(1);
            }
        }
    } else {
        no_verify
    };

    let key = match read(configuration.key_path.clone()) {
        Ok(t) => t,
        Err(e) => {
            error!("Cant read private key '{}': {}", configuration.key_path, e);
            exit(1);
        }
    };

    let config: ConfiguredConfig = ConfiguredConfig {
        cookie_config: configuration.cookie,
        audience_verifier: Arc::new(verifier),
        trusted_audiences: configuration.oidc.trusted_audiences.unwrap_or_default(),
        error_message: configuration.error_message,
        verify_redirect: configuration.verify_redirect,
        allowed_redirects: configuration.allowed_redirects,
        signer: JwsEs256Signer::from_es256_der(&key)?,
        jwt_expiry: Duration::from_secs(60 * configuration.jwt_duration),
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
    let session = match sessions.get(id) {
        Some(t) => t,
        None => {
            info!("Received callback with invalid id.");
            return HttpResponse::Unauthorized().body(config.error_message.clone());
        }
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

    let id_token = match token_response.id_token() {
        Some(t) => t,
        None => {
            return respond_unauthorized(
                "Error while parsing Id token".into(),
                "The authorization server didn't send an Id token".into(),
                config.error_message.clone(),
            )
        }
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

    info!("claims: {:#?}", claims.additional_claims());
    let time = SystemTime::now()
        .checked_add(config.jwt_expiry)
        .expect("Jwt expiry overflows data type")
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");

    let token = Jwt::<()> {
        sub: Some(claims.subject().to_string()),
        exp: Some(time.as_secs() as i64),
        ..Default::default()
    };

    let token_str = config.signer.sign(&token).unwrap().to_string();

    // Consider setting max-age or expires?
    let authorization_cookie = Cookie::build(config.cookie_config.name.clone(), token_str)
        .domain(config.cookie_config.domain.clone().unwrap_or_default())
        .same_site(actix_web::cookie::SameSite::Lax)
        .path(config.cookie_config.path.clone())
        .secure(true)
        .http_only(true)
        .finish();

    HttpResponse::Found()
        .insert_header(("LOCATION", session.redirect.clone()))
        .cookie(authorization_cookie)
        .finish()
}

fn is_url_allowed(url: &str, allowed_urls: &Vec<String>) -> bool {
    for allowed in allowed_urls {
        if allowed.ends_with('*') {
            let prefix = &allowed[..allowed.len() - 1];
            if url.starts_with(prefix) {
                return true;
            }
        } else if url == allowed {
            return true;
        }
    }
    false
}

fn respond_unauthorized(log: String, error: String, error_response: String) -> HttpResponse {
    warn!("{}: {}", log, error);
    HttpResponse::Unauthorized().body(error_response)
}
