use actix_web::error::InternalError;
use actix_web::http::StatusCode as HttpStatus;
use actix_web::{middleware as mid, web, App as ActixApp, HttpResponse, HttpServer};
use anyhow::Context as _;
use std::path::PathBuf;
use std::process::Command;

mod auth;
use auth::Password;

fn safe_path(raw: &str) -> Option<PathBuf> {
	let path = raw.parse::<PathBuf>().ok()?.canonicalize().ok()?;
	if path.starts_with(std::env::current_dir().ok()?) {
		Some(path)
	} else {
		None
	}
}

async fn root(path: web::Path<(String,)>, password: Password) -> actix_web::Result<HttpResponse> {
	let path_str = path.into_inner().0;
	let password = password.0;

	// by blocking the specific error from propagating, we can avoid leaking information about paths outside of the current directory
	let path = match safe_path(&path_str) {
		Some(path) if path.exists() => path,
		_ => return Ok(HttpResponse::new(HttpStatus::NOT_FOUND)),
	};

	let output = tokio::task::spawn_blocking(move || {
		Command::new("openssl")
			.arg("enc")
			.arg("-d")
			.arg("-pbkdf2")
			.arg("-chacha20")
			.arg("-pass=env:PASSWORD")
			.arg("-in")
			.arg(path)
			.env("PASSWORD", password)
			.output()
	})
	.await
	.unwrap()?;
	if !output.status.success() {
		return Err(
			InternalError::new(
				format!(
					"OpenSSL command failed: {}",
					std::str::from_utf8(&output.stderr).unwrap_or("(error message contained invalid utf-8)")
				),
				HttpStatus::INTERNAL_SERVER_ERROR,
			)
			.into(),
		);
	}
	let output = output.stdout;

	Ok(HttpResponse::build(HttpStatus::OK).body(output))
}

async fn main_() -> anyhow::Result<()> {
	let socket_path: PathBuf = std::env::var_os("LISTEN_ON")
		.context("Missing socket path to listen on (`LISTEN_ON` env var)")?
		.try_into()
		.context("Invalid socket path")?;

	simple_logger::SimpleLogger::new()
		.with_level(log::LevelFilter::Info)
		.init()
		.context("Initializing logging")?;

	let factory = move || {
		ActixApp::new()
			.wrap(mid::NormalizePath::trim())
			.route("/{path:.*}", web::get().to(root))
			.wrap(mid::Logger::default())
			.wrap_fn(|req, srv| {
				use actix_web::dev::Service as _;
				let res = srv.call(req);
				async {
					let res = res.await?;
					if let Some(error) = res.response().error() {
						log::error!(
							"Server error (handled by {:?}): {:?}",
							res.request().match_name(),
							error
						);
					}
					Ok(res)
				}
			})
	};
	let http = HttpServer::new(factory);

	log::info!("Listening on {}", socket_path.display());
	http
		.bind_uds(socket_path)
		.context("Binding server to address")?
		.run()
		.await
		.context("Running server")
}

fn main() -> anyhow::Result<()> {
	actix_web::rt::System::new().block_on(main_())
}
