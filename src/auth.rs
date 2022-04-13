use actix_web::dev::Payload;
use actix_web::http::header::{ContentType, HeaderName, HeaderValue};
use actix_web::http::StatusCode as HttpStatus;
use actix_web::{FromRequest, HttpRequest, HttpResponse};
use std::future::{ready, Ready};

pub struct Password(pub String);

#[derive(Debug)]
pub enum PasswordError {
	Missing,
	Invalid(&'static str),
}
impl std::fmt::Display for PasswordError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match self {
			Self::Missing => write!(f, "authorization is required to access this resource"),
			Self::Invalid(extra) => write!(
				f,
				"authorization was invalid. make sure to use Basic scheme with valid base64 data. reason: {:?}",
				extra
			),
		}
	}
}
impl std::error::Error for PasswordError {}
impl actix_web::ResponseError for PasswordError {
	fn status_code(&self) -> HttpStatus {
		match self {
			Self::Missing => HttpStatus::UNAUTHORIZED,
			Self::Invalid(_) => HttpStatus::BAD_REQUEST,
		}
	}
	fn error_response(&self) -> HttpResponse {
		let mut resp = HttpResponse::build(self.status_code())
			.content_type(ContentType::plaintext())
			.body(self.to_string());
		if let Self::Missing = self {
			resp.headers_mut().append(
				HeaderName::from_static("www-authenticate"),
				HeaderValue::from_static("Basic charset=\"UTF-8\""),
			)
		};
		resp
	}
}

impl Password {
	fn _from_request(req: &HttpRequest) -> Result<Self, PasswordError> {
		let auth = req
			.headers()
			.get("authorization")
			.ok_or(PasswordError::Missing)?;
		let auth = auth
			.to_str()
			.map_err(|_| PasswordError::Invalid("Authorization header is not valid UTF-8"))?;
		let (scheme, credentials) = auth.split_once(' ').ok_or(PasswordError::Invalid(
			"Authorization header has invalid format",
		))?;
		if !scheme.eq_ignore_ascii_case("basic") {
			return Err(PasswordError::Invalid(
				"not using Basic authorization scheme",
			));
		}
		// note: credentials are specified to be "<username>:<password>" format inside base64,
		// but for simplicity we just forward the raw bytes to the crypto algorithm.
		Ok(Self(credentials.to_owned()))
	}
}

impl FromRequest for Password {
	type Error = PasswordError;
	type Future = Ready<Result<Self, Self::Error>>;

	fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
		ready(Self::_from_request(req))
	}
}
