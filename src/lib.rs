//! A rust implementation of the verification of Telegram Login requests.
//!
//! Based on the example from the [Telegram docs](https://core.telegram.org/widgets/login#checking-authorization).
//!
//! # Examples:
//!
//! ```
//! extern crate chrono;
//! extern crate telegram_login;
//!
//! use chrono::NaiveDateTime;
//! use telegram_login::{TelegramLogin, TelegramLoginError, check_signature};
//!
//! let t_l = TelegramLogin {
//!   id: 666666666,
//!   username: Some("my_username".to_string()),
//!   first_name: Some("Some".to_string()),
//!   last_name: Some("Guy".to_string()),
//!   photo_url: Some("https://t.me/i/userpic/320/my_username.jpg".to_string()),
//!   auth_date: NaiveDateTime::from_timestamp(1543194375, 0),
//!   hash: "a9cf12636fb07b54b4c95673d017a72364472c41a760b6850bcd5405da769f80".to_string()
//! };
//!
//! let bot_token = "777777777:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
//!
//! match check_signature(bot_token, t_l) {
//!   Ok(()) => {
//!     // The login is valid, so we can log the user in.
//!   }
//!   Err(TelegramLoginError::InvalidHash) => {
//!     // The login failed, so we need to return an error to the client.
//!   }
//!   Err(TelegramLoginError::VerificationFailed) => {
//!     // The login failed, so we need to return an error to the client.
//!   }
//! }
//! ```

extern crate chrono;
extern crate hex;
extern crate ring;

use ring::{digest, hmac};

///
/// The Telegram Login data object that is returned from the Telegram Auth endpoint.
///
#[derive(Clone, Debug)]
pub struct TelegramLogin {
    pub id: i32,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub username: Option<String>,
    pub photo_url: Option<String>,
    pub auth_date: chrono::NaiveDateTime,
    pub hash: String
}

///
/// There are 2 ways in which the `check_signature` method can fail.
///
#[derive(Clone, Debug, PartialEq)]
pub enum TelegramLoginError {
    InvalidHash,
    VerificationFailed
}

///
/// Verifies that the hash in the Telegram auth object is valid.
///
/// The algorithm from the Telegram docs:
///
///  - secret_key = SHA256(<bot_token>)
///  - hex(HMAC_SHA256(data_check_string, secret_key)) == hash
///
/// # Examples:
///
/// ```
/// extern crate chrono;
/// extern crate telegram_login;
///
/// use chrono::NaiveDateTime;
/// use telegram_login::{TelegramLogin, TelegramLoginError, check_signature};
///
/// let t_l = TelegramLogin {
///   id: 666666666,
///   username: Some("my_username".to_string()),
///   first_name: Some("Some".to_string()),
///   last_name: Some("Guy".to_string()),
///   photo_url: Some("https://t.me/i/userpic/320/my_username.jpg".to_string()),
///   auth_date: NaiveDateTime::from_timestamp(1543194375, 0),
///   hash: "a9cf12636fb07b54b4c95673d017a72364472c41a760b6850bcd5405da769f80".to_string()
/// };
///
/// let bot_token = "777777777:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
///
/// match check_signature(bot_token, t_l) {
///   Ok(()) => {
///     // The login is valid, so we can log the user in.
///   }
///   Err(TelegramLoginError::InvalidHash) => {
///     // The login failed, so we need to return an error to the client.
///   }
///   Err(TelegramLoginError::VerificationFailed) => {
///     // The login failed, so we need to return an error to the client.
///   }
/// }
/// ```
pub fn check_signature(bot_token: String, user: TelegramLogin) -> Result<(), TelegramLoginError> {

    match hex::decode(&user.hash) {
        Ok(hash) => {

            let data_check_string = gen_check_string(user);
            let secret_key = digest::digest(&digest::SHA256, &bot_token.as_bytes());
            let v_key = hmac::VerificationKey::new(&digest::SHA256, secret_key.as_ref());
            hmac::verify(
                &v_key,
                data_check_string.as_bytes(),
                &hash,
            ).map_err(|_e| TelegramLoginError::VerificationFailed)
        }
        Err(_e) => Err(TelegramLoginError::InvalidHash)
    }
}

/// Converts the Struct object received from Telegram into the data_check_string as required
/// in the verification process.
///
/// From the Telegram docs:
///
/// - Data-check-string is a concatenation of all received fields, sorted in alphabetical order,
///  in the format key=<value> with a line feed character ('\n', 0xA0) used as separator
///
fn gen_check_string(data: TelegramLogin) -> String {
    struct Field<A> {
        field: String,
        value: Option<A>,
    }

    // Put the key, value pairs in order
    let fields = vec![
        Field {
            field: "auth_date".to_string(),
            value: Some(data.auth_date.timestamp().to_string()),
        },
        Field {
            field: "first_name".to_string(),
            value: data.first_name,
        },
        Field {
            field: "id".to_string(),
            value: Some(data.id.to_string()),
        },
        Field {
            field: "last_name".to_string(),
            value: data.last_name,
        },
        Field {
            field: "photo_url".to_string(),
            value: data.photo_url,
        },
        Field {
            field: "username".to_string(),
            value: data.username,
        },
    ];

    let mut result = fields
        .into_iter()
        .fold("".to_string(), |acc, f| match f.value {
            Some(val) => format!("{}{}={}\n", acc, f.field, val),
            None => acc,
        });

    // Remove the final "\n" before returning the result
    result.pop();
    result
}


#[cfg(test)]
mod tests {

    use super::*;
    use chrono::NaiveDateTime;

    #[test]
    fn test_gen_check_string() {

        let t_l = TelegramLogin {
            id: 666666666,
            username: Some("my_username".to_string()),
            first_name: Some("Some".to_string()),
            last_name: Some("Guy".to_string()),
            photo_url: Some("https://t.me/i/userpic/320/my_username.jpg".to_string()),
            auth_date: NaiveDateTime::from_timestamp(1543194375, 0),
            hash: "aaaaaaaaaaaaaaaaaeeeeeeeeee4444444444444444444444444444444444444".to_string()
        };

        assert_eq!(
            gen_check_string(t_l),
            "auth_date=1543194375\nfirst_name=Some\nid=666666666\nlast_name=Guy\nphoto_url=https://t.me/i/userpic/320/my_username.jpg\nusername=my_username"
        );
    }

    #[test]
    fn test_check_signature_success() {

        let t_l = TelegramLogin {
            id: 666666666,
            username: Some("my_username".to_string()),
            first_name: Some("Some".to_string()),
            last_name: Some("Guy".to_string()),
            photo_url: Some("https://t.me/i/userpic/320/my_username.jpg".to_string()),
            auth_date: NaiveDateTime::from_timestamp(1543194375, 0),
            hash: "a9cf12636fb07b54b4c95673d017a72364472c41a760b6850bcd5405da769f80".to_string()
        };

        assert_eq!(
            check_signature(
                "777777777:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                t_l
            ),
            Ok(())
        );
    }

    #[test]
    fn test_check_signature_err_verification_failed() {

        let t_l = TelegramLogin {
            id: 666666666,
            username: Some("my_username".to_string()),
            first_name: Some("Some".to_string()),
            last_name: Some("Guy".to_string()),
            photo_url: Some("https://t.me/i/userpic/320/my_username.jpg".to_string()),
            auth_date: NaiveDateTime::from_timestamp(1543194375, 0),
            hash: "aaaaaaaaaaaaaaaaaeeeeeeeeee4444444444444444444444444444444444444".to_string()
        };

        assert_eq!(
            check_signature(
                "777777777:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                t_l
            ),
            Err(TelegramLoginError::VerificationFailed)
        );
    }

    #[test]
    fn test_check_signature_err_invalid_hash() {

        let t_l = TelegramLogin {
            id: 666666666,
            username: Some("my_username".to_string()),
            first_name: Some("Some".to_string()),
            last_name: Some("Guy".to_string()),
            photo_url: Some("https://t.me/i/userpic/320/my_username.jpg".to_string()),
            auth_date: NaiveDateTime::from_timestamp(1543194375, 0),
            // Not HEX chars here
            hash: "xxxxxxxaaaaaaaaaaeeeeeeeeee4444444444444444444444444444444444444".to_string()
        };

        assert_eq!(
            check_signature(
                "777777777:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                t_l
            ),
            Err(TelegramLoginError::InvalidHash)
        );
    }
}
