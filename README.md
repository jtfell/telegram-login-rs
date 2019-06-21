# telegram-login-rs

A rust implementation of the verification of Telegram Login requests.

Based on the example from the [Telegram docs](https://core.telegram.org/widgets/login#checking-authorization).

## Examples:

```rust
extern crate chrono;
extern crate telegram_login;

use chrono::NaiveDateTime;
use telegram_login::{TelegramLogin, TelegramLoginError, check_signature};

let t_l = TelegramLogin {
  id: 666666666,
  username: Some("my_username".to_string()),
  first_name: Some("Some".to_string()),
  last_name: Some("Guy".to_string()),
  photo_url: Some("https://t.me/i/userpic/320/my_username.jpg".to_string()),
  auth_date: NaiveDateTime::from_timestamp(1543194375, 0),
  hash: "a9cf12636fb07b54b4c95673d017a72364472c41a760b6850bcd5405da769f80".to_string()
};

let bot_token = "777777777:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();

match check_signature(bot_token, t_l) {
  Ok(()) => {
    // The login is valid, so we can log the user in.
  }
  Err(TelegramLoginError::InvalidHash) => {
    // The login failed, so we need to return an error to the client.
  }
  Err(TelegramLoginError::VerificationFailed) => {
    // The login failed, so we need to return an error to the client.
  }
}
```
