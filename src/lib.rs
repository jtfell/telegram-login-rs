extern crate chrono;
extern crate hex;
extern crate ring;

use ring::{digest, hmac};

///
/// The Telegram Login data object
///
#[derive(Clone, Debug)]
pub struct TelegramLogin {
    pub id: i32,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub username: Option<String>,
    pub photo_url: Option<String>,
    pub auth_date: chrono::NaiveDateTime,
    pub hash: [u8; 32], // hex bytes
}

/// Converts the Struct object received from Telegram into the data_check_string as required
/// in the verification process. From the Telegram docs:
///
///  Data-check-string is a concatenation of all received fields, sorted in alphabetical order,
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

///
/// Verifies that the hash in the Telegram auth object is valid. From the Telegram docs:
///
///   hex(HMAC_SHA256(data_check_string, secret_key)) == hash
///
pub fn check_signature(bot_token: String, user: TelegramLogin) -> bool {
    let data_check_string = gen_check_string(user.clone());

    let secret_key = hmac::VerificationKey::new(&digest::SHA256, &bot_token.as_bytes());

    let res = hmac::verify(
        &secret_key,
        data_check_string.as_bytes(),
        user.hash.as_ref(),
    );

    match res {
        Ok(()) => true,
        Err(_e) => false,
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use chrono::NaiveDateTime;
    use std::convert::AsMut;

    fn copy_into_array<A, T>(slice: &[T]) -> A
    where
        A: Default + AsMut<[T]>,
        T: Copy,
    {
        let mut a = Default::default();
        <A as AsMut<[T]>>::as_mut(&mut a).copy_from_slice(slice);
        a
    }

    #[test]
    fn test_gen_check_string() {
        let hash_vec =
            hex::decode("aaaaaaaaaaaaaaaaaeeeeeeeeee4444444444444444444444444444444444444")
                .expect("Bad Hash");
        let hash = copy_into_array(&hash_vec[0..32]);

        let t_l = TelegramLogin {
            id: 777777777,
            username: Some("jtfell".to_string()),
            first_name: Some("Julian".to_string()),
            last_name: Some("Fell".to_string()),
            photo_url: Some("https://t.me/i/userpic/320/jtfell.jpg".to_string()),
            auth_date: NaiveDateTime::from_timestamp(1543140755, 0),
            hash,
        };

        assert_eq!(
            gen_check_string(t_l),
            "auth_date=1543140755\nfirst_name=Julian\nid=777777777\nlast_name=Fell\nphoto_url=https://t.me/i/userpic/320/jtfell.jpg\nusername=jtfell"
        );
    }

    #[test]
    fn test_check_signature() {
        let hash_vec =
            hex::decode("aaaaaaaaaaaaaaaaaeeeeeeeeee4444444444444444444444444444444444444")
                .expect("Bad Hash");
        let hash = copy_into_array(&hash_vec[0..32]);

        let t_l = TelegramLogin {
            id: 777777777,
            username: Some("jtfell".to_string()),
            first_name: Some("Julian".to_string()),
            last_name: Some("Fell".to_string()),
            photo_url: Some("https://t.me/i/userpic/320/jtfell.jpg".to_string()),
            auth_date: NaiveDateTime::from_timestamp(1543140755, 0),
            hash,
        };

        assert_eq!(
            check_signature(
                "888888888:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
                t_l
            ),
            true
        );
    }
}
