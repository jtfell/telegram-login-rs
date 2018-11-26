import collections
import hashlib
import hmac

def generate_hash(d, token):
  secret = hashlib.sha256()
  secret.update(token.encode('utf-8'))
  sorted_params = collections.OrderedDict(sorted(d.items()))
  param_hash = sorted_params.pop('hash')
  msg = "\n".join(["{}={}".format(k, v) for k, v in sorted_params.items()])

  return param_hash, hmac.new(secret.digest(), msg.encode('utf-8'), digestmod=hashlib.sha256).hexdigest()

tg_data = {
    "id" : '666666666',
    "first_name" : 'Some',
    "last_name" : 'Guy',
    "username" : 'my_username',
    "photo_url" : 'https://t.me/i/userpic/320/my_username.jpg',
    "auth_date":  '1543194375',
    "hash": 'a9cf12636fb07b54b4c95673d017a72364472c41a760b6850bcd5405da769f80'
}

result = generate_hash(tg_data, '777777777:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')

print(result, result[0] == result[1])
