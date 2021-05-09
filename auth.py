import json
import urllib.request
from jose import jwk, jwt
from jose.utils import base64url_decode

class CognitoAuth():
    def __init__(self, region, userpool_id, app_client_id):
        self.region = region
        self.userpool_id = userpool_id
        self.app_client_id = app_client_id
        self.keys_url = f'https://cognito-idp.{self.region}.amazonaws.com/{self.userpool_id}/.well-known/jwks.json'
        self.keys = self.__get_pub_keys()

    def __get_pub_keys(self):
        # instead of re-downloading the public keys every time
        # we download them only on cold start
        with urllib.request.urlopen(self.keys_url) as f:
            response = f.read()
            return json.loads(response.decode('utf-8'))['keys']

    def __get_token_kid(self, token):
        # get the kid from the headers prior to verification
        headers = jwt.get_unverified_headers(token)
        return headers['kid']

    def __search_for_kid_in_pub_keys(self, keys, token):
        # search for the kid in the downloaded public keys
        kid = self.__get_token_kid(token)
        for key_index in range(len(keys)):
            if kid == keys[key_index]['kid']:
                return key_index
        return False

    def __construct_public_key(self, token):
        # construct the public key
        key_index = self.__search_for_kid_in_pub_keys(self.keys, token)
        public_key = jwk.construct(self.keys[key_index])
        return public_key

    def verify_token(self, token):
        # get the last two sections of the token,
        # message and signature (encoded in base64)
        message, encoded_signature = str(token).rsplit('.', 1)
        # decode the signature
        decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
        # verify the signature
        public_key = self.__construct_public_key(token)
        if not public_key.verify(message.encode("utf8"), decoded_signature):
            # print('Signature verification failed')
            return False
        else:
            return True

if __name__ == '__main__':
    # for testing locally you can enter the JWT ID Token here
    token = ''
    auth = CognitoAuth('', '', '')
    print(auth.verify_token(token))
