import hashlib
import hmac
import json
import re
import secrets
from base64 import b64decode, b64encode
from binascii import hexlify
from typing import Any
from urllib.parse import quote

from Crypto.Cipher import AES, PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from requests import post, get

from tplinkrouterc6u.client.c6u import TplinkBaseRouter
from tplinkrouterc6u.common.exception import ClientException, ClientError


class TplinkBE230Router(TplinkBaseRouter):
    """BE230 (ui-type=svr) router client using AES + RSA-OAEP + HMAC-SHA256."""

    AES_KEY_LEN = 16
    AES_IV_LEN = 16
    SIGN_CHUNK_LEN = 53

    def __init__(self, host: str, password: str, username: str = 'admin', logger=None,
                 verify_ssl: bool = True, timeout: int = 30) -> None:
        super().__init__(host, password, username, logger, verify_ssl, timeout)
        self._url_firmware = 'admin/firmware?form=upgrade'
        self._url_ipv4_reservations = 'admin/dhcps?form=reservation'
        self._url_ipv4_dhcp_leases = 'admin/dhcps?form=client'
        self._url_smart_network = 'admin/smart_network?form=game_accelerator'
        self._url_openvpn = 'admin/openvpn?form=config'
        self._url_pptpd = 'admin/pptpd?form=config'
        self._url_vpnconn_openvpn = 'admin/vpnconn?form=config'
        self._url_vpnconn_pptpd = 'admin/vpnconn?form=config'
        self._seq = ''
        self._nn = ''
        self._ee = ''
        self._pwdNN = ''
        self._pwdEE = ''
        self._aes_key = ''
        self._aes_iv = ''
        self._hash = ''

    def supports(self) -> bool:
        try:
            response = get(
                '{}/webpages/index.html'.format(self.host),
                headers={'Accept-Encoding': 'identity'},
                timeout=10,
                verify=self._verify_ssl,
            )
            if response.status_code < 400:
                content = response.text.lower()
                if 'name="ui-type"' in content and 'content="svr"' in content:
                    return True
        except Exception:
            pass

        try:
            response = post(
                '{}/cgi-bin/luci/;stok=/login?form=keys'.format(self.host),
                data='operation=read',
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=10,
                verify=self._verify_ssl,
            )
            payload = response.json()
            if not payload.get('success'):
                return False
            block = payload.get(self._data_block) or {}
            password_key = block.get('password') or []
            key_len = len(password_key[0]) if isinstance(password_key, list) and password_key else 0
            username = block.get('username')
            mode = block.get('mode')
            return mode == 'router' and username == '' and key_len >= 512
        except Exception:
            return False

    def authorize(self) -> None:
        if not self._seq:
            self._request_seq()
        if not self._pwdNN:
            self._request_pwd()

        self._init_crypto()
        response = self._try_login()
        if response.status_code == 403 or not response.text:
            self._log_response(response, 'login')
            self._request_seq()
            self._request_pwd()
            self._init_crypto()
            response = self._try_login()

        data = response.text
        try:
            data = response.json()
            data = self._decrypt_response(data)

            if not data.get('success'):
                if self._logger:
                    self._logger.debug('TplinkRouter BE230 login failed payload: %s', data)
                error_info = data.get(self._data_block, {})
                error_code = (
                    error_info.get('errorcode')
                    or data.get('errorcode')
                    or data.get('errorCode')
                    or data.get('error_code')
                    or 'unknown error'
                )
                if error_code in {'user conflict', 'multiple login'}:
                    response = self._try_login(confirm=True)
                    data = response.json()
                    data = self._decrypt_response(data)
                    if data.get('success'):
                        self._stok = data[self._data_block]['stok']
                        if 'set-cookie' in response.headers:
                            match = re.search(r'sysauth=([^;]+)', response.headers['set-cookie'])
                            if match:
                                self._sysauth = match.group(1)
                        self._logged = True
                        return
                    if self._logger:
                        self._logger.debug(
                            'TplinkRouter BE230 login confirm failed payload: %s', data
                        )
                    error_info = data.get(self._data_block, {})
                    error_code = (
                        error_info.get('errorcode')
                        or data.get('errorcode')
                        or data.get('errorCode')
                        or data.get('error_code')
                        or 'unknown error'
                    )
                raise ClientException(
                    'TplinkRouter - {} - Login failed: {}'.format(
                        self.__class__.__name__,
                        error_code,
                    )
                )

            self._stok = data[self._data_block]['stok']
            if 'set-cookie' in response.headers:
                match = re.search(r'sysauth=([^;]+)', response.headers['set-cookie'])
                if match:
                    self._sysauth = match.group(1)

            self._logged = True

        except ClientException:
            raise
        except Exception as e:
            self._log_response(response, 'login')
            error = (
                'TplinkRouter - {} - Cannot authorize! Error - {}; Response - {}'
                .format(self.__class__.__name__, e, data)
            )
            if self._logger:
                self._logger.debug(error)
            raise ClientException(error)

    def logout(self) -> None:
        try:
            self.request('admin/system?form=logout', 'operation=write', True)
        finally:
            self._stok = ''
            self._sysauth = ''
            self._logged = False

    def request(self, path: str, data: str, ignore_response: bool = False, ignore_errors: bool = False) -> dict | None:
        if self._logged is False:
            raise Exception('Not authorised')

        url = '{}/cgi-bin/luci/;stok={}/{}'.format(self.host, self._stok, path)
        encrypted_data = self._aes_encrypt(data)
        response = self._post_encrypted(url, encrypted_data, None)

        if ignore_response:
            return None

        raw = response.text
        error = ''
        try:
            payload = response.json()
            if 'data' not in payload:
                raise Exception("Router didn't respond with JSON")
            payload = self._decrypt_response(payload)

            if self._is_valid_response(payload):
                return payload.get(self._data_block)
            if ignore_errors:
                return payload
        except Exception as e:
            self._log_response(response, 'request:{}'.format(path))
            replaced_hash = hashlib.sha256(encrypted_data.encode('utf-8')).hexdigest()
            response = self._post_encrypted(url, encrypted_data, replaced_hash)
            raw = response.text
            try:
                payload = response.json()
                if 'data' not in payload:
                    raise Exception("Router didn't respond with JSON")
                payload = self._decrypt_response(payload)
                if self._is_valid_response(payload):
                    self._hash = replaced_hash
                    return payload.get(self._data_block)
                if ignore_errors:
                    return payload
            except Exception as retry_err:
                self._log_response(response, 'request:{}:retry'.format(path))
                error = (
                    'TplinkRouter - {} - An unknown response - {}; Request {} -- Response {}'
                    .format(self.__class__.__name__, retry_err, path, raw)
                )

        if not error:
            error = (
                'TplinkRouter - {} - Response with error; Request {} - Response {}'
                .format(self.__class__.__name__, path, raw)
            )
        if self._logger:
            self._logger.debug(error)
        raise ClientError(error)

    def _post_encrypted(self, url: str, encrypted_data: str, hash_override: str | None):
        sign = self._build_sign(len(encrypted_data), is_login=False, hash_override=hash_override)
        return post(
            url,
            data={'sign': sign, 'data': encrypted_data},
            headers=self._headers_request,
            cookies={'sysauth': self._sysauth},
            timeout=self.timeout,
            verify=self._verify_ssl,
        )

    def _request_seq(self) -> None:
        url = '{}/cgi-bin/luci/;stok=/login?form=auth'.format(self.host)
        response = post(
            url,
            data='operation=read',
            headers=self._headers_login,
            timeout=self.timeout,
            verify=self._verify_ssl,
        )
        try:
            payload = response.json()
            block = payload[self._data_block]
            self._seq = str(block['seq'])
            key = block['key']
            self._nn = key[0]
            self._ee = key[1]
        except Exception as e:
            error = (
                'TplinkRouter - {} - Unknown error for seq! Error - {}; Response - {}'
                .format(self.__class__.__name__, e, response.text)
            )
            if self._logger:
                self._logger.debug(error)
            raise ClientException(error)

    def _request_pwd(self) -> None:
        url = '{}/cgi-bin/luci/;stok=/login?form=keys'.format(self.host)
        response = post(
            url,
            data='operation=read',
            headers=self._headers_login,
            timeout=self.timeout,
            verify=self._verify_ssl,
        )
        try:
            payload = response.json()
            block = payload[self._data_block]
            password_key = block['password']
            self._pwdNN = password_key[0]
            self._pwdEE = password_key[1]
        except Exception as e:
            error = (
                'TplinkRouter - {} - Unknown error for pwd! Error - {}; Response - {}'
                .format(self.__class__.__name__, e, response.text)
            )
            if self._logger:
                self._logger.debug(error)
            raise ClientException(error)

    def _init_crypto(self) -> None:
        self._aes_key = self._random_digits(self.AES_KEY_LEN)
        self._aes_iv = self._random_digits(self.AES_IV_LEN)
        self._hash = hashlib.sha256(('admin' + self.password).encode()).hexdigest()

    def _try_login(self, confirm: bool | None = None):
        url = '{}/cgi-bin/luci/;stok=/login?form=login'.format(self.host)
        encrypted_pwd = self._encrypt_password(self.password)
        payload = self._encode_params(
            {
                'password': encrypted_pwd,
                'operation': 'login',
                'confirm': True if confirm else None,
            }
        )
        encrypted = self._aes_encrypt(payload)
        sign = self._build_sign(len(encrypted), is_login=True)
        return post(
            url,
            data={'sign': sign, 'data': encrypted},
            headers=self._headers_login,
            timeout=self.timeout,
            verify=self._verify_ssl,
        )

    def _build_sign(self, data_len: int, is_login: bool, hash_override: str | None = None) -> str:
        seq_value = int(self._seq) + data_len
        hash_value = hash_override if hash_override is not None else self._hash
        if is_login:
            sign_data = 'k={}&i={}&h={}&s={}'.format(
                self._aes_key,
                self._aes_iv,
                hash_value,
                seq_value,
            )
            return self._rsa_encrypt_chunks(sign_data)

        sign_data = 'h={}&s={}'.format(hash_value, seq_value)
        return self._hmac_sign_chunks(sign_data)

    def _rsa_encrypt_chunks(self, data: str) -> str:
        key = RSA.construct((int(self._nn, 16), int(self._ee, 16)))
        cipher = PKCS1_OAEP.new(key)
        result = ''
        pos = 0
        while pos < len(data):
            chunk = data[pos:pos + self.SIGN_CHUNK_LEN].encode('utf-8')
            encrypted = cipher.encrypt(chunk)
            result += hexlify(encrypted).decode('utf-8')
            pos += self.SIGN_CHUNK_LEN
        return result

    def _encrypt_password(self, password: str) -> str:
        key = RSA.construct((int(self._pwdNN, 16), int(self._pwdEE, 16)))
        cipher = PKCS1_v1_5.new(key)
        encrypted = cipher.encrypt(password.encode('utf-8'))
        hex_value = hexlify(encrypted).decode('utf-8')
        if len(hex_value) < len(self._pwdNN):
            hex_value = hex_value.zfill(len(self._pwdNN))
        return hex_value

    def _hmac_sign_chunks(self, data: str) -> str:
        key = 'k={}&i={}'.format(self._aes_key, self._aes_iv).encode('utf-8')
        result = ''
        pos = 0
        while pos < len(data):
            chunk = data[pos:pos + self.SIGN_CHUNK_LEN].encode('utf-8')
            result += hmac.new(key, chunk, hashlib.sha256).hexdigest()
            pos += self.SIGN_CHUNK_LEN
        return result

    def _aes_encrypt(self, raw: str) -> str:
        cipher = AES.new(self._aes_key.encode('utf-8'), AES.MODE_CBC, self._aes_iv.encode('utf-8'))
        encrypted = cipher.encrypt(pad(raw.encode('utf-8'), AES.block_size))
        return b64encode(encrypted).decode('utf-8')

    def _aes_decrypt(self, data: str) -> str:
        cipher = AES.new(self._aes_key.encode('utf-8'), AES.MODE_CBC, self._aes_iv.encode('utf-8'))
        decrypted = cipher.decrypt(b64decode(data))
        return unpad(decrypted, AES.block_size).decode('utf-8')

    def _decrypt_response(self, payload: dict[str, Any]) -> dict:
        return json.loads(self._aes_decrypt(payload['data']))

    @staticmethod
    def _random_digits(length: int) -> str:
        return ''.join(secrets.choice('0123456789') for _ in range(length))

    @staticmethod
    def _encode_params(params: dict[str, Any]) -> str:
        safe = "-_.!~*'()"
        parts = []
        for key, value in params.items():
            if value is None:
                continue
            if isinstance(value, bool):
                value = 'true' if value else 'false'
            parts.append(
                '{}={}'.format(
                    quote(str(key), safe=safe),
                    quote(str(value), safe=safe),
                )
            )
        return '&'.join(parts)

    def _log_response(self, response, context: str) -> None:
        if not self._logger:
            return
        try:
            text = response.text or ''
            snippet = text[:200]
            self._logger.debug(
                'TplinkRouter BE230 %s response status=%s content_type=%s len=%s body=%r',
                context,
                response.status_code,
                response.headers.get('content-type'),
                len(text),
                snippet,
            )
        except Exception:
            self._logger.debug('TplinkRouter BE230 %s response logging failed', context)
