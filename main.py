import json
import logging
import smtplib
import time
import urllib
from email.mime.text import MIMEText
import requests

logging.basicConfig(
    filename=f'{time.strftime("%Y-%m-%d-%H-%M-%S")}debug.log',
    level=logging.DEBUG,
    format="%(asctime)s:%(levelname)s:%(message)s", filemode='w'
)


def get_all_coupons(store_id, access_token):
    headers = {
        'authority': 'www.vons.com',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="99", "Google Chrome";v="99"',
        'x-swy_version': '1.1',
        'dnt': '1',
        'x-swy_banner': 'vons',
        'x-swy-application-type': 'web',
        'sec-ch-ua-mobile': '?0',
        'authorization': f'Bearer {access_token}',
        'content-type': 'application/vnd.safeway.v2+json',
        'accept': 'application/json',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
        'x-swy_api_key': 'emjou',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-mode': 'cors',
        'sec-fetch-dest': 'empty',
        'referer': 'https://www.vons.com/justforu/coupons-deals.html',
        'accept-language': 'en-US,en;q=0.9,es-419;q=0.8,es;q=0.7',
    }

    params = (
        ('storeId', '2090'),
        ('rand', '482754'),
    )

    response = requests.get('https://www.vons.com/abs/pub/xapi/offers/companiongalleryoffer', headers=headers,
                            params=params)
    logging.debug(f'[Request]: get coupons status code: {response.status_code}')
    return response.json()['companionGalleryOffer']


def add_coupon_by_id(offer_id, store_id, offer_type, access_token):
    headers = {
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="99", "Google Chrome";v="99"',
        'x-swy_banner': 'vons',
        'swy_sso_token': f'{access_token}',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
        'referer': 'https://www.vons.com/justforu/coupons-deals.html?r=https%3A%2F%2Fwww.vons.com%2Fjustforu%2Fcoupons-deals.html',
        'accept-language': 'en-US,en;q=0.9,es-419;q=0.8,es;q=0.7',
    }

    params = (
        ('storeId', store_id),
    )

    json_data = {
        'items': [
            {
                'clipType': 'C',
                'itemId': f'{offer_id}',
                'itemType': offer_type,
            },
            {
                'clipType': 'L',
                'itemId': f'{offer_id}',
                'itemType': f'{offer_type}',
            },
        ],
    }

    response = requests.post('https://www.vons.com/abs/pub/web/j4u/api/offers/clip', headers=headers, params=params,
                             json=json_data)

    logging.debug(f'[Request]: Add coupon status code: {response.status_code}')

    return response.json()


"""
AUTHENTICATION: 
Get the sessionToken by submitting username and password. SessionToken is a short token that 
represents the user has been authenticated via okta's sign-in API as opposed to Okta's sign-in UI page. 
"""


def get_session_token(login_data):
    username = login_data['username']
    password = login_data['password']
    headers = {
        'authority': 'albertsons.okta.com',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="99", "Google Chrome";v="99"',
        'x-okta-user-agent-extended': 'okta-auth-js-1.15.0',
        'sec-ch-ua-mobile': '?0',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
        'accept': 'application/json',
        'x-requested-with': 'XMLHttpRequest',
        'dnt': '1',
        'sec-ch-ua-platform': '"Windows"',
        'origin': 'https://www.safeway.com',
        'sec-fetch-site': 'cross-site',
        'sec-fetch-mode': 'cors',
        'sec-fetch-dest': 'empty',
        'referer': 'https://www.safeway.com/',
        'accept-language': 'en-US,en;q=0.9,es-419;q=0.8,es;q=0.7',
        'cookie': 'DT=DI053aFLGcdTNKzIDnCydfhHw',
    }

    json_data = {
        'username': f'{username}',
        'password': f'{password}',
    }

    response = requests.post('https://albertsons.okta.com/api/v1/authn', headers=headers, json=json_data)
    response.raise_for_status()

    logging.debug(f'[Request]: Login status code: {response.status_code}')
    return response.json()['sessionToken']


"""AUTHORIZATION: First to get an auth code, submit the sessionToken and Safeway's SSO url as the 
redirect_uri to Okta's authorization url. Okta will respond with the redirection_uri containing the auth code. As a 
note, we disable redirects in the request call because we'll get an HTML page instead of a location. Second, 
make a get request with the redirection url containing the auth code. On their server, Safeway will exchange this 
code for an access token using a secret key. The response will have the access token in cookies. Third, the access 
token in the cookies is Json object that is Url encoded. We have to decode this to get the access token. """


def get_access_token(session_token):
    headers = {
        'authority': 'albertsons.okta.com',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="99", "Google Chrome";v="99"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'upgrade-insecure-requests': '1',
        'dnt': '1',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'sec-fetch-site': 'cross-site',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-user': '?1',
        'sec-fetch-dest': 'document',
        'referer': 'https://www.safeway.com/',
        'accept-language': 'en-US,en;q=0.9,es-419;q=0.8,es;q=0.7',
        'cookie': '_okta_original_attribution={%22utm_page%22:%22/%22%2C%22utm_date%22:%2203/09/2022%22}; DT=DI053aFLGcdTNKzIDnCydfhHw; t=default; JSESSIONID=F0A3F8D245BD10C284BCF4F0FFB8DE61',
    }

    params = (
        ('client_id', '0oap6ku01XJqIRdl42p6'),
        ('redirect_uri', 'https://www.safeway.com/bin/safeway/unified/sso/authorize'),
        ('response_type', 'code'),
        ('response_mode', 'query'),
        ('state', 'mucho-religion-hermon-girish'),
        ('nonce', 'UXjlnZSbw9JhbLc5uy3A9KieH8USBOL58UlJzaAKIMQjyx48nWrK7TOnRl1C2q8e'),
        ('prompt', 'none'),
        ('sessionToken', f'{session_token}'),
        ('scope', 'openid profile email offline_access used_credentials'),
    )

    auth_code_response = requests.get('https://albertsons.okta.com/oauth2/ausp6soxrIyPrm8rS2p6/v1/authorize',
                                      headers=headers,
                                      params=params, allow_redirects=False)
    location = auth_code_response.headers['Location']

    access_token_response = requests.get(location, allow_redirects=False)
    logging.debug(f'[Request]: Get access token status code: {access_token_response.status_code}')

    encoded_json_token_cookie = access_token_response.cookies.get_dict()['SWY_SHARED_SESSION']
    json_token_cookie = parse_url_encoded_json(encoded_json_token_cookie)
    return json_token_cookie['accessToken']


def parse_url_encoded_json(encoded):
    unencoded = urllib.parse.unquote(encoded)
    return json.loads(unencoded)


def get_json_from_file(filename):
    f = open(filename, encoding='utf-8')
    return json.load(f)


def get_login_data_from_config_json(config_json):
    return config_json['loginData']


def get_email_login_data_from_config_json(config_json):
    return config_json['emailLoginData']


def get_email_recipient(config_json):
    return config_json['emailRecipient']


def check_coupon_clipped(coupon):
    return coupon['status'] == 'C'


def get_coupon_id(coupon):
    return coupon['offerId']


def get_coupon_type(coupon):
    return coupon['offerPgm']


def get_smtp_session(email_login_data):
    SMTP_PORT = 587
    sender_address = email_login_data['email']
    sender_password = email_login_data['password']
    smtp_session = smtplib.SMTP('smtp.mail.yahoo.com', SMTP_PORT)
    smtp_session.starttls()
    smtp_session.login(sender_address, sender_password)
    return smtp_session


def send_email_message(smtp_session, config_json, message):
    email_login_data = get_email_login_data_from_config_json(config_json)
    EMAIL_FROM = email_login_data['email']
    EMAIL_TO = get_email_recipient(config_json)
    EMAIL_SUBJECT = "EzForYu:"
    mime_message = MIMEText(message)
    mime_message['Subject'] = EMAIL_SUBJECT + "Alert"
    mime_message['From'] = EMAIL_FROM
    mime_message['To'] = EMAIL_TO

    smtp_session.sendmail(EMAIL_FROM, EMAIL_TO, mime_message.as_string())
    smtp_session.quit()


def main():
    STORE_ID = 2090
    config_json = get_json_from_file('config.json')
    status = 'To be determined'
    try:
        login_data = get_login_data_from_config_json(config_json)
        session_token = get_session_token(login_data)
        access_token = get_access_token(session_token)
        coupons = get_all_coupons(store_id=STORE_ID, access_token=access_token)
        for key, coupon in coupons.items():
            if not check_coupon_clipped(coupon):
                coupon_id = get_coupon_id(coupon)
                coupon_type = get_coupon_type(coupon)
                add_coupon_by_id(offer_id=coupon_id, store_id=STORE_ID, offer_type=coupon_type,
                                 access_token=access_token)
                logging.debug(f'Coupon with id of {coupon_id} added!')
            time.sleep(1)
        logging.debug('Completed')
        status = 'Success'
    except:
        logging.exception("Error occurred in main block.")
        status = 'Error'

    try:
        email_login_data = get_email_login_data_from_config_json(config_json)
        smtp_session = get_smtp_session(email_login_data)
        send_email_message(smtp_session=smtp_session, config_json=config_json, message=status)
    except:
        logging.exception("Error occurred sending an email.")


if __name__ == '__main__':
    main()
