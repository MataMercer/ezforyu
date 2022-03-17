import json
import time
import urllib
import requests


def getAllCoupons(storeId, accessToken):
    headers = {
        'authority': 'www.vons.com',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="99", "Google Chrome";v="99"',
        'x-swy_version': '1.1',
        'dnt': '1',
        'x-swy_banner': 'vons',
        'x-swy-application-type': 'web',
        'sec-ch-ua-mobile': '?0',
        'authorization': f'Bearer {accessToken}',
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
    print(f'[Request]: get coupons status code: {response.status_code}')
    return response.json()['companionGalleryOffer']


def addCouponById(offerId, storeId, offerType, accessToken):
    headers = {
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="99", "Google Chrome";v="99"',
        'x-swy_banner': 'vons',
        'swy_sso_token': f'{accessToken}',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
        'referer': 'https://www.vons.com/justforu/coupons-deals.html?r=https%3A%2F%2Fwww.vons.com%2Fjustforu%2Fcoupons-deals.html',
        'accept-language': 'en-US,en;q=0.9,es-419;q=0.8,es;q=0.7',
    }

    params = (
        ('storeId', storeId),
    )

    json_data = {
        'items': [
            {
                'clipType': 'C',
                'itemId': f'{offerId}',
                'itemType': offerType,
            },
            {
                'clipType': 'L',
                'itemId': f'{offerId}',
                'itemType': f'{offerType}',
            },
        ],
    }

    response = requests.post('https://www.vons.com/abs/pub/web/j4u/api/offers/clip', headers=headers, params=params,
                             json=json_data)

    print(f'[Request]: Add coupon status code: {response.status_code}')
    return response.json()


"""
AUTHENTICATION: 
Get the sessionToken by submitting username and password. SessionToken is a short token that 
represents the user has been authenticated via okta's sign-in API as opposed to Okta's sign-in UI page. 
"""


def getSessionToken(loginData):
    username = loginData['username']
    password = loginData['password']
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

    print(f'[Request]: Login status code: {response.status_code}')
    return response.json()['sessionToken']


"""AUTHORIZATION: First to get an auth code, submit the sessionToken and Safeway's SSO url as the 
redirect_uri to Okta's authorization url. Okta will respond with the redirection_uri containing the auth code. As a 
note, we disable redirects in the request call because we'll get an HTML page instead of a location. Second, 
make a get request with the redirection url containing the auth code. On their server, Safeway will exchange this 
code for an access token using a secret key. The response will have the access token in cookies. Third, the access 
token in the cookies is Json object that is Url encoded. We have to decode this to get the access token. """


def getAccessToken(sessionToken):
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
        ('sessionToken', f'{sessionToken}'),
        ('scope', 'openid profile email offline_access used_credentials'),
    )

    authCodeRes = requests.get('https://albertsons.okta.com/oauth2/ausp6soxrIyPrm8rS2p6/v1/authorize', headers=headers,
                               params=params, allow_redirects=False)
    location = authCodeRes.headers['Location']

    accessTokenRes = requests.get(location, allow_redirects=False)
    print(f'[Request]: Get access token status code: {accessTokenRes.status_code}')

    encodedJsonTokenCookie = accessTokenRes.cookies.get_dict()['SWY_SHARED_SESSION']
    jsonTokenCookie = parseUrlEncodedJson(encodedJsonTokenCookie)
    return jsonTokenCookie['accessToken']


def parseUrlEncodedJson(encoded):
    unencoded = urllib.parse.unquote(encoded)
    return json.loads(unencoded)


def getJSONFromFile(filename):
    f = open(filename, encoding='utf-8')
    return json.load(f)


def getLoginDataFromConfigFile():
    return getJSONFromFile('config.json')


def checkCouponClipped(coupon):
    return coupon['status'] == 'C'


def getCouponId(coupon):
    return coupon['offerId']


def getCouponType(coupon):
    return coupon['offerPgm']


def main():
    loginData = getLoginDataFromConfigFile()
    sessionToken = getSessionToken(loginData=loginData)
    accessToken = getAccessToken(sessionToken=sessionToken)
    coupons = getAllCoupons(storeId=2090, accessToken=accessToken)
    for attribute, coupon in coupons.items():
        if not checkCouponClipped(coupon):
            couponId = getCouponId(coupon)
            couponType = getCouponType(coupon)
            addCouponById(offerId=couponId, storeId=2090, offerType=couponType, accessToken=accessToken)
            print(f'Coupon with id of {couponId} added!')
        time.sleep(1)
    print('Completed')


if __name__ == '__main__':
    main()
