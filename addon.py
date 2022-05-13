#!/usr/bin/env python
# -*- coding: utf-8 -*-

#   GNU General Public License

#   C More KODI Addon
#   Copyright (C) 2022 Mariusz89B

#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.

#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.

#   You should have received a copy of the GNU General Public License
#   along with this program. If not, see https://www.gnu.org/licenses.

#   MIT License

#   Permission is hereby granted, free of charge, to any person obtaining a copy
#   of this software and associated documentation files (the "Software"), to deal
#   in the Software without restriction, including without limitation the rights
#   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#   copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:

#   The above copyright notice and this permission notice shall be included in all
#   copies or substantial portions of the Software.

#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#   SOFTWARE.

#   Disclaimer
#   This add-on is unoffical and is not endorsed or supported by C More Entertainment in any way. Any trademarks used belong to their owning companies and organisations.

import sys

import xbmc
import xbmcaddon
import xbmcgui
import xbmcplugin
import xbmcvfs

import urllib.parse as urlparse
from urllib.parse import urlencode, quote_plus, quote, unquote

from datetime import datetime, timedelta

import requests
from requests.exceptions import HTTPError, ConnectionError, Timeout, RequestException

import re
import time
import threading
import six
import uuid

from ext import c_ext_info

base_url = sys.argv[0]
addon_handle = int(sys.argv[1])
params = dict(urlparse.parse_qsl(sys.argv[2][1:]))
addon = xbmcaddon.Addon(id='plugin.video.cmore')

exlink = params.get('url', None)
extitle = params.get('label', None)
exid = params.get('m_id', None)
excatchup = params.get('catchup', None)
exstart = params.get('start', None)
exend = params.get('end', None)

profile_path = xbmcvfs.translatePath(addon.getAddonInfo('profile'))

localized = xbmcaddon.Addon().getLocalizedString
x_localized = xbmc.getLocalizedString

path = addon.getAddonInfo('path')
resources = path + '/resources/'

thumb = path + 'icon.png'
poster = path + 'icon.png'
banner = path + 'icon.png'
fanart = resources + 'fanart.jpg'
icon = path + 'icon.png'

login = addon.getSetting('cmore_username').strip()
password = addon.getSetting('cmore_password').strip()

country = int(addon.getSetting('cmore_locale'))

base = ['https://cmore.dk', 'https://cmore.no', 'https://www.cmore.se']
referer = ['https://cmore.dk/', 'https://cmore.no/', 'https://www.cmore.se/']
host = ['www.cmore.dk', 'www.cmore.no', 'www.cmore.se']

cc = ['dk', 'no', 'se']
ca = ['DK', 'NO', 'SE']

sess = requests.Session()
timeouts = (5, 5)

UA = xbmc.getUserAgent()

class Threading(object):
    def __init__(self):
        self.thread = threading.Thread(target=self.run, args=())
        self.thread.daemon = True
        self.thread.start()

    def run(self):
        while not xbmc.Monitor().abortRequested():
            ab = check_refresh()
            if not ab:
                result = check_login()
                if result is not None:
                    validTo, beartoken, refrtoken, cookies = result

                    addon.setSetting('cmore_validto', str(validTo))
                    addon.setSetting('cmore_beartoken', str(beartoken))
                    addon.setSetting('cmore_refrtoken', str(refrtoken))
                    addon.setSetting('cmore_cookies', str(cookies))

                time.sleep(30)

            if xbmc.Monitor().waitForAbort(1):
                break

def build_url(query):
    return base_url + '?' + urlencode(query)

def add_item(label, url, mode, folder, playable, m_id=None, catchup=None, start=None, end=None, thumb=None, poster=None, banner=None, icon=None, fanart=None, plot=None, context_menu=None, item_count=None, info_labels=False, page=0):
    list_item = xbmcgui.ListItem(label=label)

    if playable:
        list_item.setProperty('IsPlayable', 'true')

        if context_menu:
            info = x_localized(19047)
            context_menu.insert(0, (info, 'Action(Info)'))

    if context_menu:
        list_item.addContextMenuItems(context_menu, replaceItems=True)

    if not info_labels:
        info_labels = {'title': label}

    list_item.setInfo(type='Video', infoLabels=info_labels)

    thumb = thumb if thumb else icon
    poster = poster if poster else icon
    banner = banner if banner else icon

    list_item.setArt({'thumb': thumb, 'poster': poster, 'banner': banner, 'fanart': fanart})

    xbmcplugin.addDirectoryItem(
        handle=addon_handle,
        url = build_url({'title': label, 'mode':mode, 'url':url, 'm_id':m_id, 'catchup':catchup, 'start':start, 'end':end, 'page':page, 'plot':plot, 'image':icon}),
        listitem=list_item,
        isFolder=folder)

def send_req(url, post=False, json=None, headers=None, data=None, params=None, cookies=None, verify=True, allow_redirects=False, timeout=None):
    try:
        if post:
            response = sess.post(url, headers=headers, json=json, data=data, params=params, cookies=cookies, verify=verify, allow_redirects=allow_redirects, timeout=timeout)
        else:
            response = sess.get(url, headers=headers, json=json, data=data, params=params, cookies=cookies, verify=verify, allow_redirects=allow_redirects, timeout=timeout)

    except HTTPError as e:
        print('HTTPError: {}'.format(str(e)))
        response = False

    except ConnectionError as e:
        print('ConnectionError: {}'.format(str(e)))
        response = False

    except Timeout as e:
        print('Timeout: {}'.format(str(e))) 
        response = False

    except RequestException as e:
        print('RequestException: {}'.format(str(e))) 
        response = False

    except:
        xbmcgui.Dialog().notification(localized(30012), localized(30006))
        response = False

    return response

def create_data():
    dashjs = str(uuid.uuid4())
    addon.setSetting('cmore_devush', str(dashjs))

    tv_client_boot_id = str(uuid.uuid4())
    addon.setSetting('cmore_tv_client_boot_id', str(tv_client_boot_id))

    timestamp = int(time.time())*1000
    addon.setSetting('cmore_timestamp', str(timestamp))

    sessionid = six.text_type(uuid.uuid4())
    addon.setSetting('cmore_sess_id', str(sessionid))

    return dashjs, tv_client_boot_id, timestamp, sessionid

def check_login():
        result = None

        valid_to = addon.getSetting('cmore_validto')
        beartoken = addon.getSetting('cmore_beartoken')
        refrtoken = addon.getSetting('cmore_refrtoken')
        cookies = addon.getSetting('cmore_cookies')

        refresh = refresh_timedelta(valid_to)

        if not valid_to:
            valid_to = datetime.now() - timedelta(days=1)

        if not beartoken and refresh < timedelta(minutes=1):
            login, profile = login_data(reconnect=True)

            result = valid_to, beartoken, refrtoken, cookies

        return result

def check_refresh():
        valid_to = addon.getSetting('cmore_validto')
        beartoken = addon.getSetting('cmore_beartoken')

        refresh = refresh_timedelta(valid_to)

        if not valid_to:
            valid_to = datetime.now() - timedelta(days=1)

        if refresh is not None:
            refr = True if not beartoken or refresh < timedelta(minutes=1) else False
        else:
            refr = False

        return refr

def refresh_timedelta(valid_to):
        result = None

        if 'Z' in valid_to:
            valid_to = iso8601.parse_date(valid_to)
        elif valid_to != '':
            if not valid_to:
                try:
                    date_time_format = '%Y-%m-%dT%H:%M:%S.%f+' + valid_to.split('+')[1]
                except:
                    date_time_format = '%Y-%m-%dT%H:%M:%S.%f+' + valid_to.split('+')[0]

                valid_to = datetime(*(time.strptime(valid_to, date_time_format)[0:6]))
                timestamp = int(time.mktime(valid_to.timetuple()))
                token_valid_to = datetime.fromtimestamp(int(timestamp))
            else:
                token_valid_to = datetime.now()
        else:
            token_valid_to = datetime.now()

        result = token_valid_to - datetime.now()

        return result

def login_service():
    try:
        dashjs = addon.getSetting('cmore_devush')
        if dashjs == '':
            try:
                msg = localized(30000)
                xbmcgui.Dialog().ok(localized(30012), str(msg))
            except:
                pass

            create_data()

        login, profile = login_data(reconnect=False)

        if login:
            run = Threading()

        return login, profile

    except Exception as ex:
        print('login_service exception: {}'.format(ex))
        xbmcgui.Dialog().notification(localized(30012), localized(30006))
    return False, None

def login_data(reconnect, retry=0):
    dashjs, tv_client_boot_id, timestamp, sessionid = create_data()

    try:
        url = 'https://log.tvoip.telia.com:6003/logstash'

        headers = {
            'accept': '*/*',
            'accept-language': 'sv,en;q=0.9,en-GB;q=0.8,en-US;q=0.7,pl;q=0.6,fr;q=0.5',
            'connection': 'keep-alive',
            'content-type': 'text/plain;charset=UTF-8',
            'DNT': '1',
            'origin': 'https://login.cmore.{cc}'.format(cc=cc[country]),
            'referer': 'https://login.cmore.{cc}/'.format(cc=cc[country]),
            'user-agent': UA,
        }

        data = {
            "bootId":tv_client_boot_id,
            "networkType":"UNKNOWN",
            "deviceId":dashjs,
            "deviceType":"WEB",
            "model":"unknown_model",
            "productName":"Microsoft Edge 101.0.1210.32",
            "platformName":"Windows",
            "platformVersion":"NT 10.0",
            "nativeVersion":"unknown_platformVersion",
            "uiName":"one-web-login",
            "client":"WEB",
            "uiVersion":"1.35.0",
            "environment":"PROD",
            "country":ca[country],
            "brand":"CMORE",
            "logType":"STATISTICS_HTTP",
            "payloads": [{
                    "sequence": 1,
                    "timestamp": timestamp,
                    "level": "ERROR",
                    "loggerId": "telia-data-backend/System",
                    "message": "Failed to get service status due to timeout after 1000 ms"
                }]
            }

        response = send_req(url, post=True, headers=headers, json=data, verify=True, timeout=timeouts)

        url = 'https://logingateway-cmore.t6a.net/logingateway/rest/v1/authenticate'

        headers = {
            'authority': 'logingateway-cmore.t6a.net',
            'accept': '*/*',
            'accept-language': 'sv,en;q=0.9,en-GB;q=0.8,en-US;q=0.7,pl;q=0.6,fr;q=0.5',
            'dnt': '1',
            'origin': 'https://login.cmore.{cc}'.format(cc=cc[country]),
            'referer': 'https://login.cmore.{cc}/'.format(cc=cc[country]),
            'user-agent': UA,
            'x-country': ca[country],
        }

        params = {
            'redirectUri': 'https://www.cmore.{cc}/'.format(cc=cc[country]),
        }

        data = {
            'deviceId': dashjs,
            'deviceType': 'WEB',
            'password': password,
            'username': login,
            'whiteLabelBrand': 'CMORE',
        }

        response = send_req(url, post=True, params=params, headers=headers, json=data, verify=True, timeout=timeouts)

        code = ''

        if response:
            j_response = response.json()
            code = j_response['redirectUri'].replace('https://www.cmore.{cc}/?code='.format(cc=cc[country]), '')

        url = 'https://logingateway.cmore.{cc}/logingateway/rest/v1/oauth/token'.format(cc=cc[country])

        headers = {
            'authority': 'logingateway.cmore.{cc}'.format(cc=cc[country]),
            'accept': 'application/json',
            'accept-language': 'sv,en;q=0.9,en-GB;q=0.8,en-US;q=0.7,pl;q=0.6,fr;q=0.5',
            'dnt': '1',
            'origin': 'https://www.cmore.{cc}'.format(cc=cc[country]),
            'referer': 'https://www.cmore.{cc}/'.format(cc=cc[country]),
            'tv-client-boot-id': tv_client_boot_id,
            'tv-client-name': 'web',
            'user-agent': UA,
            'x-country': ca[country],
        }

        params = {
            'code': code,
        }

        response = send_req(url, post=True, params=params, headers=headers, timeout=timeouts)

        if not response:
            if reconnect and retry < 3:
                retry += 1
                login_service(reconnect=True, retry=retry)
            else:
                xbmcgui.Dialog().notification(localized(30012), localized(30007))
                return False, None

        j_response = response.json()

        try:
            if 'Username/password was incorrect' in j_response['errorMessage']:
                xbmcgui.Dialog().notification(localized(30012), localized(30007))
                return False, None
        except:
            pass

        validTo = j_response.get('cmore_validTo', '')
        addon.setSetting('cmore_validto', str(validTo))

        beartoken = j_response.get('accessToken', '')
        addon.setSetting('cmore_beartoken', str(beartoken))

        refrtoken = j_response.get('refreshToken', '')
        addon.setSetting('cmore_refrtoken', str(refrtoken))

        url = 'https://ottapi.prod.telia.net/web/{cc}/tvclientgateway/rest/secure/v1/provision'.format(cc=cc[country])

        headers = {
            'accept': '*/*',
            'accept-language': 'sv,en;q=0.9,en-GB;q=0.8,en-US;q=0.7,pl;q=0.6,fr;q=0.5',
            'authorization': 'Bearer ' + beartoken,
            'DNT': '1',
            'origin': 'https://www.cmore.{cc}'.format(cc=cc[country]),
            'referer': 'https://www.cmore.{cc}/'.format(cc=cc[country]),
            'user-agent': UA,
            'tv-client-boot-id': tv_client_boot_id,
        }

        data = {
            'deviceId': dashjs,
            'drmType': 'WIDEVINE',
            'uiName': 'one-web',
            'uiVersion': '1.43.0',
            'nativeVersion': 'NT 10.0',
            'model': 'windows_desktop',
            'networkType': 'unknown',
            'productName': 'Microsoft Edge 101.0.1210.32',
            'platformName': 'Windows',
            'platformVersion': 'NT 10.0',
        }

        response = send_req(url, post=True, headers=headers, json=data, verify=True, timeout=timeouts)

        try:
            response = response.json()
            if response['errorCode'] == 61004:
                print('errorCode 61004')
                xbmcgui.Dialog().notification(localized(30012), localized(30013))
                addon.setSetting('cmore_sess_id', '')
                addon.setSetting('cmore_devush', '')
                if reconnect:
                    login_service(reconnect=True)
                else:
                    return False, None

            elif response['errorCode'] == 9030:
                print('errorCode 9030')
                if not reconnect:
                    xbmcgui.Dialog().notification(localized(30012), localized(30006))
                addon.setSetting('cmore_sess_id', '')
                addon.setSetting('cmore_devush', '')
                if reconnect:
                    login_service(reconnect=True)
                else:
                    return False, None

            elif response['errorCode'] == 61002:
                print('errorCode 61002')
                if not reconnect:
                    xbmcgui.Dialog().notification(localized(30012), localized(30006))
                tv_client_boot_id = str(uuid.uuid4())
                addon.setSetting('cmore_tv_client_boot_id', str(tv_client_boot_id))
                if reconnect:
                    login_service(reconnect=True)
                else:
                    return False, None

        except:
            pass

        cookies = {}

        cookies = sess.cookies
        addon.setSetting('cmore_cookies', str(cookies))

        url = 'https://tvclientgateway-cmore.clientapi-prod.live.tv.telia.net/tvclientgateway/rest/secure/v1/pubsub'

        headers = {
            'accept': '*/*',
            'accept-language': 'sv,en;q=0.9,en-GB;q=0.8,en-US;q=0.7,pl;q=0.6,fr;q=0.5',
            'authorization': 'Bearer ' + beartoken,
            'origin': 'https://www.cmore.{cc}'.format(cc=cc[country]),
            'referer': 'https://www.cmore.{cc}/'.format(cc=cc[country]),
            'user-agent': UA,
            'tv-client-boot-id': tv_client_boot_id,
        }

        response = send_req(url, headers=headers, cookies=sess.cookies, allow_redirects=False, timeout=timeouts)

        if not response:
            if reconnect:
                login_service(reconnect=True)
            else:
                return False, None

        response = response.json()

        usern = response['channels']['engagement']
        addon.setSetting('cmore_usern', str(usern))

        subtoken = response['config']['subscriberToken']
        addon.setSetting('cmore_subtoken', str(subtoken))

        url = 'https://engagementgateway-cmore.clientapi-prod.live.tv.telia.net/engagementgateway/rest/secure/v2/engagementinfo'

        headers = {
            'authority': 'engagementgateway-cmore.clientapi-prod.live.tv.telia.net',
            'accept': '*/*',
            'accept-language': 'sv,en;q=0.9,en-GB;q=0.8,en-US;q=0.7,pl;q=0.6,fr;q=0.5',
            'authorization': 'Bearer ' + beartoken,
            'dnt': '1',
            'origin': 'https://www.cmore.{cc}'.format(cc=cc[country]),
            'referer': 'https://www.cmore.{cc}/'.format(cc=cc[country]),
            'tv-client-boot-id': tv_client_boot_id,
            'user-agent': UA,
            'x-country': ca[country],
        }

        response = requests.get(url, headers=headers)

        if response:
            j_response = response.json()

        profile = j_response['firstName']

        return True, profile

    except Exception as ex:
        print('login_data exception: {}'.format(ex))

    return False, None

def live_channels():
    login, profile = login_service()
    if not login:
        xbmcgui.Dialog().notification(localized(30012), localized(30006))
        return

    #check_login()

    beartoken = addon.getSetting('cmore_beartoken')
    tv_client_boot_id = addon.getSetting('cmore_tv_client_boot_id')

    try:
        url = 'https://engagementgateway-cmore.clientapi-prod.live.tv.telia.net/engagementgateway/rest/secure/v2/engagementinfo'

        headers = {
            "user-agent": UA,
            "accept": "*/*",
            "accept-language": "sv,en;q=0.9,en-GB;q=0.8,en-US;q=0.7,pl;q=0.6",
            "authorization": "Bearer " + beartoken,
        }

        headers = {
            'authority': 'engagementgateway-cmore.clientapi-prod.live.tv.telia.net',
            'accept': '*/*',
            'accept-language': 'sv,en;q=0.9,en-GB;q=0.8,en-US;q=0.7,pl;q=0.6,fr;q=0.5',
            'authorization': 'Bearer ' + beartoken,
            'dnt': '1',
            'origin': 'https://settings.cmore.{cc}'.format(cc=cc[country]),
            'referer': 'https://settings.cmore.{cc}/'.format(cc=cc[country]),
            'tv-client-boot-id': tv_client_boot_id,
            'user-agent': UA,
            'x-country': ca[country],
        }

        engagementjson = send_req(url, headers=headers, verify=True)
        if not engagementjson:
            return result

        engagementjson = engagementjson.json()

        try:
            engagementLiveChannels = engagementjson['channelIds']
            print(engagementLiveChannels)
        except KeyError as k:
            engagementLiveChannels = []
            print('errorMessage: {k}'.format(k=str(k)))

        engagementPlayChannels = []

        try:
           for channel in engagementjson['stores']:
               engagementPlayChannels.append(channel['id'])

        except KeyError as k:
            print('errorMessage: {k}'.format(k=str(k)))

        url = 'https://graphql-cmore.t6a.net/graphql'

        headers = {
            'authority': 'graphql-cmore.t6a.net',
            'accept': '*/*',
            'accept-language': 'sv,en;q=0.9,en-GB;q=0.8,en-US;q=0.7,pl;q=0.6,fr;q=0.5',
            'authorization': 'Bearer ' + beartoken,
            'content-type': 'application/json',
            'dnt': '1',
            'origin': 'https://www.cmore.{cc}'.format(cc=cc[country]),
            'referer': 'https://www.cmore.{cc}/'.format(cc=cc[country]),
            'tv-client-boot-id': tv_client_boot_id,
            'tv-client-browser': 'Microsoft Edge',
            'tv-client-browser-version': '101.0.1210.32',
            'tv-client-name': 'web',
            'tv-client-os-name': 'Windows',
            'tv-client-os-version': 'NT 10.0',
            'tv-client-tz': 'Europe/Stockholm',
            'tv-client-version': '1.43.2',
            'user-agent': UA,
            'x-country': ca[country],
        }

        params = (
            ('operationName', 'getTvChannels'),
            ('variables', '{"limit":500,"offset":0}'),
            ('query', "\n    query getTvChannels($limit: Int!, $offset: Int!) {\n  channels(limit: $limit, offset: $offset) {\n    pageInfo {\n      totalCount\n      hasNextPage\n    }\n    channelItems {\n      id\n      name\n      \nicons {dark\n{source\n}}   }\n  }\n}\n    \n")
        )

        response = send_req(url, headers=headers, params=params, verify=False)

        if not response:
            xbmcgui.Dialog().notification(localized(30012), localized(30006))
            return

        j_response = response.json()
        channels = j_response['data']['channels']['channelItems']

        count = 0

        for channel in channels:
            if channel['id'] in engagementLiveChannels:

                count += 1

                exlink = channel["id"]
                name = channel["name"]

                try:
                    res = channel["resolutions"]

                    p = re.compile('\d+')
                    res_int = p.search(res[0]).group(0)

                except:
                    res_int = 0

                p = re.compile(r'(\s{0}$)'.format(ca[country]))

                r = p.search(name)
                match = r.group(1) if r else None

                if match:
                    ccCh = ''
                else:
                    ccCh = ca[country]

                if int(res_int) > 576 and ' HD' not in name:
                    title = channel["name"] + ' HD ' + ccCh
                else:
                    title = channel["name"] + ' ' + ccCh

                icon = path + 'icon.png'

                icons = channel.get('icons')
                if icons:
                    img = icons.get('dark').get('source')
                    icon = unquote(img)

                add_item(label=name, url=exlink, mode='channels', icon=icon, folder=True, playable=False, info_labels={'title':name, 'plot':name}, fanart=fanart, item_count=count)

        xbmcplugin.endOfDirectory(addon_handle)

    except Exception as ex:
        print('live_channels exception: {}'.format(ex))

def live_channel(exlink):
    cc = ['dk', 'no', 'se']

    base = ['https://cmore.dk', 'https://cmore.no', 'https://www.cmore.se']

    country            = int(addon.getSetting('cmore_locale'))
    dashjs             = addon.getSetting('cmore_devush')
    beartoken          = addon.getSetting('cmore_beartoken')
    tv_client_boot_id  = addon.getSetting('cmore_tv_client_boot_id')

    n = datetime.now()
    now = int(time.mktime(n.timetuple())) * 1000

    timestamp = str(((int(time.time() // 86400)) * 86400) * 1000)

    url = 'https://graphql-cmore.t6a.net/graphql'

    headers = {
        'authority': 'graphql-telia.t6a.net',
        'accept': '*/*',
        'accept-language': 'sv,en;q=0.9,en-GB;q=0.8,en-US;q=0.7,pl;q=0.6,fr;q=0.5',
        'authorization': 'Bearer ' + beartoken,
        'content-type': 'application/json',
        'dnt': '1',
        'origin': base[country],
        'referer': base[country]+'/',
        'tv-client-boot-id': tv_client_boot_id,
        'tv-client-browser': 'Microsoft Edge',
        'tv-client-browser-version': '101.0.1210.39',
        'tv-client-name': 'web',
        'tv-client-os-name': 'Windows',
        'tv-client-os-version': 'NT 10.0',
        'tv-client-tz': 'Europe/Stockholm',
        'tv-client-version': '1.45.1',
        'user-agent': UA,
        'x-country': ca[country],
    }

    params = (
        ('operationName', 'getTvChannel'),
        ('variables', '{"timestamp":'+timestamp+',"offset":0,"id":"'+str(exlink)+'"}'),
        ('query', "\n query getTvChannel($timestamp: Timestamp!, $limit: Int, $offset: Int!, $id: String!) {\n"
          "channel(id: $id) {\n id\n  name\n  icons {\n    dark {\n      source\n    }\n }\n  playback {\n play "
          "{\n playbackSpec {\n videoId\n videoIdType\n watchMode\n accessControl\n      }\n    }\n  }"
          "recordAndWatch\n       programs(timestamp: $timestamp, limit: $limit, offset: $offset) {\n  id\n"
          "programItems {\n id \n title\n startTime{timestamp}\n endTime{timestamp}\n live\n rerun\n __typename\n"
          "media{\n ...sport \n ...movie \n ...episode}    }\n}}}\n"
          "\nfragment sport on SportEvent{id\n title\n descriptionLong\n images{\nshowcard16x9{\nsource}}\n playback\n{\nplay{\nsubscription {\nitem{\nid \nvalidFrom{\ntimestamp} \nvalidTo{\ntimestamp} \nplaybackSpec{\nvideoId \nvideoIdType \nwatchMode \naccessControl \n__typename}\n__typename }} }}\n genre\n mediaType\n __typename\n} "
          "\nfragment movie on Movie{id\n title\n descriptionLong\n images{\nshowcard16x9{\nsource}}\n playback\n{\nplay{\nsubscription {\nitem{\nid \naudioLang{\nname} \nvalidFrom{\ntimestamp} \nvalidTo{\ntimestamp} \nplaybackSpec{\nvideoId \nvideoIdType \nwatchMode \naccessControl \n__typename}\n__typename }} }}\n genre\n mediaType\n __typename\n} "
          "\nfragment episode on Episode{id\n title\n descriptionLong\n images{\nshowcard16x9{\nsource}}\n  playback\n{\nplay{\nsubscription {\nitem{\nid \naudioLang{\nname} \nvalidFrom{\ntimestamp} \nvalidTo{\ntimestamp} \nplaybackSpec{\nvideoId \nvideoIdType \nwatchMode \naccessControl \n__typename}\n__typename }} }}\n genre\n mediaType\n __typename\n} ")
        )

    response = requests.get(url, headers=headers, params=params, verify=False).json()

    if response.get('errors', ''):
        return None, None

    program_items = response['data']['channel']['programs']['programItems']

    count = 0

    for program in program_items:
        count += 1

        now = int(time.time())

        start = program['startTime']['timestamp'] // 1000
        dt_start = datetime.fromtimestamp(start)
        st_start = dt_start.strftime('%Y-%m-%d %H:%M')

        end = program['endTime']['timestamp'] // 1000
        dt_end = datetime.fromtimestamp(end)
        st_end = dt_end.strftime('%H:%M')

        duration = end - start

        title = program['title']
        if int(now) >= int(start) and int(now) <= int(end):
            now_playing = localized(30029)
            name = title + '[B][COLOR red] [{0}] [/COLOR][/B]'.format(now_playing)
        elif int(end) >= int(now):
            name = '[COLOR grey]' + title + '[/COLOR]'
        else:
            name = title + '[COLOR limegreen] ● [/COLOR]'

        aired = st_start
        date = st_start + ' - ' + st_end

        catchup = 'LIVE'

        m_id = ''
        plot = ''
        genre = ''
        lang = ''
        img = ''

        media = program.get('media')
        if media:
            m_id = media['id'] 
            plot = media['descriptionLong']
            genre = media['genre']

            audio_lang = media.get('audioLang') 
            if audio_lang:
                lang = audio_lang.get('name')

            playback = media.get('playback')

            if playback:
                play = playback.get('play')
                if play:
                    subscription = play.get('subscription')
                    if subscription:
                        for item in subscription:
                            if item:
                                items = item.get('item')
                                if items:
                                    playback_spec = items.get('playbackSpec')
                                    if playback_spec:
                                        catchup = playback_spec.get('watchMode')

            images = media.get('images')
            if images:
                card = images['showcard16x9']
                if card:
                    src = card['source']
                    img = unquote(src)

        ext = localized(30027)
        context_menu = [('{0}'.format(ext), 'RunScript(plugin.video.cmore,0,?mode=ext,label={0})'.format(title))]

        add_item(label=name, url=exlink, mode='play', m_id=m_id, catchup=catchup, start=start, end=end, icon=img, folder=False, playable=True, info_labels={'title':title, 'originaltitle':title, 'plot':plot, 'plotoutline':plot, 'aired':aired, 'dateadded':date, 'duration':duration, 'genre':genre, 'country':lang}, fanart=fanart, context_menu=context_menu, item_count=count)

    xbmcplugin.setContent(addon_handle, 'sets')
    xbmcplugin.endOfDirectory(addon_handle)

def get_stream(exlink, catchup_type):
    stream_url = None

    #check_login()

    dashjs = addon.getSetting('cmore_devush')
    beartoken = addon.getSetting('cmore_beartoken')
    tv_client_boot_id = addon.getSetting('cmore_tv_client_boot_id')

    try:
        sessionid = six.text_type(uuid.uuid4())
        addon.setSetting('cmore_sess_id', str(sessionid))

        if catchup_type == 'LIVE':
            stream_type = 'CHANNEL'

            url = 'https://streaminggateway-telia.clientapi-prod.live.tv.telia.net/streaminggateway/rest/secure/v2/streamingticket/{type}/{exlink}?country={cc}'.format(type=stream_type, exlink=(str(exlink)), cc=ca[country])

            headers = {
                'connection': 'keep-alive',
                'tv-client-boot-id': tv_client_boot_id,
                'DNT': '1',
                'authorization': 'Bearer '+ beartoken,
                'tv-client-tz': 'Europe/Stockholm',
                'x-country': cc[country],
                'user-agent': UA,
                'content-type': 'application/json',
                'accept': '*/*',
                'origin': base[country],
                'referer': base[country]+'/',
                'accept-language': 'sv,en;q=0.9,en-GB;q=0.8,en-US;q=0.7,pl;q=0.6',
            }

            params = (
                ('country', ca[country]),
            )

            data = {
                "sessionId": sessionid,
                "whiteLabelBrand":"CMORE",
                "watchMode":catchup_type,
                "accessControl":"SUBSCRIPTION",
                "device": {
                    "deviceId": tv_client_boot_id,
                    "category":"desktop_windows",
                    "packagings":["DASH_MP4_CTR"],
                    "drmType":"WIDEVINE",
                    "capabilities":[],
                    "screen": {
                        "height":1080,
                        "width":1920
                        },
                        "os":"Windows",
                        "model":"windows_desktop"
                        },
                        "preferences": {
                            "audioLanguage":["undefined"],
                            "accessibility":[]}
                }

        else:
            stream_type = 'MEDIA'

            url = 'https://streaminggateway-telia.clientapi-prod.live.tv.telia.net/streaminggateway/rest/secure/v2/streamingticket/{type}/{exlink}?country={cc}'.format(type=stream_type, exlink=(str(exlink)), cc=ca[country])

            headers = {
                'Connection': 'keep-alive',
                'tv-client-boot-id': tv_client_boot_id,
                'DNT': '1',
                'Authorization': 'Bearer '+ beartoken,
                'tv-client-tz': 'Europe/Stockholm',
                'X-Country': cc[country],
                'User-Agent': UA,
                'content-type': 'application/json',
                'Accept': '*/*',
                'Origin': base[country],
                'Referer': base[country]+'/',
                'Accept-Language': 'sv,en;q=0.9,en-GB;q=0.8,en-US;q=0.7,pl;q=0.6',
            }

            params = (
                ('country', ca[country]),
            )

            data = {
                "sessionId": six.text_type(uuid.uuid4()),
                "whiteLabelBrand":"CMORE",
                "watchMode": catchup_type,
                "accessControl":"SUBSCRIPTION",
                "device": {
                    "deviceId": tv_client_boot_id,
                    "category":"desktop_windows",
                    "packagings":["DASH_MP4_CTR"],
                    "drmType":"WIDEVINE",
                    "capabilities":[],
                    "screen": {
                        "height":1080,
                        "width":1920
                        },
                    
                    "os":"Windows",
                    "model":"windows_desktop"
                    },

                    "preferences": {
                        "audioLanguage":[],
                        "accessibility":[]}
                }

        response = send_req(url, post=True, headers=headers, json=data, params=params, verify=True, timeout=timeouts)
        if not response:
            xbmcgui.Dialog().notification(localized(30012), localized(30006))
            return None 

        response = response.json()

        hea = ''

        LICENSE_URL = response.get('streams', '')[0].get('drm', '').get('licenseUrl', '')
        stream_url = response.get('streams', '')[0].get('url', '')
        headr = response.get('streams', '')[0].get('drm', '').get('headers', '')

        if 'X-AxDRM-Message' in headr:
            hea = 'Content-Type=&X-AxDRM-Message=' + dashjs

        elif 'x-dt-auth-token' in headr:
            hea = 'Content-Type=&x-dt-auth-token=' + headr.get('x-dt-auth-token', dashjs)

        else:
            hea = urlencode(headr)

            if 'Content-Type=&' not in hea:
                hea = 'Content-Type=&' + hea

        license_url = LICENSE_URL + '|' + hea + '|R{SSM}|'

        if stream_url is not None and stream_url != "":
            return stream_url, license_url

    except Exception as ex:
        xbmcgui.Dialog().notification(localized(30012), localized(30006))
        print('get_stream exception while looping: {}\n Data: {}'.format(ex, str(stream_url)))

    return None, None

def play(exlink, title, media_id, catchup_type, start, end):

    now = int(time.time())

    if int(now) >= int(start) and int(now) <= int(end):
        response = xbmcgui.Dialog().yesno(localized(30012), localized(30014))
        if response:
            exlink = media_id
            catchup_type = 'STARTOVER'
        else:
            catchup_type = 'LIVE'
    elif int(end) >= int(now):
        xbmcgui.Dialog().ok(localized(30012), localized(30028))
        return
    else:
        if media_id:
            exlink = media_id

    strm_url, license_url = get_stream(exlink, catchup_type)

    PROTOCOL = 'mpd'
    DRM = 'com.widevine.alpha'

    import inputstreamhelper
    is_helper = inputstreamhelper.Helper(PROTOCOL, drm=DRM)
    if is_helper.check_inputstream():
        play_item = xbmcgui.ListItem(path=strm_url)
        play_item.setInfo( type="Video", infoLabels={ "Title": title, } )
        play_item.setContentLookup(False)
        play_item.setProperty('inputstream', is_helper.inputstream_addon)
        play_item.setMimeType('application/xml+dash')
        play_item.setProperty('inputstream.adaptive.license_type', DRM)
        play_item.setProperty('inputstream.adaptive.license_key', license_url)
        play_item.setProperty('inputstream.adaptive.stream_headers', 'Referer: https://www.cmore.se/&User-Agent='+quote(UA))
        play_item.setProperty('inputstream.adaptive.manifest_type', 'mpd')
        play_item.setProperty('IsPlayable', 'true')
        if catchup_type != 'LIVE':
            play_item.setProperty('inputstream.adaptive.play_timeshift_buffer', 'true')

        xbmcplugin.setResolvedUrl(addon_handle, True, listitem=play_item)

def home():
    login, profile = login_service()
    if login:
        add_item(label=localized(30009).format(profile), url='', mode='logged', icon=icon, fanart=fanart, folder=False, playable=False)
        add_item(label=localized(30010), url='', mode='live', icon=icon, fanart=fanart, folder=True, playable=False)
    else:
        add_item(label=localized(30008), url='', mode='login', icon=icon, fanart=fanart, folder=False, playable=False)

    xbmcplugin.endOfDirectory(addon_handle)

def router(param):
    args = dict(urlparse.parse_qsl(param))
    if args:
        mode = args.get('mode', None)
        if mode == 'play':
            play(exlink, extitle, exid, excatchup, exstart, exend)

        elif mode == 'channels':
            live_channel(exlink)

        elif mode == 'live':
            live_channels()

        elif mode == 'ext':
            c_ext_info()

        elif mode == 'login':
            addon.openSettings()
            xbmc.executebuiltin('Container.Refresh()')

    else:
        home()

if __name__ == '__main__':
    router(sys.argv[2][1:])