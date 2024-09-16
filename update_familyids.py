#!/usr/bin/python3
# -*- coding: utf-8 -*-

import requests
import json

famid_link = 'https://raw.githubusercontent.com/microsoft/uf2/master/utils/uf2families.json'


def download_list():
    res = requests.get(famid_link)
    res.raise_for_status()
    dict = json.loads(res.text)
    return dict


if __name__ == '__main__':
    famidList = download_list()
    res = []
    for i in range(len(famidList)):
        res.append('{' + famidList[i]['id'] + ', "' + famidList[i]['description'] + '"},')
    res.sort()
    for i in range(len(res)):
        print(res[i])
