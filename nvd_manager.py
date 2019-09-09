# -*- coding: utf-8 -*-

import os
import requests
import json
import zipfile

from bs4 import BeautifulSoup

def check_CVE_updates():
    """ This function crawls the NIST CVE pages, and 
        automatically check the latest change of CVE data 
    """

    # CVE data folder and configuration file check
    if os.path.isdir(os.getcwd() + "/cve/"):
        print("CVE data folder is founded.")
    else:
        print("CVE data folder is not founded.")
        os.makedirs("cve")
    try:
        with open("./cve/cve-conf.json", "r") as f:
            cve_json_conf = json.load(f)
    except FileNotFoundError:
        print("CVE data configuration file is not founded.")
        cve_json_conf = dict()

    # NIST CVE page crawling
    nist_cve_url = 'https://nvd.nist.gov/vuln/data-feeds'
    req = requests.get(nist_cve_url)
    html = req.text
    soup = BeautifulSoup(html, 'html.parser')
    
    tables = soup.select('div.row')
    cves = tables[8].select('tr.xml-feed-desc-row')

    # lastest CVE data check
    print("CVE name     : Updated Timestamp")
    for cve in cves:
        tds = cve.find_all('td')
        if tds:
            cve_name = cve.find_all('td')[0].text # CVE name
            update_date = cve.find_all('td')[1].text # CVE update date
            zip_url = cve.find('a')['href'].replace(".meta", ".json.zip") # CVE file(zip) url
            print(f"{cve_name:<12} : {update_date:>29}...", end="")
            if cve_name in cve_json_conf.keys():
                if update_date == cve_json_conf[cve_name]['Updated']:
                    # latest
                    print(" Latest data.")
                else:
                    # need to be updated
                    print(" Old data.", end="")
                    download_CVE(zip_url, "./cve/", cve_name + ".json.zip")
                    print(" Latest CVE data file in downloaded.")
            else:
                cve_json_conf[cve_name] = dict()
                print(" New data.", end="")
                download_CVE(zip_url, "./cve/", cve_name + ".json.zip")
                print(" Latest CVE data file in downloaded.")
            cve_json_conf[cve_name]['Updated'] = update_date
            cve_json_conf[cve_name]['zip_url'] = zip_url
    with open("./cve/cve-conf.json", "w") as f:
        json.dump(cve_json_conf, f)

def download_CVE(url, file_dir, file_name):
    """ This function download CVE file using inserted URL
    """
    with open(file_dir + file_name, "wb") as f:    # open in binary mode
        response = requests.get(url)    # get requests
        f.write(response.content)       # write to file
    zip_file = zipfile.ZipFile(file_dir + file_name)
    zip_file.extractall(file_dir)
    os.remove(file_dir + file_name)

if __name__ == "__main__":
    check_CVE_updates()
