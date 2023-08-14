'''
Name: cvecheck.py
Author: Luis Eduardo Uribe Alvarez
Company: TIVIT
Description: Given a list of CVE's the appliction checks if these CVE's exist on EPSS checklists and on KEV
'''

import requests
import pandas as pd
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define search function for EPSS given a list
def searchEPSS(cve_list):
    api_url = "https://api.first.org/data/v1/epss?cve=" + cve_list
    response = requests.get(api_url)
    return (response.json()["data"])

df_cve_excel = pd.read_excel("listado.xlsx")
cve_list = list(df_cve_excel["cve"])
#cve_list = ["CVE-2023-34362","CVE-2021-44228","CVE-2023-00001"]
cve_str = ','.join(map(str,cve_list))
df_cve = pd.DataFrame(cve_list, columns=["cve"])

# Exploited Prediction Scoring System (EPSS) search
epss_list = searchEPSS(cve_str)

# Create DataFrame to export
df_epss = pd.DataFrame(epss_list)

# Known Exploited Vulnerabilities (KEV)
kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
response = requests.get(kev_url, verify=False)
kev_vulns = response.json()["vulnerabilities"]

# Merge DataFrames into one
df_kev = pd.DataFrame(kev_vulns)
df_kev.rename(columns={"cveID":"cve"}, inplace=True)

df_cve_epss = pd.merge(df_cve, df_epss, how="left", on=["cve"])
df_cve_epss_kev = pd.merge(df_cve_epss, df_kev, how="left", on=["cve"])

# Export results to Excel
filename = "filtrocve.xlsx"
df_cve_epss_kev.to_excel(filename)
print('DataFrame has been written to an Excel file successfully.')