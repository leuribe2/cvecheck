'''
Name: cvecheck.py
Author: Luis Eduardo Uribe Alvarez
Company: TIVIT
Description: Given a list of CVE's the appliction checks if these CVE's exist on EPSS checklists and on KEV
'''

import requests
import pandas as pd
import argparse
import math
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define search function for EPSS given a list
def searchEPSS(cve_list):
    # The API allows for a limited number of group of cve. We need to check in multiple groups
    data = []
    base_range = 0
    if (len(cve_list) > 50):
        cve_list_grps = math.ceil(len(cve_list)/50)
        for iteration in range (0, cve_list_grps):
            cve_str = ','.join(map(str,cve_list[base_range:((iteration+1)*50)-1]))
            api_url = "https://api.first.org/data/v1/epss?cve=" + cve_str
            base_range = base_range + 50
            response = requests.get(api_url)
            data = data + response.json()["data"]
        return data
    else:
        cve_str = ','.join(map(str,cve_list))
        api_url = "https://api.first.org/data/v1/epss?cve=" + cve_str
        response = requests.get(api_url)
        return (response.json()["data"])

def checkCVE(input, output):
    # Input Excel File
    df_cve = pd.read_excel(input)
    cve_list = list(df_cve["cve"])

    # Exploited Prediction Scoring System (EPSS) search
    epss_list = searchEPSS(cve_list)

    # Create EPSS DataFrame to export
    df_epss = pd.DataFrame(epss_list)

    # Known Exploited Vulnerabilities (KEV)
    kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    response = requests.get(kev_url, verify=False)
    kev_vulns = response.json()["vulnerabilities"]

    # Create KEV DataFrame
    df_kev = pd.DataFrame(kev_vulns)
    df_kev.rename(columns={"cveID":"cve"}, inplace=True)
    # Merge DataFrames into one
    df_cve_epss = pd.merge(df_cve, df_epss, how="left", on=["cve"])
    df_cve_epss_kev = pd.merge(df_cve_epss, df_kev, how="left", on=["cve"])
    df_cve_epss_kev["kev"] = [0 if pd.isna(vendor) else 1 for vendor in df_cve_epss_kev["vendorProject"]]
    df_cve_epss_kev["epss"] = df_cve_epss_kev["epss"].astype(float)
    df_cve_epss_kev["cvss"] = df_cve_epss_kev["cvss"].fillna(5)
    # Fill all remaining NaN with 0
    df_cve_epss_kev = df_cve_epss_kev.fillna(0)
    # If CVSS is not present, we use 0.1 as CVSS as it is the minimum score for CVSS
    #df_cve_epss_kev["cvss"] = [0.1 if pd.isna(cvss) else cvss for cvss in df_cve_epss_kev["cvss"]]
    #df_cve_epss_kev["base_score"] = (df_cve_epss_kev["cvss"]/10)*df_cve_epss_kev["epss"]
    #df_cve_epss_kev["final_score"] = df_cve_epss_kev["base_score"].where(df_cve_epss_kev["kev"] < 1, df_cve_epss_kev["base_score"] + 0.1)
    #df_cve_epss_kev["aver_score"] = ((df_cve_epss_kev["cvss"]/10)+df_cve_epss_kev["epss"]+df_cve_epss_kev["kev"])/3
    df_cve_epss_kev["score"] = (((df_cve_epss_kev["cvss"]/10)*0.5)+(df_cve_epss_kev["epss"]*0.3)+(df_cve_epss_kev["kev"]*0.2))*100

    # Sort the dataframe by score descendant
    df_cve_epss_kev.sort_values(by=["score"], ascending=False, inplace=True)
    print(df_cve_epss_kev.head())

    # Export results to Excel
    df_cve_epss_kev.to_excel(output)
    print('DataFrame has been written to an Excel file successfully.')

if __name__ == "__main__":
    # Initialize argument parser
    parser = argparse.ArgumentParser()
    # Adding arguments 
    parser.add_argument("--input", help = "CVE input file.", type = str)
    parser.add_argument("--output", help = "Output file.", type = str)
    args = parser.parse_args()
    
    if (args.input != None and args.output != None):
        checkCVE(args.input, args.output)
    else:
        parser.print_help()