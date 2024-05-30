
"""
THIS FILE IS USED FOR UPDATING THE INITIAL VALUES INVOLVED IN THE DATABASE. ffrom the offest 0 with 2000 records.
"""

import urllib.request, json
import mysql.connector
from pandas import json_normalize
import mysql.connector
from mysql.connector import Error


def load_data_mysql(data):
    try:
        # Establish the database connection
        #connecting to the MySQL database (running on local host)
        #data needed for the project stored in CVENVD DATABASE 
        #details masked...
        conn = mysql.connector.connect (
             host='localhost',
            database='cvenvd',
            user='user',
            password='pwd'
        )
        if conn.is_connected():
            cur = conn.cursor()
            # Flatten the JSON data
            vulnerabilities = json_normalize(data['vulnerabilities'])
            # Insert data into vulnerabilities table
            for vuln in data['vulnerabilities']:
                cve = vuln['cve']
                cur.execute("""
                    INSERT INTO vulnerabilities (id, sourceIdentifier, published, lastModified, vulnStatus)
                    VALUES (%s, %s, %s, %s, %s)""", (
                    cve['id'],
                    cve['sourceIdentifier'],
                    cve['published'],
                    cve['lastModified'],
                    cve['vulnStatus']
                ))

                # Insert data into descriptions table
                for desc in cve.get('descriptions', []):
                    cur.execute("""
                        INSERT INTO descriptions (id, lang, value)
                        VALUES (%s, %s, %s)""", (
                        cve['id'],
                        desc['lang'],
                        desc['value']
                    ))

                # Insert data into cvssMetricV2 table
                if 'metrics' in cve and 'cvssMetricV2' in cve['metrics']:
                    for metric in cve['metrics']['cvssMetricV2']:
                        cvss_data = metric['cvssData']
                        cur.execute("""
                            INSERT INTO cvssMetricV2 (id, source, type, version, vectorString, accessVector, accessComplexity, authentication, confidentialityImpact, integrityImpact, availabilityImpact, baseScore, baseSeverity, exploitabilityScore, impactScore, acInsufInfo, obtainAllPrivilege, obtainUserPrivilege, obtainOtherPrivilege, userInteractionRequired)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""", (
                            cve['id'],
                            metric['source'],
                            metric['type'],
                            cvss_data['version'],
                            cvss_data['vectorString'],
                            cvss_data['accessVector'],
                            cvss_data['accessComplexity'],
                            cvss_data['authentication'],
                            cvss_data['confidentialityImpact'],
                            cvss_data['integrityImpact'],
                            cvss_data['availabilityImpact'],
                            cvss_data['baseScore'],
                            metric['baseSeverity'],
                            metric['exploitabilityScore'],
                            metric['impactScore'],
                            metric['acInsufInfo'],
                            metric['obtainAllPrivilege'],
                            metric['obtainUserPrivilege'],
                            metric['obtainOtherPrivilege'],
                            metric['userInteractionRequired']
                        ))

                # Insert data into cvssMetricV3 table for both V3.0 and V3.1
                for version in ['cvssMetricV30', 'cvssMetricV31']:
                    if 'metrics' in cve and version in cve['metrics']:
                        for metric in cve['metrics'][version]:
                            cvss_data = metric['cvssData']
                            cur.execute("""
                                INSERT INTO cvssMetricV3 (id, source, type, version, vectorString, attackVector, attackComplexity, privilegesRequired, userInteraction, scope, confidentialityImpact, integrityImpact, availabilityImpact, baseScore, baseSeverity, exploitabilityScore, impactScore)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""", (
                                cve['id'],
                                metric['source'],
                                metric['type'],
                                cvss_data['version'],
                                cvss_data['vectorString'],
                                cvss_data['attackVector'],
                                cvss_data['attackComplexity'],
                                cvss_data['privilegesRequired'],
                                cvss_data['userInteraction'],
                                cvss_data['scope'],
                                cvss_data['confidentialityImpact'],
                                cvss_data['integrityImpact'],
                                cvss_data['availabilityImpact'],
                                cvss_data['baseScore'],
                                cvss_data['baseSeverity'],
                                metric['exploitabilityScore'],
                                metric['impactScore']
                            ))

                # Insert data into weaknesses and description_weakness tables
                if 'weaknesses' in cve:
                    for weakness in cve['weaknesses']:
                        cur.execute("""
                            INSERT INTO weaknesses (id, source, type)
                            VALUES (%s, %s, %s)""", (
                            cve['id'],
                            weakness.get('source', 'N/A'),
                            weakness.get('type', 'N/A')
                        ))
                        for desc in weakness.get('description', []):
                            cur.execute("""
                                INSERT INTO description_weakness (id, lang, value)
                                VALUES (%s, %s, %s)""", (
                                cve['id'],
                                desc.get('lang', 'N/A'),
                                desc.get('value', 'N/A')
                            ))

                # Insert data into configurations and cpeMatch tables
                if 'configurations' in cve:
                    for config in cve['configurations']:
                        for node in config.get('nodes', []):
                            cur.execute("""
                                INSERT INTO configurations (id, node_operator, node_negate)
                                VALUES (%s, %s, %s)""", (
                                cve['id'],
                                node.get('operator'),
                                node.get('negate')
                            ))
                            for cpematch in node.get('cpeMatch', []):
                                cur.execute("""
                                    INSERT INTO cpeMatch (id, vulnerable, criteria, matchCriteriaId)
                                    VALUES (%s, %s, %s, %s)""", (
                                    cve['id'],
                                    cpematch['vulnerable'],
                                    cpematch['criteria'],
                                    cpematch['matchCriteriaId']
                                ))

                # Insert data into references table
                if 'references' in cve:
                    for ref in cve['references']:
                        cur.execute("""
                            INSERT INTO refer (id, url, source)
                            VALUES (%s, %s, %s)""", (
                            cve['id'],
                            ref['url'],
                            ref['source']
                        ))

            # Commit changes to the database
            conn.commit()
    
    except Error as e:
        print(f"Error: {e}")
        if conn.is_connected():
            conn.rollback()
    finally:
        if conn.is_connected():
            cur.close()
            conn.close()


#load the endpoint for getting data
curr_url="https://services.nvd.nist.gov/rest/json/cves/2.0"

#load the data of api to the json file named : json_database 
with urllib.request.urlopen(curr_url) as url:
    data = json.load(url)
    with open("json_database.json", 'w') as f:
        json.dump(data, f)

#data contains all the records
with open("json_database.json", "r") as f :
    data = json.load(f)




'''
loop = 0
while (loop < 127) :
    urllink = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000&startIndex="+str(loop*2000)
    loop += 1

    #load the data of api to the json file named : json_database 
    with urllib.request.urlopen(urllink) as url:
        data = json.load(url)
        with open("json_database.json", 'w') as f:
            json.dump(data, f)
    
    #data contains all the records
    with open("json_database.json", "r") as f :
        data = json.load(f)

    load_data_mysql(data)
    '''