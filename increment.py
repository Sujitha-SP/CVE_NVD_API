"""
THIS FILE ALLOWS FOR INCREMENTAL UPDATES ON ALL THE VALUES WHEN TAKEN IN CHUNKS.
"""

import requests
import mysql.connector
from datetime import datetime
import urllib, json


#get the data to be changed from one chunk to another only if the timestamp is better.
def fetch_incremental_cve_data(last_updated, loop) :
    if (loop < 126) :
        urllink = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000&startIndex="+str(loop*2000)

    #load the data of api to the json file named : json_database 
    with urllib.request.urlopen(urllink) as url:
        data = json.load(url)
        with open("json_database.json", 'w') as f:
            json.dump(data, f)
    
    #data contains all the records
    with open("json_database.json", "r") as f :
        data = json.load(f)

    #check for the timestamps :
    json_timestamp = datetime.fromisoformat(data.get('timestamp', 'N/A'))
    if json_timestamp > last_updated :
        return data 
    else :
        return None


#get the last updated timestamp from the Database
def get_last_updated_timestamp(cursor):
    cursor.execute("SELECT last_updated FROM sync_metadata WHERE key_name = 'last_cve_sync'")
    result = cursor.fetchone()
    if result:
        return result[0]
    else:
        return datetime.min


#update the timestamp after incremental changes.
def update_last_updated_timestamp(cursor, new_timestamp):
    cursor.execute("UPDATE sync_metadata SET last_updated = %s WHERE key_name = 'last_cve_sync'", (new_timestamp,))

#update teh data itself to database.
def update_database_with_cve_data(data, cursor):
    for vuln in data['vulnerabilities']:
        cve = vuln['cve']
        # Insert or update the vulnerabilities table
        cursor.execute("""
            INSERT INTO vulnerabilities (id, sourceIdentifier, published, lastModified, vulnStatus)
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE sourceIdentifier=VALUES(sourceIdentifier), published=VALUES(published), lastModified=VALUES(lastModified), vulnStatus=VALUES(vulnStatus)
        """, (
            cve['id'],
            cve['sourceIdentifier'],
            cve['published'],
            cve['lastModified'],
            cve['vulnStatus']
        ))

        for desc in cve['descriptions']:
            cursor.execute("""
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
                cursor.execute("""
                INSERT INTO cvssMetricV2 (id, source, type, version, vectorString, accessVector, accessComplexity, authentication, confidentialityImpact, integrityImpact, availabilityImpact, baseScore, baseSeverity, exploitabilityScore, impactScore, acInsufInfo, obtainAllPrivilege, obtainUserPrivilege, obtainOtherPrivilege, userInteractionRequired)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE id=VALUES(id), source=VALUES(source), type=VALUES(type), version=VALUES(version), vectorString=VALUES(vectorString), accessVector=VALUES(accessVector), accessComplexity=VALUES(accessComplexity), authentication=VALUES(authentication), confidentialityImpact=VALUES(confidentialityImpact),integrityImpact=VALUES(integrityImpact), availabilityImpact=VALUES(availabilityImpact), baseScore=VALUES(baseScore), baseSeverity=VALUES(baseSeverity), exploitabilityScore=VALUES(exploitabilityScore), impactScore=VALUES(impactScore), acInsufInfo=VALUES(acInsufInfo), obtainAllPrivilege=VALUES(obtainAllPrivilege), obtainUserPrivilege=VALUES(obtainUserPrivilege), obtainOtherPrivilege=VALUES(obtainOtherPrivilege), userInteractionRequired=VALUES(userInteractionRequired)""", (
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
            )
        )

        #for the cvssmetric V3 table
        if 'metrics' in cve and 'cvssMetricV30' in cve['metrics']:

            #first for cvssMetric V30
            for metric in cve['metrics']['cvssMetricV30']:
                cvss_data = metric['cvssData']
                cursor.execute("""
                INSERT INTO cvssMetricV3 (id, source, type, version, vectorString, attackVector, attackComplexity, privilegesRequired,  userInteraction, scope, confidentialityImpact, integrityImpact, availabilityImpact, baseScore, baseSeverity, exploitabilityScore, impactScore)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE id=VALUE(id), source=VALUE(source), type=VALUE(type), version=VALUE(version), vectorString=VALUE(vectorString), attackVector=VALUE(attacjVector), attackComplexity=VALUE(attackComplexity), privilegesRequired=VALUE(privilegesRequired),  userInteraction=VALUE(userInteraction), scope=VALUE(scope), confidentialityImpact=VALUE(confidentialityImpact), integrityImpact=VALUE(integrityImpact), availabilityImpact=VALUE(availabilityImpact), baseScore=VALUE(baseScore), baseSeverity=VALUE(baseSeverity), exploitabilityScore=VALUE(exploitabilityScore), impactScore=VALUE(impactScore)""", (
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
            )
        )
    
        #for the cvssmetric V3 table
        if 'metrics' in cve and 'cvssMetricV31' in cve['metrics']:

            #first for cvssMetric V31
            for metric in cve['metrics']['cvssMetricV31']:
                cvss_data = metric['cvssData']
                cursor.execute("""
                INSERT INTO cvssMetricV3 (id, source, type, version, vectorString, attackVector, attackComplexity, privilegesRequired,  userInteraction, scope, confidentialityImpact, integrityImpact, availabilityImpact, baseScore, baseSeverity, exploitabilityScore, impactScore)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE id=VALUE(id), source=VALUE(source), type=VALUE(type), version=VALUE(version), vectorString=VALUE(vectorString), attackVector=VALUE(attacjVector), attackComplexity=VALUE(attackComplexity), privilegesRequired=VALUE(privilegesRequired),  userInteraction=VALUE(userInteraction), scope=VALUE(scope), confidentialityImpact=VALUE(confidentialityImpact), integrityImpact=VALUE(integrityImpact), availabilityImpact=VALUE(availabilityImpact), baseScore=VALUE(baseScore), baseSeverity=VALUE(baseSeverity), exploitabilityScore=VALUE(exploitabilityScore), impactScore=VALUE(impactScore)""", (
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

        #insert into weakness table & description_weakness table 
        if 'weaknesses' in cve:
            weakn_data = cve.get('weaknesses', [])
            for weakness in weakn_data :
                cursor.execute("""
                INSERT INTO weaknesses (id, source, type)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE id=VALUE(id), source=VALUE(source), type=VALUE(type) """, (
                    cve['id'],
                    weakness.get('source', 'N/A'),
                    weakness.get('type', 'N/A')
            )
        )
            description = weakness.get('description', [])
            for desc in description :
                cursor.execute("""
                INSERT INTO description_weakness (id, lang, value)
                VALUES (%s, %s, %s) ON DUPLICATE KEY UPDATE id = VALUE(id), lang = VALUE(lang), value = VALUE(value)""", (
                    cve['id'],
                    desc.get('lang', 'N/A'),
                    desc.get('value', 'N/A')
            )
        )

    
        #insert into configurations table
        if 'configurations' in cve :
            config_data = cve.get('configurations', [])
        
            for config in config_data :
                node_data = config.get('nodes', [])
                for node in node_data :
                    cursor.execute(
                    """INSERT INTO configurations (id, node_operator, node_negate)
                    VALUES (%s, %s, %s)
                    ON DUPLICATE KEY UPDATE id=VALUE(id), node_operator=VALUE(node_operator), node_negate= VALUE(node_negate)""",(
                        cve['id'],
                        node.get('operator'),
                        node.get('negate')
                    )
                )
                
                    #cpeMatch is in a nested loop of nodes in configurations. Add in a separate table
                    cpematch_data = node.get('cpeMatch', [])
                    for cpematch in cpematch_data :
                        cursor.execute(
                        """INSERT INTO cpeMatch (id, vulnerable, criteria, matchCriteriaId)
                        VALUES (%s, %s, %s, %s)
                        ON DUPLICATE KEY UPDATE id=VALUE(id), vulnerable=VALUE(vulnerable), criteria=VALUE(criteria), matchCriteriaId=VALUE(matchCriteriaId)""",(
                            cve['id'],
                            cpematch['vulnerable'],
                            cpematch['criteria'],
                            cpematch['matchCriteriaId']
                        )
                    )


        if 'references' in cve :
            for ref in cve['references'] :
                cursor.execute(
                """INSERT INTO refer (id, url, source)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE id = VALUE(id), url= VALUE(url), source=VALUE(source)""", (
                    cve['id'],
                    ref['url'],
                    ref['source']
            )
        )


#MAIN RUNNER for incremental updatation to the BACKEND MYSQL based on timestamps 
def sync_cve_data():
    try:
        # Connect to MySQL database
        conn = mysql.connector.connect(
            host='localhost',
            database='cvenvd',
            user='user',
            password='pwd'
        )
        cursor = conn.cursor(dictionary=True)
        
        # Get the last updated timestamp
        last_updated = get_last_updated_timestamp(cursor)
        
        # Fetch the incremental CVE data
        #chunk size initialization of offset 
        loop = 0
        data = fetch_incremental_cve_data(last_updated, loop)
        # Update the local database with the fetched data
        update_database_with_cve_data(data, cursor)
        
        # Update the last updated timestamp
        if data :
            new_last_updated = max(data.get('timestamp', 'N/A'), last_updated)
            update_last_updated_timestamp(cursor, new_last_updated)
        
        # Commit changes
        conn.commit()
        print("DONE")

    except Exception as e:
        print(f"Error: {e}")
        if conn.is_connected():
            conn.rollback()

    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

# Run the synchronization
sync_cve_data()
