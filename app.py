from flask import Flask, jsonify, render_template, request, redirect, url_for, session
import mysql.connector

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Needed to use sessions

# Database configuration
db_config = {
    'user': 'user',
    'password': 'pwd',
    'host': 'localhost',
    'database': 'cvenvd'
}

# Function to fetch data from MySQL to display in FRONT PAGE
def get_records(pgno):
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    offset = (pgno - 1) * 10
    cursor.execute("SELECT * FROM vulnerabilities LIMIT 10 OFFSET %s", (offset,))
    users = cursor.fetchall()
    cursor.close()
    conn.close()
    return users

#for getting cves data from mysql database
def get_cves_detail(cves_id):
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    #create cursor for the mysql 
    cursor.execute("SELECT * FROM configurations where id = %s ", (cves_id,))
    config = cursor.fetchall()
    cursor.execute("SELECT * FROM descriptions where id = %s ", (cves_id,))
    description = cursor.fetchall()
    cursor.execute("SELECT * FROM cvssmetricv2 where id = %s ", (cves_id,))
    cvssmetricV2 = cursor.fetchall()
    cursor.execute("SELECT * FROM cvssmetricv3 where id = %s ", (cves_id,))
    cvssmetricV3 = cursor.fetchall()
    cursor.execute("SELECT * FROM cpematch where id = %s ", (cves_id,))
    cpematch = cursor.fetchall()

    cursor.close()
    conn.close()


    return { "configurations" : config, "descriptions": description, "cvssmetricV2":cvssmetricV2, "cvssmetricV3":cvssmetricV3, "cpematch":cpematch}



#FUNCTIONS FOR THE PAGE 

# Route to display data in HTML table based on the PAGE OFFSET
@app.route('/')
def cves_table():
    pgno = session.get('pgno', 1)
    recs = get_records(pgno)
    return render_template("front.html", recs=recs, pgno=pgno)


#create the page offset for session refresh.
@app.route('/nextPage', methods=['POST'])
def next_page():
    pgno = session.get('pgno', 1)
    pgno += 1
    if pgno > 199:  #there are 2000 pages in total
        pgno = 1
    session['pgno'] = pgno
    return redirect(url_for('cves_table'))


#Redirect to the CVES page when clicked on the ID in table
@app.route('/cves/<string:cves_id>')
def cves_detail(cves_id):
    cves_data = get_cves_detail(cves_id)
    if cves_data is None:
        return "Data not found", 404
    return render_template("cves.html", 
                           config=cves_data['configurations'], 
                           cves_id= cves_id, 
                           descriptions=cves_data['descriptions'],
                           metricv3 = cves_data['cvssmetricV3'],
                           metricv2 = cves_data['cvssmetricV2'],
                           cpe = cves_data['cpematch']
                        )


@app.route('/filteringID', methods=['POST']) 
def filterById() :
    #create cursor for the mysql
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    #get the id from the input field.
    cves_id = request.form['cves_id'] 
    cursor.execute("SELECT * FROM vulnerabilities where id = %s ", (cves_id,))
    cves_data = cursor.fetchall()
    conn.close()
    cursor.close()

    if cves_data :
        return render_template("front.html", recs=cves_data, pgno=1)


@app.route('/filteringScore', methods=['POST']) 
def filterByScore() :
    #create cursor for the mysql
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    #get the metric type from the input field 
    # metrics : verion 2 or 3 
    metric_name = request.form['metric_name'] 
    #get the score range from the input field.
    # score ranges : 0-2 2-4 4-6 6-8 8-10
    cves_score = request.form['cves_score'] 
    start, end = cves_score.split('-')
    start = float(start)
    end = float(end)

    #get from the database
    query = f""" 
    SELECT vulnerabilities.id, vulnerabilities.sourceIdentifier, vulnerabilities.published, vulnerabilities.lastModified, vulnerabilities.vulnStatus
    FROM vulnerabilities
    INNER JOIN {metric_name} ON vulnerabilities.id = {metric_name}.id
    WHERE {metric_name}.basescore BETWEEN %s AND %s
    """
    cursor.execute(query, (start, end))

    cves_data = cursor.fetchall()
    conn.close()
    cursor.close()
    
    if cves_data :
        return render_template("front.html", recs=cves_data, pgno=1)

'''
import urllib, json
from increment import sync_cve_data()

#allows the data to be temporarily bought in through indexing 
@app.route('/ChunkSelection', method=['POST']) 
def load_data_chunk() :
    loop = ['chunkNumber']
    urllink = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000&startIndex="+str(loop*2000)

    #load the data of api to the json file named : json_database 
    with urllib.request.urlopen(urllink) as url:
        data = json.load(url)
        with open("json_database.json", 'w') as f:
            json.dump(data, f)
    
    #data contains all the records
    with open("json_database.json", "r") as f :
        data = json.load(f)

    sync_cve_data()
'''

if __name__ == '__main__':
    app.run(debug=True)
