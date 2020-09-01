from flask import Flask, render_template
import json
from flask import request
from flask import jsonify
import shodan
import requests
import base64
import psycopg2


app = Flask(__name__)
result_data = []
remember_proxy_header = []
proxy_headers = ["HTTP_VIA","HTTP_X_FORWARDED_FOR","HTTP_FORWARDED_FOR", 
"HTTP_X_FORWARDED", "HTTP_FORWARDED", "HTTP_CLIENT_IP", "HTTP_FORWARDED_FOR_IP", "VIA", 
"X_FORWARDED_FOR", "FORWARDED_FOR", "X_FORWARDED", "FORWARDED", "CLIENT_IP", "FORWARDED_FOR_IP", 
"HTTP_PROXY_CONNECTION","PROXY-AGENT","HTTP_X_CLUSTER_CLIENT_IP","HTTP_PROXY_CONNECTION",
"X-PROXY-ID","Proxy-Connection","X-PROXY-ID","MT-PROXY-ID","X-TINYPROXY","X-Forwarded-For"]


server_answer_string = ""
proxy_answer_string  = ""
hashes = []
remember_possible_canvas_hash = ""

def detect_proxy_header(data):
    for x in range(len(proxy_headers)):
    	global proxy_answer_string
    	if proxy_headers[x] in data:
    		remember_proxy_header.append(proxy_headers[x])
    		proxy_answer_string = proxy_answer_string + proxy_headers[x] +" : " + data [proxy_headers[x]] + " |"
    if(len(remember_proxy_header)):
    	return True
    else:
    	return False
    
def detect_proxy(ip):
	url = "https://www.ipqualityscore.com/api/json/ip/pA5PECZYW7A1pFMc8YdkvEqJ1wI5exad/" + ip
	response = requests.get(url)
	json 	 = response.json()
	if((json["proxy"]==1)):
		return True
	else:
		return False

def detect_tor(ip):
	response = requests.get("https://check.torproject.org/torbulkexitlist")
	if ip in response.text:
		return True
	else : 
		return False

def detect_vpn(ip):
	url = "https://www.ipqualityscore.com/api/json/ip/pA5PECZYW7A1pFMc8YdkvEqJ1wI5exad/" + ip
	response = requests.get(url)
	json 	 = response.json()
	if(json["active_vpn"]==1 or json["vpn"]==1 ):
		return True
	else:
		return False

@app.route("/")
def index():
   return render_template("index.html")

def detect_hash(hash_data):
	encodedBytes = base64.b64encode(hash_data.encode("utf-8"))
	encodedStr 	 = str(encodedBytes, "utf-8")
	return encodedStr

def canvas_fingerprint(canvas_data):
	encodedBytes = base64.b64encode(canvas_data.encode("utf-8"))
	encodedStr 	 = str(encodedBytes, "utf-8")
	return encodedStr[220:240]

@app.route('/fastcheck',methods=['POST']) # tor browser can't load canvas 
def fast_check():
	if(detect_tor(request.remote_addr)):
		return "Tor"
	else:
		return "No"

def tor_browser(ip):
	if(detect_tor(ip)):
		return True
	else:
		return False

@app.route('/drop',methods=['GET'])
def drop_database():
	conn = psycopg2.connect(dbname='fingerprint', user='postgres', password='1234', host='localhost')
	cursor = conn.cursor()
	cursor.execute("DROP TABLE %s;"%"fingerprint");
	conn.commit()
	cursor.close()
	return "Database droped!"

def update_database(cursor,row,conn):
	sql ="""UPDATE FINGERPRINT
    SET VISITED = VISITED + 1
    WHERE USER_NUM =""" + str(row)
	cursor.execute(sql)
	cursor.execute("SELECT * from FINGERPRINT")

def database(hash_data,canvas_hash_data):
    conn = psycopg2.connect(dbname='fingerprint', user='postgres', password='1234', host='localhost')
    cursor = conn.cursor()
    print("Database opened successfully")
    cursor.execute('''CREATE TABLE IF NOT EXISTS FINGERPRINT (HASH TEXT NOT NULL,CANVAS_HASH TEXT NOT NULL,USER_NUM INT NOT NULL,VISITED INT NOT NULL );''')
    conn.commit()
    user_count = 0
    print('Table connected\n')
    hash_check = False
    canvas_hash_check=False
    cursor.execute("SELECT * from FINGERPRINT")
    rows = cursor.fetchall()
    if len(rows)>0:
    	print("More!")
    	user_count = len(rows)
    	remember_x=-1
    	for x in range(len(rows)):
    		if rows[x][1] == canvas_hash_data:
    			hash_check =True
    			remember_x = x
    			break
    		if rows[x][0] == hash_data:
    			canvas_hash_check=True
    			remember_x = x
    			break
    	if canvas_hash_check:
    		update_database(cursor,rows[remember_x][2],conn)
    		conn.commit()
    		cursor.close()
    		return str(str(rows[remember_x][2]) + " You visited this web-site " + str(rows[remember_x][3]+1) + " times ")
    	elif hash_check:
    		update_database(cursor,rows [remember_x][2],conn)
    		conn.commit()
    		cursor.close()
    		return str(str(rows[remember_x][2]) + " You visited this web-site " + str(rows[remember_x][3] +1) + " times ")
    	
    	cursor.execute("INSERT INTO FINGERPRINT (HASH,CANVAS_HASH,USER_NUM,VISITED) VALUES ('%s','%s','%d','%d');""" % (hash_data,canvas_hash_data,user_count+1,1))
    	conn.commit()
    	cursor.close()
    	return str(str(user_count+1)+" You are first time on this web-site ! ")

    else:
    	print("Table is clear!")
    	user_count = 1
    	cursor.execute("INSERT INTO FINGERPRINT (HASH,CANVAS_HASH,USER_NUM,VISITED) VALUES ('%s','%s','%d','%d');""" % (hash_data,canvas_hash_data,user_count,user_count))
    	conn.commit()
    	cursor.close()
    	return str(str(user_count) + " You are first time on this web-site ! ")

@app.route('/language',methods = ['POST'])
def language():
	language = request.form['language']
	print(language)

@app.route('/postmethod', methods = ['POST'])
def postmethod():
    global remember_proxy_header
    global proxy_answer_string
    server_answer_string = "" 
    proxy_answer_string  = ""
    ip     = request.remote_addr
    data   = request.headers
    remember_proxy_header.clear()
    detecting_count = 0 
    server_answer_string = server_answer_string + ip 
    tor = tor_browser(ip)
    print(data)
    main_hash 		 = detect_hash(request.form['hash'])
    if tor == False:
    	main_canvas_hash = canvas_fingerprint(request.form['canvas'])
    else:
    	main_canvas_hash = "Tor"
    user_num 		 = database(main_hash,main_canvas_hash)
    if (detect_tor(ip)):
    	server_answer_string 	= server_answer_string   + "| Tor Detected ! |"
    	detecting_count		 	= detecting_count		 + 1
    	return server_answer_string
    if (detect_proxy_header(data)):
    	server_answer_string 	= server_answer_string   + "| Proxy Header Detected :" + proxy_answer_string
    	detecting_count		 	= detecting_count		 + 1
    if (detect_proxy(ip)):
    	server_answer_string 	= server_answer_string   + "| Proxy server using detected! |"
    	detecting_count		 	= detecting_count		 + 1
    if (detect_vpn(ip)) :
    	server_answer_string 	= server_answer_string 	 + "| Vpn detected ! |"
    	detecting_count		 	= detecting_count 	     + 1
    if(detecting_count == 0):
    	server_answer_string = server_answer_string + "| No Proxy/Vpn/Tor detected ! |"
    return {"ip_info": server_answer_string , "hash": main_hash[0:20] , "user" : user_num , "canvas_hash" : main_canvas_hash}
    
if __name__ == "__main__":
    app.run(host='192.168.31.37', port=int("80"), debug=True)
    print(result_data)