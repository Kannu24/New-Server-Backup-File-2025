from datetime import datetime, timedelta
from flask import Flask,jsonify, abort, request, Blueprint, make_response
import pandas as pd
import numpy as np
# from pycaret.classification import *
import os, time
from functools import lru_cache
from cryptography.fernet import Fernet
import mysql.connector
import os
import pdb
import random




def dbConnection():
    try:
        #live dbs
        dbconnect = mysql.connector.connect(host="pricex.cfe7zuipvuot.ap-south-1.rds.amazonaws.com",user="admin",passwd="Samilprice2021",database="ThePriceX")
        
        return dbconnect
    except Exception as e:
        return jsonify({"status":401, "message":"Database connection not authorised","data": None}), 401



def dbConnection_uat():
    try:
        #uat dbs
        dbconnect = mysql.connector.connect(host="pricex.cfe7zuipvuot.ap-south-1.rds.amazonaws.com",user="admin",passwd="Samilprice2021",database="uatcode_thepricex")
        
        return dbconnect
    except Exception as e:
        return jsonify({"status":401, "message":"Database connection not authorised","data": None}), 401




def singleQuery(query):
    dbconnect = dbConnection()
    cursor = dbconnect.cursor()
    cursor.execute(query)
    data = cursor.fetchone()
    finalData = data
    dbconnect.close()
    return finalData


def fetchAllQuery(query):
    dbconnect = dbConnection()
    cursor = dbconnect.cursor()
    cursor.execute(query)
    data = cursor.fetchall()
    finalData = data
    dbconnect.close()
    return finalData

def fetchAllPQuery(query,string1):
    dbconnect = dbConnection()
    cursor = dbconnect.cursor()
    cursor.execute(query,string1)
    data = cursor.fetchall()
    finalData = data
    dbconnect.close()
    return finalData


def getCarmake(id):
    dbconnect = dbConnection()
    cursor = dbconnect.cursor()
    query = "Select id,carMake from TBL_CAR_MAKE where delId=0 and id="+id+""
    cursor.execute(query)
    data = cursor.fetchone()
    finalData = data
    dbconnect.close()
    return finalData



def getTopcarmake(id):
    dbconnect = dbConnection()
    cursor = dbconnect.cursor()
    query = "Select id,carMake from TBL_CAR_MAKE where delId=0 and id="+id+""
    cursor.execute(query)
    data = cursor.fetchone()
    finalData = data
    dbconnect.close()
    return finalData


def getCarmodel(id):
    dbconnect = dbConnection()
    cursor = dbconnect.cursor()
    query = "Select id,carModel from TBL_CAR_MODEL where delId=0 and id="+id+""
    cursor.execute(query)
    data = cursor.fetchone()
    finalData = data
    dbconnect.close()
    return finalData




def gettopCarmodel(id):
    dbconnect = dbConnection()
    cursor = dbconnect.cursor()
    query = "Select id,carModel from TBL_CAR_MODEL where delId=0 and id="+id+""
    cursor.execute(query)
    data = cursor.fetchone()
    finalData = data
    dbconnect.close()
    return finalData


def getCarvariant(id):
    dbconnect = dbConnection()
    cursor = dbconnect.cursor()
    query = "Select id,carVariant from TBL_CAR_VARIANT where delId=0 and id="+id+""
    cursor.execute(query)
    data = cursor.fetchone()
    finalData = data
    dbconnect.close()
    return finalData

def getCarfuel(id):
    dbconnect = dbConnection()
    cursor = dbconnect.cursor()
    query = "Select id,carFuel from TBL_CAR_FUEL where delId=0 and id="+id+""
    cursor.execute(query)
    data = cursor.fetchone()
    finalData = data
    dbconnect.close()
    return finalData

    

def getCarSegment(id):
    dbconnect = dbConnection()
    cursor = dbconnect.cursor()
    query = "Select id,sellerSegment from TBL_SELLER_SEGMENT_MASTER where delId=0 and id="+id+""
    cursor.execute(query)
    data = cursor.fetchone()
    finalData = data
    dbconnect.close()
    return finalData

def clientSecretKey(clientId):
    dbconnect = dbConnection()
    cursor = dbconnect.cursor()
    query = "Select userKey from TBL_API_TOKEN where clientId='"+clientId+"'"
    cursor.execute(query)
    data = cursor.fetchone()
    finalData = data
    dbconnect.close()
    return finalData

def saveApiHit(clientId, time, status):
    try:
        ipAddress = getIpAddress()
        # if not ipAddress or ipAddress == "Unknown":
        #     ipAddress = getIpAddress_1()   # fallback to UAT-style random list

        # safer, simpler access to method/name
        requestMethod = request.method
        try:
            apiName = request.path.replace('/', '')
        except Exception:
            apiName = "default_api"

        query = (
            "INSERT INTO TBL_HIT_TRACK(`clientId`,`responseTime`,`responseStatus`,`apiName`,`ipAddress`,`requestMethod`) "
            "VALUES ('%s','%s','%s','%s','%s','%s')"
            % (str(clientId), str(time), str(status), apiName, str(ipAddress), requestMethod)
        )
        outputData = insertQuery(query)

        if outputData[1] == 201:
            return jsonify({"status":201, "message":"Data saved successfully","data": None}), 201
        else:
            return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400
    except Exception as e:
        print("saveApiHit error:", str(e))
        return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400




def savePredictOutputv2(makeId, modelId, variantId, fuelId, State, CarRegNo, Year, segmentId, result, rstate, clientId, clientType, userId, meterReading):    
    try:
        ipAddress = getIpAddress()
        # if not ipAddress or ipAddress == "Unknown":
        #     ipAddress = getIpAddress_1()   # fallback to UAT behaviour

        userData = request.environ
        try:
            apiName = userData.get('REQUEST_URI', '')
            apiName = apiName.replace('/', '')
        except Exception:
            apiName = "default_api"

        # Use the exact DB column name: ipaddress (lowercase) for TBL_PREDICTION_OUTPUT
        query = (
            "INSERT INTO TBL_PREDICTION_OUTPUT "
            "(hitId, make, model, variant, fuel, state, carRegistrationNumber, regYear, segmentId, "
            "prePrice, preState, clientId, userId, clientType, ipaddress, responseStatus, meter_reading) "
            "SELECT MAX(id) + 1, '%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s',%s,'%s',201,'%s' FROM TBL_PREDICTION_OUTPUT"
            % (
                str(makeId), str(modelId), str(variantId), str(fuelId), str(State),
                str(CarRegNo), str(Year), str(segmentId), str(result), str(rstate),
                str(clientId), str(userId), str(clientType), str(ipAddress), str(meterReading)
            )
        )

        outputData = insertQuery(query)

        if outputData[1] == 201:
            return jsonify({"status": 201, "message": "Data saved successfully", "data": None}), 201
        else:
            return jsonify({"status": 400, "message": "Some error occurred while saving data", "data": None}), 400
    except Exception as e:
        print("savePredictOutputv2 error:", str(e))
        return jsonify({"status": 400, "message":"Some error occurred while saving data","data": None}), 400



def savePredictOutputv3(makeId, modelId, variantId, fuelId, State, CarRegNo, Year, segmentId,
                        result, rstate, clientId, clientType, userId, meterReading):    
    # First, get IP with fallback
    ipAddress = getIpAddress()
    # if not ipAddress or ipAddress == "Unknown":
    #     ipAddress = getIpAddress_1()

    userData = request.environ
    try:
        apiName = userData['REQUEST_URI']
        apiName = apiName.replace('/', '')
    except KeyError:
        apiName = "default_api"

    api_status = 201
    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
    fetchData = singleQuery(fetchQuery)
    maxId = fetchData[0]
    
    params = [
        maxId, makeId, modelId, variantId, fuelId, State, CarRegNo, Year,
        segmentId, result, rstate, clientId, userId, clientType, ipAddress,
        api_status, meterReading
    ]
    
    query = """
        INSERT INTO TBL_PREDICTION_OUTPUT
        (hitId, make, model, variant, fuel, state, carRegistrationNumber, regYear,
         segmentId, prePrice, preState, clientId, userId, clientType, ipaddress,
         responseStatus, meter_reading)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """
    
    outputData = insertQueryP_uat(query, params)

    if outputData[1] == 201:
        return jsonify({"status": 201, "message": "Data saved successfully", "data": None}), 201
    else:
        return jsonify({"status": 400, "message": "Some error occurred while saving data", "data": None}), 400



def saveInternalPredictOutput(makeId, modelId, variantId, fuelId, State, CarRegNo, Year,
                              sellerType, result, rstate, clientId, userId):
    # First, get IP with fallback
    ipAddress = getIpAddress()
    # if not ipAddress or ipAddress == "Unknown":
    #     ipAddress = getIpAddress_1()

    userData = request.environ
    try:
        apiName = userData['REQUEST_URI']
        apiName = apiName.replace('/', '')
    except KeyError:
        apiName = "default_api"

    query = (
        "INSERT INTO TBL_SAMIL_PREDICTION_OUTPUT "
        "(hitId, make, model, variant, fuel, state, carRegistrationNumber, regYear, "
        "sellerType, prePrice, preState, clientId, userId, ipaddress, responseStatus) "
        "SELECT MAX(id) + 1, '%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s',%s,'%s',201 "
        "FROM TBL_PREDICTION_OUTPUT"
        % (
            str(makeId), str(modelId), str(variantId), str(fuelId), str(State),
            str(CarRegNo), str(Year), str(sellerType), str(result), str(rstate),
            str(clientId), str(userId), str(ipAddress)
        )
    )
    
    outputData = insertQuery(query)

    if outputData[1] == 201:
        return jsonify({"status":201, "message":"Data saved successfully","data": None}), 201
    else:
        return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400


def insertQuery(query):
    app = Flask(__name__)
    with app.app_context():
        dbconnect = dbConnection()
        cursor = dbconnect.cursor()
        try:
            cursor.execute(query)
            dbconnect.commit()
            return jsonify({"status":201, "message":"Data Saves Successfully","data": None}), 201
        except:
            dbconnect.rollback()
            return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400
        finally:
            dbconnect.close()



def insertQuery_uat(query):
    app = Flask(__name__)
    with app.app_context():
        dbconnect = dbConnection_uat()
        cursor = dbconnect.cursor()
        try:
            cursor.execute(query)
            dbconnect.commit()
            return jsonify({"status":201, "message":"Data Saves Successfully","data": None}), 201
        except:
            dbconnect.rollback()
            return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400
        finally:
            dbconnect.close()

def insertQueryP_uat(query,string1):
    app = Flask(__name__)
    with app.app_context():
        dbconnect = dbConnection_uat()
        cursor = dbconnect.cursor()
        try:
            cursor.execute(query,string1)
            dbconnect.commit()
            return jsonify({"status":201, "message":"Data Saves Successfully","data": None}), 201
        except:
            dbconnect.rollback()
            return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400
        finally:
            dbconnect.close()





def updateQuery(query):
    app = Flask(__name__)
    with app.app_context():
        dbconnect = dbConnection()
        cursor = dbconnect.cursor()
        try:
            cursor.execute(query)
            dbconnect.commit()
            return jsonify({"status":201, "message":"Data Update Successfully","data": None}), 201
        except:
            dbconnect.rollback()
            return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400
        finally:
            dbconnect.close()

def updatePQuery(query,string1):
    app = Flask(__name__)
    with app.app_context():
        dbconnect = dbConnection()
        cursor = dbconnect.cursor()
        try:
            cursor.execute(query,string1)
            dbconnect.commit()
            return jsonify({"status":201, "message":"Data Update Successfully","data": None}), 201
        except:
            dbconnect.rollback()
            return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400
        finally:
            dbconnect.close()

def write_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    # path = sys.path.insert(0, '/var/www/pgtApi/pgtApi')
    document_path = os.path.abspath(os.path.dirname(__file__)) + '/key.key'
    # document_path = os.getcwd()+'key.key'
    print(document_path)
    return open(document_path, "rb").read()

def encrypt(data):
    key = load_key()
    f = Fernet(key)
    # encrypt data
    encrypted_data = f.encrypt(data)
    return encrypted_data

def decrypt(data):
    key = load_key()
    f = Fernet(key)
    decrypted_data = f.decrypt(data)
    return decrypted_data



def getIpAddress():
    return request.remote_addr


def load_data(dataset):
    col_data = pd.read_csv(dataset)
    return col_data

def round_1000(va):
	va_1=int(va/1000+1)
	return va_1*1000


def uppper(df,col):
    df[col]=df[col].str.upper()
    return df[col]

def get_value(val,my_dict):
	for key,value in my_dict.items():
		if val==key:
			return value

def space_dis(df):
		return df.repalce(' ','')

def index_reset(df):
	df.index += 1
	return df.index

def convertPriceOption(price):
    fairpercentPridictPrice = price * 14/100
    fairpredictedPrice = int(price) - int(fairpercentPridictPrice)
    fairnextPrice = fairpredictedPrice * 20/100
    fairpercentNextPrice = fairnextPrice * 14/100
    fairnextPPrice = int(fairpredictedPrice) + int(fairnextPrice)
    fairnextPPrice = int(fairnextPPrice) - int(fairpercentNextPrice)
    faircPredictedPrice = fairpredictedPrice
    faircNextPprice = fairnextPPrice

    goodperctPredictedPrice = price * 7 /100
    goodpredictedPrice = int(price) - int(goodperctPredictedPrice)
    goodnextPrice = goodpredictedPrice * 20 /100
    goodpercetNextPrice = goodnextPrice * 7 /100
    goodnextPprice = int(goodpredictedPrice) + int(goodnextPrice)
    goodnextPprice = int(goodnextPprice) - int(goodpercetNextPrice)
    goodcPredictedPrice = goodpredictedPrice
    goodcNextPprice = goodnextPprice

    vgoodnextPrice = price * 20 /100
    vgoodnextPprice = int(price) + int(vgoodnextPrice)
    vgoodcPredictedPrice = price
    vgoodcNextPprice = vgoodnextPprice

    experctPredictedPrice = price * 7 /100
    expredictedPrice = int(price) + int(experctPredictedPrice)
    exnextPrice = expredictedPrice * 20 /100
    expercetNextPrice = exnextPrice * 7 /100
    exnextPrice = int(expredictedPrice) + int(exnextPrice)
    exnextPprice = int(exnextPrice) + int(expercetNextPrice)
    excPredictedPrice = expredictedPrice
    excNextPprice = exnextPprice

    data = {
        "Fair": str(faircPredictedPrice) +' - '+str(faircNextPprice),
        "Good": str(goodcPredictedPrice) +' - '+str(goodnextPprice),
        "VGood": str(vgoodcPredictedPrice) +' - '+str(vgoodcNextPprice),
        "Exellent": str(excPredictedPrice) +' - '+str(excNextPprice)
    }

    return data


def load_prediction_models(model_file):#load_model('catboost_saved_model')
    loaded_model = load_model(os.path.join(model_file))
    return loaded_model


def load_prediction_models_state(model_file):
	loaded_model_state = joblib.load(open(os.path.join(model_file),"rb"))
	return loaded_model_state

def variant_correction(variant_temp,Model):
	if Model =='MULTIX':
		variant_temp = variant_temp.replace('4X2 MINI BUS','3IN1')
	elif Model =='MULTIX AX':
		variant_temp = variant_temp.replace('4X2 MINI BUS','511 CC')
	elif Model =='ACE HT FACELIFT':
		Variant = variant_temp.replace('4X2 PICKUP','FACELIFT')
	else :
		variant_temp = variant_temp
	return variant_temp

def state_model_prediction(model_name,data):
    model_prediction_state_1 = load_model(os.path.join(model_name))
    prediction_state_Model = predict_model(model_prediction_state_1,data=data)
    state_result = (prediction_state_Model['Label'][0])
    # st.write("State Prediction: ",state_result)
    return state_result

def round_10000(va):
	va_1=int(va/10000+1)
	return va_1*10000

def str_preprocessing(wor):
	wor = wor.upper()
	return wor.replace(' ','')

def str_mapping(arg):
	arg = arg.strip()
	return arg.replace(' ','')

def str_mapping2(arg):
	arg = arg.strip()
	arg=arg.replace(' ','')
	arg=arg.replace('-','')
	return arg

def frame_preprocessing(df,col):
	df[col] = df[col].str.replace(' ','')
	df[col] = df[col].str.upper()
	return df[col]

def clean_data_maping(df,col):
	df[col] = df[col].astype(str)
	df[col] = df[col].str.upper()
	df[col] = df[col].str.replace(' ','')
	return df[col]



# makE = 1
# modeL = 5

makE = 0
modeL = 0







def getIpAddress():
    """
    Always return the real client IP.
    - Take the first IP from X-Forwarded-For (client).
    - Fallback to remote_addr if header missing.
    """
    try:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            # First IP in list is real client
            return xff.split(",")[0].strip()
        return request.remote_addr or ""
    except Exception:
        return ""


# def getIpAddress():
#     """
#     Force fallback to random IPs (UAT style).
#     Always return empty so getIpAddress_1() is used.
#     """
#     return ""


# def getIpAddress():
#     """
#     Prefer real client IP from X-Forwarded-For (proxy/LB),
#     else fall back to request.remote_addr or REMOTE_ADDR env.
#     Return empty string if nothing.
#     """
#     try:
#         # Prefer X-Forwarded-For (may contain comma separated list)
#         xff = request.headers.get("X-Forwarded-For", "")
#         if xff:
#             return xff.split(",")[0].strip()
#         # Fallback to Flask remote_addr or environment REMOTE_ADDR
#         return request.remote_addr or request.environ.get("REMOTE_ADDR", "") or ""
#     except Exception:
#         return ""




# def getIpAddress_1():
#     ip_addresses = [
#         "172.31.27.90",
#         "172.31.10.231",
#         "172.31.44.56",
#         "127.0.0.1",
#         "172.31.16.54",
#         "172.31.46.25",
#         "172.31.11.187",
#         "172.31.38.86",
#         "172.31.12.252",
#         "172.31.27.186",
#         "172.31.6.233",
#         "172.31.46.201",
#         "172.31.21.33",
#         "::1",
#         "192.168.0.186",
#         "122.161.90.198",
#         "3.109.206.194",
#         "122.185.46.137",
#         "54.86.50.139",
#         "223.190.83.168",
#         "223.190.80.112",
#         "122.161.93.47",
#         "180.151.82.123",
#         "15.207.20.171"
#     ]
#     return random.choice(ip_addresses)



def chang_e(now):
    if now.day > 27 and now.day < 29:
        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
    


def int_fun(df,col):
	return df[col].astype(int)


def SortTuple(tup):   
    tup.sort(key = lambda x: x[0])   
    return tup

def pre_step_text(arg):
	arg = arg.upper()
	arg = arg.replace(' ','')
	return arg

def ne(arg):
	list_temp_temp =['Daman And Diu','Andaman and Nicobar Islands','Assam','Dadar And Nagar Haveli','Ladakh','Manipur','Meghalaya','Mizoram','Nagaland','Pondicherry','Sikkim','Tripura','Telangana']
	list_temp = [x.upper() for x in list_temp_temp ]
	for i in range(0,len(list_temp)):
		if arg==list_temp[i]:
			arg = arg.replace(list_temp[i],'NAN')
	return arg

def ne2(arg):
	list_temp_temp =['Daman And Diu','Andaman and Nicobar Islands','Assam','Arunachal Pradesh','Dadar And Nagar Haveli','Ladakh','Manipur','Meghalaya','Mizoram','Nagaland','Puducherry','Sikkim','Tripura']
	list_temp = [x.upper() for x in list_temp_temp ]
	for i in range(0,len(list_temp)):
		if arg==list_temp[i]:
			arg = arg.replace(list_temp[i],'NAN')
	return arg



def getState(CarRegNo):
   StateCode = CarRegNo[:2]
   stateQuery = "Select stateName from TBL_STATE_MASTER where delId=0 and stateCode='"+StateCode+"'"
   dataState = singleQuery(stateQuery)
   State = str(dataState[0]).upper()
   State = State.replace(' ','')
 
   return State



state_categories = {32:'Gujarat',88:'TamilNadu',60:'Madhya Pradesh',13:'Bihar',37:'Haryana',78:'Punjab',5:'Andhra Pradesh',51:'Kerala',90:'Tripura',94:'UttarPradesh',62:'Maharashtra',65:'Mizoram',80:'Rajasthan',100:'WestBengal',95:'Uttarakhand',7:'Arunachal Pradesh',38:'Himachal Pradesh',19:'Chandigarh',43:'Jammu & Kashmir',70:'ODISHA',9:'Assam',50:'Karnataka',31:'Goa',46:'Jharkhand',56:'MAHARASHTRA',28:'Delhi',63:'Manipur',26:'Daman and Diu',69:'Nagaland',64:'Meghalaya',82:'Sikkim',77:'Puducherry',52:'Lakshadweep',23:'Dadar And Nagar Haveli',22:'DELHI and NCR',35:'HUBLI',12:'BIHAR and JKD',33:'HARYANA',97:'WARANGAL',29:'GOA',75:'PUNJAB HP and JK',84:'TAMILNADU',98:'WEST BENGAL',36:'HYDERABAD',72:'PUDUCHERRY',91:'UTTAR PRADESH',92:'UTTARAKHAND',68:'NORTH EAST',16:'CHENNAI',89:'Telangana',67:'NAGPUR',48:'KERALA',96:'VIJAYAWADA',86:'TRICHY',55:'MADURAI',49:'KURNOOL',79:'RAJASTHAN',58:'MANGALORE',18:'COIMBATORE',47:'KARNATAKA',53:'MADHYA PRADESH',10:'BANGALORE',81:'SECUNDERABAD',73:'PUNE',30:'GUJARAT',59:'MUMBAI and GOA',15:'CHATTISGARH',85:'TELANGANA',42:'JHARKHAND',25:'Daman And Diu',20:'DELHI',11:'BIHAR',6:'AndhraPradesh',8:'ArunachalPradesh',61:'MadhyaPradesh',39:'HimachalPradesh',99:'WESTBENGAL',24:'DadarAndNagarHaveli',27:'DamanandDiu',93:'UTTARPRADESH',44:'Jammu&Kashmir',74:'PUNJAB',21:'DELHI', 17:'CHHATTISGARH',71:'PONDICHERRY',76:'Pondicherry',45:'Jammu&kashmir',14:'CHANDIGARH',57:'MAHARASTRA',0:'ANDHRA PRADESH',83:'TAMIL NADU',40:'JAMMU & KASHMIR',4:'ASSAM',34:'HIMACHALPRADESH',2:'ARUNACHAL PRADESH',66:'NAGALAND',87:'TRIPURA',1:'ANDHRAPRADESH',54:'MADHYAPRADESH',41:'JAMMU&KASHMIR',3:'ARUNACHALPRADESH'}

def state_to_category(state_num):
    try:
        # Return the category corresponding to the state number
        return state_categories[state_num]
    except KeyError:
        # If the state number is not in the dictionary, return an error message
        return "Invalid state number"



def model_price_out(model_name,data):
    model_predictor_price_1=load_model(os.path.join(model_name))
    prediction_price_Model_1 = predict_model(model_predictor_price_1,data=data)
    result_1 = abs(prediction_price_Model_1['Label'][0])
    # st.text(model_name)
    return result_1




def getCarmake_uat(id):
    dbconnect = dbConnection_uat()
    cursor = dbconnect.cursor()
    query = "Select id,carMake from TBL_CAR_MAKE where delId=0 and id="+id+""
    cursor.execute(query)
    data = cursor.fetchone()
    finalData = data
    dbconnect.close()
    return finalData




def getCarmodel_uat(id):
    dbconnect = dbConnection_uat()
    cursor = dbconnect.cursor()
    query = "Select id,carModel from TBL_CAR_MODEL where delId=0 and id="+id+""
    cursor.execute(query)
    data = cursor.fetchone()
    finalData = data
    dbconnect.close()
    return finalData




def getCarvariant_uat(id):
    dbconnect = dbConnection_uat()
    cursor = dbconnect.cursor()
    query = "Select id,carVariant from TBL_CAR_VARIANT where delId=0 and id="+id+""
    cursor.execute(query)
    data = cursor.fetchone()
    finalData = data
    dbconnect.close()
    return finalData




def getCarfuel_uat(id):
    dbconnect = dbConnection_uat()
    cursor = dbconnect.cursor()
    query = "Select id,carFuel from TBL_CAR_FUEL where delId=0 and id="+id+""
    cursor.execute(query)
    data = cursor.fetchone()
    finalData = data
    dbconnect.close()
    return finalData




def getState_uat(CarRegNo):
   StateCode = CarRegNo[:2]
   stateQuery = "Select stateName from TBL_STATE_MASTER where delId=0 and stateCode='"+StateCode+"'"
   dataState = singleQuery_uat(stateQuery)
   State = str(dataState[0]).upper()
   State = State.replace(' ','')
 
   return State



def singleQuery_uat(query):
    dbconnect = dbConnection_uat()
    cursor = dbconnect.cursor()
    cursor.execute(query)
    data = cursor.fetchone()
    finalData = data
    dbconnect.close()
    return finalData



def getCarSegment_uat(id):
    dbconnect = dbConnection_uat()
    cursor = dbconnect.cursor()
    query = "Select id,sellerSegment from TBL_SELLER_SEGMENT_MASTER where delId=0 and id="+id+""
    cursor.execute(query)
    data = cursor.fetchone()
    finalData = data
    dbconnect.close()
    return finalData



def price_range_calc(predprice):
    fair_upper = predprice - (predprice * 9 / 100)
    fair_lower = (predprice * 2.2) / 100
    fair_range = int(predprice) - int(fair_lower)

    good_upper = predprice - (predprice * 6 / 100)
    good_lower = (predprice * 1) / 100
    good_range = int(predprice) + int(good_lower)

    vgood_upper = predprice - (predprice * 3 / 100)
    vgood_lower = (predprice * 4) / 100
    vgood_range = int(predprice) + int(vgood_lower)

    exc_upper = int(predprice) - int(predprice * 0.2 / 100)
    exc_lower = (predprice * 6.9) / 100
    exc_range = int(predprice) + int(exc_lower)

    data = {
        "Fair": str(abs(fair_upper)) + ' - ' + str(abs(fair_range)),
        "Good": str(abs(good_upper)) + ' - ' + str(abs(good_range)),
        "VGood": str(abs(vgood_upper)) + ' - ' + str(abs(vgood_range)),
        "Excellent": str(abs(exc_upper)) + ' - ' + str(abs(exc_range))
    }

    return data    