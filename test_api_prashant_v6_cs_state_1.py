import uuid
from datetime import datetime, timedelta
from flask import jsonify, abort, request, Blueprint, make_response
from flask_restful import reqparse
import pandas as pd
import numpy as np
from datetime import date
from pathlib import Path
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from functools import lru_cache
import gc
from flask import redirect, request, jsonify
from apiFunction import *
import pickle
import random
import json
import datetime
import logging
import re
import math
from pytz import timezone
import os
from dotenv import load_dotenv

load_dotenv()  # Load .env variables

SESSION_EXPIRY_MINUTES = int(os.getenv("SESSION_EXPIRY_MINUTES", 15))  # default to 5 minutes
ABSOLUTE_MAX_SESSION_MINUTES = 1440  # 24 hours

# # Use Indian Standard Time (IST)
# india = timezone('Asia/Kolkata')

import logging
logging.basicConfig(level=logging.WARNING)


REQUEST_API = Blueprint('test_api_prashant_v6_cs_state_1', __name__)


@REQUEST_API.route("/debug/ip", methods=["GET"])
def debug_ip():
    return jsonify({
        "X-Forwarded-For": request.headers.get("X-Forwarded-For", ""),
        "X-Real-IP": request.headers.get("X-Real-IP", ""),
        "access_route": request.access_route,
        "remote_addr": request.remote_addr,
        "final_ip": getIpAddress()
    })


# ✅ Validate Host Header to Prevent Host Header Attacks

# ✅ Trusted Hosts


# Load allowed hosts from .env (comma-separated)


TRUSTED_HOSTS = {'api.thepricex.com', 'localhost', '127.0.0.1'}

@REQUEST_API.before_request
def validate_host_header():
    raw_host = request.headers.get("Host", "").split(":")[0]
    fwd_host = request.headers.get("X-Forwarded-Host", "").split(":")[0]

    # ✅ Get client IP
    if request.headers.getlist("X-Forwarded-For"):
        client_ip = request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    else:
        client_ip = request.remote_addr or request.environ.get("REMOTE_ADDR", "Unknown")

    logging.warning(
        f"Received Host: {raw_host}, X-Forwarded-Host: {fwd_host}, Client-IP: {client_ip}"
    )

    # Block if the Host header is not trusted
    if raw_host not in TRUSTED_HOSTS:
        return jsonify({
            "status": 400,
            "message": "Invalid Host Header (Host)",
            "data": None
        }), 400

    # Block if someone injects a bad X-Forwarded-Host
    if fwd_host and fwd_host not in TRUSTED_HOSTS:
        return jsonify({
            "status": 400,
            "message": "Invalid Host Header (X-Forwarded-Host)",
            "data": None
        }), 400




# TRUSTED_HOSTS = {'api.thepricex.com', 'localhost', '127.0.0.1'}

# @REQUEST_API.before_request
# def validate_host_header():
#     raw_host = request.headers.get("Host", "").split(":")[0]
#     fwd_host = request.headers.get("X-Forwarded-Host", "").split(":")[0]

#     logging.warning(f"Received Host: {raw_host}, X-Forwarded-Host: {fwd_host}")

#     # Block if the Host header is not trusted
#     if raw_host not in TRUSTED_HOSTS:
#         return jsonify({
#             "status": 400,
#             "message": "Invalid Host Header (Host)",
#             "data": None
#         }), 400

#     # Block if someone injects a bad X-Forwarded-Host
#     if fwd_host and fwd_host not in TRUSTED_HOSTS:
#         return jsonify({
#             "status": 400,
#             "message": "Invalid Host Header (X-Forwarded-Host)",
#             "data": None
#         }), 400





@REQUEST_API.before_request
def sanitize_all_inputs():
    """
    Global input sanitizer for ALL API endpoints.
    - Blocks < and > characters everywhere (prevent HTML/JS injection).
    - Enforces numeric-only on specific whitelisted ID fields.
    """

    # ✅ List of fields that must be numeric-only
    numeric_id_fields = {"variantid", "makeid", "modelid", "fuelid", "yearid"}

    def has_bad_chars(val: str) -> bool:
        return any(c in val for c in ["<", ">"])

    def is_strict_numeric(val: str) -> bool:
        return val.isdigit()

    # ✅ Helper to validate values
    def validate_field(key, value, source=""):
        if not isinstance(value, str):
            return None
        if has_bad_chars(value):
            return jsonify({
                "status": 400,
                "message": f"Invalid characters in {source} field '{key}'",
                "data": None
            }), 400
        if key.lower() in numeric_id_fields and not is_strict_numeric(value):
            return jsonify({
                "status": 400,
                "message": f"Invalid format for '{key}', must be numeric only",
                "data": None
            }), 400
        return None

    # ✅ Query params
    for key, value in request.args.items():
        error = validate_field(key, value, "query parameter")
        if error:
            return error

    # ✅ Form-data
    if request.form:
        for key, value in request.form.items():
            error = validate_field(key, value, "form")
            if error:
                return error

    # ✅ JSON body
    if request.is_json:
        try:
            data = request.get_json()
            if isinstance(data, dict):
                for key, value in data.items():
                    error = validate_field(key, value, "JSON")
                    if error:
                        return error
        except Exception:
            pass


# TRUSTED_HOSTS = {'api.thepricex.com', 'localhost', '127.0.0.1'}

# @REQUEST_API.before_request
# def validate_host_header():
#     host = request.headers.get("X-Forwarded-Host", request.host).split(":")[0]
#     logging.warning(f"Received Host: {host}")  # 👀 Logs incoming host headers

#     if host not in TRUSTED_HOSTS:
#         return jsonify({
#             "status": 400,
#             "message": "Invalid Host Header",
#             "data": None
#         }), 400




def get_blueprint():
    """Return the blueprint for the main app module"""
    return REQUEST_API


# -----------------------------
# ✅ TOKEN REQUIRED DECORATOR
# -----------------------------

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # 1️⃣ Extract token from header
        if 'Authorization' in request.headers:
            parts = request.headers['Authorization'].split(' ')
            if len(parts) == 2:
                token = bytes(parts[1], 'utf8')

        if not token:
            return jsonify({"status": 401, "message": "Token is missing", "data": None}), 401

        try:
            decrypted = decrypt(token)
            data = decrypted.decode('utf-8')
            print("🔓 Decrypted token:", data)
        except Exception as e:
            print("❌ Token decryption error:", str(e))
            return jsonify({"status": 401, "message": "Invalid Token Format", "data": None}), 401

        now = datetime.datetime.now()

        # 2️⃣ Handle NEW format: clientId|password|timestamp
        if '|' in data:
            parts = data.split("|")
            if len(parts) != 3:
                return jsonify({"status": 401, "message": "Malformed Token", "data": None}), 401

            clientId, secretKey, expire_ts = parts

            try:
                expire_time = datetime.datetime.fromtimestamp(int(expire_ts))
            except Exception:
                return jsonify({"status": 401, "message": "Invalid expiry timestamp", "data": None}), 401

            if now > expire_time:
                return jsonify({"status": 401, "message": "Session expired. Please reauthenticate.", "data": None}), 401

        # 3️⃣ Handle LEGACY format: clientId-password
        elif '-' in data:
            parts = data.split("-", 1)
            if len(parts) != 2:
                return jsonify({"status": 401, "message": "Malformed legacy token", "data": None}), 401

            clientId, secretKey = parts
        else:
            return jsonify({"status": 401, "message": "Malformed Token", "data": None}), 401

        # 4️⃣ DB Check
        query = f"""
            SELECT a.clientId, a.clientName, b.apiPassword, a.emailId, a.apiAccess, b.apiSecretKey
            FROM TBL_CLIENTMASTER a
            LEFT JOIN TBL_CLIENT_API_TOKEN b ON a.clientId = b.clientId
            WHERE a.clientId = '{clientId}' AND a.delId=0 AND b.delId=0
        """
        authData = singleQuery(query)

        if not authData:
            return jsonify({"status": 401, "message": "Authentication Error. Invalid Token", "data": None}), 401

        dbhashpassword = authData[2]
        dbsecret = authData[5]

        print("🔐 DB hashed password:", dbhashpassword)
        print("🔐 DB plain secretKey:", dbsecret)
        print("🔐 Token secretKey    :", secretKey)

        is_valid = check_password_hash(dbhashpassword, secretKey) or (secretKey == dbsecret)

        if is_valid:
            return f(authData, *args, **kwargs)
        else:
            return jsonify({"status": 401, "message": "Authentication Error. Invalid Token", "data": None}), 401

    return decorated


# def token_required(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         token = None

#         if 'Authorization' in request.headers:
#             rheader = request.headers['Authorization']
#             parts = rheader.split(' ')
#             if len(parts) == 2:
#                 token = bytes(parts[1], 'utf8')

#         if not token:
#             return jsonify({"status": 401, "message": "Token is missing", "data": None}), 401

#         try:
#             decrypted = decrypt(token)
#             data = decrypted.decode('utf-8')
#         except Exception as e:
#             print("❌ Token decryption error:", str(e))
#             traceback.print_exc()
#             return jsonify({"status": 401, "message": "Invalid Token Format", "data": None}), 401

#         now = datetime.datetime.now()

#         # ✅ New format: clientId|password|timestamp
#         if '|' in data:
#             parts = data.split("|")
#             if len(parts) != 3:
#                 return jsonify({"status": 401, "message": "Malformed Token", "data": None}), 401

#             clientId, secretKey, expire_ts = parts

#             try:
#                 expire_time = datetime.datetime.fromtimestamp(int(expire_ts))
#             except Exception:
#                 return jsonify({"status": 401, "message": "Invalid expiry timestamp", "data": None}), 401

#             if now > expire_time:
#                 return jsonify({
#                     "status": 401,
#                     "message": "Session expired. Please reauthenticate.",
#                     "data": None
#                 }), 401

#         # ✅ Legacy format: clientId-secretKey
#         elif '-' in data:
#             parts = data.split("-", 1)
#             if len(parts) != 2:
#                 return jsonify({"status": 401, "message": "Malformed legacy token", "data": None}), 401
#             clientId, secretKey = parts
#         else:
#             return jsonify({"status": 401, "message": "Malformed Token", "data": None}), 401

#         # ✅ DB lookup
#         query = f"""
#             SELECT a.clientId, a.clientName, b.apiPassword, a.emailId, a.apiAccess, b.apiSecretKey
#             FROM TBL_CLIENTMASTER a
#             LEFT JOIN TBL_CLIENT_API_TOKEN b ON a.clientId = b.clientId
#             WHERE a.clientId = '{clientId}' AND a.delId=0 AND b.delId=0
#         """
#         authData = singleQuery(query)

#         if not authData:
#             return jsonify({
#                 "status": 401,
#                 "message": "Authentication Error. Invalid Token",
#                 "data": None
#             }), 401

#         dbhashpassword = authData[2]
#         dbsecret = authData[5]

#         print("🔐 Debug — token validation start")
#         print(" - Token clientId       :", clientId)
#         print(" - Token secretKey      :", secretKey)
#         print(" - DB hashed password   :", dbhashpassword)
#         print(" - DB plain secret key  :", dbsecret)

#         # ✅ Use either hash check or raw match
#         is_valid = check_password_hash(dbhashpassword, secretKey) or (secretKey == dbsecret)

#         if is_valid:
#             return f(authData, *args, **kwargs)
#         else:
#             return jsonify({
#                 "status": 401,
#                 "message": "Authentication Error. Invalid Token",
#                 "data": None
#             }), 401

#     return decorated



# -----------------------------
# ✅ REGISTER API
# -----------------------------

@REQUEST_API.route('/registerApi', methods=['POST'])
def create_user():
    try:
        parser = reqparse.RequestParser(bundle_errors=True)
        parser.add_argument('clientId', type=str)
        parser.add_argument('labelName', type=str)
        parser.add_argument('password', type=str)
        args = parser.parse_args()

        if not args.clientId or not args.labelName or not args.password:
            return jsonify({"status": 406, "message": "All fields are required", "data": None}), 406

        # 🔐 Hash password
        hashed_password = generate_password_hash(args.password, method='pbkdf2:sha256')

        # ⏱ Token expiration
        now = datetime.datetime.now()
        expire_at = now + datetime.timedelta(minutes=15)
        expire_ts = int(expire_at.timestamp())

        # 🔐 Encode token
        encodedKey = f"{args.clientId}|{args.password}|{expire_ts}"
        print("🔐 Token Info:")
        print(" - Created At      :", now)
        print(" - Expires At      :", expire_at)
        print(" - Encoded Payload :", encodedKey)

        encrypted = encrypt(encodedKey.encode())
        if not encrypted:
            raise Exception("Encryption failed")

        token_str = encrypted.decode('utf-8')

        # 🔁 Ensure client exists in TBL_CLIENTMASTER
        check_master = f"SELECT * FROM TBL_CLIENTMASTER WHERE clientId = '{args.clientId}'"
        existing_master = singleQuery(check_master)

        if not existing_master:
            insert_master = f"""
                INSERT INTO TBL_CLIENTMASTER (clientId, clientName, delId)
                VALUES ('{args.clientId}', '{args.labelName}', 0)
            """
            insertQuery(insert_master)

        # ❌ Invalidate old tokens
        update_old = f"""
            UPDATE TBL_CLIENT_API_TOKEN
            SET delId = 1
            WHERE clientId = '{args.clientId}' AND delId = 0
        """
        updateQuery(update_old)

        # ✅ Insert new token
        insert_token = f"""
            INSERT INTO TBL_CLIENT_API_TOKEN (clientId, labelName, apiPassword, apiSecretKey)
            VALUES ('{args.clientId}', '{args.labelName}', '{hashed_password}', '{args.password}')
        """
        result = insertQuery(insert_token)

        if result[1] == 201:
            return jsonify({
                "status": 201,
                "message": "Token created successfully",
                "data": {"secretToken": token_str}
            }), 201
        else:
            return jsonify({"status": 400, "message": "Failed to create token", "data": None}), 400

    except Exception as e:
        print("⚠️ Register API ERROR:", str(e))
        traceback.print_exc()
        return jsonify({"error": "Server error"}), 500

# -----------------------------
# ✅ LOGOUT API
# -----------------------------
@REQUEST_API.route('/logout', methods=['POST'])
@token_required
def logout(authData):
    try:
        clientId = authData[0]
        query = f"UPDATE TBL_CLIENT_API_TOKEN SET delId = 1 WHERE clientId = '{clientId}' AND delId = 0"
        result = updateQuery(query)
        if result[1] == 201:
            return jsonify({"status": 200, "message": "Successfully logged out"}), 200
        else:
            return jsonify({"status": 400, "message": "Logout failed"}), 400
    except Exception as e:
        print("Logout Error:", str(e))
        return jsonify({"status": 500, "message": "Internal Server Error"}), 500

# def token_required(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         token = None

#         if 'Authorization' in request.headers:
#             rheader = request.headers['Authorization']
#             dheader = rheader.split(' ')
#             token =  bytes(dheader[1],'utf8')

#         if not token:
#             return jsonify({"status": 401,"message": "Token is missing","data":None}), 401
        
#         try:
#             decrypted = decrypt(token)
#         except:
#             return jsonify({"status": 401, "message":"Authentication Error. invalid Token Used", "data": None}), 401

        
#         # data = decrypted.decode('utf-8')
#         # data = data.split("-", 1)
#         # clientId = data[0]
#         # secretKey = data[1]


#         data = decrypted.decode('utf-8')
#         if '|' in data:


#             parts = data.split("|")
#             if len(parts) != 3:


#                 return jsonify({"status": 401, "message": "Malformed Token", "data": None}), 401

#             clientId, secretKey, expire_ts = parts
#             expire_time = datetime.datetime.utcfromtimestamp(int(expire_ts))

#             if datetime.datetime.utcnow() > expire_time:

#                 return jsonify({"status": 401, "message": "Session expired. Please reauthenticate.", "data": None}), 401
            
#         elif '-' in data:
#             parts = data.split("-", 1)
#             if len(parts) != 2:
#                 return jsonify({"status": 401, "message": "Malformed Token", "data": None}), 401
#             clientId, secretKey = parts
#         else:


#             return jsonify({"status": 401, "message": "Malformed Token", "data": None}), 401
 

#         query = "Select a.clientId, a.clientName ,b.apiPassword, a.emailId, a.apiAccess,b.apiSecretKey from TBL_CLIENTMASTER a left join TBL_CLIENT_API_TOKEN b on a.clientId = b.clientId where a.clientId='"+ clientId +"' and a.delId=0 and b.delId=0"
#         authData = singleQuery(query)
#         if not authData:
#             return jsonify({"status": 401, "message":"Authentication Error. invalid Token Used", "data": None}), 401
#         clientId = authData[0]
#         dbusername = authData[1]
#         dbhashpassword = authData[2]
#         dbemail = authData[3]
#         apiaccess = authData[4]
#         if check_password_hash(dbhashpassword, secretKey):
#             return f(authData, *args, **kwargs)
#         else:
#             return jsonify({"status": 401, "message":"Authentication Error. Invalid Token Used","data": None}), 401

#     return decorated



# now = datetime.datetime.now()


# @REQUEST_API.route('/registerApi', methods=['POST']) 
# def create_user():
#     try:
        
#         parser = reqparse.RequestParser(bundle_errors=True)
#         parser.add_argument('clientId', type=str)
#         parser.add_argument('labelName', type=str)
#         parser.add_argument('password', type=str)
#         args = parser.parse_args()

        

#         if not args.clientId:
#             return jsonify({"status": 406, "message": "Client Id not be empty", "data": None}), 406
#         if not args.labelName:
#             return jsonify({"status": 406, "message": "Username not be empty", "data": None}), 406
#         if not args.password:
#             return jsonify({"status": 406, "message": "Password not be empty", "data": None}), 406

        
#         hashed_password = generate_password_hash(args.password, method='sha256')

#         # expire_at = (datetime.datetime.utcnow() + datetime.timedelta(minutes=30)).timestamp()
#         # encodedKey = f"{args.clientId}|{args.password}|{int(expire_at)}"
#         # encrypted = encrypt(encodedKey.encode())

#         expire_at_dt = datetime.datetime.utcnow() + datetime.timedelta(minutes=SESSION_EXPIRY_MINUTES)

#         # expire_at_dt = datetime.datetime.utcnow() + datetime.timedelta(minutes=2)
#         expire_ts = int(expire_at_dt.timestamp())
#         encodedKey = f"{args.clientId}|{args.password}|{expire_ts}"
#         print("🔐 TOKEN BEFORE ENCRYPT:", encodedKey) # new change

#         encrypted = encrypt(encodedKey.encode())
#         token_str = encrypted.decode('utf-8')

        
        
#         sqlQuery = 'Select * from TBL_CLIENT_API_TOKEN where clientId="'+ args.clientId +'" and delId=0'
#         sqlData = singleQuery(sqlQuery)

        
#         if not sqlData:
#             query = 'Insert into TBL_CLIENT_API_TOKEN(clientId,labelName,apiPassword)values ("'+ args.clientId +'","'+ args.labelName +'","'+ hashed_password +'")'
            
#             regData = insertQuery(query)
#             if regData[1] == 201:
#                 tokenData = {"secretToken": encrypted.decode('utf-8')}
#                 return jsonify({"status": 201, "message":"new user entry created","data": tokenData}), 201
#             else:
#                 return jsonify({"status": 400, "message":"Some error occurred while saving data","data": None}), 400
#         else:
#             upQuery = 'Update TBL_CLIENT_API_TOKEN set delId=1 where clientId="'+ args.clientId +'" and delId=0 order by createdAt desc'
            
#             query = 'Insert into TBL_CLIENT_API_TOKEN(clientId,labelName,apiPassword)values ("'+ args.clientId +'","'+ args.labelName +'","'+ hashed_password +'")'
            
            
#             upData = updateQuery(upQuery)
#             if upData[1] == 201:
#                 regData = insertQuery(query)
#                 if regData[1] == 201:

#                     # tokenData = {"secretToken": token_str}
#                     # return jsonify({"status": 201, "message": "new user entry created", "data": tokenData}), 201


#                     tokenData = {"secretToken": encrypted.decode('utf-8')}
#                     return jsonify({"status": 201, "message":"new user entry created","data": tokenData}), 201
#                 else:

#                     return jsonify({"status": 400, "message":"Some error occurred while saving data","data": None}), 400
#             else:
                
#                 return jsonify({"status": 400, "message":"Some error occurred while updating data","data": None}), 400

#     except Exception as e:
#         print("⚠️ Register API ERROR:", str(e))
#         return jsonify({"error": "Server error"}), 500





# @REQUEST_API.route('/logout', methods=['POST'])
# @token_required
# def logout(authData):
#     try:
#         clientId = authData[0]
#         upQuery = f"UPDATE TBL_CLIENT_API_TOKEN SET delId = 1 WHERE clientId = '{clientId}' AND delId = 0"
#         updateData = updateQuery(upQuery)
#         if updateData[1] == 201:
#             return jsonify({"status": 200, "message": "Successfully logged out"}), 200
#         else:
#             return jsonify({"status": 400, "message": "Logout failed"}), 400
#     except Exception as e:
#         print("Logout Error:", str(e))
#         return jsonify({"status": 500, "message": "Internal Server Error"}), 500















# @REQUEST_API.route('/registerApi', methods=['POST'])
# #@token_required
# def create_user(data):
    
#     # print(data)
#     start = time.process_time()
#     # if data[4] == 0:

#     #     return jsonify({"status": 401,'message' : 'User unathorised to used API'}), 401

#     userData = request.headers.get('User-Agent')
#     # parser = reqparse.RequestParser(bundle_errors=True)
#     # parser.add_argument('clientId', type=str, required=True, help = 'Please Enter Client Id')
#     # parser.add_argument('labelName', type=str, required=True, help = 'Please Enter Client Name')
#     # parser.add_argument('password', type=str, help="Please Enter Password")
#     # args = parser.parse_args()
#     # if not args.clientId:
#     #     return jsonify({"status": 406, "message": "Client Id not be empty", "data": None}), 406
#     # if not args.labelName:
#     #     return jsonify({"status": 406, "message": "Username not be empty", "data": None}), 406
#     # if not args.password:
#     #     return jsonify({"status": 406, "message": "Password not be empty", "data": None}), 406

#     # hashed_password = generate_password_hash(args.password,method='sha256')
#     # encodedKey = args.clientId + '-'+ args.password

#     # expire_at = (datetime.datetime.utcnow() + datetime.timedelta(minutes=30)).timestamp()
#     # encodedKey = f"{args.clientId}|{args.password}|{int(expire_at)}"

#     parser = reqparse.RequestParser(bundle_errors=True)
#     parser.add_argument('clientId', type=str)
#     parser.add_argument('labelName', type=str)
#     parser.add_argument('password', type=str)
#     args = parser.parse_args()

#     if not args.clientId:

#         return jsonify({"status": 406, "message": "Client Id not be empty", "data": None}), 406
#     if not args.labelName:

#         return jsonify({"status": 406, "message": "Username not be empty", "data": None}), 406
#     if not args.password:

#         return jsonify({"status": 406, "message": "Password not be empty", "data": None}), 406

#     hashed_password = generate_password_hash(args.password, method='sha256')
#     expire_at = (datetime.datetime.utcnow() + datetime.timedelta(minutes=15)).timestamp()
#     encodedKey = f"{args.clientId}|{args.password}|{int(expire_at)}"
#     encodedKey = encodedKey.encode()
#     encrypted = encrypt(encodedKey)

    
#     #encodedKey = encodedKey.encode()
#     #encrypted = encrypt(encodedKey)
#     sqlQuery = 'Select * from TBL_CLIENT_API_TOKEN where clientId="'+ args.clientId +'" and delId=0'
#     sqlData = singleQuery(sqlQuery)
#     if not sqlData:
#         query = 'Insert into TBL_CLIENT_API_TOKEN(clientId,labelName,apiPassword)values ("'+ args.clientId +'","'+ args.labelName +'","'+ hashed_password +'")'
#         regData = insertQuery(query)
#         if regData[1] == 201:
#             request_time = "%.2gs" % (time.process_time() - start)
#             tokenData = {"secretToken": encrypted.decode('utf-8')}
#             saveApiHit(args.clientId, request_time,201)
#             return jsonify({"status": 201, "message":"new user entry created","data": tokenData}), 201
#         else:
#             request_time = "%.2gs" % (time.process_time() - start)
#             saveApiHit(args.clientId, request_time,400)
#             return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400
#     else:
#         upQuery = 'Update TBL_CLIENT_API_TOKEN set delId=1 where clientId="'+ args.clientId +'" and delId=0 order by createdAt desc'
#         query = 'Insert into TBL_CLIENT_API_TOKEN(clientId,labelName,apiPassword)values ("'+ args.clientId +'","'+ args.labelName +'","'+ hashed_password +'")'
#         upData = updateQuery(upQuery)
#         if upData[1] == 201:
#             regData = insertQuery(query)
#             if regData[1] == 201:
#                 request_time = "%.2gs" % (time.process_time() - start)
#                 tokenData = {"secretToken": encrypted.decode('utf-8')}
#                 saveApiHit(args.clientId, request_time,201)
#                 return jsonify({"status": 201, "message":"new user entry created","data": tokenData}), 201
#             else:
#                 request_time = "%.2gs" % (time.process_time() - start)
#                 saveApiHit(args.clientId, request_time,400)
#                 return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400
#         else:
#             request_time = "%.2gs" % (time.process_time() - start)
#             saveApiHit(args.clientId, request_time,400)
#             return jsonify({"status": 400, "message":"Some error occured while updating data","data": None}), 400








# def savePredictOutputv2(make, model, variant, fuel, state, regno, year, segmentId,
#                         price, predState, clientId, clientType, userId, meterReading):
#     try:
#         query = f"""
#         INSERT INTO TBL_PREDICTION_OUTPUT (
#             make, model, variant, fuel, state,
#             carRegistrationNumber, regYear, segmentId,
#             prePrice, preState, clientId, clientType,
#             userId, meter_reading
#         ) VALUES (
#             '{make}', '{model}', '{variant}', '{fuel}', '{state}',
#             '{regno}', '{year}', {segmentId if segmentId else 'NULL'},
#             '{price}', '{predState}', '{clientId}', '{clientType}',
#             '{userId}', {meterReading}
#         );
#         """
#         print("DEBUG insert query:\n", query)
#         return insertQuery(query)
#     except Exception as e:
#         print("Insert error:", str(e))
#         return (False, 400, str(e))





import datetime
import random

def savePredictOutputv2(make, model, variant, fuel, state, regno, year, segmentId,
                        price, predState, clientId, clientType, userId, meterReading):
    try:
        # Generate unique hitId
        hit_id = "HIT" + datetime.datetime.now().strftime("%Y%m%d%H%M%S") + str(random.randint(100, 999))

        # capture IP (prefer real, fallback to random list)
        ipAddress = getIpAddress()
        # if not ipAddress or ipAddress == "Unknown":
        #     ipAddress = getIpAddress_1()

        # SQL INSERT query - note ipaddress column (lowercase)
        query = f"""
        INSERT INTO TBL_PREDICTION_OUTPUT (
            hitId, make, model, variant, fuel, state,
            carRegistrationNumber, regYear, segmentId,
            prePrice, preState, clientId, clientType,
            userId, meter_reading, ipaddress
        ) VALUES (
            '{hit_id}', '{make}', '{model}', '{variant}', '{fuel}', '{state}',
            '{regno}', '{year}', {segmentId if segmentId else 'NULL'},
            '{price}', '{predState}', '{clientId}', '{clientType}',
            '{userId}', {meterReading}, '{ipAddress}'
        );
        """
        print("DEBUG insert query:\n", query)

        result = insertQuery(query)
        # Return the hit_id and the response code from insertQuery
        return (hit_id, result[1])
    except Exception as e:
        print("Insert error:", str(e))
        return (None, 400, str(e))




# def savePredictOutputv2(make, model, variant, fuel, state, regno, year, segmentId,
#                         price, predState, clientId, clientType, userId, meterReading):
#     try:
#         # Generate unique hitId
#         hit_id = "HIT" + datetime.datetime.now().strftime("%Y%m%d%H%M%S") + str(random.randint(100, 999))

#         # SQL INSERT query with hitId field
#         query = f"""
#         INSERT INTO TBL_PREDICTION_OUTPUT (
#             hitId, make, model, variant, fuel, state,
#             carRegistrationNumber, regYear, segmentId,
#             prePrice, preState, clientId, clientType,
#             userId, meter_reading
#         ) VALUES (
#             '{hit_id}', '{make}', '{model}', '{variant}', '{fuel}', '{state}',
#             '{regno}', '{year}', {segmentId if segmentId else 'NULL'},
#             '{price}', '{predState}', '{clientId}', '{clientType}',
#             '{userId}', {meterReading}
#         );
#         """
#         print("DEBUG insert query:\n", query)

#         result = insertQuery(query)
#         # Return the hit_id with the insert result
#         return (hit_id, result[1])  # assuming result = (True/False, 201/400, errorMessage)

#     except Exception as e:
#         print("Insert error:", str(e))
#         return (None, 400, str(e))




@REQUEST_API.route('/predictedpricev2', methods=['POST'])
@token_required
def predicted_price2(data):
    import time, json
    start = time.process_time()

    if data[4] == 0:
        return jsonify({"status": 401, "message": "User unathorised to used API"}), 401

    # Fetch subscription info
    fetchQuery = f"""
        SELECT clientId, activeSubscription, totalHitCount, hitCountAvailable
        FROM TBL_SUBSCRIPTION_COUNT_MASTER
        WHERE clientId = '{data[0]}'
    """
    fetchData = singleQuery(fetchQuery)
    if not fetchData:
        return jsonify({"status": 401, "message": "Some Error occured. Kindly contact Administrator for help"}), 401

    totalHitCount = fetchData[2]
    totalHitAvailable = int(fetchData[3])
    if totalHitAvailable < 1:
        return jsonify({"status": 401, "message": "You have exhausted your API hit. Kindly recharge or topup hit"}), 401

    userData = request.headers.get('User-Agent')

    parser = reqparse.RequestParser(bundle_errors=True)
    parser.add_argument('vtype', type=str, required=True, help="Please Enter vehicle type")
    parser.add_argument('make', type=str, required=True, help="Please Enter vehicle make")
    parser.add_argument('model', type=str, required=True, help="Please Enter vehicle model")
    parser.add_argument('variant', type=str, required=True, help="Please Enter vehicle variant")
    parser.add_argument('fuel', type=str, required=True, help="Please Enter vehicle fuel")
    parser.add_argument('regno', type=str, required=True, help="Please Enter vehicle number")
    parser.add_argument('mfgyear', type=str, required=True, help="Please Enter vehicle manufacturing year")
    parser.add_argument('METERREADING', type=str, required=True, help="Please Enter vehicle meter reading")
    parser.add_argument('clientId', type=str, required=True, help="Please Enter client id")
    parser.add_argument('clientType', type=str, required=True, help="Please Enter client type")
    parser.add_argument('userId', type=str, required=True, help="Please Enter user id")
    args = parser.parse_args()

    # --- Sanitization only for identifiers ---
    def sanitize_identifier(value: str, field_name: str) -> str:
        if not isinstance(value, str):
            raise ValueError(f"{field_name} must be a string")
        if "<" in value or ">" in value:   # block script injection
            raise ValueError(f"Invalid characters in {field_name}")
        return value.strip()

    try:
        args.clientId = sanitize_identifier(args.clientId, "clientId")
        args.clientType = sanitize_identifier(args.clientType, "clientType")
        args.userId = sanitize_identifier(args.userId, "userId")
    except ValueError as ve:
        return jsonify({"status": 400, "message": str(ve), "data": None}), 400

    # --- Validation for required fields ---
    if not args.vtype:
        return jsonify({"status": 406, "message": "Vehicle type cannot be empty", "data": None}), 406
    if not args.make:
        return jsonify({"status": 406, "message": "Vehicle Make cannot be empty", "data": None}), 406
    if not args.model:
        return jsonify({"status": 406, "message": "Vehicle Model cannot be empty", "data": None}), 406
    if not args.variant:
        return jsonify({"status": 406, "message": "Vehicle Variant cannot be empty", "data": None}), 406
    if not args.fuel:
        return jsonify({"status": 406, "message": "Vehicle Fuel cannot be empty", "data": None}), 406
    if not args.regno:
        return jsonify({"status": 406, "message": "Vehicle Registration Number cannot be empty", "data": None}), 406
    if not args.mfgyear:
        return jsonify({"status": 406, "message": "Vehicle Year cannot be empty", "data": None}), 406
    if not args.METERREADING:
        return jsonify({"status": 406, "message": "Meter Reading cannot be empty", "data": None}), 406
    if not args.clientId:
        return jsonify({"status": 406, "message": "Client Id cannot be empty", "data": None}), 406
    if not args.clientType:
        return jsonify({"status": 406, "message": "Client Type cannot be empty", "data": None}), 406




# @REQUEST_API.route('/predictedpricev2', methods=['POST'])
# @token_required
# def predicted_price2(data):
#     start = time.process_time()
#     if data[4] == 0:
#         return jsonify({"status": 401,'message' : 'User unathorised to used API'}), 401
#     fetchQuery = 'Select clientId, activeSubscription, totalHitCount, hitCountAvailable from TBL_SUBSCRIPTION_COUNT_MASTER where clientId="'+data[0]+'"'
#     fetchData = singleQuery(fetchQuery)
#     if not fetchData:
#         return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
#     totalHitCount = fetchData[2]
#     totalHitAvailable = int(fetchData[3])
#     if totalHitAvailable < 1:
#         return jsonify({"status": 401,'message' : 'You have exhausted your API hit. Kindly recharge or topup hit'}), 401


#     userData = request.headers.get('User-Agent')
#     parser = reqparse.RequestParser(bundle_errors=True)
#     parser.add_argument('vtype', type=str, required=True, help = "Please Enter vehicle type")
#     parser.add_argument('make', type=str, required=True, help = "Please Enter vehicle make")
#     parser.add_argument('model', type=str, help="Please Enter vehicle model")
#     parser.add_argument('variant', type=str, help="Please Enter vehicle variant")
#     parser.add_argument('fuel', type=str, help="Please Enter vehicle fuel")
#     parser.add_argument('regno', type=str, help="Please Enter vehicle number")
#     parser.add_argument('mfgyear', type=str, help="Please Enter vehicle manufacturing year")
#     parser.add_argument('METERREADING', type=str, help="Please Enter vehicle manufacturing year")
#     parser.add_argument('clientId', type=str, help="Please Enter client id")
#     parser.add_argument('clientType', type=str, help="Please Enter client type id")
#     parser.add_argument('userId', type=str, help="Please Enter user id")
#     args = parser.parse_args()

#     # print(args)

#     if not args.vtype:
#         return jsonify({"status": 406,"return": "Vehicle type not be empty", "data": None}), 406
#     if not args.make:
#         return jsonify({"status": 406,"return": "Vehicle Make not be empty", "data": None}), 406
#     if not args.model:
#         return jsonify({"status": 406,"return": "Vehicle Model not be empty", "data": None}), 406
#     if not args.variant:
#         return jsonify({"status": 406,"return": "Vehicle Variant not be empty", "data": None}), 406
#     if not args.fuel:
#         return jsonify({"status": 406,"return": "Vehicle Fuel not be empty", "data": None}), 406
#     if not args.regno:
#         return jsonify({"status": 406,"return": "Vehicle Registrtion Number not be empty", "data": None}), 406
#     if not args.mfgyear:
#         return jsonify({"status": 406,"return": "Vehicle Year not be empty", "data": None}), 406
#     if not args.METERREADING:
#         return jsonify({"status": 406,"return": "Meter Reading not be empty", "data": None}), 406
#     if not args.clientId:
#         return jsonify({"status": 406,"return": "Client Id not be empty", "data": None}), 406
#     if not args.clientType:
#         return jsonify({"status": 406,"return": "Client Type not be empty", "data": None}), 406
    



    vehicleCategory = args.vtype.upper()
    
    segmentId = ''
    predState = ''    


    if vehicleCategory == '4W':

        carMake = getCarmake_uat(args.make)
        carModel = getCarmodel_uat(args.model)
        carVariant = getCarvariant_uat(args.variant)
        carFuel = getCarfuel_uat(args.fuel)
        state = args.regno[:2]

        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        CV_State_Clean = getState_uat(state)
        CV_State_Clean = CV_State_Clean.upper()
        METERREADING = args.METERREADING
        MAKE_YEAR = args.mfgyear


        print(MAKE_YEAR,Make_Clean.replace(' ',''),Model_Clean.replace(' ',''),Variant_Clean.replace(' ',''),Fuel_Clean,CV_State_Clean.replace(' ',''),METERREADING)
    

        try:
            try:
                X = pd.DataFrame(columns=['MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','CV_State_Clean','METERREADING'],data=np.array([MAKE_YEAR,Make_Clean.strip().replace(' ', ''),Model_Clean.strip().replace(' ', ''),Variant_Clean.strip().replace(' ', ''),Fuel_Clean,CV_State_Clean.strip().replace(' ', ''),METERREADING]).reshape(1,7))
                predPrice = fourw_ncs_test.predict(X)[0]
                predPrice = int(predPrice)
                print(predPrice)
            except Exception as e:
                print(e)


            newHitCount = totalHitAvailable -1
            saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,MAKE_YEAR,segmentId,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)
            

            if saveData[1] == 201:

                if 1 != 1:
                    chang_e()


                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updateQuery(updateHitQuery)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401                    
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": predPrice,
                        "state": predState
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200            


            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                updateData = updateQuery(updateHitQuery)                
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        
        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,MAKE_YEAR,segmentId,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)            
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400
            




    elif vehicleCategory == '2W':

        carMake = getCarmake_uat(args.make)
        carModel = getCarmodel_uat(args.model)
        carVariant = getCarvariant_uat(args.variant)
        carFuel = getCarfuel_uat(args.fuel)
        state = args.regno[:2]

        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        State_Clean = getState_uat(state).upper()

        METERREADING = args.METERREADING
        MAKEYEAR = args.mfgyear

        print(Make_Clean, Model_Clean, Variant_Clean, State_Clean, MAKEYEAR)

        try:

            try:
                X = pd.DataFrame(
                    columns=['MAKEYEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','State_Clean','METERREADING'],
                    data=np.array([
                        MAKEYEAR,
                        Make_Clean.strip(),    # ✅ keep "HARLEY DAVIDSON" intact
                        Model_Clean.strip(),
                        Variant_Clean.strip(),
                        Fuel_Clean.strip(),
                        State_Clean.strip(),
                        METERREADING
                    ]).reshape(1,7)
                )

                predPrice = two_w_ncs_test.predict(X)[0]
                predPrice = int(predPrice)
                print(predPrice)
            except Exception as e:
                print(e)

            newHitCount = totalHitAvailable - 1
            saveData = savePredictOutputv2(
                args.make, args.model, args.variant, args.fuel,
                State_Clean, args.regno, MAKEYEAR, segmentId,
                predPrice, predState, args.clientId,
                args.clientType, args.userId, args.METERREADING
            )

            if saveData[1] == 201:

                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                updateData = updateQuery(updateHitQuery)
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                fetchData = singleQuery(fetchQuery)
                data = {
                    "price": predPrice,
                    "state": predState
                }

                saveApiHit(args.clientId, request_time,200)
                data_json = json.dumps(data, default=lambda x: x.tolist())
                return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200            

            else:
            
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                updateData = updateQuery(updateHitQuery)                
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv2(
                args.make,args.model,args.variant,args.fuel,
                State_Clean,args.regno,MAKEYEAR,segmentId,
                result,rstate,args.clientId,args.clientType,
                args.userId,args.METERREADING
            )
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400



    # elif vehicleCategory == '2W':

    #     carMake = getCarmake_uat(args.make)
    #     carModel = getCarmodel_uat(args.model)
    #     carVariant = getCarvariant_uat(args.variant)
    #     carFuel = getCarfuel_uat(args.fuel)
    #     state = args.regno[:2]


    #     Make_Clean = carMake[1].upper()
    #     #Make_Clean = Make_Clean.replace('HARLEY DAVIDSON', 'HARLEYDAVIDSON')
    #     Model_Clean = carModel[1].upper()
    #     Variant_Clean = carVariant[1].upper()
    #     Fuel_Clean = carFuel[1].upper()
        
    #     State_Clean = getState_uat(state)
    #     State_Clean = State_Clean.upper()

    #     METERREADING = args.METERREADING
    #     MAKEYEAR = args.mfgyear

    #     print(Make_Clean,Model_Clean,Variant_Clean,State_Clean,MAKEYEAR)
        
    #     #print(MAKEYEAR,Make_Clean,Model_Clean,Variant_Clean,Fuel_Clean,State_Clean,METERREADING)
        

    #     try:    
    #         try:
    #             X = pd.DataFrame(columns=['MAKEYEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','State_Clean','METERREADING'],data=np.array([MAKEYEAR,Make_Clean.strip().replace(' ',''),Model_Clean.strip().replace(' ',''),Variant_Clean.strip().replace(' ',''),Fuel_Clean,State_Clean.strip().replace(' ',''),METERREADING]).reshape(1,7))
    #             predPrice = two_w_ncs_test.predict(X)[0]
    #             predPrice = int(predPrice)
    #             print(predPrice)
    #         except Exception as e:
    #             print(e)


    #         newHitCount = totalHitAvailable -1
    #         saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,State_Clean,args.regno,MAKEYEAR,segmentId,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)

    #         if saveData[1] == 201:

    #             if 1 != 1:
    #                 chang_e()

    #             else:
    #                 request_time = "%.2gs" % (time.process_time() - start)
    #                 updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
    #                 fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
    #                 updateData = updateQuery(updateHitQuery)
    #                 if not updateData:
    #                     return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
    #                 fetchData = singleQuery(fetchQuery)
    #                 data = {
    #                     "price": predPrice,
    #                     "state": predState
    #                 }
    #                 saveApiHit(args.clientId, request_time,200)
    #                 data_json = json.dumps(data, default=lambda x: x.tolist())
    #                 return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200            

    #         else:
    #             request_time = "%.2gs" % (time.process_time() - start)
    #             updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
    #             updateData = updateQuery(updateHitQuery)                
    #             if not updateData:
    #                 return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
    #             saveApiHit(args.clientId, request_time,400)
    #             return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        
    #     except:
    #         result = ''
    #         rstate = ''
    #         saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,State_Clean,args.regno,MAKEYEAR,segmentId,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
    #         fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
    #         if saveData[1] == 201:
    #             fetchData = singleQuery(fetchQuery)
    #             request_time = "%.2gs" % (time.process_time() - start)
    #             saveApiHit(args.clientId, request_time,200)
    #             return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
    #         else:
    #             request_time = "%.2gs" % (time.process_time() - start)
    #             saveApiHit(args.clientId, request_time,400)
    #             return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400
        
        


    
    elif vehicleCategory == '3W':
        carMake = getCarmake_uat(args.make)
        carModel = getCarmodel_uat(args.model)
        carVariant = getCarvariant_uat(args.variant)
        carFuel = getCarfuel_uat(args.fuel)
        state = args.regno[:2]


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        
        State_Clean = getState_uat(state)
        State_Clean = State_Clean.upper()

        METERREADING = args.METERREADING
        MAKE_YEAR = args.mfgyear

        print(Make_Clean,Model_Clean,Variant_Clean,State_Clean,MAKE_YEAR)
        

        try:
            try:
                X = pd.DataFrame(columns=['MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','State_Clean','METERREADING'],data=np.array([MAKE_YEAR,Make_Clean.strip().replace(' ', ''),Model_Clean.strip().replace(' ', ''),Variant_Clean.strip().replace(' ', ''),Fuel_Clean,State_Clean.strip().replace(' ', ''),METERREADING]).reshape(1,7))
                predPrice = three_w_ncs_test.predict(X)[0]
                predPrice = int(predPrice)
                print(predPrice)
            except Exception as e:
                print(e)


            
            newHitCount = totalHitAvailable -1           
            saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,State_Clean,args.regno,MAKE_YEAR,segmentId,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)
            

            if saveData[1] == 201:

                if 1 != 1:
                    chang_e()

                
                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updateQuery(updateHitQuery)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": predPrice,
                        "state": predState
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200            

            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                updateData = updateQuery(updateHitQuery)                
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,State_Clean,args.regno,MAKE_YEAR,segmentId,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400



    elif vehicleCategory == 'CE':

        carMake = getCarmake_uat(args.make)
        carModel = getCarmodel_uat(args.model)
        carVariant = getCarvariant_uat(args.variant)
        carFuel = getCarfuel_uat(args.fuel)
        state = args.regno[:2]


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        # Fuel_Clean = carFuel[1].upper()
        CV_State_Clean = getState_uat(state)
        CV_State_Clean = CV_State_Clean.upper()
        METERREADING = args.METERREADING
        MAKE_YEAR = args.mfgyear

        Fuel_Clean = 'DIESEL'

        if Fuel_Clean == 'null':
            Fuel_Clean = 'DIESEL'


        print(Make_Clean,Model_Clean,Variant_Clean,CV_State_Clean,MAKE_YEAR)


        try:
            try:
                X = pd.DataFrame(columns=['MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','CV_State_Clean','METERREADING'],data=np.array([MAKE_YEAR,Make_Clean.strip().replace(' ', ''),Model_Clean.strip().replace(' ', ''),Variant_Clean.strip().replace(' ', ''),Fuel_Clean,CV_State_Clean.strip().replace(' ', ''),METERREADING]).reshape(1,7))
                predPrice = ce_ncs_test.predict(X)[0]
                predPrice = int(predPrice)
                print(predPrice)
            except Exception as e:
                print(e)


            
            newHitCount = totalHitAvailable -1        
            saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,MAKE_YEAR,segmentId,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)
            

            if saveData[1] == 201:

                if 1 != 1:
                    chang_e()


                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updateQuery(updateHitQuery)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": predPrice,
                        "state": predState.upper()
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200            

            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                updateData = updateQuery(updateHitQuery)                
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,MAKE_YEAR,segmentId,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400


    elif vehicleCategory == 'CV':

        carMake = getCarmake_uat(args.make)
        carModel = getCarmodel_uat(args.model)
        carVariant = getCarvariant_uat(args.variant)
        carFuel = getCarfuel_uat(args.fuel)
        state = args.regno[:2]


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        CV_State_Clean = getState_uat(state)
        CV_State_Clean = CV_State_Clean.upper()        

        # if CV_State_Clean == 'CHHATTISGARH':
        #     CV_State_Clean = 'CHATTISGARH'

        # else:
        #     CV_State_Clean = CV_State_Clean


        Meter_Reading = args.METERREADING
        MAKEYEAR = args.mfgyear

        print(Make_Clean,Model_Clean,Variant_Clean,CV_State_Clean,MAKEYEAR,Meter_Reading)
             
        
        try:
            try:
                X = pd.DataFrame(columns=['MAKEYEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','CV_State_Clean','Meter_Reading'],data=np.array([MAKEYEAR,Make_Clean.strip().replace(' ', ''),Model_Clean.strip().replace(' ', ''),Variant_Clean.strip().replace(' ', ''),Fuel_Clean,CV_State_Clean.strip().replace(' ', ''),Meter_Reading]).reshape(1,7))
                predPrice = cv_ncs_test.predict(X)[0]
                predPrice = int(predPrice)
                print(predPrice)
            except Exception as e:
                print(e)


            
            newHitCount = totalHitAvailable -1
            saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,MAKEYEAR,segmentId,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)

            if saveData[1] == 201:


                if 1 != 1:
                    chang_e()


                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updateQuery(updateHitQuery)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": predPrice,
                        "state": predState.upper()
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200            

            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                updateData = updateQuery(updateHitQuery)                
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,MAKEYEAR,segmentId,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400



    elif vehicleCategory == 'FE':

        carMake = getCarmake_uat(args.make)
        carModel = getCarmodel_uat(args.model)
        carVariant = getCarvariant_uat(args.variant)
        carFuel = getCarfuel_uat(args.fuel)
        state = args.regno[:2]


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        CV_State_Clean = getState_uat(state)
        CV_State_Clean = CV_State_Clean.upper()
        METERREADING = args.METERREADING
        MAKE_YEAR = args.mfgyear

        print(Make_Clean,Model_Clean,Variant_Clean,CV_State_Clean,MAKE_YEAR)
        
        try:    
            try:
                X = pd.DataFrame(columns=['MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','CV_State_Clean','METERREADING'],data=np.array([MAKE_YEAR,Make_Clean.replace(' ',''),Model_Clean.strip().replace(' ', ''),Variant_Clean.strip().replace(' ', ''),Fuel_Clean,CV_State_Clean.strip().replace(' ', ''),METERREADING]).reshape(1,7))
                predPrice = fe_ncs_test.predict(X)[0]
                predPrice = int(predPrice)
                print(predPrice)
            except Exception as e:
                print(e)

            newHitCount = totalHitAvailable -1
            saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,MAKE_YEAR,segmentId,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)



            if saveData[1] == 201:

                if 1 != 1:
                    chang_e()

                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updateQuery(updateHitQuery)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": predPrice,
                        "state": predState
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200            

            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                updateData = updateQuery(updateHitQuery)                
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        
        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,MAKE_YEAR,segmentId,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        
        else:
            return jsonify({"status": 400, "message":"Wrong vehicle category type","data": None}), 400





import random

# ===============================
# Helper: Random State Selector
# ===============================
used_states = {}

def get_random_state(exclude_state, clientId):
    # get all available states
    available_states = list(state_categories.values())
    available_states = [s.upper().replace(" ", "") for s in available_states]

    # exclude regno-derived state
    if exclude_state in available_states:
        available_states.remove(exclude_state)

    # exclude already used states for this client
    already_used = used_states.get(clientId, set())
    available_states = [s for s in available_states if s not in already_used]

    if not available_states:
        # reset if all states used
        used_states[clientId] = set()
        available_states = list(state_categories.values())
        available_states = [s.upper().replace(" ", "") for s in available_states]
        if exclude_state in available_states:
            available_states.remove(exclude_state)

    chosen_state = random.choice(available_states)

    # update memory
    if clientId not in used_states:
        used_states[clientId] = set()
    used_states[clientId].add(chosen_state)

    return chosen_state


# ===============================
# API Function
# ===============================
@REQUEST_API.route('/predictedsegprice', methods=['POST'])
@token_required
def predicted_segprice(data):
    start = time.process_time()
    if data[4] == 0:
        return jsonify({"status": 401, 'message': 'User unathorised to use API'}), 401

    fetchQuery = f'''
        Select clientId, activeSubscription, totalHitCount, hitCountAvailable 
        from TBL_SUBSCRIPTION_COUNT_MASTER 
        where clientId="{data[0]}"
    '''
    fetchData = singleQuery(fetchQuery)
    if not fetchData:
        return jsonify({"status": 401, 'message': 'Some Error occured. Kindly contact Administrator for help'}), 401

    totalHitAvailable = int(fetchData[3])
    if totalHitAvailable < 1:
        return jsonify({"status": 401, 'message': 'You have exhausted your API hit. Kindly recharge or topup hit'}), 401

    parser = reqparse.RequestParser(bundle_errors=True)
    parser.add_argument('vtype', type=str, required=True)
    parser.add_argument('make', type=str, required=True)
    parser.add_argument('model', type=str, required=True)
    parser.add_argument('variant', type=str, required=True)
    parser.add_argument('fuel', type=str, required=True)
    parser.add_argument('regno', type=str, required=True)
    parser.add_argument('mfgyear', type=str, required=True)
    parser.add_argument('seller_segment', type=str, required=True)
    parser.add_argument('METERREADING', type=str, required=True)
    parser.add_argument('clientId', type=str, required=True)
    parser.add_argument('clientType', type=str, required=True)
    parser.add_argument('userId', type=str, required=True)
    args = parser.parse_args()

    vehicleCategory = args.vtype.upper()

    if vehicleCategory == '4W':
        carMake = getCarmake_uat(args.make)
        carModel = getCarmodel_uat(args.model)
        carVariant = getCarvariant_uat(args.variant)
        carFuel = getCarfuel_uat(args.fuel)
        state = args.regno[:2]
        carSegment = getCarSegment_uat(args.seller_segment)

        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        CV_State_Clean = getState_uat(state).upper()  # ✅ original state from regno
        METERREADING = args.METERREADING
        MAKE_YEAR = args.mfgyear
        SELLER_SEGMENT = carSegment[1].upper()

        if SELLER_SEGMENT == "BANKS & NBFC":
            SELLER_SEGMENT = "BANK&NBFC"

        try:
            # ---------- Price Prediction ----------
            X = pd.DataFrame([[ 
                MAKE_YEAR, Make_Clean.strip().replace(' ', ''),
                Model_Clean.strip().replace(' ', ''),
                Variant_Clean.strip().replace(' ', ''),
                Fuel_Clean, CV_State_Clean.strip().replace(' ', ''),
                METERREADING, SELLER_SEGMENT.strip().replace(' ', '')
            ]], columns=[
                'MAKE_YEAR','Make_Clean','Model_Clean',
                'Variant_Clean','Fuel_Clean','CV_State_Clean',
                'METERREADING','SELLER_SEGMENT'
            ])

            predPrice = int(fourw_cs_test.predict(X)[0])
            print("✅ Predicted Price:", predPrice)

            # ---------- Random State Selection ----------
            predState = get_random_state(CV_State_Clean, args.clientId)
            print("🎲 Random Suggested State:", predState)

            # ---------- Save Output ----------
            newHitCount = totalHitAvailable - 1
            saveData = savePredictOutputv2(
                args.make, args.model, args.variant, args.fuel,
                CV_State_Clean,       # ✅ regno state → state column
                args.regno, args.mfgyear, args.seller_segment,
                predPrice, predState, # ✅ predicted → preState column
                args.clientId, args.clientType,
                args.userId, args.METERREADING
            )

            if saveData[1] == 201:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = f"""
                    UPDATE TBL_SUBSCRIPTION_COUNT_MASTER
                    SET hitCountAvailable='{newHitCount}'
                    WHERE clientId='{args.clientId}' AND delId=0
                """
                updateQuery(updateHitQuery)

                fetchData = singleQuery('SELECT max(id) as hitId FROM TBL_PREDICTION_OUTPUT')

                # ✅ log API hit so it shows in dashboard
                saveApiHit(args.clientId, request_time, 200)

                return jsonify({
                    "status": 200,
                    "message": "Price & State predicted successfully",
                    "data": {
                        "price": f"{predPrice}-{predState.upper()}",
                        "regno_state": CV_State_Clean.upper(),
                        "predicted_state": predState.upper()
                    },
                    "hitid": fetchData[0]
                }), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time, 400)
                return jsonify({"status":400,"message":"Some error occured while saving data","data":None}),400

        except Exception as e:
            print("❌ General error:", str(e))
            request_time = "%.2gs" % (time.process_time() - start)
            savePredictOutputv2(
                args.make, args.model, args.variant, args.fuel,
                CV_State_Clean, args.regno, args.mfgyear, args.seller_segment,
                '', '', args.clientId, args.clientType,
                args.userId, args.METERREADING
            )
            saveApiHit(args.clientId, request_time, 400)
            return jsonify({"status":400,"message":"Some error occured","data":None}),400




# Original 4W Code:

# @REQUEST_API.route('/predictedsegprice', methods=['POST'])
# @token_required
# def predicted_segprice(data):
#     start = time.process_time()
#     if data[4] == 0:
#         return jsonify({"status": 401,'message' : 'User unathorised to used API'}), 401
#     fetchQuery = 'Select clientId, activeSubscription, totalHitCount, hitCountAvailable from TBL_SUBSCRIPTION_COUNT_MASTER where clientId="'+data[0]+'"'
#     fetchData = singleQuery(fetchQuery)
#     if not fetchData:
#         return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
#     totalHitCount = fetchData[2]
#     totalHitAvailable = int(fetchData[3])
#     if totalHitAvailable < 1:
#         return jsonify({"status": 401,'message' : 'You have exhausted you API hit. Kindly recharge or topup hit'}), 401

#     userData = request.headers.get('User-Agent')
#     parser = reqparse.RequestParser(bundle_errors=True)
#     parser.add_argument('vtype', type=str, required=True, help = "Please Enter vehicle type")
#     parser.add_argument('make', type=str, required=True, help = "Please Enter vehicle make")
#     parser.add_argument('model', type=str, help="Please Enter vehicle model")
#     parser.add_argument('variant', type=str, help="Please Enter vehicle variant")
#     parser.add_argument('fuel', type=str, help="Please Enter vehicle fuel")
#     parser.add_argument('regno', type=str, help="Please Enter vehicle number")
#     parser.add_argument('mfgyear', type=str, help="Please Enter vehicle manufacturing year")
#     parser.add_argument('seller_segment', type=str, help="Please Enter segment")
#     parser.add_argument('METERREADING', type=str, help="Please Enter segment")
#     parser.add_argument('clientId', type=str, help="Please Enter client id")
#     parser.add_argument('clientType', type=str, help="Please Enter client type id")
#     parser.add_argument('userId', type=str, help="Please Enter user id")
#     args = parser.parse_args()
#     # print(args)


#     if not args.vtype:
#         return jsonify({"status": 406,"return": "Vehicle type not be empty", "data": None}), 406
#     if not args.make:
#         return jsonify({"status": 406,"return": "Vehicle Make not be empty", "data": None}), 406
#     if not args.model:
#         return jsonify({"status": 406,"return": "Vehicle Model not be empty", "data": None}), 406
#     if not args.variant:
#         return jsonify({"status": 406,"return": "Vehicle Variant not be empty", "data": None}), 406
#     if not args.fuel:
#         return jsonify({"status": 406,"return": "Vehicle Fuel not be empty", "data": None}), 406
#     if not args.regno:
#         return jsonify({"status": 406,"return": "Vehicle Registrtion Number not be empty", "data": None}), 406
#     if not args.mfgyear:
#         return jsonify({"status": 406,"return": "Vehicle Year not be empty", "data": None}), 406
#     if not args.seller_segment:
#         return jsonify({"status": 406,"return": "Segment not be empty", "data": None}), 406
#     if not args.METERREADING:
#         return jsonify({"status": 406,"return": "Meter Reading not be empty", "data": None}), 406    
#     if not args.clientId:
#         return jsonify({"status": 406,"return": "Client Id not be empty", "data": None}), 406
#     if not args.clientType:
#         return jsonify({"status": 406,"return": "Client Type not be empty", "data": None}), 406

#     vehicleCategory = args.vtype.upper()
    
    

    # if vehicleCategory == '4W':

    #     carMake = getCarmake_uat(args.make)
    #     carModel = getCarmodel_uat(args.model)
    #     carVariant = getCarvariant_uat(args.variant)
    #     carFuel = getCarfuel_uat(args.fuel)
    #     state = args.regno[:2]
    #     carSegment = getCarSegment_uat(args.seller_segment)


    #     Make_Clean = carMake[1].upper()
    #     Model_Clean = carModel[1].upper()
    #     Variant_Clean = carVariant[1].upper()
    #     Fuel_Clean = carFuel[1].upper()
    #     CV_State_Clean = getState_uat(state)
    #     CV_State_Clean = CV_State_Clean.upper()
    #     METERREADING = args.METERREADING
    #     MAKE_YEAR = args.mfgyear
    #     SELLER_SEGMENT = carSegment[1].upper()
    #     # SELLER_SEGMENT = "RETAIL"

    #     if SELLER_SEGMENT == "BANKS & NBFC":
    #         SELLER_SEGMENT = "BANK&NBFC"

    #     # elif SEGMENT == "LEASING":
    #     #     SELLER_SEGMENT = "RETAIL"

    #     # elif SEGMENT == "ALL":
    #     #     SELLER_SEGMENT = "RETAIL"


    #     print(MAKE_YEAR,Make_Clean.replace(' ',''),Model_Clean.replace(' ',''),Variant_Clean.replace(' ',''),Fuel_Clean,CV_State_Clean,SELLER_SEGMENT.replace(' ',''),METERREADING)

    #     try:
    #         try:
    #             X = pd.DataFrame(columns=['MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','CV_State_Clean','METERREADING','SELLER_SEGMENT'],data=np.array([MAKE_YEAR,Make_Clean.strip().replace(' ', ''),Model_Clean.strip().replace(' ', ''),Variant_Clean.strip().replace(' ', ''),Fuel_Clean,CV_State_Clean.strip().replace(' ', ''),METERREADING,SELLER_SEGMENT.strip().replace(' ', '')]).reshape(1,8))
    #             predPrice = fourw_cs_test.predict(X)[0]
    #             predPrice = int(predPrice)
    #         except Exception as e:
    #             print(e)
            

    #         MAKEYEAR = MAKE_YEAR
    #         CLEANEDMake = Make_Clean
    #         CLEANEDModel = Model_Clean
    #         CLEANEDVariant = Variant_Clean
    #         CLEANEDfueltype = Fuel_Clean
    #         SOLDAMOUNT = predPrice
    #         SELLER_SEGMENT = 'RETAIL'
    #         METERREADING = METERREADING
    #         Segment = '4W'
            
            
            
    #         try:
    #             X1 = pd.DataFrame(columns=['MAKEYEAR', 'CLEANEDMake', 'CLEANEDModel', 'CLEANEDVariant','CLEANEDfueltype', 'SOLDAMOUNT', 'SELLER_SEGMENT', 'METERREADING','Segment'],data=np.array([MAKEYEAR, CLEANEDMake, CLEANEDModel, CLEANEDVariant,CLEANEDfueltype, SOLDAMOUNT, SELLER_SEGMENT, METERREADING,Segment]).reshape(1,9))
    #             state_num = state_model.predict(X1)[0]
    #             # print(state_num)
                
    #             predState = state_to_category(state_num)
    #             print(predState)
            
    #         except:
    #             predState = "DELHI"



            
    #         newHitCount = totalHitAvailable -1
    #         saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)
    #         if saveData[1] == 201:


    #             if 1 != 1:
    #                 chang_e()

    #             else:
    #                 request_time = "%.2gs" % (time.process_time() - start)
    #                 updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
    #                 fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
    #                 updateData = updateQuery(updateHitQuery)
    #                 if not updateData:
    #                     return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
    #                 fetchData = singleQuery(fetchQuery)
    #                 data = {
    #                     "price": predPrice,
    #                     "state": predState.upper()
    #                 }
    #                 saveApiHit(args.clientId, request_time,200)
    #                 data_json = json.dumps(data, default=lambda x: x.tolist())
    #                 return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200

    #         else:
    #             request_time = "%.2gs" % (time.process_time() - start)
    #             updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
    #             updateData = updateQuery(updateHitQuery)
    #             if not updateData:
    #                 return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
    #             saveApiHit(args.clientId, request_time,400)
    #             return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400


    #     except:
    #         result = ''
    #         rstate = ''
    #         saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
    #         fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'

    #         if saveData[1] == 201:
    #             fetchData = singleQuery(fetchQuery)
    #             request_time = "%.2gs" % (time.process_time() - start)
    #             saveApiHit(args.clientId, request_time,200)
    #             print({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]})
    #             return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200

    #         else:
    #             request_time = "%.2gs" % (time.process_time() - start)
    #             saveApiHit(args.clientId, request_time,400)
    #             return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

    
        # CV Original code :
        
    # elif vehicleCategory == 'CV':
        
    #     carMake = getCarmake_uat(args.make)
    #     carModel = getCarmodel_uat(args.model)
    #     carVariant = getCarvariant_uat(args.variant)
    #     carFuel = getCarfuel_uat(args.fuel)
    #     state = args.regno[:2]
    #     carSegment = getCarSegment_uat(args.seller_segment)


    #     Make_Clean = carMake[1].upper()
    #     Model_Clean = carModel[1].upper()
    #     Variant_Clean = carVariant[1].upper()
    #     Fuel_Clean = carFuel[1].upper()
    #     CV_State_Clean = getState_uat(state)
    #     CV_State_Clean = CV_State_Clean.upper()
    #     Meter_Reading = args.METERREADING
    #     MAKEYEAR = args.mfgyear
    #     SELLER_SEGMENT = carSegment[1].upper()
    #     # SELLER_SEGMENT = "RETAIL"

    #     if SELLER_SEGMENT == "BANKS & NBFC":
    #         SELLER_SEGMENT = "BANK&NBFC"

    #     # elif SEGMENT == "LEASING":
    #     #     SELLER_SEGMENT = "RETAIL"

    #     # elif SEGMENT == "ALL":
    #     #     SELLER_SEGMENT = "RETAIL"



    #     print(MAKEYEAR,Make_Clean,Model_Clean,Variant_Clean,Fuel_Clean,CV_State_Clean,SELLER_SEGMENT.replace(' ',''),Meter_Reading)

    #     try:
    #         try:
    #             X = pd.DataFrame(columns=['MAKEYEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','CV_State_Clean','SELLER_SEGMENT','Meter_Reading'],data=np.array([MAKEYEAR,Make_Clean.strip().replace(' ', ''),Model_Clean.strip().replace(' ', ''),Variant_Clean.strip().replace(' ', ''),Fuel_Clean,CV_State_Clean.strip().replace(' ', ''),SELLER_SEGMENT.strip().replace(' ', ''),Meter_Reading]).reshape(1,8))
    #             predPrice = cv_cs_test.predict(X)[0]
    #             predPrice = int(predPrice)
    #         except Exception as e:
    #             print(e)




    #         MAKEYEAR = MAKEYEAR
    #         CLEANEDMake = Make_Clean
    #         CLEANEDModel = Model_Clean
    #         CLEANEDVariant = Variant_Clean
    #         CLEANEDfueltype = Fuel_Clean
    #         SOLDAMOUNT = predPrice
    #         SELLER_SEGMENT = 'RETAIL'
    #         METERREADING = Meter_Reading
    #         Segment = 'CV'
            
            
            
    #         try:
    #             X1 = pd.DataFrame(columns=['MAKEYEAR', 'CLEANEDMake', 'CLEANEDModel', 'CLEANEDVariant','CLEANEDfueltype', 'SOLDAMOUNT', 'SELLER_SEGMENT', 'METERREADING','Segment'],data=np.array([MAKEYEAR, CLEANEDMake, CLEANEDModel, CLEANEDVariant,CLEANEDfueltype, SOLDAMOUNT, SELLER_SEGMENT, METERREADING,Segment]).reshape(1,9))
    #             state_num = state_model.predict(X1)[0]
    #             # print(state_num)
                
    #             predState = state_to_category(state_num)
    #             print(predState)
    #         except:
    #             predState = "DELHI"

            
    #         newHitCount = totalHitAvailable -1
    #         saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)
    #         if saveData[1] == 201:


    #             if 1 != 1:
    #                 chang_e()


    #             else:
    #                 request_time = "%.2gs" % (time.process_time() - start)
    #                 updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
    #                 fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
    #                 updateData = updateQuery(updateHitQuery)
    #                 if not updateData:
    #                     return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
    #                 fetchData = singleQuery(fetchQuery)
    #                 data = {
    #                     "price": predPrice,
    #                     "state": predState.upper()
    #                 }
    #                 saveApiHit(args.clientId, request_time,200)
    #                 data_json = json.dumps(data, default=lambda x: x.tolist())
    #                 return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200

    #         else:
    #             request_time = "%.2gs" % (time.process_time() - start)
    #             updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
    #             updateData = updateQuery(updateHitQuery)
    #             if not updateData:
    #                 return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
    #             saveApiHit(args.clientId, request_time,400)
    #             return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

    #     except:
    #         result = ''
    #         rstate = ''
    #         saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
    #         fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
    #         if saveData[1] == 201:
    #             fetchData = singleQuery(fetchQuery)
    #             request_time = "%.2gs" % (time.process_time() - start)
    #             saveApiHit(args.clientId, request_time,200)
    #             return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
    #         else:
    #             request_time = "%.2gs" % (time.process_time() - start)
    #             saveApiHit(args.clientId, request_time,400)
    #             return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400



    elif vehicleCategory == 'CV':
        
    # -----------------------------
    # Safe DB lookup with fallback
    # -----------------------------
        carMake = getCarmake_uat(args.make) or ("", args.make)
        carModel = getCarmodel_uat(args.model) or ("", args.model)
        carVariant = getCarvariant_uat(args.variant) or ("", args.variant)
        carFuel = getCarfuel_uat(args.fuel) or ("", args.fuel)
        carSegment = getCarSegment_uat(args.seller_segment) or ("", args.seller_segment)

        state = args.regno[:2]

    # Clean values (fallback-safe)
        Make_Clean = str(carMake[1]).upper().strip()
        Model_Clean = str(carModel[1]).upper().strip()
        Variant_Clean = str(carVariant[1]).upper().strip()
        Fuel_Clean = str(carFuel[1]).upper().strip()
        SELLER_SEGMENT = str(carSegment[1]).upper().strip()
        CV_State_Clean = getState_uat(state).upper()   # ✅ regno-derived state
        Meter_Reading = args.METERREADING
        MAKEYEAR = args.mfgyear

        if SELLER_SEGMENT == "BANKS & NBFC":
            SELLER_SEGMENT = "BANK&NBFC"

        print(MAKEYEAR, Make_Clean, Model_Clean, Variant_Clean,
            Fuel_Clean, CV_State_Clean, SELLER_SEGMENT, Meter_Reading)

        try:
        # ---------- Price Prediction ----------
            X = pd.DataFrame([[ 
                MAKEYEAR, Make_Clean.replace(" ", ""),
                Model_Clean.replace(" ", ""),
                Variant_Clean.replace(" ", ""),
                Fuel_Clean, CV_State_Clean.replace(" ", ""),
                SELLER_SEGMENT.replace(" ", ""), Meter_Reading
            ]], columns=[
                'MAKEYEAR','Make_Clean','Model_Clean','Variant_Clean',
                'Fuel_Clean','CV_State_Clean','SELLER_SEGMENT','Meter_Reading'
            ])
            predPrice = int(cv_cs_test.predict(X)[0])
            print("✅ Predicted Price:", predPrice)

        # ---------- Random State Selection ----------
            predState = get_random_state(CV_State_Clean, args.clientId)
            print("🎲 Random Suggested State:", predState)

        # ---------- Save Output ----------
            newHitCount = totalHitAvailable - 1
            saveData = savePredictOutputv2(
                args.make, args.model, args.variant, args.fuel,
                CV_State_Clean,          # ✅ regno state → state column
                args.regno, args.mfgyear, args.seller_segment,
                predPrice, predState,    # ✅ predicted state with price
                args.clientId, args.clientType,
                args.userId, args.METERREADING
            )

            if saveData[1] == 201:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = f"""
                    UPDATE TBL_SUBSCRIPTION_COUNT_MASTER
                    SET hitCountAvailable='{newHitCount}'
                    WHERE clientId='{args.clientId}' AND delId=0
                """
                updateData = updateQuery(updateHitQuery)
                if not updateData:
                    return jsonify({"status": 401, "message": "Some Error occured. Kindly contact Administrator for help"}), 401

                fetchData = singleQuery("SELECT max(id) as hitId FROM TBL_PREDICTION_OUTPUT")

            # ✅ log API hit
                saveApiHit(args.clientId, request_time, 200)

                return jsonify({
                    "status": 200,
                    "message": "Price & State predicted successfully",
                    "data": {
                        "price": f"{predPrice}-{predState.upper()}",
                        "regno_state": CV_State_Clean.upper(),
                        "predicted_state": predState.upper()
                    },
                    "hitid": fetchData[0]
                }), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateQuery(f"""
                    UPDATE TBL_SUBSCRIPTION_COUNT_MASTER
                    SET hitCountAvailable='{newHitCount}'
                    WHERE clientId='{args.clientId}' AND delId=0
                """)
                saveApiHit(args.clientId, request_time, 400)
                return jsonify({"status": 400, "message": "Some error occured while saving data", "data": None}), 400

        except Exception as e:
            print("❌ CV General error:", str(e))
            request_time = "%.2gs" % (time.process_time() - start)
            savePredictOutputv2(
                args.make, args.model, args.variant, args.fuel,
                CV_State_Clean, args.regno, args.mfgyear, args.seller_segment,
                '', '', args.clientId, args.clientType,
                args.userId, args.METERREADING
            )
            saveApiHit(args.clientId, request_time, 400)
            return jsonify({"status": 400, "message": "Some error occured", "data": None}), 400
    
        


    elif vehicleCategory == 'CE':
        
    # ✅ Safe DB fetch with fallback
        carMake = getCarmake_uat(args.make) or ("", args.make)
        carModel = getCarmodel_uat(args.model) or ("", args.model)
        carVariant = getCarvariant_uat(args.variant) or ("", args.variant)
        carFuel = getCarfuel_uat(args.fuel) or ("", "DIESEL")  # Always diesel
        state = args.regno[:2]
        carSegment = getCarSegment_uat(args.seller_segment) or ("", args.seller_segment)

        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = "DIESEL"   # ✅ Force diesel
        CV_State_Clean = getState_uat(state).upper()
        METERREADING = args.METERREADING
        MAKE_YEAR = args.mfgyear
        SELLER_SEGMENT = carSegment[1].upper()

        if SELLER_SEGMENT == "BANKS & NBFC":
            SELLER_SEGMENT = "BANK&NBFC"

        print(MAKE_YEAR, Make_Clean, Model_Clean, Variant_Clean,
            Fuel_Clean, CV_State_Clean, SELLER_SEGMENT.replace(' ', ''), METERREADING)

        try:
        # ---------- Price Prediction ----------
            X = pd.DataFrame([[
                MAKE_YEAR, Make_Clean.strip().replace(' ', ''),
                Model_Clean.strip().replace(' ', ''),
                Variant_Clean.strip().replace(' ', ''),
                Fuel_Clean, CV_State_Clean.strip().replace(' ', ''),
                METERREADING, SELLER_SEGMENT.strip().replace(' ', '')
            ]], columns=[
                'MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean',
                'Fuel_Clean','CV_State_Clean','METERREADING','SELLER_SEGMENT'
            ])
            predPrice = int(ce_cs_test.predict(X)[0])
            print("✅ Predicted Price:", predPrice)

        # ---------- Random State Selection ----------
            predState = get_random_state(CV_State_Clean, args.clientId)
            print("🎲 Random Suggested State:", predState)

        # ---------- Save Output ----------
            newHitCount = totalHitAvailable - 1
            saveData = savePredictOutputv2(
                args.make, args.model, args.variant, args.fuel,
                CV_State_Clean, args.regno, args.mfgyear, args.seller_segment,
                predPrice, predState,
                args.clientId, args.clientType,
                args.userId, args.METERREADING
            )

            if saveData[1] == 201:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = f"""
                    UPDATE TBL_SUBSCRIPTION_COUNT_MASTER
                    SET hitCountAvailable='{newHitCount}'
                    WHERE clientId='{args.clientId}' AND delId=0
                """
                updateData = updateQuery(updateHitQuery)
                if not updateData:
                    return jsonify({"status": 401, "message": "Some Error occured. Kindly contact Administrator for help"}), 401

                fetchData = singleQuery("SELECT max(id) as hitId FROM TBL_PREDICTION_OUTPUT")

            # ✅ log API hit
                saveApiHit(args.clientId, request_time, 200)

                return jsonify({
                    "status": 200,
                    "message": "Price & State predicted successfully",
                    "data": {
                        "price": f"{predPrice}-{predState.upper()}",
                        "regno_state": CV_State_Clean.upper(),
                        "predicted_state": predState.upper()
                    },
                    "hitid": fetchData[0]
                }), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = f"""
                    UPDATE TBL_SUBSCRIPTION_COUNT_MASTER
                    SET hitCountAvailable='{newHitCount}'
                    WHERE clientId='{args.clientId}' AND delId=0
                """
                updateQuery(updateHitQuery)
                saveApiHit(args.clientId, request_time, 400)
                return jsonify({"status": 400, "message": "Some error occured while saving data", "data": None}), 400

        except Exception as e:
            print("❌ CE General error:", str(e))
            request_time = "%.2gs" % (time.process_time() - start)
            savePredictOutputv2(
                args.make, args.model, args.variant, args.fuel,
                CV_State_Clean, args.regno, args.mfgyear, args.seller_segment,
                '', '', args.clientId, args.clientType,
                args.userId, args.METERREADING
            )
            saveApiHit(args.clientId, request_time, 400)
            return jsonify({"status": 400, "message": "Some error occured", "data": None}), 400





    # CE Original Code :

    # elif vehicleCategory == 'CE':
        
    #     carMake = getCarmake_uat(args.make)
    #     carModel = getCarmodel_uat(args.model)
    #     carVariant = getCarvariant_uat(args.variant)
    #     carFuel = getCarfuel_uat(args.fuel)
    #     state = args.regno[:2]
    #     carSegment = getCarSegment_uat(args.seller_segment)


    #     Make_Clean = carMake[1].upper()
    #     Model_Clean = carModel[1].upper()
    #     Variant_Clean = carVariant[1].upper()
    #     # Fuel_Clean = carFuel[1].upper()
    #     CV_State_Clean = getState_uat(state)
    #     CV_State_Clean = CV_State_Clean.upper()
    #     METERREADING = args.METERREADING
    #     MAKE_YEAR = args.mfgyear

    #     Fuel_Clean = 'DIESEL'

    #     if Fuel_Clean == 'null':
    #         Fuel_Clean = 'DIESEL'
        
    #     SELLER_SEGMENT = carSegment[1].upper()
    #     # SELLER_SEGMENT = "RETAIL"

    #     if SELLER_SEGMENT == "BANKS & NBFC":
    #         SELLER_SEGMENT = "BANK&NBFC"

    #     # elif SEGMENT == "LEASING":
    #     #     SELLER_SEGMENT = "RETAIL"

    #     # elif SEGMENT == "ALL":
    #     #     SELLER_SEGMENT = "RETAIL"


    #     print(MAKE_YEAR,Make_Clean,Model_Clean,Variant_Clean,Fuel_Clean,CV_State_Clean,SELLER_SEGMENT.replace(' ',''),METERREADING)


    #     try:
    #         try:
    #             X = pd.DataFrame(columns=['MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','CV_State_Clean','METERREADING','SELLER_SEGMENT'],data=np.array([MAKE_YEAR,Make_Clean.strip().replace(' ', ''),Model_Clean.strip().replace(' ', ''),Variant_Clean.strip().replace(' ', ''),Fuel_Clean,CV_State_Clean.strip().replace(' ', ''),METERREADING,SELLER_SEGMENT.strip().replace(' ', '')]).reshape(1,8))
    #             predPrice = ce_cs_test.predict(X)[0]
    #             predPrice = int(predPrice)
    #         except Exception as e:
    #             print(e)


    #         MAKEYEAR = MAKE_YEAR
    #         CLEANEDMake = Make_Clean
    #         CLEANEDModel = Model_Clean
    #         CLEANEDVariant = Variant_Clean
    #         CLEANEDfueltype = Fuel_Clean
    #         SOLDAMOUNT = predPrice
    #         SELLER_SEGMENT = 'RETAIL'
    #         METERREADING = METERREADING
    #         Segment = 'CE'
            
            
            
    #         try:
    #             X1 = pd.DataFrame(columns=['MAKEYEAR', 'CLEANEDMake', 'CLEANEDModel', 'CLEANEDVariant','CLEANEDfueltype', 'SOLDAMOUNT', 'SELLER_SEGMENT', 'METERREADING','Segment'],data=np.array([MAKEYEAR, CLEANEDMake, CLEANEDModel, CLEANEDVariant,'DIESEL', SOLDAMOUNT, SELLER_SEGMENT, METERREADING,Segment]).reshape(1,9))
    #             state_num = state_model.predict(X1)[0]
    #             # print(state_num)
                
    #             predState = state_to_category(state_num)
    #             print(predState)
    #         except:
    #             predState = "DELHI"


            
    #         newHitCount = totalHitAvailable -1
    #         saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)
    #         if saveData[1] == 201:


    #             if 1 != 1:
    #                 chang_e()


    #             else:
    #                 request_time = "%.2gs" % (time.process_time() - start)
    #                 updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
    #                 fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
    #                 updateData = updateQuery(updateHitQuery)
    #                 if not updateData:
    #                     return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
    #                 fetchData = singleQuery(fetchQuery)
    #                 data = {
    #                     "price": predPrice,
    #                     "state": predState.upper()
    #                 }
    #                 saveApiHit(args.clientId, request_time,200)
    #                 data_json = json.dumps(data, default=lambda x: x.tolist())
    #                 return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200

    #         else:
    #             request_time = "%.2gs" % (time.process_time() - start)
    #             updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
    #             updateData = updateQuery(updateHitQuery)
    #             if not updateData:
    #                 return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
    #             saveApiHit(args.clientId, request_time,400)
    #             return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

    #     except:
    #         result = ''
    #         rstate = ''
    #         saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
    #         fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
    #         if saveData[1] == 201:
    #             fetchData = singleQuery(fetchQuery)
    #             request_time = "%.2gs" % (time.process_time() - start)
    #             saveApiHit(args.clientId, request_time,200)
    #             return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
    #         else:
    #             request_time = "%.2gs" % (time.process_time() - start)
    #             saveApiHit(args.clientId, request_time,400)
    #             return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400


    
    elif vehicleCategory == '2W':
        
    # ✅ Safe DB fetch with fallback
        carMake = getCarmake_uat(args.make) or ("", args.make)
        carModel = getCarmodel_uat(args.model) or ("", args.model)
        carVariant = getCarvariant_uat(args.variant) or ("", args.variant)
        carFuel = getCarfuel_uat(args.fuel) or ("", args.fuel)
        state = args.regno[:2]
        carSegment = getCarSegment_uat(args.seller_segment) or ("", args.seller_segment)

        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        State_Clean = getState_uat(state).upper()
        METERREADING = args.METERREADING
        MAKEYEAR = args.mfgyear

        Customer_Segmentation = carSegment[1].upper()
        if Customer_Segmentation == "BANKS & NBFC":
            Customer_Segmentation = "BANK&NBFC"

        print(MAKEYEAR, Make_Clean, Model_Clean, Variant_Clean,
            Fuel_Clean, State_Clean, Customer_Segmentation.replace(' ', ''), METERREADING)

        try:
        # ---------- Price Prediction ----------
            X = pd.DataFrame([[
                MAKEYEAR, Make_Clean.strip().replace(' ', ''),
                Model_Clean.strip().replace(' ', ''),
                Variant_Clean.strip().replace(' ', ''),
                Fuel_Clean, State_Clean.strip().replace(' ', ''),
                Customer_Segmentation.strip().replace(' ', ''), METERREADING
            ]], columns=[
                'MAKEYEAR','Make_Clean','Model_Clean','Variant_Clean',
                'Fuel_Clean','State_Clean','Customer_Segmentation','METERREADING'
            ])
            predPrice = int(two_w_cs_test.predict(X)[0])
            print("✅ Predicted Price:", predPrice)

        # ---------- Random State Selection ----------
            predState = get_random_state(State_Clean, args.clientId)
            print("🎲 Random Suggested State:", predState)

        # ---------- Save Output ----------
            newHitCount = totalHitAvailable - 1
            saveData = savePredictOutputv2(
                args.make, args.model, args.variant, args.fuel,
                State_Clean, args.regno, args.mfgyear, args.seller_segment,
                predPrice, predState,
                args.clientId, args.clientType,
                args.userId, args.METERREADING
            )

            if saveData[1] == 201:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = f"""
                    UPDATE TBL_SUBSCRIPTION_COUNT_MASTER
                    SET hitCountAvailable='{newHitCount}'
                    WHERE clientId='{args.clientId}' AND delId=0
                """
                updateData = updateQuery(updateHitQuery)
                if not updateData:
                    return jsonify({"status": 401, "message": "Some Error occured. Kindly contact Administrator for help"}), 401

                fetchData = singleQuery("SELECT max(id) as hitId FROM TBL_PREDICTION_OUTPUT")

            # ✅ log API hit
                saveApiHit(args.clientId, request_time, 200)

                return jsonify({
                    "status": 200,
                    "message": "Price & State predicted successfully",
                    "data": {
                        "price": f"{predPrice}-{predState.upper()}",
                        "regno_state": State_Clean.upper(),
                        "predicted_state": predState.upper()
                    },
                    "hitid": fetchData[0]
                }), 200
            else:
                
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = f"""
                    UPDATE TBL_SUBSCRIPTION_COUNT_MASTER
                    SET hitCountAvailable='{newHitCount}'
                    WHERE clientId='{args.clientId}' AND delId=0
                """
                updateQuery(updateHitQuery)
                saveApiHit(args.clientId, request_time, 400)
                return jsonify({"status": 400, "message": "Some error occured while saving data", "data": None}), 400

        except Exception as e:
            print("❌ 2W General error:", str(e))
            request_time = "%.2gs" % (time.process_time() - start)
            savePredictOutputv2(
                args.make, args.model, args.variant, args.fuel,
                State_Clean, args.regno, args.mfgyear, args.seller_segment,
                '', '', args.clientId, args.clientType,
                args.userId, args.METERREADING
            )
            saveApiHit(args.clientId, request_time, 400)
            return jsonify({"status": 400, "message": "Some error occured", "data": None}), 400

    


    # elif vehicleCategory == '2W':

    #     carMake = getCarmake_uat(args.make)
    #     carModel = getCarmodel_uat(args.model)
    #     carVariant = getCarvariant_uat(args.variant)
    #     carFuel = getCarfuel_uat(args.fuel)
    #     state = args.regno[:2]
    #     carSegment = getCarSegment_uat(args.seller_segment)


    #     Make_Clean = carMake[1].upper()
    #     Model_Clean = carModel[1].upper()
    #     Variant_Clean = carVariant[1].upper()
    #     Fuel_Clean = carFuel[1].upper()
    #     State_Clean = getState_uat(state)
    #     State_Clean = State_Clean.upper()
    #     METERREADING = args.METERREADING
    #     MAKEYEAR = args.mfgyear
        
    #     Customer_Segmentation = carSegment[1].upper()
    #     # Customer_Segmentation = "RETAIL"

    #     if Customer_Segmentation == "BANKS & NBFC":
    #         Customer_Segmentation = "BANK&NBFC"

    #     # elif SEGMENT == "LEASING":
    #     #     Customer_Segmentation = "RETAIL"

    #     # elif SEGMENT == "ALL":
    #     #     Customer_Segmentation = "RETAIL"


    #     print(MAKEYEAR,Make_Clean,Model_Clean,Variant_Clean,Fuel_Clean,State_Clean,Customer_Segmentation.replace(' ',''),METERREADING)


    #     try:
    #         try:
    #             X = pd.DataFrame(columns=['MAKEYEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','State_Clean','Customer_Segmentation','METERREADING'],data=np.array([MAKEYEAR,Make_Clean.strip().replace(' ',''),Model_Clean.strip().replace(' ',''),Variant_Clean.strip().replace(' ',''),Fuel_Clean,State_Clean.strip().replace(' ',''),Customer_Segmentation,METERREADING]).reshape(1,8))
    #             predPrice = two_w_cs_test.predict(X)[0]
    #             predPrice = int(predPrice)
            
    #         except Exception as e:
    #             print(e)



    #         MAKEYEAR = MAKEYEAR
    #         CLEANEDMake = Make_Clean
    #         CLEANEDModel = Model_Clean
    #         CLEANEDVariant = Variant_Clean
    #         CLEANEDfueltype = Fuel_Clean
    #         SOLDAMOUNT = predPrice
    #         SELLER_SEGMENT = 'RETAIL'
    #         METERREADING = METERREADING
    #         Segment = '2W'
            
            
            
    #         try:
    #             X1 = pd.DataFrame(columns=['MAKEYEAR', 'CLEANEDMake', 'CLEANEDModel', 'CLEANEDVariant','CLEANEDfueltype', 'SOLDAMOUNT', 'SELLER_SEGMENT', 'METERREADING','Segment'],data=np.array([MAKEYEAR, CLEANEDMake, CLEANEDModel, CLEANEDVariant,CLEANEDfueltype, SOLDAMOUNT, SELLER_SEGMENT, METERREADING,Segment]).reshape(1,9))
    #             state_num = state_model.predict(X1)[0]
    #             # print(state_num)
                
    #             predState = state_to_category(state_num)
    #             print(predState)
    #         except:
    #             predState = "DELHI"


            
    #         newHitCount = totalHitAvailable -1
    #         saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,State_Clean,args.regno,args.mfgyear,args.seller_segment,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)

    #         if saveData[1] == 201:

    #             if 1 != 1:
    #                 chang_e()


    #             else:
    #                 request_time = "%.2gs" % (time.process_time() - start)
    #                 updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
    #                 fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
    #                 updateData = updateQuery(updateHitQuery)
    #                 if not updateData:
    #                     return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
    #                 fetchData = singleQuery(fetchQuery)
    #                 data = {
    #                     "price": predPrice,
    #                     "state": predState.upper()
    #                 }
    #                 saveApiHit(args.clientId, request_time,200)
    #                 data_json = json.dumps(data, default=lambda x: x.tolist())
    #                 return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200

    #         else:
    #             request_time = "%.2gs" % (time.process_time() - start)
    #             updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
    #             updateData = updateQuery(updateHitQuery)
    #             if not updateData:
    #                 return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
    #             saveApiHit(args.clientId, request_time,400)
    #             return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

    #     except:
    #         result = ''
    #         rstate = ''
    #         saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,State_Clean,args.regno,args.mfgyear,args.seller_segment,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
    #         fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
    #         if saveData[1] == 201:
    #             fetchData = singleQuery(fetchQuery)
    #             request_time = "%.2gs" % (time.process_time() - start)
    #             saveApiHit(args.clientId, request_time,200)
    #             return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
    #         else:
    #             request_time = "%.2gs" % (time.process_time() - start)
    #             saveApiHit(args.clientId, request_time,400)
    #             return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400


    
    elif vehicleCategory == '3W':
        
    # ✅ Safe DB fetch with fallback
        carMake = getCarmake_uat(args.make) or ("", args.make)
        carModel = getCarmodel_uat(args.model) or ("", args.model)
        carVariant = getCarvariant_uat(args.variant) or ("", args.variant)
        carFuel = getCarfuel_uat(args.fuel) or ("", args.fuel)
        state = args.regno[:2]
        carSegment = getCarSegment_uat(args.seller_segment) or ("", args.seller_segment)

        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        State_Clean = getState_uat(state).upper()
        SELLERSEGMENT = carSegment[1].upper()

        if SELLERSEGMENT == "BANKS & NBFC":
            SELLERSEGMENT = "BANK&NBFC"        

        METERREADING = args.METERREADING
        MAKE_YEAR = args.mfgyear

        print(MAKE_YEAR, Make_Clean, Model_Clean, Variant_Clean,
            Fuel_Clean, State_Clean, SELLERSEGMENT.replace(' ', ''), METERREADING)

        try:
        # ---------- Price Prediction ----------
            X = pd.DataFrame([[
                MAKE_YEAR, Make_Clean.strip().replace(' ', ''),
                Model_Clean.strip().replace(' ', ''),
                Variant_Clean.strip().replace(' ', ''),
                Fuel_Clean, State_Clean.strip().replace(' ', ''),
                METERREADING, SELLERSEGMENT.strip().replace(' ', '')
            ]], columns=[
                'MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean',
                'Fuel_Clean','State_Clean','METERREADING','SELLERSEGMENT'
            ])
            predPrice = int(three_w_cs_test.predict(X)[0])
            print("✅ Predicted Price:", predPrice)

        # ---------- Random State Selection ----------
            predState = get_random_state(State_Clean, args.clientId)
            print("🎲 Random Suggested State:", predState)

        # ---------- Save Output ----------
            newHitCount = totalHitAvailable - 1
            saveData = savePredictOutputv2(
                args.make, args.model, args.variant, args.fuel,
                State_Clean, args.regno, args.mfgyear, args.seller_segment,
                predPrice, predState,
                args.clientId, args.clientType,
                args.userId, args.METERREADING
            )

            if saveData[1] == 201:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = f"""
                    UPDATE TBL_SUBSCRIPTION_COUNT_MASTER
                    SET hitCountAvailable='{newHitCount}'
                    WHERE clientId='{args.clientId}' AND delId=0
                """
                updateData = updateQuery(updateHitQuery)
                if not updateData:
                    return jsonify({"status": 401, "message": "Some Error occured. Kindly contact Administrator for help"}), 401

                fetchData = singleQuery("SELECT max(id) as hitId FROM TBL_PREDICTION_OUTPUT")

            # ✅ log API hit
                saveApiHit(args.clientId, request_time, 200)

                return jsonify({
                    "status": 200,
                    "message": "Price & State predicted successfully",
                    "data": {
                        "price": f"{predPrice}-{predState.upper()}",
                        "regno_state": State_Clean.upper(),
                        "predicted_state": predState.upper()
                    },
                    "hitid": fetchData[0]
                }), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = f"""
                    UPDATE TBL_SUBSCRIPTION_COUNT_MASTER
                    SET hitCountAvailable='{newHitCount}'
                    WHERE clientId='{args.clientId}' AND delId=0
                """
                updateQuery(updateHitQuery)
                saveApiHit(args.clientId, request_time, 400)
                return jsonify({"status": 400, "message": "Some error occured while saving data", "data": None}), 400

        except Exception as e:
            print("❌ 3W General error:", str(e))
            request_time = "%.2gs" % (time.process_time() - start)
            savePredictOutputv2(
                args.make, args.model, args.variant, args.fuel,
                State_Clean, args.regno, args.mfgyear, args.seller_segment,
                '', '', args.clientId, args.clientType,
                args.userId, args.METERREADING
            )
            saveApiHit(args.clientId, request_time, 400)
            return jsonify({"status": 400, "message": "Some error occured", "data": None}), 400

    
    
    


    # elif vehicleCategory == '3W':

    #     carMake = getCarmake_uat(args.make)
    #     carModel = getCarmodel_uat(args.model)
    #     carVariant = getCarvariant_uat(args.variant)
    #     carFuel = getCarfuel_uat(args.fuel)
    #     state = args.regno[:2]
    #     carSegment = getCarSegment_uat(args.seller_segment)


    #     Make_Clean = carMake[1].upper()
    #     Model_Clean = carModel[1].upper()
    #     Variant_Clean = carVariant[1].upper()
    #     Fuel_Clean = carFuel[1].upper()
    #     STATE_MAPPED = getState_uat(state)
    #     State_Clean = STATE_MAPPED.upper()
    #     SELLERSEGMENT = carSegment[1].upper()

    #     if SELLERSEGMENT == "BANKS & NBFC":
    #         SELLERSEGMENT = "BANK&NBFC"        

    #     METERREADING = args.METERREADING
    #     MAKE_YEAR = args.mfgyear


    #     print(MAKE_YEAR,Make_Clean,Model_Clean,Variant_Clean,Fuel_Clean,State_Clean,'RETAIL',METERREADING)
        

    #     try:
    #         try:
    #             X = pd.DataFrame(columns=['MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','State_Clean','METERREADING','SELLERSEGMENT'],data=np.array([MAKE_YEAR,Make_Clean.strip().replace(' ', ''),Model_Clean.strip().replace(' ', ''),Variant_Clean.strip().replace(' ', ''),Fuel_Clean,State_Clean.strip().replace(' ', ''),METERREADING,SELLERSEGMENT.strip().replace(' ', '')]).reshape(1,8))
    #             predPrice = three_w_cs_test.predict(X)[0]
    #             predPrice = int(predPrice)
    #         except Exception as e:
    #             print(e)


    #         MAKEYEAR = MAKE_YEAR
    #         CLEANEDMake = Make_Clean
    #         CLEANEDModel = Model_Clean
    #         CLEANEDVariant = Variant_Clean
    #         CLEANEDfueltype = Fuel_Clean
    #         SOLDAMOUNT = predPrice
    #         SELLER_SEGMENT = 'RETAIL'
    #         METERREADING = METERREADING
    #         Segment = '3W'
            
            
            
    #         try:
    #             X1 = pd.DataFrame(columns=['MAKEYEAR', 'CLEANEDMake', 'CLEANEDModel', 'CLEANEDVariant','CLEANEDfueltype', 'SOLDAMOUNT', 'SELLER_SEGMENT', 'METERREADING','Segment'],data=np.array([MAKEYEAR, CLEANEDMake, CLEANEDModel, CLEANEDVariant,CLEANEDfueltype, SOLDAMOUNT, SELLER_SEGMENT, METERREADING,Segment]).reshape(1,9))
    #             state_num = state_model.predict(X1)[0]
    #             # print(state_num)
                
    #             predState = state_to_category(state_num)
    #             print(predState)
            
    #         except:
    #             predState = "DELHI"


            
    #         newHitCount = totalHitAvailable -1
    #         saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,State_Clean,args.regno,args.mfgyear,args.seller_segment,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)
    #         if saveData[1] == 201:

    #             if 1 != 1:
    #                 chang_e()


    #             else:
    #                 request_time = "%.2gs" % (time.process_time() - start)
    #                 updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
    #                 fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
    #                 updateData = updateQuery(updateHitQuery)
    #                 if not updateData:
    #                     return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
    #                 fetchData = singleQuery(fetchQuery)
    #                 data = {
    #                     "price": predPrice,
    #                     "state": predState.upper()
    #                 }
    #                 saveApiHit(args.clientId, request_time,200)
    #                 data_json = json.dumps(data, default=lambda x: x.tolist())
    #                 return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200            
            
    #         else:
    #             request_time = "%.2gs" % (time.process_time() - start)
    #             updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
    #             updateData = updateQuery(updateHitQuery)
    #             if not updateData:
    #                 return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
    #             saveApiHit(args.clientId, request_time,400)
    #             return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        
    #     except:
    #         result = ''
    #         rstate = ''
    #         saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,State_Clean,args.regno,args.mfgyear,args.seller_segment,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
    #         fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
    #         if saveData[1] == 201:
    #             fetchData = singleQuery(fetchQuery)
    #             request_time = "%.2gs" % (time.process_time() - start)
    #             saveApiHit(args.clientId, request_time,200)
    #             return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
    #         else:
    #             request_time = "%.2gs" % (time.process_time() - start)
    #             saveApiHit(args.clientId, request_time,400)
    #             return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400


    
    
    
    elif vehicleCategory == 'FE':
        
    # ✅ Safe DB fetch with fallback
        carMake = getCarmake_uat(args.make) or ("", args.make)
        carModel = getCarmodel_uat(args.model) or ("", args.model)
        carVariant = getCarvariant_uat(args.variant) or ("", args.variant)
        carFuel = getCarfuel_uat(args.fuel) or ("", args.fuel)
        state = args.regno[:2]
        carSegment = getCarSegment_uat(args.seller_segment) or ("", args.seller_segment)

        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        CV_State_Clean = getState_uat(state).upper()
        METERREADING = args.METERREADING
        MAKE_YEAR = args.mfgyear

        SELLER_SEGMENT = carSegment[1].upper()
        if SELLER_SEGMENT == "BANKS & NBFC":
            SELLER_SEGMENT = "BANK&NBFC"

        print(MAKE_YEAR, Make_Clean, Model_Clean, Variant_Clean,
            Fuel_Clean, CV_State_Clean, SELLER_SEGMENT.replace(' ', ''), METERREADING)

        try:
        # ---------- Price Prediction ----------
            X = pd.DataFrame([[
                MAKE_YEAR, Make_Clean.strip().replace(' ', ''),
                Model_Clean.strip().replace(' ', ''),
                Variant_Clean.strip().replace(' ', ''),
                Fuel_Clean, CV_State_Clean.strip().replace(' ', ''),
                METERREADING, SELLER_SEGMENT.strip().replace(' ', '')
            ]], columns=[
                'MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean',
                'Fuel_Clean','CV_State_Clean','METERREADING','SELLER_SEGMENT'
            ])
            predPrice = int(fe_cs_test.predict(X)[0])
            print("✅ Predicted Price:", predPrice)

        # ---------- Random State Selection ----------
            predState = get_random_state(CV_State_Clean, args.clientId)
            print("🎲 Random Suggested State:", predState)

        # ---------- Save Output ----------
            newHitCount = totalHitAvailable - 1
            saveData = savePredictOutputv2(
                args.make, args.model, args.variant, args.fuel,
                CV_State_Clean, args.regno, args.mfgyear, args.seller_segment,
                predPrice, predState,
                args.clientId, args.clientType,
                args.userId, args.METERREADING
            )

            if saveData[1] == 201:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = f"""
                    UPDATE TBL_SUBSCRIPTION_COUNT_MASTER
                    SET hitCountAvailable='{newHitCount}'
                    WHERE clientId='{args.clientId}' AND delId=0
                """
                updateData = updateQuery(updateHitQuery)
                if not updateData:
                    return jsonify({"status": 401, "message": "Some Error occured. Kindly contact Administrator for help"}), 401

                fetchData = singleQuery("SELECT max(id) as hitId FROM TBL_PREDICTION_OUTPUT")

            # ✅ log API hit
                saveApiHit(args.clientId, request_time, 200)

                return jsonify({
                    "status": 200,
                    "message": "Price & State predicted successfully",
                    "data": {
                        "price": f"{predPrice}-{predState.upper()}",
                        "regno_state": CV_State_Clean.upper(),
                        "predicted_state": predState.upper()
                    },
                    "hitid": fetchData[0]
                }), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = f"""
                    UPDATE TBL_SUBSCRIPTION_COUNT_MASTER
                    SET hitCountAvailable='{newHitCount}'
                    WHERE clientId='{args.clientId}' AND delId=0
                """
                updateQuery(updateHitQuery)
                saveApiHit(args.clientId, request_time, 400)
                return jsonify({"status": 400, "message": "Some error occured while saving data", "data": None}), 400

        except Exception as e:
            print("❌ FE General error:", str(e))
            request_time = "%.2gs" % (time.process_time() - start)
            savePredictOutputv2(
                args.make, args.model, args.variant, args.fuel,
                CV_State_Clean, args.regno, args.mfgyear, args.seller_segment,
                '', '', args.clientId, args.clientType,
                args.userId, args.METERREADING
            )
            saveApiHit(args.clientId, request_time, 400)
            return jsonify({"status": 400, "message": "Some error occured", "data": None}), 400
    
    
    

    # elif vehicleCategory == 'FE':

    #     carMake = getCarmake_uat(args.make)
    #     carModel = getCarmodel_uat(args.model)
    #     carVariant = getCarvariant_uat(args.variant)
    #     carFuel = getCarfuel_uat(args.fuel)
    #     state = args.regno[:2]
    #     carSegment = getCarSegment_uat(args.seller_segment)


    #     Make_Clean = carMake[1].upper()
    #     Model_Clean = carModel[1].upper()
    #     Variant_Clean = carVariant[1].upper()
    #     Fuel_Clean = carFuel[1].upper()
    #     CV_State_Clean = getState_uat(state)
    #     CV_State_Clean = CV_State_Clean.upper()
    #     METERREADING = args.METERREADING
    #     MAKE_YEAR = args.mfgyear

    #     SELLER_SEGMENT = carSegment[1].upper()
    #     # SELLER_SEGMENT = "RETAIL"

    #     if SELLER_SEGMENT == "BANKS & NBFC":
    #         SELLER_SEGMENT = "BANK&NBFC"

    #     # elif SEGMENT == "LEASING":
    #     #     SELLER_SEGMENT = "RETAIL"

    #     # elif SEGMENT == "ALL":
    #     #     SELLER_SEGMENT = "RETAIL"


        
    #     print(MAKE_YEAR,Make_Clean,Model_Clean,Variant_Clean,Fuel_Clean,CV_State_Clean,SELLER_SEGMENT.replace(' ',''),METERREADING)


    #     try:
    #         try:
    #             X = (pd.DataFrame(columns=['MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','CV_State_Clean','METERREADING','SELLER_SEGMENT'],data=np.array([MAKE_YEAR,Make_Clean.strip().replace(' ',''),Model_Clean.strip().replace(' ',''),Variant_Clean.strip().replace(' ',''),Fuel_Clean,CV_State_Clean.strip().replace(' ',''),METERREADING,SELLER_SEGMENT.strip().replace(' ','')]).reshape(1,8)))
    #             predPrice = fe_cs_test.predict(X)[0]
    #             predPrice = int(predPrice)
    #         except Exception as e:
    #             print(e)

    #         MAKEYEAR = MAKE_YEAR
    #         CLEANEDMake = Make_Clean
    #         CLEANEDModel = Model_Clean
    #         CLEANEDVariant = Variant_Clean
    #         CLEANEDfueltype = Fuel_Clean
    #         SOLDAMOUNT = predPrice
    #         SELLER_SEGMENT = 'RETAIL'
    #         METERREADING = METERREADING
    #         Segment = 'FE'
            
                    
    #         try:
    #             X1 = pd.DataFrame(columns=['MAKEYEAR', 'CLEANEDMake', 'CLEANEDModel', 'CLEANEDVariant','CLEANEDfueltype', 'SOLDAMOUNT', 'SELLER_SEGMENT', 'METERREADING','Segment'],data=np.array([MAKEYEAR, CLEANEDMake, CLEANEDModel, CLEANEDVariant,CLEANEDfueltype, SOLDAMOUNT, SELLER_SEGMENT, METERREADING,Segment]).reshape(1,9))
    #             state_num = state_model.predict(X1)[0]
                        
    #             predState = state_to_category(state_num)
    #             print(predState)
    #         except:
    #             predState = 'DELHI'



            
    #         newHitCount = totalHitAvailable -1
    #         saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)
    #         if saveData[1] == 201:

    #             if 1 != 1:
    #                 chang_e()


    #             else:
    #                 request_time = "%.2gs" % (time.process_time() - start)
    #                 updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
    #                 fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
    #                 updateData = updateQuery(updateHitQuery)
    #                 if not updateData:
    #                     return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
    #                 fetchData = singleQuery(fetchQuery)
    #                 data = {
    #                     "price": predPrice,
    #                     "state": predState.upper()
    #                 }
    #                 saveApiHit(args.clientId, request_time,200)
    #                 data_json = json.dumps(data, default=lambda x: x.tolist())
    #                 return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200            
            
    #         else:
    #             request_time = "%.2gs" % (time.process_time() - start)
    #             updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
    #             updateData = updateQuery(updateHitQuery)
    #             if not updateData:
    #                 return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
    #             saveApiHit(args.clientId, request_time,400)
    #             return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

    #     except:
    #         result = ''
    #         rstate = ''
    #         saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
    #         fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
    #         if saveData[1] == 201:
    #             fetchData = singleQuery(fetchQuery)
    #             request_time = "%.2gs" % (time.process_time() - start)
    #             saveApiHit(args.clientId, request_time,200)
    #             return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
    #         else:
    #             request_time = "%.2gs" % (time.process_time() - start)
    #             saveApiHit(args.clientId, request_time,400)
    #             return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400




    # else:
    #     return jsonify({"status": 400, "message":"Wrong vehicle category type","data": None}), 400




@REQUEST_API.route('/app_predictedprice_uat', methods=['POST'])
@token_required
def app_predictedprice_uat(data):
    start = time.process_time()
    if data[4] == 0:
        return jsonify({"status": 401,'message' : 'User unathorised to used API'}), 401
    fetchQuery = 'Select clientId, activeSubscription, totalHitCount, hitCountAvailable from TBL_SUBSCRIPTION_COUNT_MASTER where clientId="'+data[0]+'"'
    fetchData = singleQuery(fetchQuery)
    if not fetchData:
        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
    totalHitCount = fetchData[2]
    totalHitAvailable = int(fetchData[3])
    if totalHitAvailable < 1:
        return jsonify({"status": 401,'message' : 'You have exhausted you API hit. Kindly recharge or topup hit'}), 401

    userData = request.headers.get('User-Agent')
    parser = reqparse.RequestParser(bundle_errors=True)
    parser.add_argument('vtype', type=str, required=True, help = "Please Enter vehicle type")
    parser.add_argument('make', type=str, required=True, help = "Please Enter vehicle make")
    parser.add_argument('model', type=str, help="Please Enter vehicle model")
    parser.add_argument('variant', type=str, help="Please Enter vehicle variant")
    parser.add_argument('fuel', type=str, help="Please Enter vehicle fuel")
    parser.add_argument('regno', type=str, help="Please Enter vehicle number")
    parser.add_argument('mfgyear', type=str, help="Please Enter vehicle manufacturing year")
    parser.add_argument('seller_segment', type=str, help="Please Enter segment")
    parser.add_argument('METERREADING', type=str, help="Please Enter segment")
    parser.add_argument('clientId', type=str, help="Please Enter client id")
    parser.add_argument('clientType', type=str, help="Please Enter client type id")
    parser.add_argument('userId', type=str, help="Please Enter user id")
    args = parser.parse_args()
    # print(args)


    if not args.vtype:
        return jsonify({"status": 406,"return": "Vehicle type not be empty", "data": None}), 406
    if not args.make:
        return jsonify({"status": 406,"return": "Vehicle Make not be empty", "data": None}), 406
    if not args.model:
        return jsonify({"status": 406,"return": "Vehicle Model not be empty", "data": None}), 406
    if not args.variant:
        return jsonify({"status": 406,"return": "Vehicle Variant not be empty", "data": None}), 406
    if not args.fuel:
        return jsonify({"status": 406,"return": "Vehicle Fuel not be empty", "data": None}), 406
    if not args.regno:
        return jsonify({"status": 406,"return": "Vehicle Registrtion Number not be empty", "data": None}), 406
    if not args.mfgyear:
        return jsonify({"status": 406,"return": "Vehicle Year not be empty", "data": None}), 406
    if not args.seller_segment:
        return jsonify({"status": 406,"return": "Segment not be empty", "data": None}), 406
    if not args.METERREADING:
        return jsonify({"status": 406,"return": "Meter Reading not be empty", "data": None}), 406    
    if not args.clientId:
        return jsonify({"status": 406,"return": "Client Id not be empty", "data": None}), 406
    if not args.clientType:
        return jsonify({"status": 406,"return": "Client Type not be empty", "data": None}), 406

    vehicleCategory = args.vtype.upper()

    if vehicleCategory == '4W':

        carMake = getCarmake_uat(args.make)
        carModel = getCarmodel_uat(args.model)
        carVariant = getCarvariant_uat(args.variant)
        carFuel = getCarfuel_uat(args.fuel)
        state = args.regno[:2]
        carSegment = getCarSegment_uat(args.seller_segment)


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        CV_State_Clean = getState_uat(state)
        CV_State_Clean = CV_State_Clean.upper()
        METERREADING = args.METERREADING
        MAKE_YEAR = args.mfgyear
        SELLER_SEGMENT = carSegment[1].upper()
        # SELLER_SEGMENT = "RETAIL"

        if SELLER_SEGMENT == "BANKS & NBFC":
            SELLER_SEGMENT = "BANK&NBFC"

        # elif SEGMENT == "LEASING":
        #     SELLER_SEGMENT = "RETAIL"

        elif SELLER_SEGMENT == "ALL":
            SELLER_SEGMENT = "RETAIL"


        print(MAKE_YEAR,Make_Clean.replace(' ',''),Model_Clean.replace(' ',''),Variant_Clean.replace(' ',''),Fuel_Clean,CV_State_Clean,SELLER_SEGMENT.replace(' ',''),METERREADING)

        try:
            X = pd.DataFrame(columns=['MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','CV_State_Clean','METERREADING','SELLER_SEGMENT'],data=np.array([MAKE_YEAR,Make_Clean.strip().replace(' ', ''),Model_Clean.strip().replace(' ', ''),Variant_Clean.strip().replace(' ', ''),Fuel_Clean,CV_State_Clean.strip().replace(' ', ''),METERREADING,SELLER_SEGMENT.strip().replace(' ', '')]).reshape(1,8))  

            predPrice = fourw_cs_test.predict(X)[0]
            predPrice = int(predPrice)
            
            MAKEYEAR = MAKE_YEAR
            CLEANEDMake = Make_Clean
            CLEANEDModel = Model_Clean
            CLEANEDVariant = Variant_Clean
            CLEANEDfueltype = Fuel_Clean
            SOLDAMOUNT = predPrice
            SELLER_SEGMENT = 'RETAIL'
            METERREADING = METERREADING
            Segment = '4W'
            
            
            
            try:
                X1 = pd.DataFrame(columns=['MAKEYEAR', 'CLEANEDMake', 'CLEANEDModel', 'CLEANEDVariant','CLEANEDfueltype', 'SOLDAMOUNT', 'SELLER_SEGMENT', 'METERREADING','Segment'],data=np.array([MAKEYEAR, CLEANEDMake, CLEANEDModel, CLEANEDVariant,CLEANEDfueltype, SOLDAMOUNT, SELLER_SEGMENT, METERREADING,Segment]).reshape(1,9))
                state_num = state_model.predict(X1)[0]
                # print(state_num)
                
                predState = state_to_category(state_num)
                print(predState)
            
            except:
                predState = "DELHI"



            
            newHitCount = totalHitAvailable -1
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)
            if saveData[1] == 201:


                if 1 != 1:
                    chang_e()

                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updateQuery(updateHitQuery)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": price_range_calc(predPrice),
                        "state": predState.upper()
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200

            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                updateData = updateQuery(updateHitQuery)
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400


        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'

            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                print({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]})
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200

            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

    
        
    elif vehicleCategory == 'CV':
        
        carMake = getCarmake_uat(args.make)
        carModel = getCarmodel_uat(args.model)
        carVariant = getCarvariant_uat(args.variant)
        carFuel = getCarfuel_uat(args.fuel)
        state = args.regno[:2]
        carSegment = getCarSegment_uat(args.seller_segment)


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        CV_State_Clean = getState_uat(state)
        CV_State_Clean = CV_State_Clean.upper()
        Meter_Reading = args.METERREADING
        MAKEYEAR = args.mfgyear
        SELLER_SEGMENT = carSegment[1].upper()
        # SELLER_SEGMENT = "RETAIL"

        if SELLER_SEGMENT == "BANKS & NBFC":
            SELLER_SEGMENT = "BANK&NBFC"

        # elif SEGMENT == "LEASING":
        #     SELLER_SEGMENT = "RETAIL"

        elif SELLER_SEGMENT == "ALL":
            SELLER_SEGMENT = "RETAIL"



        print(MAKEYEAR,Make_Clean,Model_Clean,Variant_Clean,Fuel_Clean,CV_State_Clean,SELLER_SEGMENT.replace(' ',''),Meter_Reading)

        try:
            X = pd.DataFrame(columns=['MAKEYEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','CV_State_Clean','SELLER_SEGMENT','Meter_Reading'],data=np.array([MAKEYEAR,Make_Clean.strip().replace(' ', ''),Model_Clean.strip().replace(' ', ''),Variant_Clean.strip().replace(' ', ''),Fuel_Clean,CV_State_Clean.strip().replace(' ', ''),SELLER_SEGMENT.strip().replace(' ', ''),Meter_Reading]).reshape(1,8))
            

            predPrice = cv_cs_test.predict(X)[0]
            predPrice = int(predPrice)


            MAKEYEAR = MAKEYEAR
            CLEANEDMake = Make_Clean
            CLEANEDModel = Model_Clean
            CLEANEDVariant = Variant_Clean
            CLEANEDfueltype = Fuel_Clean
            SOLDAMOUNT = predPrice
            SELLER_SEGMENT = 'RETAIL'
            METERREADING = Meter_Reading
            Segment = 'CV'
            
            
            
            try:
                X1 = pd.DataFrame(columns=['MAKEYEAR', 'CLEANEDMake', 'CLEANEDModel', 'CLEANEDVariant','CLEANEDfueltype', 'SOLDAMOUNT', 'SELLER_SEGMENT', 'METERREADING','Segment'],data=np.array([MAKEYEAR, CLEANEDMake, CLEANEDModel, CLEANEDVariant,CLEANEDfueltype, SOLDAMOUNT, SELLER_SEGMENT, METERREADING,Segment]).reshape(1,9))
                state_num = state_model.predict(X1)[0]
                # print(state_num)
                
                predState = state_to_category(state_num)
                print(predState)
            except:
                predState = "DELHI"

            
            newHitCount = totalHitAvailable -1
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)
            if saveData[1] == 201:


                if 1 != 1:
                    chang_e()


                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updateQuery(updateHitQuery)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": price_range_calc(predPrice),
                        "state": predState.upper()
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200

            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                updateData = updateQuery(updateHitQuery)
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400




    elif vehicleCategory == 'CE':
        
        carMake = getCarmake_uat(args.make)
        carModel = getCarmodel_uat(args.model)
        carVariant = getCarvariant_uat(args.variant)
        carFuel = getCarfuel_uat(args.fuel)
        state = args.regno[:2]
        carSegment = getCarSegment_uat(args.seller_segment)


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        # Fuel_Clean = carFuel[1].upper()
        CV_State_Clean = getState_uat(state)
        CV_State_Clean = CV_State_Clean.upper()
        METERREADING = args.METERREADING
        MAKE_YEAR = args.mfgyear

        Fuel_Clean = 'DIESEL'

        if Fuel_Clean == 'null':
            Fuel_Clean = 'DIESEL'
        
        SELLER_SEGMENT = carSegment[1].upper()
        # SELLER_SEGMENT = "RETAIL"

        if SELLER_SEGMENT == "BANKS & NBFC":
            SELLER_SEGMENT = "BANK&NBFC"

        # elif SEGMENT == "LEASING":
        #     SELLER_SEGMENT = "RETAIL"

        elif SELLER_SEGMENT == "ALL":
            SELLER_SEGMENT = "RETAIL"


        print(MAKE_YEAR,Make_Clean,Model_Clean,Variant_Clean,Fuel_Clean,CV_State_Clean,SELLER_SEGMENT.replace(' ',''),METERREADING)


        try:
            X = pd.DataFrame(columns=['MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','CV_State_Clean','METERREADING','SELLER_SEGMENT'],data=np.array([MAKE_YEAR,Make_Clean.strip().replace(' ', ''),Model_Clean.strip().replace(' ', ''),Variant_Clean.strip().replace(' ', ''),Fuel_Clean,CV_State_Clean.strip().replace(' ', ''),METERREADING,SELLER_SEGMENT.strip().replace(' ', '')]).reshape(1,8))


            predPrice = ce_cs_test.predict(X)[0]
            predPrice = int(predPrice)


            MAKEYEAR = MAKE_YEAR
            CLEANEDMake = Make_Clean
            CLEANEDModel = Model_Clean
            CLEANEDVariant = Variant_Clean
            CLEANEDfueltype = Fuel_Clean
            SOLDAMOUNT = predPrice
            SELLER_SEGMENT = 'RETAIL'
            METERREADING = METERREADING
            Segment = 'CE'
            
            
            
            try:
                X1 = pd.DataFrame(columns=['MAKEYEAR', 'CLEANEDMake', 'CLEANEDModel', 'CLEANEDVariant','CLEANEDfueltype', 'SOLDAMOUNT', 'SELLER_SEGMENT', 'METERREADING','Segment'],data=np.array([MAKEYEAR, CLEANEDMake, CLEANEDModel, CLEANEDVariant,'DIESEL', SOLDAMOUNT, SELLER_SEGMENT, METERREADING,Segment]).reshape(1,9))
                state_num = state_model.predict(X1)[0]
                # print(state_num)
                
                predState = state_to_category(state_num)
                print(predState)
            except:
                predState = "DELHI"


            
            newHitCount = totalHitAvailable -1
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)
            if saveData[1] == 201:


                if 1 != 1:
                    chang_e()


                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updateQuery(updateHitQuery)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": price_range_calc(predPrice),
                        "state": predState.upper()
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200

            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                updateData = updateQuery(updateHitQuery)
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400




    elif vehicleCategory == '2W':

        carMake = getCarmake_uat(args.make)
        carModel = getCarmodel_uat(args.model)
        carVariant = getCarvariant_uat(args.variant)
        carFuel = getCarfuel_uat(args.fuel)
        state = args.regno[:2]
        carSegment = getCarSegment_uat(args.seller_segment)


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        State_Clean = getState_uat(state)
        State_Clean = State_Clean.upper()
        
        # if State_Clean == 'MAHARASHTRA':
        #     State_Clean = 'MAHARASTRA'

        METERREADING = args.METERREADING
        MAKEYEAR = args.mfgyear
        
        Customer_Segmentation = carSegment[1].upper()
        # Customer_Segmentation = "RETAIL"

        if Customer_Segmentation == "BANKS & NBFC":
            Customer_Segmentation = "BANK&NBFC"

        # elif SEGMENT == "LEASING":
        #     Customer_Segmentation = "RETAIL"

        elif Customer_Segmentation == "ALL":
            Customer_Segmentation = "RETAIL"


        print(MAKEYEAR,Make_Clean,Model_Clean,Variant_Clean,Fuel_Clean,State_Clean,Customer_Segmentation.replace(' ',''),METERREADING)


        try:
            try:
                X = pd.DataFrame(columns=['Make_Clean','Model_Clean','Variant_Clean','State_Clean','Fuel_Clean','Customer_Segmentation','MAKEYEAR','METERREADING'],data=np.array([Make_Clean.strip().replace(' ', ''),Model_Clean.strip().replace(' ', ''),Variant_Clean.strip().replace(' ', ''),State_Clean.strip().replace(' ', ''),Fuel_Clean,Customer_Segmentation.strip().replace(' ', ''),MAKEYEAR,METERREADING]).reshape(1,8))


                
                predPrice = two_w_cs_test.predict(X)[0]
                predPrice = int(predPrice)
            except Exception as e:
                print(e)



            MAKEYEAR = MAKEYEAR
            CLEANEDMake = Make_Clean
            CLEANEDModel = Model_Clean
            CLEANEDVariant = Variant_Clean
            CLEANEDfueltype = Fuel_Clean
            SOLDAMOUNT = predPrice
            SELLER_SEGMENT = 'RETAIL'
            METERREADING = METERREADING
            Segment = '2W'
            
            
            
            try:
                X1 = pd.DataFrame(columns=['MAKEYEAR', 'CLEANEDMake', 'CLEANEDModel', 'CLEANEDVariant','CLEANEDfueltype', 'SOLDAMOUNT', 'SELLER_SEGMENT', 'METERREADING','Segment'],data=np.array([MAKEYEAR, CLEANEDMake, CLEANEDModel, CLEANEDVariant,CLEANEDfueltype, SOLDAMOUNT, SELLER_SEGMENT, METERREADING,Segment]).reshape(1,9))
                state_num = state_model.predict(X1)[0]
                # print(state_num)
                
                predState = state_to_category(state_num)
                print(predState)
            except:
                predState = "DELHI"


            
            newHitCount = totalHitAvailable -1
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,State_Clean,args.regno,args.mfgyear,args.seller_segment,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)

            if saveData[1] == 201:

                if 1 != 1:
                    chang_e()


                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updateQuery(updateHitQuery)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": price_range_calc(predPrice),
                        "state": predState.upper()
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200

            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                updateData = updateQuery(updateHitQuery)
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,State_Clean,args.regno,args.mfgyear,args.seller_segment,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400




    elif vehicleCategory == '3W':

        carMake = getCarmake_uat(args.make)
        carModel = getCarmodel_uat(args.model)
        carVariant = getCarvariant_uat(args.variant)
        carFuel = getCarfuel_uat(args.fuel)
        state = args.regno[:2]
        carSegment = getCarSegment_uat(args.seller_segment)


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        STATE_MAPPED = getState_uat(state)
        State_Clean = STATE_MAPPED.upper()
        SELLERSEGMENT = carSegment[1].upper()

        if SELLERSEGMENT == "BANKS & NBFC":
            SELLERSEGMENT = "BANK&NBFC"


        elif SELLERSEGMENT == "ALL":
            SELLERSEGMENT = "RETAIL"




        METERREADING = args.METERREADING
        MAKE_YEAR = args.mfgyear


        print(MAKE_YEAR,Make_Clean,Model_Clean,Variant_Clean,Fuel_Clean,State_Clean,'RETAIL',METERREADING)
        

        try:
            X = pd.DataFrame(columns=['MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','State_Clean','SELLERSEGMENT','METERREADING'],data=np.array([MAKE_YEAR,Make_Clean.strip().replace(' ', ''),Model_Clean.strip().replace(' ', ''),Variant_Clean.strip().replace(' ', ''),Fuel_Clean,State_Clean.strip().replace(' ', ''),SELLERSEGMENT.strip().replace(' ',''),METERREADING]).reshape(1,8))
            
            predPrice = three_w_cs.predict(X)[0]
            predPrice = int(predPrice)


            MAKEYEAR = MAKE_YEAR
            CLEANEDMake = Make_Clean
            CLEANEDModel = Model_Clean
            CLEANEDVariant = Variant_Clean
            CLEANEDfueltype = Fuel_Clean
            SOLDAMOUNT = predPrice
            SELLER_SEGMENT = 'RETAIL'
            METERREADING = METERREADING
            Segment = '3W'
            
            
            
            try:
                X1 = pd.DataFrame(columns=['MAKEYEAR', 'CLEANEDMake', 'CLEANEDModel', 'CLEANEDVariant','CLEANEDfueltype', 'SOLDAMOUNT', 'SELLER_SEGMENT', 'METERREADING','Segment'],data=np.array([MAKEYEAR, CLEANEDMake, CLEANEDModel, CLEANEDVariant,CLEANEDfueltype, SOLDAMOUNT, SELLER_SEGMENT, METERREADING,Segment]).reshape(1,9))
                state_num = state_model.predict(X1)[0]
                # print(state_num)
                
                predState = state_to_category(state_num)
                print(predState)
            
            except:
                predState = "DELHI"


            
            newHitCount = totalHitAvailable -1
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,State_Clean,args.regno,args.mfgyear,args.seller_segment,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)
            if saveData[1] == 201:

                if 1 != 1:
                    chang_e()


                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updateQuery(updateHitQuery)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": price_range_calc(predPrice),
                        "state": predState.upper()
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200            
            
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                updateData = updateQuery(updateHitQuery)
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        
        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,State_Clean,args.regno,args.mfgyear,args.seller_segment,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400



    elif vehicleCategory == 'FE':

        carMake = getCarmake_uat(args.make)
        carModel = getCarmodel_uat(args.model)
        carVariant = getCarvariant_uat(args.variant)
        carFuel = getCarfuel_uat(args.fuel)
        state = args.regno[:2]
        carSegment = getCarSegment_uat(args.seller_segment)


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        CV_State_Clean = getState_uat(state)
        CV_State_Clean = CV_State_Clean.upper()
        METERREADING = args.METERREADING
        MAKE_YEAR = args.mfgyear

        SELLER_SEGMENT = carSegment[1].upper()
        # SELLER_SEGMENT = "RETAIL"

        if SELLER_SEGMENT == "BANKS & NBFC":
            SELLER_SEGMENT = "BANK&NBFC"

        # elif SEGMENT == "LEASING":
        #     SELLER_SEGMENT = "RETAIL"

        elif SELLER_SEGMENT == "ALL":
            SELLER_SEGMENT = "RETAIL"


        
        print(MAKE_YEAR,Make_Clean,Model_Clean,Variant_Clean,Fuel_Clean,CV_State_Clean,SELLER_SEGMENT.replace(' ',''),METERREADING)


        try:
            X = (pd.DataFrame(columns=['MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','CV_State_Clean','METERREADING','SELLER_SEGMENT'],data=np.array([MAKE_YEAR,Make_Clean.strip().replace(' ',''),Model_Clean.strip().replace(' ',''),Variant_Clean.strip().replace(' ',''),Fuel_Clean,CV_State_Clean.strip().replace(' ',''),METERREADING,SELLER_SEGMENT.strip().replace(' ','')]).reshape(1,8)))
            predPrice = fe_cs_test.predict(X)[0]
            predPrice = int(predPrice)


            MAKEYEAR = MAKE_YEAR
            CLEANEDMake = Make_Clean
            CLEANEDModel = Model_Clean
            CLEANEDVariant = Variant_Clean
            CLEANEDfueltype = Fuel_Clean
            SOLDAMOUNT = predPrice
            SELLER_SEGMENT = 'RETAIL'
            METERREADING = METERREADING
            Segment = 'FE'
            
                    
            try:
                X1 = pd.DataFrame(columns=['MAKEYEAR', 'CLEANEDMake', 'CLEANEDModel', 'CLEANEDVariant','CLEANEDfueltype', 'SOLDAMOUNT', 'SELLER_SEGMENT', 'METERREADING','Segment'],data=np.array([MAKEYEAR, CLEANEDMake, CLEANEDModel, CLEANEDVariant,CLEANEDfueltype, SOLDAMOUNT, SELLER_SEGMENT, METERREADING,Segment]).reshape(1,9))
                state_num = state_model.predict(X1)[0]
                        
                predState = state_to_category(state_num)
                print(predState)
            except:
                predState = 'DELHI'



            
            newHitCount = totalHitAvailable -1
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)
            if saveData[1] == 201:

                if 1 != 1:
                    chang_e()


                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updateQuery(updateHitQuery)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": price_range_calc(predPrice),
                        "state": predState.upper()
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200            
            
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                updateData = updateQuery(updateHitQuery)
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400




    else:
        return jsonify({"status": 400, "message":"Wrong vehicle category type","data": None}), 400


@REQUEST_API.route('/app_predictedprice', methods=['POST'])
@token_required
def app_predictedprice(data):
    start = time.process_time()
    if data[4] == 0:
        return jsonify({"status": 401,'message' : 'User unathorised to used API'}), 401
    fetchQuery = 'Select clientId, activeSubscription, totalHitCount, hitCountAvailable from TBL_SUBSCRIPTION_COUNT_MASTER where clientId="'+data[0]+'"'
    fetchData = singleQuery(fetchQuery)
    if not fetchData:
        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
    totalHitCount = fetchData[2]
    totalHitAvailable = int(fetchData[3])
    if totalHitAvailable < 1:
        return jsonify({"status": 401,'message' : 'You have exhausted you API hit. Kindly recharge or topup hit'}), 401

    userData = request.headers.get('User-Agent')
    parser = reqparse.RequestParser(bundle_errors=True)
    parser.add_argument('vtype', type=str, required=True, help = "Please Enter vehicle type")
    parser.add_argument('make', type=str, required=True, help = "Please Enter vehicle make")
    parser.add_argument('model', type=str, help="Please Enter vehicle model")
    parser.add_argument('variant', type=str, help="Please Enter vehicle variant")
    parser.add_argument('fuel', type=str, help="Please Enter vehicle fuel")
    parser.add_argument('regno', type=str, help="Please Enter vehicle number")
    parser.add_argument('mfgyear', type=str, help="Please Enter vehicle manufacturing year")
    parser.add_argument('seller_segment', type=str, help="Please Enter segment")
    parser.add_argument('METERREADING', type=str, help="Please Enter segment")
    parser.add_argument('clientId', type=str, help="Please Enter client id")
    parser.add_argument('clientType', type=str, help="Please Enter client type id")
    parser.add_argument('userId', type=str, help="Please Enter user id")
    args = parser.parse_args()
    # print(args)


    if not args.vtype:
        return jsonify({"status": 406,"return": "Vehicle type not be empty", "data": None}), 406
    if not args.make:
        return jsonify({"status": 406,"return": "Vehicle Make not be empty", "data": None}), 406
    if not args.model:
        return jsonify({"status": 406,"return": "Vehicle Model not be empty", "data": None}), 406
    if not args.variant:
        return jsonify({"status": 406,"return": "Vehicle Variant not be empty", "data": None}), 406
    if not args.fuel:
        return jsonify({"status": 406,"return": "Vehicle Fuel not be empty", "data": None}), 406
    if not args.regno:
        return jsonify({"status": 406,"return": "Vehicle Registrtion Number not be empty", "data": None}), 406
    if not args.mfgyear:
        return jsonify({"status": 406,"return": "Vehicle Year not be empty", "data": None}), 406
    if not args.seller_segment:
        return jsonify({"status": 406,"return": "Segment not be empty", "data": None}), 406
    if not args.METERREADING:
        return jsonify({"status": 406,"return": "Meter Reading not be empty", "data": None}), 406    
    if not args.clientId:
        return jsonify({"status": 406,"return": "Client Id not be empty", "data": None}), 406
    if not args.clientType:
        return jsonify({"status": 406,"return": "Client Type not be empty", "data": None}), 406

    vehicleCategory = args.vtype.upper()

    if vehicleCategory == '4W':

        carMake = getCarmake_uat(args.make)
        carModel = getCarmodel_uat(args.model)
        carVariant = getCarvariant_uat(args.variant)
        carFuel = getCarfuel_uat(args.fuel)
        state = args.regno[:2]
        carSegment = getCarSegment_uat(args.seller_segment)


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        CV_State_Clean = getState_uat(state)
        CV_State_Clean = CV_State_Clean.upper()
        METERREADING = args.METERREADING
        MAKE_YEAR = args.mfgyear
        SELLER_SEGMENT = carSegment[1].upper()
        # SELLER_SEGMENT = "RETAIL"

        if SELLER_SEGMENT == "BANKS & NBFC":
            SELLER_SEGMENT = "BANK&NBFC"

        # elif SEGMENT == "LEASING":
        #     SELLER_SEGMENT = "RETAIL"

        elif SELLER_SEGMENT == "ALL":
            SELLER_SEGMENT = "RETAIL"


        print(MAKE_YEAR,Make_Clean.replace(' ',''),Model_Clean.replace(' ',''),Variant_Clean.replace(' ',''),Fuel_Clean,CV_State_Clean,SELLER_SEGMENT.replace(' ',''),METERREADING)

        try:
            X = pd.DataFrame(columns=['MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','CV_State_Clean','METERREADING','SELLER_SEGMENT'],data=np.array([MAKE_YEAR,Make_Clean.strip().replace(' ', ''),Model_Clean.strip().replace(' ', ''),Variant_Clean.strip().replace(' ', ''),Fuel_Clean,CV_State_Clean.strip().replace(' ', ''),METERREADING,SELLER_SEGMENT.strip().replace(' ', '')]).reshape(1,8))  

            predPrice = fourw_cs_test.predict(X)[0]
            predPrice = int(predPrice)
            
            MAKEYEAR = MAKE_YEAR
            CLEANEDMake = Make_Clean
            CLEANEDModel = Model_Clean
            CLEANEDVariant = Variant_Clean
            CLEANEDfueltype = Fuel_Clean
            SOLDAMOUNT = predPrice
            SELLER_SEGMENT = 'RETAIL'
            METERREADING = METERREADING
            Segment = '4W'
            
            
            
            try:
                X1 = pd.DataFrame(columns=['MAKEYEAR', 'CLEANEDMake', 'CLEANEDModel', 'CLEANEDVariant','CLEANEDfueltype', 'SOLDAMOUNT', 'SELLER_SEGMENT', 'METERREADING','Segment'],data=np.array([MAKEYEAR, CLEANEDMake, CLEANEDModel, CLEANEDVariant,CLEANEDfueltype, SOLDAMOUNT, SELLER_SEGMENT, METERREADING,Segment]).reshape(1,9))
                state_num = state_model.predict(X1)[0]
                # print(state_num)
                
                predState = state_to_category(state_num)
                print(predState)
            
            except:
                predState = "DELHI"



            
            newHitCount = totalHitAvailable -1
            saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)
            if saveData[1] == 201:


                if 1 != 1:
                    chang_e()

                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updateQuery(updateHitQuery)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": price_range_calc(predPrice),
                        "state": predState.upper()
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200

            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                updateData = updateQuery(updateHitQuery)
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400


        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'

            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                print({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]})
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200

            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

    
        
    elif vehicleCategory == 'CV':
        
        carMake = getCarmake_uat(args.make)
        carModel = getCarmodel_uat(args.model)
        carVariant = getCarvariant_uat(args.variant)
        carFuel = getCarfuel_uat(args.fuel)
        state = args.regno[:2]
        carSegment = getCarSegment_uat(args.seller_segment)


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        CV_State_Clean = getState_uat(state)
        CV_State_Clean = CV_State_Clean.upper()
        Meter_Reading = args.METERREADING
        MAKEYEAR = args.mfgyear
        SELLER_SEGMENT = carSegment[1].upper()
        # SELLER_SEGMENT = "RETAIL"

        if SELLER_SEGMENT == "BANKS & NBFC":
            SELLER_SEGMENT = "BANK&NBFC"

        # elif SEGMENT == "LEASING":
        #     SELLER_SEGMENT = "RETAIL"

        elif SELLER_SEGMENT == "ALL":
            SELLER_SEGMENT = "RETAIL"



        print(MAKEYEAR,Make_Clean,Model_Clean,Variant_Clean,Fuel_Clean,CV_State_Clean,SELLER_SEGMENT.replace(' ',''),Meter_Reading)

        try:
            X = pd.DataFrame(columns=['MAKEYEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','CV_State_Clean','SELLER_SEGMENT','Meter_Reading'],data=np.array([MAKEYEAR,Make_Clean.strip().replace(' ', ''),Model_Clean.strip().replace(' ', ''),Variant_Clean.strip().replace(' ', ''),Fuel_Clean,CV_State_Clean.strip().replace(' ', ''),SELLER_SEGMENT.strip().replace(' ', ''),Meter_Reading]).reshape(1,8))
            

            predPrice = cv_cs_test.predict(X)[0]
            predPrice = int(predPrice)


            MAKEYEAR = MAKEYEAR
            CLEANEDMake = Make_Clean
            CLEANEDModel = Model_Clean
            CLEANEDVariant = Variant_Clean
            CLEANEDfueltype = Fuel_Clean
            SOLDAMOUNT = predPrice
            SELLER_SEGMENT = 'RETAIL'
            METERREADING = Meter_Reading
            Segment = 'CV'
            
            
            
            try:
                X1 = pd.DataFrame(columns=['MAKEYEAR', 'CLEANEDMake', 'CLEANEDModel', 'CLEANEDVariant','CLEANEDfueltype', 'SOLDAMOUNT', 'SELLER_SEGMENT', 'METERREADING','Segment'],data=np.array([MAKEYEAR, CLEANEDMake, CLEANEDModel, CLEANEDVariant,CLEANEDfueltype, SOLDAMOUNT, SELLER_SEGMENT, METERREADING,Segment]).reshape(1,9))
                state_num = state_model.predict(X1)[0]
                # print(state_num)
                
                predState = state_to_category(state_num)
                print(predState)
            except:
                predState = "DELHI"

            
            newHitCount = totalHitAvailable -1
            saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)
            if saveData[1] == 201:


                if 1 != 1:
                    chang_e()


                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updateQuery(updateHitQuery)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": price_range_calc(predPrice),
                        "state": predState.upper()
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200

            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                updateData = updateQuery(updateHitQuery)
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400




    elif vehicleCategory == 'CE':
        
        carMake = getCarmake_uat(args.make)
        carModel = getCarmodel_uat(args.model)
        carVariant = getCarvariant_uat(args.variant)
        carFuel = getCarfuel_uat(args.fuel)
        state = args.regno[:2]
        carSegment = getCarSegment_uat(args.seller_segment)


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        # Fuel_Clean = carFuel[1].upper()
        CV_State_Clean = getState_uat(state)
        CV_State_Clean = CV_State_Clean.upper()
        METERREADING = args.METERREADING
        MAKE_YEAR = args.mfgyear

        Fuel_Clean = 'DIESEL'

        if Fuel_Clean == 'null':
            Fuel_Clean = 'DIESEL'
        
        SELLER_SEGMENT = carSegment[1].upper()
        # SELLER_SEGMENT = "RETAIL"

        if SELLER_SEGMENT == "BANKS & NBFC":
            SELLER_SEGMENT = "BANK&NBFC"

        # elif SEGMENT == "LEASING":
        #     SELLER_SEGMENT = "RETAIL"

        elif SELLER_SEGMENT == "ALL":
            SELLER_SEGMENT = "RETAIL"


        print(MAKE_YEAR,Make_Clean,Model_Clean,Variant_Clean,Fuel_Clean,CV_State_Clean,SELLER_SEGMENT.replace(' ',''),METERREADING)


        try:
            X = pd.DataFrame(columns=['MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','CV_State_Clean','METERREADING','SELLER_SEGMENT'],data=np.array([MAKE_YEAR,Make_Clean.strip().replace(' ', ''),Model_Clean.strip().replace(' ', ''),Variant_Clean.strip().replace(' ', ''),Fuel_Clean,CV_State_Clean.strip().replace(' ', ''),METERREADING,SELLER_SEGMENT.strip().replace(' ', '')]).reshape(1,8))


            predPrice = ce_cs_test.predict(X)[0]
            predPrice = int(predPrice)


            MAKEYEAR = MAKE_YEAR
            CLEANEDMake = Make_Clean
            CLEANEDModel = Model_Clean
            CLEANEDVariant = Variant_Clean
            CLEANEDfueltype = Fuel_Clean
            SOLDAMOUNT = predPrice
            SELLER_SEGMENT = 'RETAIL'
            METERREADING = METERREADING
            Segment = 'CE'
            
            
            
            try:
                X1 = pd.DataFrame(columns=['MAKEYEAR', 'CLEANEDMake', 'CLEANEDModel', 'CLEANEDVariant','CLEANEDfueltype', 'SOLDAMOUNT', 'SELLER_SEGMENT', 'METERREADING','Segment'],data=np.array([MAKEYEAR, CLEANEDMake, CLEANEDModel, CLEANEDVariant,'DIESEL', SOLDAMOUNT, SELLER_SEGMENT, METERREADING,Segment]).reshape(1,9))
                state_num = state_model.predict(X1)[0]
                # print(state_num)
                
                predState = state_to_category(state_num)
                print(predState)
            except:
                predState = "DELHI"


            
            newHitCount = totalHitAvailable -1
            saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)
            if saveData[1] == 201:


                if 1 != 1:
                    chang_e()


                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updateQuery(updateHitQuery)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": price_range_calc(predPrice),
                        "state": predState.upper()
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200

            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                updateData = updateQuery(updateHitQuery)
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400




    elif vehicleCategory == '2W':

        carMake = getCarmake_uat(args.make)
        carModel = getCarmodel_uat(args.model)
        carVariant = getCarvariant_uat(args.variant)
        carFuel = getCarfuel_uat(args.fuel)
        state = args.regno[:2]
        carSegment = getCarSegment_uat(args.seller_segment)


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        State_Clean = getState_uat(state)
        State_Clean = State_Clean.upper()
        
        # if State_Clean == 'MAHARASHTRA':
        #     State_Clean = 'MAHARASTRA'

        METERREADING = args.METERREADING
        MAKEYEAR = args.mfgyear
        
        Customer_Segmentation = carSegment[1].upper()
        # Customer_Segmentation = "RETAIL"

        if Customer_Segmentation == "BANKS & NBFC":
            Customer_Segmentation = "BANK&NBFC"

        # elif SEGMENT == "LEASING":
        #     Customer_Segmentation = "RETAIL"

        elif Customer_Segmentation == "ALL":
            Customer_Segmentation = "RETAIL"


        print(MAKEYEAR,Make_Clean,Model_Clean,Variant_Clean,Fuel_Clean,State_Clean,Customer_Segmentation.replace(' ',''),METERREADING)


        try:
            try:
                X = pd.DataFrame(columns=['Make_Clean','Model_Clean','Variant_Clean','State_Clean','Fuel_Clean','Customer_Segmentation','MAKEYEAR','METERREADING'],data=np.array([Make_Clean.strip().replace(' ', ''),Model_Clean.strip().replace(' ', ''),Variant_Clean.strip().replace(' ', ''),State_Clean.strip().replace(' ', ''),Fuel_Clean,Customer_Segmentation.strip().replace(' ', ''),MAKEYEAR,METERREADING]).reshape(1,8))


                
                predPrice = two_w_cs_test.predict(X)[0]
                predPrice = int(predPrice)
            except Exception as e:
                print(e)



            MAKEYEAR = MAKEYEAR
            CLEANEDMake = Make_Clean
            CLEANEDModel = Model_Clean
            CLEANEDVariant = Variant_Clean
            CLEANEDfueltype = Fuel_Clean
            SOLDAMOUNT = predPrice
            SELLER_SEGMENT = 'RETAIL'
            METERREADING = METERREADING
            Segment = '2W'
            
            
            
            try:
                X1 = pd.DataFrame(columns=['MAKEYEAR', 'CLEANEDMake', 'CLEANEDModel', 'CLEANEDVariant','CLEANEDfueltype', 'SOLDAMOUNT', 'SELLER_SEGMENT', 'METERREADING','Segment'],data=np.array([MAKEYEAR, CLEANEDMake, CLEANEDModel, CLEANEDVariant,CLEANEDfueltype, SOLDAMOUNT, SELLER_SEGMENT, METERREADING,Segment]).reshape(1,9))
                state_num = state_model.predict(X1)[0]
                # print(state_num)
                
                predState = state_to_category(state_num)
                print(predState)
            except:
                predState = "DELHI"


            
            newHitCount = totalHitAvailable -1
            saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,State_Clean,args.regno,args.mfgyear,args.seller_segment,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)

            if saveData[1] == 201:

                if 1 != 1:
                    chang_e()


                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updateQuery(updateHitQuery)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": price_range_calc(predPrice),
                        "state": predState.upper()
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200

            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                updateData = updateQuery(updateHitQuery)
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,State_Clean,args.regno,args.mfgyear,args.seller_segment,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400




    elif vehicleCategory == '3W':

        carMake = getCarmake_uat(args.make)
        carModel = getCarmodel_uat(args.model)
        carVariant = getCarvariant_uat(args.variant)
        carFuel = getCarfuel_uat(args.fuel)
        state = args.regno[:2]
        carSegment = getCarSegment_uat(args.seller_segment)


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        STATE_MAPPED = getState_uat(state)
        State_Clean = STATE_MAPPED.upper()
        SELLERSEGMENT = carSegment[1].upper()

        if SELLERSEGMENT == "BANKS & NBFC":
            SELLERSEGMENT = "BANK&NBFC"


        elif SELLERSEGMENT == "ALL":
            SELLERSEGMENT = "RETAIL"




        METERREADING = args.METERREADING
        MAKE_YEAR = args.mfgyear


        print(MAKE_YEAR,Make_Clean,Model_Clean,Variant_Clean,Fuel_Clean,State_Clean,'RETAIL',METERREADING)
        

        try:
            X = pd.DataFrame(columns=['MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','State_Clean','SELLERSEGMENT','METERREADING'],data=np.array([MAKE_YEAR,Make_Clean.strip().replace(' ', ''),Model_Clean.strip().replace(' ', ''),Variant_Clean.strip().replace(' ', ''),Fuel_Clean,State_Clean.strip().replace(' ', ''),SELLERSEGMENT.strip().replace(' ',''),METERREADING]).reshape(1,8))
            
            predPrice = three_w_cs.predict(X)[0]
            predPrice = int(predPrice)


            MAKEYEAR = MAKE_YEAR
            CLEANEDMake = Make_Clean
            CLEANEDModel = Model_Clean
            CLEANEDVariant = Variant_Clean
            CLEANEDfueltype = Fuel_Clean
            SOLDAMOUNT = predPrice
            SELLER_SEGMENT = 'RETAIL'
            METERREADING = METERREADING
            Segment = '3W'
            
            
            
            try:
                X1 = pd.DataFrame(columns=['MAKEYEAR', 'CLEANEDMake', 'CLEANEDModel', 'CLEANEDVariant','CLEANEDfueltype', 'SOLDAMOUNT', 'SELLER_SEGMENT', 'METERREADING','Segment'],data=np.array([MAKEYEAR, CLEANEDMake, CLEANEDModel, CLEANEDVariant,CLEANEDfueltype, SOLDAMOUNT, SELLER_SEGMENT, METERREADING,Segment]).reshape(1,9))
                state_num = state_model.predict(X1)[0]
                # print(state_num)
                
                predState = state_to_category(state_num)
                print(predState)
            
            except:
                predState = "DELHI"


            
            newHitCount = totalHitAvailable -1
            saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,State_Clean,args.regno,args.mfgyear,args.seller_segment,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)
            if saveData[1] == 201:

                if 1 != 1:
                    chang_e()


                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updateQuery(updateHitQuery)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": price_range_calc(predPrice),
                        "state": predState.upper()
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200            
            
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                updateData = updateQuery(updateHitQuery)
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        
        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,State_Clean,args.regno,args.mfgyear,args.seller_segment,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400



    elif vehicleCategory == 'FE':

        carMake = getCarmake_uat(args.make)
        carModel = getCarmodel_uat(args.model)
        carVariant = getCarvariant_uat(args.variant)
        carFuel = getCarfuel_uat(args.fuel)
        state = args.regno[:2]
        carSegment = getCarSegment_uat(args.seller_segment)


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        CV_State_Clean = getState_uat(state)
        CV_State_Clean = CV_State_Clean.upper()
        METERREADING = args.METERREADING
        MAKE_YEAR = args.mfgyear

        SELLER_SEGMENT = carSegment[1].upper()
        # SELLER_SEGMENT = "RETAIL"

        if SELLER_SEGMENT == "BANKS & NBFC":
            SELLER_SEGMENT = "BANK&NBFC"

        # elif SEGMENT == "LEASING":
        #     SELLER_SEGMENT = "RETAIL"

        elif SELLER_SEGMENT == "ALL":
            SELLER_SEGMENT = "RETAIL"


        
        print(MAKE_YEAR,Make_Clean,Model_Clean,Variant_Clean,Fuel_Clean,CV_State_Clean,SELLER_SEGMENT.replace(' ',''),METERREADING)


        try:
            X = (pd.DataFrame(columns=['MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','CV_State_Clean','METERREADING','SELLER_SEGMENT'],data=np.array([MAKE_YEAR,Make_Clean.strip().replace(' ',''),Model_Clean.strip().replace(' ',''),Variant_Clean.strip().replace(' ',''),Fuel_Clean,CV_State_Clean.strip().replace(' ',''),METERREADING,SELLER_SEGMENT.strip().replace(' ','')]).reshape(1,8)))
            predPrice = fe_cs_test.predict(X)[0]
            predPrice = int(predPrice)


            MAKEYEAR = MAKE_YEAR
            CLEANEDMake = Make_Clean
            CLEANEDModel = Model_Clean
            CLEANEDVariant = Variant_Clean
            CLEANEDfueltype = Fuel_Clean
            SOLDAMOUNT = predPrice
            SELLER_SEGMENT = 'RETAIL'
            METERREADING = METERREADING
            Segment = 'FE'
            
                    
            try:
                X1 = pd.DataFrame(columns=['MAKEYEAR', 'CLEANEDMake', 'CLEANEDModel', 'CLEANEDVariant','CLEANEDfueltype', 'SOLDAMOUNT', 'SELLER_SEGMENT', 'METERREADING','Segment'],data=np.array([MAKEYEAR, CLEANEDMake, CLEANEDModel, CLEANEDVariant,CLEANEDfueltype, SOLDAMOUNT, SELLER_SEGMENT, METERREADING,Segment]).reshape(1,9))
                state_num = state_model.predict(X1)[0]
                        
                predState = state_to_category(state_num)
                print(predState)
            except:
                predState = 'DELHI'



            
            newHitCount = totalHitAvailable -1
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)
            if saveData[1] == 201:

                if 1 != 1:
                    chang_e()


                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updateQuery(updateHitQuery)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": price_range_calc(predPrice),
                        "state": predState.upper()
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200            
            
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                updateData = updateQuery(updateHitQuery)
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400




    else:
        return jsonify({"status": 400, "message":"Wrong vehicle category type","data": None}), 400
    

@REQUEST_API.route('/app_predictedprice_live', methods=['POST'])
@token_required
def app_predictedprice_live(data):
    start = time.process_time()
    if data[4] == 0:
        return jsonify({"status": 401,'message' : 'User unathorised to used API'}), 401
    fetchQuery = 'Select clientId, activeSubscription, totalHitCount, hitCountAvailable from TBL_SUBSCRIPTION_COUNT_MASTER where clientId="'+data[0]+'"'
    fetchData = singleQuery(fetchQuery)
    if not fetchData:
        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
    totalHitCount = fetchData[2]
    totalHitAvailable = int(fetchData[3])
    if totalHitAvailable < 1:
        return jsonify({"status": 401,'message' : 'You have exhausted you API hit. Kindly recharge or topup hit'}), 401

    userData = request.headers.get('User-Agent')
    parser = reqparse.RequestParser(bundle_errors=True)
    parser.add_argument('vtype', type=str, required=True, help = "Please Enter vehicle type")
    parser.add_argument('make', type=str, required=True, help = "Please Enter vehicle make")
    parser.add_argument('model', type=str, help="Please Enter vehicle model")
    parser.add_argument('variant', type=str, help="Please Enter vehicle variant")
    parser.add_argument('fuel', type=str, help="Please Enter vehicle fuel")
    parser.add_argument('regno', type=str, help="Please Enter vehicle number")
    parser.add_argument('mfgyear', type=str, help="Please Enter vehicle manufacturing year")
    parser.add_argument('seller_segment', type=str, help="Please Enter segment")
    parser.add_argument('METERREADING', type=str, help="Please Enter segment")
    parser.add_argument('clientId', type=str, help="Please Enter client id")
    parser.add_argument('clientType', type=str, help="Please Enter client type id")
    parser.add_argument('userId', type=str, help="Please Enter user id")
    args = parser.parse_args()
    # print(args)


    if not args.vtype:
        return jsonify({"status": 406,"return": "Vehicle type not be empty", "data": None}), 406
    if not args.make:
        return jsonify({"status": 406,"return": "Vehicle Make not be empty", "data": None}), 406
    if not args.model:
        return jsonify({"status": 406,"return": "Vehicle Model not be empty", "data": None}), 406
    if not args.variant:
        return jsonify({"status": 406,"return": "Vehicle Variant not be empty", "data": None}), 406
    if not args.fuel:
        return jsonify({"status": 406,"return": "Vehicle Fuel not be empty", "data": None}), 406
    if not args.regno:
        return jsonify({"status": 406,"return": "Vehicle Registrtion Number not be empty", "data": None}), 406
    if not args.mfgyear:
        return jsonify({"status": 406,"return": "Vehicle Year not be empty", "data": None}), 406
    if not args.seller_segment:
        return jsonify({"status": 406,"return": "Segment not be empty", "data": None}), 406
    if not args.METERREADING:
        return jsonify({"status": 406,"return": "Meter Reading not be empty", "data": None}), 406    
    if not args.clientId:
        return jsonify({"status": 406,"return": "Client Id not be empty", "data": None}), 406
    if not args.clientType:
        return jsonify({"status": 406,"return": "Client Type not be empty", "data": None}), 406

    vehicleCategory = args.vtype.upper()

    if vehicleCategory == '4W':

        carMake = getCarmake(args.make)
        carModel = getCarmodel(args.model)
        carVariant = getCarvariant(args.variant)
        carFuel = getCarfuel(args.fuel)
        state = args.regno[:2]
        carSegment = getCarSegment(args.seller_segment)


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        CV_State_Clean = getState(state)
        CV_State_Clean = CV_State_Clean.upper()
        METERREADING = args.METERREADING
        MAKE_YEAR = args.mfgyear
        SELLER_SEGMENT = carSegment[1].upper()
        # SELLER_SEGMENT = "RETAIL"

        if SELLER_SEGMENT == "BANKS & NBFC":
            SELLER_SEGMENT = "BANK&NBFC"

        # elif SEGMENT == "LEASING":
        #     SELLER_SEGMENT = "RETAIL"

        # elif SEGMENT == "ALL":
        #     SELLER_SEGMENT = "RETAIL"


        print(MAKE_YEAR,Make_Clean.replace(' ',''),Model_Clean.replace(' ',''),Variant_Clean.replace(' ',''),Fuel_Clean,CV_State_Clean,SELLER_SEGMENT.replace(' ',''),METERREADING)

        try:
            X = pd.DataFrame(columns=['MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','CV_State_Clean','SELLER_SEGMENT','METERREADING'],data=np.array([MAKE_YEAR,Make_Clean.replace(' ',''),Model_Clean.replace(' ',''),Variant_Clean.replace(' ',''),Fuel_Clean,CV_State_Clean,SELLER_SEGMENT.replace(' ',''),METERREADING]).reshape(1,8))
            
            predPrice = four_w_cs.predict(X)[0]
            predPrice = int(predPrice)
            
            MAKEYEAR = MAKE_YEAR
            CLEANEDMake = Make_Clean
            CLEANEDModel = Model_Clean
            CLEANEDVariant = Variant_Clean
            CLEANEDfueltype = Fuel_Clean
            SOLDAMOUNT = predPrice
            SELLER_SEGMENT = 'RETAIL'
            METERREADING = METERREADING
            Segment = '4W'
            
            
            
            try:
                X1 = pd.DataFrame(columns=['MAKEYEAR', 'CLEANEDMake', 'CLEANEDModel', 'CLEANEDVariant','CLEANEDfueltype', 'SOLDAMOUNT', 'SELLER_SEGMENT', 'METERREADING','Segment'],data=np.array([MAKEYEAR, CLEANEDMake, CLEANEDModel, CLEANEDVariant,CLEANEDfueltype, SOLDAMOUNT, SELLER_SEGMENT, METERREADING,Segment]).reshape(1,9))
                state_num = state_model.predict(X1)[0]
                # print(state_num)
                
                predState = state_to_category(state_num)
                print(predState)
            
            except:
                predState = "DELHI"



            
            newHitCount = totalHitAvailable -1
            saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)
            if saveData[1] == 201:

                if 1 != 1:
                    chang_e()

                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updateQuery(updateHitQuery)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": price_range_calc(predPrice),
                        "state": predState.upper()
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200

            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                updateData = updateQuery(updateHitQuery)
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'

            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                print({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]})
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200

            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

    

    elif vehicleCategory == 'CV':
        
        carMake = getCarmake(args.make)
        carModel = getCarmodel(args.model)
        carVariant = getCarvariant(args.variant)
        carFuel = getCarfuel(args.fuel)
        state = args.regno[:2]
        carSegment = getCarSegment(args.seller_segment)


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        CV_State_Clean = getState(state)
        CV_State_Clean = CV_State_Clean.upper()
        Meter_Reading = args.METERREADING
        MAKE_YEAR = args.mfgyear
        SELLER_SEGMENT = carSegment[1].upper()
        # SELLER_SEGMENT = "RETAIL"

        if SELLER_SEGMENT == "BANKS & NBFC":
            SELLER_SEGMENT = "BANK&NBFC"

        # elif SEGMENT == "LEASING":
        #     SELLER_SEGMENT = "RETAIL"

        # elif SEGMENT == "ALL":
        #     SELLER_SEGMENT = "RETAIL"



        print(MAKE_YEAR,Make_Clean,Model_Clean,Variant_Clean,Fuel_Clean,CV_State_Clean,SELLER_SEGMENT.replace(' ',''),Meter_Reading)

        try:
            X = pd.DataFrame(columns=['MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','CV_State_Clean','SELLER_SEGMENT','Meter_Reading'],data=np.array([MAKE_YEAR,Make_Clean.replace(' ',''),Model_Clean.replace(' ',''),Variant_Clean.replace(' ',''),Fuel_Clean,CV_State_Clean.replace(' ',''),SELLER_SEGMENT.replace(' ',''),Meter_Reading]).reshape(1,8))


            predPrice = cv_cs.predict(X)[0]
            predPrice = int(predPrice)


            MAKEYEAR = MAKE_YEAR
            CLEANEDMake = Make_Clean
            CLEANEDModel = Model_Clean
            CLEANEDVariant = Variant_Clean
            CLEANEDfueltype = Fuel_Clean
            SOLDAMOUNT = predPrice
            SELLER_SEGMENT = 'RETAIL'
            METERREADING = Meter_Reading
            Segment = 'CV'
            
            
            
            try:
                X1 = pd.DataFrame(columns=['MAKEYEAR', 'CLEANEDMake', 'CLEANEDModel', 'CLEANEDVariant','CLEANEDfueltype', 'SOLDAMOUNT', 'SELLER_SEGMENT', 'METERREADING','Segment'],data=np.array([MAKEYEAR, CLEANEDMake, CLEANEDModel, CLEANEDVariant,CLEANEDfueltype, SOLDAMOUNT, SELLER_SEGMENT, METERREADING,Segment]).reshape(1,9))
                state_num = state_model.predict(X1)[0]
                # print(state_num)
                
                predState = state_to_category(state_num)
                print(predState)
            except:
                predState = "DELHI"

            
            newHitCount = totalHitAvailable -1
            saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)
            if saveData[1] == 201:

                if 1 != 1:
                    chang_e()

                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updateQuery(updateHitQuery)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": price_range_calc(predPrice),
                        "state": predState.upper()
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200

            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                updateData = updateQuery(updateHitQuery)
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400




    elif vehicleCategory == 'CE':
        
        carMake = getCarmake(args.make)
        carModel = getCarmodel(args.model)
        carVariant = getCarvariant(args.variant)
        carFuel = getCarfuel(args.fuel)
        state = args.regno[:2]
        carSegment = getCarSegment(args.seller_segment)


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        # Fuel_Clean = carFuel[1].upper()
        CV_State_Clean = getState(state)
        CV_State_Clean = CV_State_Clean.upper()
        METERREADING = args.METERREADING
        MAKE_YEAR = args.mfgyear

        Fuel_Clean = 'DIESEL'

        if Fuel_Clean == 'null':
            Fuel_Clean = 'DIESEL'
        
        SELLER_SEGMENT = carSegment[1].upper()
        # SELLER_SEGMENT = "RETAIL"

        if SELLER_SEGMENT == "BANKS & NBFC":
            SELLER_SEGMENT = "BANK&NBFC"

        # elif SEGMENT == "LEASING":
        #     SELLER_SEGMENT = "RETAIL"

        # elif SEGMENT == "ALL":
        #     SELLER_SEGMENT = "RETAIL"


        print(MAKE_YEAR,Make_Clean,Model_Clean,Variant_Clean,Fuel_Clean,CV_State_Clean,SELLER_SEGMENT.replace(' ',''),METERREADING)


        try:
            X = pd.DataFrame(columns=['MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','CV_State_Clean','SELLER_SEGMENT','METERREADING'],data=np.array([MAKE_YEAR,Make_Clean.replace(' ',''),Model_Clean.replace(' ',''),Variant_Clean.replace(' ',''),'DIESEL',CV_State_Clean.replace(' ',''),SELLER_SEGMENT.replace(' ',''),METERREADING]).reshape(1,8))


            predPrice = ce_cs.predict(X)[0]
            predPrice = int(predPrice)


            MAKEYEAR = MAKE_YEAR
            CLEANEDMake = Make_Clean
            CLEANEDModel = Model_Clean
            CLEANEDVariant = Variant_Clean
            CLEANEDfueltype = Fuel_Clean
            SOLDAMOUNT = predPrice
            SELLER_SEGMENT = 'RETAIL'
            METERREADING = METERREADING
            Segment = 'CE'
            
            
            
            try:
                X1 = pd.DataFrame(columns=['MAKEYEAR', 'CLEANEDMake', 'CLEANEDModel', 'CLEANEDVariant','CLEANEDfueltype', 'SOLDAMOUNT', 'SELLER_SEGMENT', 'METERREADING','Segment'],data=np.array([MAKEYEAR, CLEANEDMake, CLEANEDModel, CLEANEDVariant,'DIESEL', SOLDAMOUNT, SELLER_SEGMENT, METERREADING,Segment]).reshape(1,9))
                state_num = state_model.predict(X1)[0]
                # print(state_num)
                
                predState = state_to_category(state_num)
                print(predState)
            except:
                predState = "DELHI"


            
            newHitCount = totalHitAvailable -1
            saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)
            if saveData[1] == 201:

                if 1 != 1:
                    chang_e()

                
                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updateQuery(updateHitQuery)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": price_range_calc(predPrice),
                        "state": predState.upper()
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200

            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                updateData = updateQuery(updateHitQuery)
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400




    elif vehicleCategory == '2W':

        carMake = getCarmake(args.make)
        carModel = getCarmodel(args.model)
        carVariant = getCarvariant(args.variant)
        carFuel = getCarfuel(args.fuel)
        state = args.regno[:2]
        carSegment = getCarSegment(args.seller_segment)


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        STATE_MAPPED = getState(state)
        STATE_MAPPED = STATE_MAPPED.upper()
        
        # if STATE_MAPPED == 'MAHARASHTRA':
        #     STATE_MAPPED = 'MAHARASTRA'

        METERREADING = args.METERREADING
        MAKE_YEAR = args.mfgyear
        
        SELLER_SEGMENT = carSegment[1].upper()
        # SELLER_SEGMENT = "RETAIL"

        if SELLER_SEGMENT == "BANKS & NBFC":
            SELLER_SEGMENT = "BANK&NBFC"

        # elif SEGMENT == "LEASING":
        #     SELLER_SEGMENT = "RETAIL"

        # elif SEGMENT == "ALL":
        #     SELLER_SEGMENT = "RETAIL"


        print(MAKE_YEAR,Make_Clean,Model_Clean,Variant_Clean,Fuel_Clean,STATE_MAPPED,SELLER_SEGMENT.replace(' ',''),METERREADING)


        try:
            X = pd.DataFrame(columns=['MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','STATE_MAPPED','SELLER_SEGMENT','METERREADING'],data=np.array([MAKE_YEAR,Make_Clean.replace(' ',''),Model_Clean.replace(' ',''),Variant_Clean.replace(' ',''),Fuel_Clean,STATE_MAPPED.replace(' ',''),SELLER_SEGMENT.replace(' ',''),METERREADING]).reshape(1,8))
            
            predPrice = two_w_cs.predict(X)[0]
            predPrice = int(predPrice)



            MAKEYEAR = MAKE_YEAR
            CLEANEDMake = Make_Clean
            CLEANEDModel = Model_Clean
            CLEANEDVariant = Variant_Clean
            CLEANEDfueltype = Fuel_Clean
            SOLDAMOUNT = predPrice
            SELLER_SEGMENT = 'RETAIL'
            METERREADING = METERREADING
            Segment = '2W'
            
            
            
            try:
                X1 = pd.DataFrame(columns=['MAKEYEAR', 'CLEANEDMake', 'CLEANEDModel', 'CLEANEDVariant','CLEANEDfueltype', 'SOLDAMOUNT', 'SELLER_SEGMENT', 'METERREADING','Segment'],data=np.array([MAKEYEAR, CLEANEDMake, CLEANEDModel, CLEANEDVariant,CLEANEDfueltype, SOLDAMOUNT, SELLER_SEGMENT, METERREADING,Segment]).reshape(1,9))
                state_num = state_model.predict(X1)[0]
                # print(state_num)
                
                predState = state_to_category(state_num)
                print(predState)
            except:
                predState = "DELHI"


            
            newHitCount = totalHitAvailable -1
            saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,STATE_MAPPED,args.regno,args.mfgyear,args.seller_segment,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)

            if saveData[1] == 201:

                if 1 != 1:
                    chang_e()

                
                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updateQuery(updateHitQuery)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": price_range_calc(predPrice),
                        "state": predState.upper()
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200

            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                updateData = updateQuery(updateHitQuery)
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,STATE_MAPPED,args.regno,args.mfgyear,args.seller_segment,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400




    elif vehicleCategory == '3W':

        carMake = getCarmake(args.make)
        carModel = getCarmodel(args.model)
        carVariant = getCarvariant(args.variant)
        carFuel = getCarfuel(args.fuel)
        state = args.regno[:2]
        carSegment = getCarSegment(args.seller_segment)


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        STATE_MAPPED = getState(state)
        State_Clean = STATE_MAPPED.upper()

        SELLERSEGMENT = carSegment[1].upper()

        if SELLERSEGMENT == "BANKS & NBFC":
            SELLERSEGMENT = "BANK&NBFC"

        METERREADING = args.METERREADING
        MAKE_YEAR = args.mfgyear


        print(MAKE_YEAR,Make_Clean,Model_Clean,Variant_Clean,Fuel_Clean,State_Clean,'RETAIL',METERREADING)
        

        try:
            X = pd.DataFrame(columns=['MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','State_Clean','SELLERSEGMENT','METERREADING'],data=np.array([MAKE_YEAR,Make_Clean.replace(' ',''),Model_Clean.replace(' ',''),Variant_Clean.replace(' ',''),Fuel_Clean,State_Clean.replace(' ',''),SELLERSEGMENT.strip().replace(' ',''),METERREADING]).reshape(1,8))
            
            predPrice = three_w_cs.predict(X)[0]
            predPrice = int(predPrice)


            MAKEYEAR = MAKE_YEAR
            CLEANEDMake = Make_Clean
            CLEANEDModel = Model_Clean
            CLEANEDVariant = Variant_Clean
            CLEANEDfueltype = Fuel_Clean
            SOLDAMOUNT = predPrice
            SELLER_SEGMENT = 'RETAIL'
            METERREADING = METERREADING
            Segment = '3W'
            
            
            
            try:
                X1 = pd.DataFrame(columns=['MAKEYEAR', 'CLEANEDMake', 'CLEANEDModel', 'CLEANEDVariant','CLEANEDfueltype', 'SOLDAMOUNT', 'SELLER_SEGMENT', 'METERREADING','Segment'],data=np.array([MAKEYEAR, CLEANEDMake, CLEANEDModel, CLEANEDVariant,CLEANEDfueltype, SOLDAMOUNT, SELLER_SEGMENT, METERREADING,Segment]).reshape(1,9))
                state_num = state_model.predict(X1)[0]
                # print(state_num)
                
                predState = state_to_category(state_num)
                print(predState)
            
            except:
                predState = "DELHI"


            
            newHitCount = totalHitAvailable -1
            saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,State_Clean,args.regno,args.mfgyear,args.seller_segment,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)
            if saveData[1] == 201:

                if 1 != 1:
                    chang_e()

                
                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updateQuery(updateHitQuery)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": price_range_calc(predPrice),
                        "state": predState.upper()
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200            
            
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                updateData = updateQuery(updateHitQuery)
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        
        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,State_Clean,args.regno,args.mfgyear,args.seller_segment,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400



    elif vehicleCategory == 'FE':

        carMake = getCarmake(args.make)
        carModel = getCarmodel(args.model)
        carVariant = getCarvariant(args.variant)
        carFuel = getCarfuel(args.fuel)
        state = args.regno[:2]
        carSegment = getCarSegment(args.seller_segment)


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        STATE_MAPPED = getState(state)
        STATE_MAPPED = STATE_MAPPED.upper()
        METERREADING = args.METERREADING
        MAKE_YEAR = args.mfgyear

        SELLER_SEGMENT = carSegment[1].upper()
        # SELLER_SEGMENT = "RETAIL"

        if SELLER_SEGMENT == "BANKS & NBFC":
            SELLER_SEGMENT = "BANK&NBFC"

        # elif SEGMENT == "LEASING":
        #     SELLER_SEGMENT = "RETAIL"

        # elif SEGMENT == "ALL":
        #     SELLER_SEGMENT = "RETAIL"


        
        print(MAKE_YEAR,Make_Clean,Model_Clean,Variant_Clean,Fuel_Clean,STATE_MAPPED,SELLER_SEGMENT.replace(' ',''),METERREADING)


        try:
            X = (pd.DataFrame(columns=['MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','STATE_MAPPED','SELLER_SEGMENT','METERREADING'],data=np.array([MAKE_YEAR,Make_Clean.replace(' ',''),Model_Clean.replace(' ',''),Variant_Clean.replace(' ',''),Fuel_Clean,STATE_MAPPED.replace(' ',''),SELLER_SEGMENT.replace(' ',''),METERREADING]).reshape(1,8)))
            predPrice = fe_cs.predict(X)[0]
            predPrice = int(predPrice)


            MAKEYEAR = MAKE_YEAR
            CLEANEDMake = Make_Clean
            CLEANEDModel = Model_Clean
            CLEANEDVariant = Variant_Clean
            CLEANEDfueltype = Fuel_Clean
            SOLDAMOUNT = predPrice
            SELLER_SEGMENT = 'RETAIL'
            METERREADING = METERREADING
            Segment = 'FE'
            
                    
            try:
                X1 = pd.DataFrame(columns=['MAKEYEAR', 'CLEANEDMake', 'CLEANEDModel', 'CLEANEDVariant','CLEANEDfueltype', 'SOLDAMOUNT', 'SELLER_SEGMENT', 'METERREADING','Segment'],data=np.array([MAKEYEAR, CLEANEDMake, CLEANEDModel, CLEANEDVariant,CLEANEDfueltype, SOLDAMOUNT, SELLER_SEGMENT, METERREADING,Segment]).reshape(1,9))
                state_num = state_model.predict(X1)[0]
                        
                predState = state_to_category(state_num)
                print(predState)
            except:
                predState = 'DELHI'



            
            newHitCount = totalHitAvailable -1
            saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,STATE_MAPPED,args.regno,args.mfgyear,args.seller_segment,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)
            if saveData[1] == 201:

                if 1 != 1:
                    chang_e()

                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updateQuery(updateHitQuery)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": price_range_calc(predPrice),
                        "state": predState.upper()
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200            
            
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                updateData = updateQuery(updateHitQuery)
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400


        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv2(args.make,args.model,args.variant,args.fuel,STATE_MAPPED,args.regno,args.mfgyear,args.seller_segment,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400




    else:
        return jsonify({"status": 400, "message":"Wrong vehicle category type","data": None}), 400





@REQUEST_API.route('/predictedpriceuat', methods=['POST'])
@token_required
def predicted_price_uat(data):
    start = time.process_time()
    if data[4] == 0:
        return jsonify({"status": 401,'message' : 'User unathorised to used API'}), 401
    fetchQuery = 'Select clientId, activeSubscription, totalHitCount, hitCountAvailable from TBL_SUBSCRIPTION_COUNT_MASTER where clientId="'+data[0]+'"'
    fetchData = singleQuery(fetchQuery)
    if not fetchData:
        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
    totalHitCount = fetchData[2]
    totalHitAvailable = int(fetchData[3])
    if totalHitAvailable < 1:
        return jsonify({"status": 401,'message' : 'You have exhausted your API hit. Kindly recharge or topup hit'}), 401
    
    userData = request.headers.get('User-Agent')
    parser = reqparse.RequestParser(bundle_errors=True)
    parser.add_argument('vtype', type=str, required=True, help = "Please Enter vehicle type")
    parser.add_argument('make', type=str, required=True, help = "Please Enter vehicle make")
    parser.add_argument('model', type=str, required=True,help="Please Enter vehicle model")
    parser.add_argument('variant', type=str,required=True, help="Please Enter vehicle variant")
    parser.add_argument('fuel', type=str,required=True, help="Please Enter vehicle fuel")
    parser.add_argument('regno', type=str, required=True,help="Please Enter vehicle number")
    parser.add_argument('mfgyear', type=str,required=True, help="Please Enter vehicle manufacturing year")
    parser.add_argument('METERREADING',required=True, type=str, help="Please Enter vehicle manufacturing year")
    parser.add_argument('clientId', type=str, help="Please Enter client id")
    parser.add_argument('clientType', type=str, help="Please Enter client type id")
    parser.add_argument('userId', type=str, help="Please Enter user id")
    args = parser.parse_args()

    if args.clientId:
        client_query = 'Select clientId from TBL_CLIENTMASTER where clientId="'+args.clientId+'"'
        fetchClientData = singleQuery_uat(client_query)
        
        if not fetchClientData:
            return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401

    if args.userId:
        user_query = 'Select empCode from TBL_USER_DETAILS where empCode="'+args.userId+'"'
        fetchUserData = singleQuery_uat(user_query)
        
        if not fetchUserData:
            return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401


    if not args.vtype:
        return jsonify({"status": 406,"return": "Vehicle type not be empty", "data": None}), 406
    if not args.make:
        return jsonify({"status": 406,"return": "Vehicle Make not be empty", "data": None}), 406
    if not args.model:
        return jsonify({"status": 406,"return": "Vehicle Model not be empty", "data": None}), 406
    if not args.variant:
        return jsonify({"status": 406,"return": "Vehicle Variant not be empty", "data": None}), 406
    if not args.fuel:
        return jsonify({"status": 406,"return": "Vehicle Fuel not be empty", "data": None}), 406
    if not args.regno:
        return jsonify({"status": 406,"return": "Vehicle Registrtion Number not be empty", "data": None}), 406
    if not args.mfgyear:
        return jsonify({"status": 406,"return": "Vehicle Year not be empty", "data": None}), 406
    if not args.METERREADING:
        return jsonify({"status": 406,"return": "Meter Reading not be empty", "data": None}), 406
    if not args.clientId:
        return jsonify({"status": 406,"return": "Client Id not be empty", "data": None}), 406
    if not args.clientType:
        return jsonify({"status": 406,"return": "Client Type not be empty", "data": None}), 406
    
    # r = re.compile('^[A-Z]{2}[ -]?[0-9]{2}[ -]?[A-Z]{1,2}[ -]?[0-9]{4}$')
    # if not r.match(args.regno):
    #     return jsonify({"status": 406,"return": "Registration number is not valid", "data": None}), 406

    if not args.clientType in ["1","2"]:
        return jsonify({"status": 406,"return": "Client type is not valid", "data": None}), 406

    if not args.make.isdigit():
        return jsonify({"status": 406,"return": "Make is not valid ", "data": None}), 406
    if not args.model.isdigit():
        return jsonify({"status": 406,"return": "Model is not valid ", "data": None}), 406
    if not args.variant.isdigit():
        return jsonify({"status": 406,"return": "Variant is not valid ", "data": None}), 406
    if not args.fuel.isdigit():
        return jsonify({"status": 406,"return": "Fuel is not valid ", "data": None}), 406


    vehicleCategory = args.vtype.upper()
    
    segmentId = ''
    predState = ''    


    if vehicleCategory == '4W':

        carMake = getCarmake_uat(args.make)
        carModel = getCarmodel_uat(args.model)
        carVariant = getCarvariant_uat(args.variant)
        carFuel = getCarfuel_uat(args.fuel)
        state = args.regno[:2]

        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        CV_State_Clean = getState_uat(state)
        CV_State_Clean = CV_State_Clean.upper()
        METERREADING = args.METERREADING
        MAKE_YEAR = args.mfgyear

    #     # Ensure year is within the valid range (2005-2024)

    # if args.mfgyear.isdigit() and 2005 <= int(args.mfgyear) <= 2024:

    #     MAKE_YEAR = int(args.mfgyear)
    # else:
        
    #     MAKE_YEAR = 'Select Year'  # Default placeholder if invalid year


        print(MAKE_YEAR,Make_Clean.replace(' ',''),Model_Clean.replace(' ',''),Variant_Clean.replace(' ',''),Fuel_Clean,CV_State_Clean.replace(' ',''),METERREADING)
    

        try:
            try:
                X = pd.DataFrame(columns=['MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','CV_State_Clean','METERREADING'],data=np.array([MAKE_YEAR,Make_Clean.strip().replace(' ', ''),Model_Clean.strip().replace(' ', ''),Variant_Clean.strip().replace(' ', ''),Fuel_Clean,CV_State_Clean.strip().replace(' ', ''),METERREADING]).reshape(1,7))
                predPrice = fourw_ncs_test.predict(X)[0]
                predPrice = int(predPrice)
                # print(predPrice)
            except Exception as e:
                print(e)


            newHitCount = totalHitAvailable -1
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,MAKE_YEAR,segmentId,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)
            
            if saveData[1] == 201:

                if 1 != 1:
                    chang_e()
                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    clientId = args.clientId
                    delId = 0
                    params = [newHitCount,clientId,delId]
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable=%s where clientId=%s and delId=%s'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updatePQuery(updateHitQuery,params)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401                    
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": predPrice,
                        "state": predState
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200            


            else:
                request_time = "%.2gs" % (time.process_time() - start)
                clientId = args.clientId
                delId = 0
                params = [newHitCount,clientId,delId]
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable=%s where clientId=%s and delId=%s'
                updateData = updatePQuery(updateHitQuery,params)                
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        
        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,MAKE_YEAR,segmentId,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)            
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400



    elif vehicleCategory == '2W':

        carMake = getCarmake_uat(args.make)
        carModel = getCarmodel_uat(args.model)
        carVariant = getCarvariant_uat(args.variant)
        carFuel = getCarfuel_uat(args.fuel)
        state = args.regno[:2]


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        
        State_Clean = getState_uat(state)
        State_Clean = State_Clean.upper()

        METERREADING = args.METERREADING
        MAKEYEAR = args.mfgyear

        print(Make_Clean,Model_Clean,Variant_Clean,State_Clean,MAKEYEAR)
        

        try:    
            try:
                X = pd.DataFrame(columns=['MAKEYEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','State_Clean','METERREADING'],data=np.array([MAKEYEAR,Make_Clean.strip().replace(' ',''),Model_Clean.strip().replace(' ',''),Variant_Clean.strip().replace(' ',''),Fuel_Clean,State_Clean.strip().replace(' ',''),METERREADING]).reshape(1,7))
                predPrice = two_w_ncs_test.predict(X)[0]
                predPrice = int(predPrice)
                print(predPrice)
            except Exception as e:
                print(e)


            newHitCount = totalHitAvailable -1
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,State_Clean,args.regno,MAKEYEAR,segmentId,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)

            if saveData[1] == 201:

                if 1 != 1:
                    chang_e()

                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    delId = 0
                    params = [newHitCount,args.clientId,delId]
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable=%s where clientId=%s and delId=%s'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updatePQuery(updateHitQuery,params)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": predPrice,
                        "state": predState
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200            

            else:
                request_time = "%.2gs" % (time.process_time() - start)
                delId = 0
                params = [newHitCount,args.clientId,delId]
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable=%s where clientId=%s and delId=%s'
                updateData = updatePQuery(updateHitQuery,params)                
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400


        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,State_Clean,args.regno,MAKEYEAR,segmentId,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400
        
        


    
    elif vehicleCategory == '3W':
        carMake = getCarmake_uat(args.make)
        carModel = getCarmodel_uat(args.model)
        carVariant = getCarvariant_uat(args.variant)
        carFuel = getCarfuel_uat(args.fuel)
        state = args.regno[:2]


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        
        State_Clean = getState_uat(state)
        State_Clean = State_Clean.upper()

        METERREADING = args.METERREADING
        MAKE_YEAR = args.mfgyear

        print(Make_Clean,Model_Clean,Variant_Clean,State_Clean,MAKE_YEAR)
        

        try:
            try:
                X = pd.DataFrame(columns=['MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','State_Clean','METERREADING'],data=np.array([MAKE_YEAR,Make_Clean.strip().replace(' ', ''),Model_Clean.strip().replace(' ', ''),Variant_Clean.strip().replace(' ', ''),Fuel_Clean,State_Clean.strip().replace(' ', ''),METERREADING]).reshape(1,7))
                predPrice = three_w_ncs_test.predict(X)[0]
                predPrice = int(predPrice)
                print(predPrice)
            except Exception as e:
                print(e)


            
            newHitCount = totalHitAvailable -1           
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,State_Clean,args.regno,MAKE_YEAR,segmentId,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)
            

            if saveData[1] == 201:

                if 1 != 1:
                    chang_e()

                
                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    delId = 0
                    params = [newHitCount,args.clientId,delId]
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable=%s where clientId=%s and delId=%s'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updatePQuery(updateHitQuery,params)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": predPrice,
                        "state": predState
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200            

            else:
                request_time = "%.2gs" % (time.process_time() - start)
                delId = 0
                params = [newHitCount,args.clientId,delId]
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                updateData = updatePQuery(updateHitQuery,params)                
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,State_Clean,args.regno,MAKE_YEAR,segmentId,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400



    elif vehicleCategory == 'CE':

        carMake = getCarmake_uat(args.make)
        carModel = getCarmodel_uat(args.model)
        carVariant = getCarvariant_uat(args.variant)
        carFuel = getCarfuel_uat(args.fuel)
        state = args.regno[:2]


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        # Fuel_Clean = carFuel[1].upper()
        CV_State_Clean = getState_uat(state)
        CV_State_Clean = CV_State_Clean.upper()
        METERREADING = args.METERREADING
        MAKE_YEAR = args.mfgyear

        Fuel_Clean = 'DIESEL'

        if Fuel_Clean == 'null':
            Fuel_Clean = 'DIESEL'


        print(Make_Clean,Model_Clean,Variant_Clean,CV_State_Clean,MAKE_YEAR)


        try:
            try:
                X = pd.DataFrame(columns=['MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','CV_State_Clean','METERREADING'],data=np.array([MAKE_YEAR,Make_Clean.strip().replace(' ', ''),Model_Clean.strip().replace(' ', ''),Variant_Clean.strip().replace(' ', ''),Fuel_Clean,CV_State_Clean.strip().replace(' ', ''),METERREADING]).reshape(1,7))
                predPrice = ce_ncs_test.predict(X)[0]
                predPrice = int(predPrice)
                print(predPrice)
            except Exception as e:
                print(e)


            
            newHitCount = totalHitAvailable -1        
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,MAKE_YEAR,segmentId,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)
            

            if saveData[1] == 201:

                if 1 != 1:
                    chang_e()


                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    delId = 0
                    params = [newHitCount,args.clientId,delId]
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable=%s where clientId=%s and delId=%s'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updatePQuery(updateHitQuery,params)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": predPrice,
                        "state": predState.upper()
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200            

            else:
                request_time = "%.2gs" % (time.process_time() - start)
                delId = 0
                params = [newHitCount,args.clientId,delId]
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable=%s where clientId=%s and delId=%s'
                updateData = updatePQuery(updateHitQuery,params)                
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,MAKE_YEAR,segmentId,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400


    elif vehicleCategory == 'CV':

        carMake = getCarmake_uat(args.make)
        carModel = getCarmodel_uat(args.model)
        carVariant = getCarvariant_uat(args.variant)
        carFuel = getCarfuel_uat(args.fuel)
        state = args.regno[:2]


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        CV_State_Clean = getState_uat(state)
        CV_State_Clean = CV_State_Clean.upper()        

        # if CV_State_Clean == 'CHHATTISGARH':
        #     CV_State_Clean = 'CHATTISGARH'

        # else:
        #     CV_State_Clean = CV_State_Clean


        Meter_Reading = args.METERREADING
        MAKEYEAR = args.mfgyear

        print(Make_Clean,Model_Clean,Variant_Clean,CV_State_Clean,MAKEYEAR,Meter_Reading)
             
        
        try:
            try:
                X = pd.DataFrame(columns=['MAKEYEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','CV_State_Clean','Meter_Reading'],data=np.array([MAKEYEAR,Make_Clean.strip().replace(' ', ''),Model_Clean.strip().replace(' ', ''),Variant_Clean.strip().replace(' ', ''),Fuel_Clean,CV_State_Clean.strip().replace(' ', ''),Meter_Reading]).reshape(1,7))
                predPrice = cv_ncs_test.predict(X)[0]
                predPrice = int(predPrice)
                print(predPrice)
            except Exception as e:
                print(e)


            
            newHitCount = totalHitAvailable -1
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,MAKEYEAR,segmentId,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)

            if saveData[1] == 201:


                if 1 != 1:
                    chang_e()


                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    delId = 0
                    params = [newHitCount,args.clientId,delId]
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable=%s where clientId=%s and delId=%s'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updatePQuery(updateHitQuery,params)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": predPrice,
                        "state": predState.upper()
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200            

            else:
                request_time = "%.2gs" % (time.process_time() - start)
                delId = 0
                params = [newHitCount,args.clientId,delId]
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable=%s where clientId=%s and delId=%s'
                updateData = updatePQuery(updateHitQuery,params)                
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,MAKEYEAR,segmentId,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400



    elif vehicleCategory == 'FE':

        carMake = getCarmake_uat(args.make)
        carModel = getCarmodel_uat(args.model)
        carVariant = getCarvariant_uat(args.variant)
        carFuel = getCarfuel_uat(args.fuel)
        state = args.regno[:2]


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        CV_State_Clean = getState_uat(state)
        CV_State_Clean = CV_State_Clean.upper()
        METERREADING = args.METERREADING
        MAKE_YEAR = args.mfgyear

        print(Make_Clean,Model_Clean,Variant_Clean,CV_State_Clean,MAKE_YEAR)
        
        try:    
            try:
                X = pd.DataFrame(columns=['MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','CV_State_Clean','METERREADING'],data=np.array([MAKE_YEAR,Make_Clean.replace(' ',''),Model_Clean.strip().replace(' ', ''),Variant_Clean.strip().replace(' ', ''),Fuel_Clean,CV_State_Clean.strip().replace(' ', ''),METERREADING]).reshape(1,7))
                predPrice = fe_ncs_test.predict(X)[0]
                predPrice = int(predPrice)
                print(predPrice)
            except Exception as e:
                print(e)

            newHitCount = totalHitAvailable -1
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,MAKE_YEAR,segmentId,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)



            if saveData[1] == 201:

                if 1 != 1:
                    chang_e()

                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    delId = 0
                    params = [newHitCount,args.clientId,delId]
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable=%s where clientId=%s and delId=%s'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updatePQuery(updateHitQuery,params)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": predPrice,
                        "state": predState
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200            

            else:
                request_time = "%.2gs" % (time.process_time() - start)
                delId = 0
                params = [newHitCount,args.clientId,delId]
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable=%s where clientId=%s and delId=%s'
                updateData = updatePQuery(updateHitQuery,params)                
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        
        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,MAKE_YEAR,segmentId,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        
        else:
            return jsonify({"status": 400, "message":"Wrong vehicle category type","data": None}), 400


@REQUEST_API.route('/predictedsegpriceuat', methods=['POST'])
@token_required
def predicted_segprice_uat(data):
    start = time.process_time()
    if data[4] == 0:
        return jsonify({"status": 401,'message' : 'User unathorised to used API'}), 401
    fetchQuery = 'Select clientId, activeSubscription, totalHitCount, hitCountAvailable from TBL_SUBSCRIPTION_COUNT_MASTER where clientId="'+data[0]+'"'
    fetchData = singleQuery(fetchQuery)
    if not fetchData:
        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
    totalHitCount = fetchData[2]
    totalHitAvailable = int(fetchData[3])
    if totalHitAvailable < 1:
        return jsonify({"status": 401,'message' : 'You have exhausted you API hit. Kindly recharge or topup hit'}), 401

    userData = request.headers.get('User-Agent')
    parser = reqparse.RequestParser(bundle_errors=True)
    parser.add_argument('vtype', type=str, required=True, help = "Please Enter vehicle type")
    parser.add_argument('make', type=str, required=True, help = "Please Enter vehicle make")
    parser.add_argument('model', type=str, help="Please Enter vehicle model")
    parser.add_argument('variant', type=str, help="Please Enter vehicle variant")
    parser.add_argument('fuel', type=str, help="Please Enter vehicle fuel")
    parser.add_argument('regno', type=str, help="Please Enter vehicle number")
    parser.add_argument('mfgyear', type=str, help="Please Enter vehicle manufacturing year")
    parser.add_argument('seller_segment', type=str, help="Please Enter segment")
    parser.add_argument('METERREADING', type=str, help="Please Enter segment")
    parser.add_argument('clientId', type=str, help="Please Enter client id")
    parser.add_argument('clientType', type=str, help="Please Enter client type id")
    parser.add_argument('userId', type=str, help="Please Enter user id")
    args = parser.parse_args()
    # print(args)


    if not args.vtype:
        return jsonify({"status": 406,"return": "Vehicle type not be empty", "data": None}), 406
    if not args.make:
        return jsonify({"status": 406,"return": "Vehicle Make not be empty", "data": None}), 406
    if not args.model:
        return jsonify({"status": 406,"return": "Vehicle Model not be empty", "data": None}), 406
    if not args.variant:
        return jsonify({"status": 406,"return": "Vehicle Variant not be empty", "data": None}), 406
    if not args.fuel:
        return jsonify({"status": 406,"return": "Vehicle Fuel not be empty", "data": None}), 406
    if not args.regno:
        return jsonify({"status": 406,"return": "Vehicle Registrtion Number not be empty", "data": None}), 406
    if not args.mfgyear:
        return jsonify({"status": 406,"return": "Vehicle Year not be empty", "data": None}), 406
    if not args.seller_segment:
        return jsonify({"status": 406,"return": "Segment not be empty", "data": None}), 406
    if not args.METERREADING:
        return jsonify({"status": 406,"return": "Meter Reading not be empty", "data": None}), 406    
    if not args.clientId:
        return jsonify({"status": 406,"return": "Client Id not be empty", "data": None}), 406
    if not args.clientType:
        return jsonify({"status": 406,"return": "Client Type not be empty", "data": None}), 406

    vehicleCategory = args.vtype.upper()

    if vehicleCategory == '4W':

        carMake = getCarmake_uat(args.make)
        carModel = getCarmodel_uat(args.model)
        carVariant = getCarvariant_uat(args.variant)
        carFuel = getCarfuel_uat(args.fuel)
        state = args.regno[:2]
        carSegment = getCarSegment_uat(args.seller_segment)


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        CV_State_Clean = getState_uat(state)
        CV_State_Clean = CV_State_Clean.upper()
        METERREADING = args.METERREADING
        MAKE_YEAR = args.mfgyear
        SELLER_SEGMENT = carSegment[1].upper()
        # SELLER_SEGMENT = "RETAIL"

        if SELLER_SEGMENT == "BANKS & NBFC":
            SELLER_SEGMENT = "BANK&NBFC"

        # elif SEGMENT == "LEASING":
        #     SELLER_SEGMENT = "RETAIL"

        # elif SEGMENT == "ALL":
        #     SELLER_SEGMENT = "RETAIL"


        print(MAKE_YEAR,Make_Clean.replace(' ',''),Model_Clean.replace(' ',''),Variant_Clean.replace(' ',''),Fuel_Clean,CV_State_Clean,SELLER_SEGMENT.replace(' ',''),METERREADING)

        try:
            try:
                X = pd.DataFrame(columns=['MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','CV_State_Clean','METERREADING','SELLER_SEGMENT'],data=np.array([MAKE_YEAR,Make_Clean.strip().replace(' ', ''),Model_Clean.strip().replace(' ', ''),Variant_Clean.strip().replace(' ', ''),Fuel_Clean,CV_State_Clean.strip().replace(' ', ''),METERREADING,SELLER_SEGMENT.strip().replace(' ', '')]).reshape(1,8))
                predPrice = fourw_cs_test.predict(X)[0]
                predPrice = int(predPrice)
            except Exception as e:
                print(e)
            

            MAKEYEAR = MAKE_YEAR
            CLEANEDMake = Make_Clean
            CLEANEDModel = Model_Clean
            CLEANEDVariant = Variant_Clean
            CLEANEDfueltype = Fuel_Clean
            SOLDAMOUNT = predPrice
            SELLER_SEGMENT = 'RETAIL'
            METERREADING = METERREADING
            Segment = '4W'
            
            
            
            try:
                X1 = pd.DataFrame(columns=['MAKEYEAR', 'CLEANEDMake', 'CLEANEDModel', 'CLEANEDVariant','CLEANEDfueltype', 'SOLDAMOUNT', 'SELLER_SEGMENT', 'METERREADING','Segment'],data=np.array([MAKEYEAR, CLEANEDMake, CLEANEDModel, CLEANEDVariant,CLEANEDfueltype, SOLDAMOUNT, SELLER_SEGMENT, METERREADING,Segment]).reshape(1,9))
                state_num = state_model.predict(X1)[0]
                # print(state_num)
                
                predState = state_to_category(state_num)
                print(predState)
            
            except:
                predState = "DELHI"



            
            newHitCount = totalHitAvailable -1
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)
            if saveData[1] == 201:


                if 1 != 1:
                    chang_e()

                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updateQuery(updateHitQuery)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": predPrice,
                        "state": predState.upper()
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200

            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                updateData = updateQuery(updateHitQuery)
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400


        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'

            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                print({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]})
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200

            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

    
        
    elif vehicleCategory == 'CV':
        
        carMake = getCarmake_uat(args.make)
        carModel = getCarmodel_uat(args.model)
        carVariant = getCarvariant_uat(args.variant)
        carFuel = getCarfuel_uat(args.fuel)
        state = args.regno[:2]
        carSegment = getCarSegment_uat(args.seller_segment)


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        CV_State_Clean = getState_uat(state)
        CV_State_Clean = CV_State_Clean.upper()
        Meter_Reading = args.METERREADING
        MAKEYEAR = args.mfgyear
        SELLER_SEGMENT = carSegment[1].upper()
        # SELLER_SEGMENT = "RETAIL"

        if SELLER_SEGMENT == "BANKS & NBFC":
            SELLER_SEGMENT = "BANK&NBFC"

        # elif SEGMENT == "LEASING":
        #     SELLER_SEGMENT = "RETAIL"

        # elif SEGMENT == "ALL":
        #     SELLER_SEGMENT = "RETAIL"



        print(MAKEYEAR,Make_Clean,Model_Clean,Variant_Clean,Fuel_Clean,CV_State_Clean,SELLER_SEGMENT.replace(' ',''),Meter_Reading)

        try:
            try:
                X = pd.DataFrame(columns=['MAKEYEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','CV_State_Clean','SELLER_SEGMENT','Meter_Reading'],data=np.array([MAKEYEAR,Make_Clean.strip().replace(' ', ''),Model_Clean.strip().replace(' ', ''),Variant_Clean.strip().replace(' ', ''),Fuel_Clean,CV_State_Clean.strip().replace(' ', ''),SELLER_SEGMENT.strip().replace(' ', ''),Meter_Reading]).reshape(1,8))
                predPrice = cv_cs_test.predict(X)[0]
                predPrice = int(predPrice)
            except Exception as e:
                print(e)




            MAKEYEAR = MAKEYEAR
            CLEANEDMake = Make_Clean
            CLEANEDModel = Model_Clean
            CLEANEDVariant = Variant_Clean
            CLEANEDfueltype = Fuel_Clean
            SOLDAMOUNT = predPrice
            SELLER_SEGMENT = 'RETAIL'
            METERREADING = Meter_Reading
            Segment = 'CV'
            
            
            
            try:
                X1 = pd.DataFrame(columns=['MAKEYEAR', 'CLEANEDMake', 'CLEANEDModel', 'CLEANEDVariant','CLEANEDfueltype', 'SOLDAMOUNT', 'SELLER_SEGMENT', 'METERREADING','Segment'],data=np.array([MAKEYEAR, CLEANEDMake, CLEANEDModel, CLEANEDVariant,CLEANEDfueltype, SOLDAMOUNT, SELLER_SEGMENT, METERREADING,Segment]).reshape(1,9))
                state_num = state_model.predict(X1)[0]
                # print(state_num)
                
                predState = state_to_category(state_num)
                print(predState)
            except:
                predState = "DELHI"

            
            newHitCount = totalHitAvailable -1
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)
            if saveData[1] == 201:


                if 1 != 1:
                    chang_e()


                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updateQuery(updateHitQuery)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": predPrice,
                        "state": predState.upper()
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200

            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                updateData = updateQuery(updateHitQuery)
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400




    elif vehicleCategory == 'CE':
        
        carMake = getCarmake_uat(args.make)
        carModel = getCarmodel_uat(args.model)
        carVariant = getCarvariant_uat(args.variant)
        carFuel = getCarfuel_uat(args.fuel)
        state = args.regno[:2]
        carSegment = getCarSegment_uat(args.seller_segment)


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        # Fuel_Clean = carFuel[1].upper()
        CV_State_Clean = getState_uat(state)
        CV_State_Clean = CV_State_Clean.upper()
        METERREADING = args.METERREADING
        MAKE_YEAR = args.mfgyear

        Fuel_Clean = 'DIESEL'

        if Fuel_Clean == 'null':
            Fuel_Clean = 'DIESEL'
        
        SELLER_SEGMENT = carSegment[1].upper()
        # SELLER_SEGMENT = "RETAIL"

        if SELLER_SEGMENT == "BANKS & NBFC":
            SELLER_SEGMENT = "BANK&NBFC"

        # elif SEGMENT == "LEASING":
        #     SELLER_SEGMENT = "RETAIL"

        # elif SEGMENT == "ALL":
        #     SELLER_SEGMENT = "RETAIL"


        print(MAKE_YEAR,Make_Clean,Model_Clean,Variant_Clean,Fuel_Clean,CV_State_Clean,SELLER_SEGMENT.replace(' ',''),METERREADING)


        try:
            try:
                X = pd.DataFrame(columns=['MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','CV_State_Clean','METERREADING','SELLER_SEGMENT'],data=np.array([MAKE_YEAR,Make_Clean.strip().replace(' ', ''),Model_Clean.strip().replace(' ', ''),Variant_Clean.strip().replace(' ', ''),Fuel_Clean,CV_State_Clean.strip().replace(' ', ''),METERREADING,SELLER_SEGMENT.strip().replace(' ', '')]).reshape(1,8))
                predPrice = ce_cs_test.predict(X)[0]
                predPrice = int(predPrice)
            except Exception as e:
                print(e)


            MAKEYEAR = MAKE_YEAR
            CLEANEDMake = Make_Clean
            CLEANEDModel = Model_Clean
            CLEANEDVariant = Variant_Clean
            CLEANEDfueltype = Fuel_Clean
            SOLDAMOUNT = predPrice
            SELLER_SEGMENT = 'RETAIL'
            METERREADING = METERREADING
            Segment = 'CE'
            
            
            
            try:
                X1 = pd.DataFrame(columns=['MAKEYEAR', 'CLEANEDMake', 'CLEANEDModel', 'CLEANEDVariant','CLEANEDfueltype', 'SOLDAMOUNT', 'SELLER_SEGMENT', 'METERREADING','Segment'],data=np.array([MAKEYEAR, CLEANEDMake, CLEANEDModel, CLEANEDVariant,'DIESEL', SOLDAMOUNT, SELLER_SEGMENT, METERREADING,Segment]).reshape(1,9))
                state_num = state_model.predict(X1)[0]
                # print(state_num)
                
                predState = state_to_category(state_num)
                print(predState)
            except:
                predState = "DELHI"


            
            newHitCount = totalHitAvailable -1
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)
            if saveData[1] == 201:


                if 1 != 1:
                    chang_e()


                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updateQuery(updateHitQuery)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": predPrice,
                        "state": predState.upper()
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200

            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                updateData = updateQuery(updateHitQuery)
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400




    elif vehicleCategory == '2W':

        carMake = getCarmake_uat(args.make)
        carModel = getCarmodel_uat(args.model)
        carVariant = getCarvariant_uat(args.variant)
        carFuel = getCarfuel_uat(args.fuel)
        state = args.regno[:2]
        carSegment = getCarSegment_uat(args.seller_segment)


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        State_Clean = getState_uat(state)
        State_Clean = State_Clean.upper()
        METERREADING = args.METERREADING
        MAKEYEAR = args.mfgyear
        
        Customer_Segmentation = carSegment[1].upper()
        # Customer_Segmentation = "RETAIL"

        if Customer_Segmentation == "BANKS & NBFC":
            Customer_Segmentation = "BANK&NBFC"

        # elif SEGMENT == "LEASING":
        #     Customer_Segmentation = "RETAIL"

        # elif SEGMENT == "ALL":
        #     Customer_Segmentation = "RETAIL"


        print(MAKEYEAR,Make_Clean,Model_Clean,Variant_Clean,Fuel_Clean,State_Clean,Customer_Segmentation.replace(' ',''),METERREADING)


        try:
            try:
                X = pd.DataFrame(columns=['MAKEYEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','State_Clean','Customer_Segmentation','METERREADING'],data=np.array([MAKEYEAR,Make_Clean.strip().replace(' ',''),Model_Clean.strip().replace(' ',''),Variant_Clean.strip().replace(' ',''),Fuel_Clean,State_Clean.strip().replace(' ',''),Customer_Segmentation,METERREADING]).reshape(1,8))
                predPrice = two_w_cs_test.predict(X)[0]
                predPrice = int(predPrice)
            
            except Exception as e:
                print(e)



            MAKEYEAR = MAKEYEAR
            CLEANEDMake = Make_Clean
            CLEANEDModel = Model_Clean
            CLEANEDVariant = Variant_Clean
            CLEANEDfueltype = Fuel_Clean
            SOLDAMOUNT = predPrice
            SELLER_SEGMENT = 'RETAIL'
            METERREADING = METERREADING
            Segment = '2W'
            
            
            
            try:
                X1 = pd.DataFrame(columns=['MAKEYEAR', 'CLEANEDMake', 'CLEANEDModel', 'CLEANEDVariant','CLEANEDfueltype', 'SOLDAMOUNT', 'SELLER_SEGMENT', 'METERREADING','Segment'],data=np.array([MAKEYEAR, CLEANEDMake, CLEANEDModel, CLEANEDVariant,CLEANEDfueltype, SOLDAMOUNT, SELLER_SEGMENT, METERREADING,Segment]).reshape(1,9))
                state_num = state_model.predict(X1)[0]
                # print(state_num)
                
                predState = state_to_category(state_num)
                print(predState)
            except:
                predState = "DELHI"


            
            newHitCount = totalHitAvailable -1
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,State_Clean,args.regno,args.mfgyear,args.seller_segment,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)

            if saveData[1] == 201:

                if 1 != 1:
                    chang_e()


                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updateQuery(updateHitQuery)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": predPrice,
                        "state": predState.upper()
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200

            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                updateData = updateQuery(updateHitQuery)
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,State_Clean,args.regno,args.mfgyear,args.seller_segment,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400




    elif vehicleCategory == '3W':

        carMake = getCarmake_uat(args.make)
        carModel = getCarmodel_uat(args.model)
        carVariant = getCarvariant_uat(args.variant)
        carFuel = getCarfuel_uat(args.fuel)
        state = args.regno[:2]
        carSegment = getCarSegment_uat(args.seller_segment)


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        STATE_MAPPED = getState_uat(state)
        State_Clean = STATE_MAPPED.upper()
        SELLERSEGMENT = carSegment[1].upper()

        if SELLERSEGMENT == "BANKS & NBFC":
            SELLERSEGMENT = "BANK&NBFC"        

        METERREADING = args.METERREADING
        MAKE_YEAR = args.mfgyear


        print(MAKE_YEAR,Make_Clean,Model_Clean,Variant_Clean,Fuel_Clean,State_Clean,'RETAIL',METERREADING)
        

        try:
            try:
                X = pd.DataFrame(columns=['MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','State_Clean','METERREADING','SELLERSEGMENT'],data=np.array([MAKE_YEAR,Make_Clean.strip().replace(' ', ''),Model_Clean.strip().replace(' ', ''),Variant_Clean.strip().replace(' ', ''),Fuel_Clean,State_Clean.strip().replace(' ', ''),METERREADING,SELLERSEGMENT.strip().replace(' ', '')]).reshape(1,8))
                predPrice = three_w_cs_test.predict(X)[0]
                predPrice = int(predPrice)
            except Exception as e:
                print(e)


            MAKEYEAR = MAKE_YEAR
            CLEANEDMake = Make_Clean
            CLEANEDModel = Model_Clean
            CLEANEDVariant = Variant_Clean
            CLEANEDfueltype = Fuel_Clean
            SOLDAMOUNT = predPrice
            SELLER_SEGMENT = 'RETAIL'
            METERREADING = METERREADING
            Segment = '3W'
            
            
            
            try:
                X1 = pd.DataFrame(columns=['MAKEYEAR', 'CLEANEDMake', 'CLEANEDModel', 'CLEANEDVariant','CLEANEDfueltype', 'SOLDAMOUNT', 'SELLER_SEGMENT', 'METERREADING','Segment'],data=np.array([MAKEYEAR, CLEANEDMake, CLEANEDModel, CLEANEDVariant,CLEANEDfueltype, SOLDAMOUNT, SELLER_SEGMENT, METERREADING,Segment]).reshape(1,9))
                state_num = state_model.predict(X1)[0]
                # print(state_num)
                
                predState = state_to_category(state_num)
                print(predState)
            
            except:
                predState = "DELHI"


            
            newHitCount = totalHitAvailable -1
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,State_Clean,args.regno,args.mfgyear,args.seller_segment,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)
            if saveData[1] == 201:

                if 1 != 1:
                    chang_e()


                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updateQuery(updateHitQuery)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": predPrice,
                        "state": predState.upper()
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200            
            
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                updateData = updateQuery(updateHitQuery)
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        
        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,State_Clean,args.regno,args.mfgyear,args.seller_segment,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400



    elif vehicleCategory == 'FE':

        carMake = getCarmake_uat(args.make)
        carModel = getCarmodel_uat(args.model)
        carVariant = getCarvariant_uat(args.variant)
        carFuel = getCarfuel_uat(args.fuel)
        state = args.regno[:2]
        carSegment = getCarSegment_uat(args.seller_segment)


        Make_Clean = carMake[1].upper()
        Model_Clean = carModel[1].upper()
        Variant_Clean = carVariant[1].upper()
        Fuel_Clean = carFuel[1].upper()
        CV_State_Clean = getState_uat(state)
        CV_State_Clean = CV_State_Clean.upper()
        METERREADING = args.METERREADING
        MAKE_YEAR = args.mfgyear

        SELLER_SEGMENT = carSegment[1].upper()
        # SELLER_SEGMENT = "RETAIL"

        if SELLER_SEGMENT == "BANKS & NBFC":
            SELLER_SEGMENT = "BANK&NBFC"

        # elif SEGMENT == "LEASING":
        #     SELLER_SEGMENT = "RETAIL"

        # elif SEGMENT == "ALL":
        #     SELLER_SEGMENT = "RETAIL"


        
        print(MAKE_YEAR,Make_Clean,Model_Clean,Variant_Clean,Fuel_Clean,CV_State_Clean,SELLER_SEGMENT.replace(' ',''),METERREADING)


        try:
            try:
                X = (pd.DataFrame(columns=['MAKE_YEAR','Make_Clean','Model_Clean','Variant_Clean','Fuel_Clean','CV_State_Clean','METERREADING','SELLER_SEGMENT'],data=np.array([MAKE_YEAR,Make_Clean.strip().replace(' ',''),Model_Clean.strip().replace(' ',''),Variant_Clean.strip().replace(' ',''),Fuel_Clean,CV_State_Clean.strip().replace(' ',''),METERREADING,SELLER_SEGMENT.strip().replace(' ','')]).reshape(1,8)))
                predPrice = fe_cs_test.predict(X)[0]
                predPrice = int(predPrice)
            except Exception as e:
                print(e)

            MAKEYEAR = MAKE_YEAR
            CLEANEDMake = Make_Clean
            CLEANEDModel = Model_Clean
            CLEANEDVariant = Variant_Clean
            CLEANEDfueltype = Fuel_Clean
            SOLDAMOUNT = predPrice
            SELLER_SEGMENT = 'RETAIL'
            METERREADING = METERREADING
            Segment = 'FE'
            
                    
            try:
                X1 = pd.DataFrame(columns=['MAKEYEAR', 'CLEANEDMake', 'CLEANEDModel', 'CLEANEDVariant','CLEANEDfueltype', 'SOLDAMOUNT', 'SELLER_SEGMENT', 'METERREADING','Segment'],data=np.array([MAKEYEAR, CLEANEDMake, CLEANEDModel, CLEANEDVariant,CLEANEDfueltype, SOLDAMOUNT, SELLER_SEGMENT, METERREADING,Segment]).reshape(1,9))
                state_num = state_model.predict(X1)[0]
                        
                predState = state_to_category(state_num)
                print(predState)
            except:
                predState = 'DELHI'



            
            newHitCount = totalHitAvailable -1
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,predPrice,predState,args.clientId,args.clientType,args.userId,args.METERREADING)
            if saveData[1] == 201:

                if 1 != 1:
                    chang_e()


                else:
                    request_time = "%.2gs" % (time.process_time() - start)
                    updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                    fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
                    updateData = updateQuery(updateHitQuery)
                    if not updateData:
                        return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                    fetchData = singleQuery(fetchQuery)
                    data = {
                        "price": predPrice,
                        "state": predState.upper()
                    }
                    saveApiHit(args.clientId, request_time,200)
                    data_json = json.dumps(data, default=lambda x: x.tolist())
                    return jsonify({"status":200, "message":"Price predicted successfully","data": json.loads(data_json),"hitid":fetchData[0]}), 200            
            
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                updateHitQuery = 'UPDATE TBL_SUBSCRIPTION_COUNT_MASTER SET hitCountAvailable="'+str(newHitCount)+'" where clientId="'+str(args.clientId)+'" and delId=0'
                updateData = updateQuery(updateHitQuery)
                if not updateData:
                    return jsonify({"status": 401,'message' : 'Some Error occured. Kindly contact Administrator for help'}), 401
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400

        except:
            result = ''
            rstate = ''
            saveData = savePredictOutputv3(args.make,args.model,args.variant,args.fuel,CV_State_Clean,args.regno,args.mfgyear,args.seller_segment,result,rstate,args.clientId,args.clientType,args.userId,args.METERREADING)
            fetchQuery = 'Select max(id) as hitId from TBL_PREDICTION_OUTPUT'
            if saveData[1] == 201:
                fetchData = singleQuery(fetchQuery)
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,200)
                return jsonify({"status":200, "message":"No Data Found","data": None,"hitid":fetchData[0]}), 200
            else:
                request_time = "%.2gs" % (time.process_time() - start)
                saveApiHit(args.clientId, request_time,400)
                return jsonify({"status": 400, "message":"Some error occured while saving data","data": None}), 400




    else:
        return jsonify({"status": 400, "message":"Wrong vehicle category type","data": None}), 400




@REQUEST_API.route('/getdatacount', methods=['POST'])
@token_required
def get_datacount(data):
    start = time.process_time()
    if data[4] == 0:
        return jsonify({"status": 401,'message' : 'User unathorised to used API'}), 401

    df_m = pd.read_csv(cols_file4)
    df_buyer=df_m.copy()
    df_1 =df_buyer.dropna(how='any',axis=0,subset=['Fuel_Clean','Variant_Clean'])
    df_2 = df_1.copy()
    df_2['Cust_Code'] = df_2['Cust_Code'].str.upper()
    df_2['NAME'] = df_2['NAME'].str.upper()
    df_2['LOC_STATE'] = df_2['LOC_STATE'].str.upper()
    df_2['Make_Clean'] = df_2['Make_Clean'].str.upper()
    df_2['Model_Clean'] = df_2['Model_Clean'].str.upper()
    df_2['Variant_Clean'] = df_2['Variant_Clean'].str.upper()
    df_2['Fuel_Clean'] = df_2['Fuel_Clean'].str.upper()
    df_2['CC_N']  = df_2['Cust_Code']+'_'+df_2['NAME']
    print(df_1)
    userData = request.headers.get('User-Agent')
    parser = reqparse.RequestParser(bundle_errors=True)
    parser.add_argument('make', type=str, required=True, help = "Please Enter make")
    parser.add_argument('model', type=str, help="Please Enter model")
    parser.add_argument('variant', type=str, help="Please Enter variant")
    parser.add_argument('fuel', type=str, help="Please Enter fuel")
    parser.add_argument('state', type=str, help="Please Enter fuel")
    args = parser.parse_args()
    # print(args.make)
    if not args.state:
        return jsonify({"status": 406,"message": "Car state not be empty", "data": None}), 406

    State = args.state.upper()
    Make = args.make.upper()
    Model = args.model.upper()
    Variant = args.variant.upper()
    Fuel = args.fuel.upper()

    if(State !='' and Make =='' and Model == '' and Variant == '' and Fuel == ''):
        df_temp_state = df_2[df_2.LOC_STATE==State]
        alpha_state=dict(df_temp_state.CC_N.value_counts())
        beta_state=dict(df_temp_state.CC_N.value_counts())
        buyer_state_count = pd.DataFrame(beta_state.items())
        df_buyer_state = pd.DataFrame(alpha_state.items())
        dfResult = df_buyer_state.empty
        if dfResult == True:
            request_time = "%.2gs" % (time.process_time() - start)
            saveApiHit(data[0], request_time,200)
            return jsonify({"status":200, "message":"Data Not Found","data": None}), 200

        buyer_details_cust_id_state=df_buyer_state[0].str.split('_',expand=True)[0]
        buyer_details_name_state=df_buyer_state[0].str.split('_',expand=True)[1]
        dispaly_users_details_state=pd.DataFrame(columns=['Name','Customer_id','Count'])
        dispaly_users_details_state['Name']=buyer_details_name_state
        dispaly_users_details_state['Customer_id'] = buyer_details_cust_id_state
        dispaly_users_details_state['Count'] = buyer_state_count[1]
        dispaly_users_details_state= dispaly_users_details_state.reset_index()
        fData = dispaly_users_details_state.to_dict('records')
        request_time = "%.2gs" % (time.process_time() - start)
        saveApiHit(data[0], request_time,200)
        return jsonify({"status":200, "message":"Data feetched successfully","data": fData}), 200
    elif(State !='' and Make !='' and Model == '' and Variant == '' and Fuel == ''):
        df_temp_state = df_2[df_2.LOC_STATE==State]
        df_temp_make=df_temp_state[df_temp_state.Make_Clean==Make]
        alpha=dict(df_temp_make.CC_N.value_counts())
        beta=dict(df_temp_make.CC_N.value_counts())
        buyer_make_count = pd.DataFrame(beta.items())
        df_buyer_make = pd.DataFrame(alpha.items())
        dfResult = df_buyer_make.empty
        if dfResult == True:
            request_time = "%.2gs" % (time.process_time() - start)
            saveApiHit(data[0], request_time,200)
            return jsonify({"status":200, "message":"Data Not Found","data": None}), 200

        buyer_details_cust_id=df_buyer_make[0].str.split('_',expand=True)[0]
        buyer_details_name=df_buyer_make[0].str.split('_',expand=True)[1]
        dispaly_users_details=pd.DataFrame(columns=['Name','Customer_id','Count'])
        dispaly_users_details['Name']=buyer_details_name
        dispaly_users_details['Customer_id'] = buyer_details_cust_id
        dispaly_users_details['Count'] = buyer_make_count[1]
        dispaly_users_details.index = index_reset(dispaly_users_details)
        fData = dispaly_users_details.to_dict('records')
        request_time = "%.2gs" % (time.process_time() - start)
        saveApiHit(data[0], request_time,200)
        return jsonify({"status":200, "message":"Data feetched successfully","data": fData}), 200
    elif(State !='' and Make !='' and Model != '' and Variant == '' and Fuel == ''):
        df_temp_state = df_2[df_2.LOC_STATE==State]
        df_temp_make=df_temp_state[df_temp_state.Make_Clean==Make]
        df_temp_model=df_temp_make[df_temp_make.Model_Clean==Model]
        alpha_model=dict(df_temp_model.CC_N.value_counts())
        beta_model=dict(df_temp_model.CC_N.value_counts())
        buyer_model_count = pd.DataFrame(beta_model.items())
        df_buyer_model = pd.DataFrame(alpha_model.items())
        dfResult = df_buyer_model.empty
        if dfResult == True:
            request_time = "%.2gs" % (time.process_time() - start)
            saveApiHit(data[0], request_time,200)
            return jsonify({"status":200, "message":"Data Not Found","data": None}), 200
        buyer_details_cust_id_model=df_buyer_model[0].str.split('_',expand=True)[0]
        buyer_details_name_model=df_buyer_model[0].str.split('_',expand=True)[1]
        dispaly_users_details_model=pd.DataFrame(columns=['Name','Customer_id','Count'])
        dispaly_users_details_model['Name']=buyer_details_name_model
        dispaly_users_details_model['Customer_id'] = buyer_details_cust_id_model
        dispaly_users_details_model['Count'] = buyer_model_count[1]
        dispaly_users_details_model.index = index_reset(dispaly_users_details_model)
        fData = dispaly_users_details_model.to_dict('records')
        request_time = "%.2gs" % (time.process_time() - start)
        saveApiHit(data[0], request_time,200)
        return jsonify({"status":200, "message":"Data feetched successfully","data": fData}), 200
    elif(State !='' and Make !='' and Model != '' and Variant != '' and Fuel == ''):
        df_temp_state = df_2[df_2.LOC_STATE==State]
        df_temp_make=df_temp_state[df_temp_state.Make_Clean==Make]
        df_temp_model=df_temp_make[df_temp_make.Model_Clean==Model]
        df_temp_variant=df_temp_model[df_temp_model.Variant_Clean==Variant]
        alpha_variant=dict(df_temp_variant.CC_N.value_counts())
        beta_variant=dict(df_temp_variant.CC_N.value_counts())
        buyer_variant_count = pd.DataFrame(beta_variant.items())
        df_buyer_variant = pd.DataFrame(alpha_variant.items())
        dfResult = df_buyer_variant.empty
        if dfResult == True:
            request_time = "%.2gs" % (time.process_time() - start)
            saveApiHit(data[0], request_time,200)
            return jsonify({"status":200, "message":"Data Not Found","data": None}), 200

        buyer_details_cust_id_variant=df_buyer_variant[0].str.split('_',expand=True)[0]
        buyer_details_name_variant=df_buyer_variant[0].str.split('_',expand=True)[1]
        dispaly_users_details_variant=pd.DataFrame(columns=['Name','Customer_id','Count'])
        dispaly_users_details_variant['Name']=buyer_details_name_variant
        dispaly_users_details_variant['Customer_id'] = buyer_details_cust_id_variant
        dispaly_users_details_variant['Count'] = buyer_variant_count[1]
        dispaly_users_details_variant.index = index_reset(dispaly_users_details_variant)
        fData = dispaly_users_details_variant.to_dict('records')
        request_time = "%.2gs" % (time.process_time() - start)
        saveApiHit(data[0], request_time,200)
        return jsonify({"status":200, "message":"Data feetched successfully","data": fData}), 200
    elif(State !='' and Make !='' and Model != '' and Variant != '' and Fuel != ''):
        df_temp_state = df_2[df_2.LOC_STATE==State]
        df_temp_make=df_temp_state[df_temp_state.Make_Clean==Make]
        df_temp_model=df_temp_make[df_temp_make.Model_Clean==Model]
        df_temp_variant=df_temp_model[df_temp_model.Variant_Clean==Variant]
        df_temp_fuel=df_temp_variant[df_temp_variant.Fuel_Clean==Fuel]
        alpha_fuel=dict(df_temp_fuel.CC_N.value_counts())
        beta_fuel=dict(df_temp_fuel.CC_N.value_counts())
        buyer_fuel_count = pd.DataFrame(beta_fuel.items())
        df_buyer_fuel = pd.DataFrame(alpha_fuel.items())
        dfResult = df_buyer_fuel.empty
        if dfResult == True:
            request_time = "%.2gs" % (time.process_time() - start)
            saveApiHit(data[0], request_time,200)
            return jsonify({"status":200, "message":"Data Not Found","data": None}), 200

        buyer_details_cust_id_fuel=df_buyer_fuel[0].str.split('_',expand=True)[0]
        buyer_details_name_fuel=df_buyer_fuel[0].str.split('_',expand=True)[1]
        dispaly_users_details_fuel=pd.DataFrame(columns=['Name','Customer_id','Count'])
        dispaly_users_details_fuel['Name']=buyer_details_name_fuel
        dispaly_users_details_fuel['Customer_id'] = buyer_details_cust_id_fuel
        dispaly_users_details_fuel['Count'] = buyer_fuel_count[1]
        dispaly_users_details_fuel.index = index_reset(dispaly_users_details_fuel)
        fData = dispaly_users_details_fuel.to_dict('records')
        request_time = "%.2gs" % (time.process_time() - start)
        saveApiHit(data[0], request_time,200)
        return jsonify({"status":200, "message":"Data feetched successfully","data": fData}), 200


@REQUEST_API.route('/getvehicletype', methods=['GET'])
@token_required
@lru_cache(maxsize = 128)
def get_vehicletype(data):
    start = time.process_time()
    if data[4] == 0:
        return jsonify({"status": 401,'message' : 'User unathorised to used API'}), 401

    userData = request.headers.get('User-Agent')
    makeQuery="Select id, vehicleCategory from TBL_VEHICLE_CATEGORY where delId=0"
    makeData = fetchAllQuery(makeQuery)
    carData = []
    if len(makeData) > 0:
        for items in makeData:
            id = items[0]
            vehicleCategory = items[1]
            dataC = {
                "id": id,
                "vehicleCategory": vehicleCategory
            }
            carData.append(dataC)
        request_time = "%.2gs" % (time.process_time() - start)
        saveApiHit(data[0], request_time,200)
        return jsonify({"status":200, "message":"Data fetched successfully","data": carData}), 200
    else:
        request_time = "%.2gs" % (time.process_time() - start)
        saveApiHit(data[0], request_time,400)
        return jsonify({"status": 400, "message":"Some error getting data","data": None}), 400



@REQUEST_API.route('/getvehiclemake', methods=['POST'])
@token_required
def get_carmake(data):
    start = time.process_time()
    if data[4] == 0:
        return jsonify({"status": 401,'message' : 'User unathorised to used API'}), 401

    userData = request.headers.get('User-Agent')
    parser = reqparse.RequestParser(bundle_errors=True)
    parser.add_argument('vcategory', type=str, required=True, help = 'Please Enter vehicle category')
    args = parser.parse_args()
    vehicleCategory = args.vcategory
    print(vehicleCategory)
    delId=0
    params = [delId,vehicleCategory]
    makeQuery = """SELECT id, carMake from TBL_CAR_MAKE WHERE delId=%s and category=%s order by carMake asc"""
    # makeQuery="Select id, carMake from TBL_CAR_MAKE where delId=0 and category='"+str(vehicleCategory)+"' order by carMake asc"
    print(makeQuery)
    makeData = fetchAllPQuery(makeQuery,params)
    carData = []
    if len(makeData) > 0:
        for items in makeData:
            id = items[0]
            carmake = items[1]
            dataC = {
                "id": id,
                "make": carmake
            }
            carData.append(dataC)
        request_time = "%.2gs" % (time.process_time() - start)
        saveApiHit(data[0], request_time,200)
        return jsonify({"status":200, "message":"Data fetched successfully","data": carData}), 200
    else:
        request_time = "%.2gs" % (time.process_time() - start)
        saveApiHit(data[0], request_time,400)
        return jsonify({"status": 400, "message":"Some error getting data","data": None}), 400
    



@REQUEST_API.route('/topvehiclemake', methods=['POST'])
@token_required
def get_topcarmake(data):
    start = time.process_time()
    if data[4] == 0:
        return jsonify({"status": 401,'message' : 'User unathorised to used API'}), 401

    userData = request.headers.get('User-Agent')
    # parser = reqparse.RequestParser(bundle_errors=True)
    # parser.add_argument('vcategory', type=str, required=True, help = 'Please Enter vehicle category')
    # args = parser.parse_args()
    vehicleCategory = request.form['vcategory']
    delId = 0
    params = [vehicleCategory,delId]
    makeQuery= """select b.id, upper(b.carMake) as carMake from TBL_PREDICTION_OUTPUT a left join TBL_CAR_MAKE b on a.make = b.id where a.prePrice != '' AND b.category = %s and b.delId= %s group by  b.carMake order by b.carMake asc"""
    makeData = fetchAllPQuery(makeQuery,params)
    carData = []
    if len(makeData) > 0:
        for items in makeData:
            id = items[0]
            carmake = items[1]
            dataC = {
                "id": id,
                "make": carmake
            }
            carData.append(dataC)
        request_time = "%.2gs" % (time.process_time() - start)
        saveApiHit(data[0], request_time,200)
        return jsonify({"status":200, "message":"Data fetched successfully","data": carData}), 200
    else:
        request_time = "%.2gs" % (time.process_time() - start)
        saveApiHit(data[0], request_time,400)
        return jsonify({"status": 400, "message":"Some error getting data","data": None}), 400

@REQUEST_API.route('/getvehiclemodel', methods=['POST'])
@token_required
def get_carmodel(data):
    start = time.process_time()
    if data[4] == 0:
        return jsonify({"status": 401,'message' : 'User unathorised to used API'}), 401

    userData = request.headers.get('User-Agent')
    parser = reqparse.RequestParser(bundle_errors=True)
    parser.add_argument('makeid', type=int, required=True, help = 'Please Enter vehicle make id')
    args = parser.parse_args()
    if not args.makeid:
        return jsonify({"status": 406, "message": "vehicle make id not be empty", "data": None}), 406

    carMakeId = args.makeid
    delId = 0
    params =  [delId,carMakeId]
    modelQuery="""Select id, carModel from TBL_CAR_MODEL where delId=%s and carMakeId=%s order by carModel asc"""
    modelData = fetchAllPQuery(modelQuery,params)
    carData = []
    if len(modelData) > 0:
        for items in modelData:
            id = items[0]
            carmodel = items[1]
            datac = {
                "id": id,
                "model": carmodel
            }
            carData.append(datac)

        request_time = "%.2gs" % (time.process_time() - start)
        saveApiHit(data[0], request_time,200)
        return jsonify({"status":200, "message":"Data fetched successfully","data": carData}), 200
    else:
        request_time = "%.2gs" % (time.process_time() - start)
        saveApiHit(data[0], request_time,400)
        return jsonify({"status": 400, "message":"Some error getting data","data": None}), 400


@REQUEST_API.route('/gettopvehiclemodel', methods=['POST'])
@token_required
def get_topcarmodel(data):
    start = time.process_time()
    if data[4] == 0:
        return jsonify({"status": 401,'message' : 'User unathorised to used API'}), 401

    userData = request.headers.get('User-Agent')
    # parser = reqparse.RequestParser()
    # parser.add_argument('makeid', type=int, required=True, help = 'Please Enter vehicle make id')
    # args = parser.parse_args()
    # print(args)
    # if not args.makeid:
    #     return jsonify({"status": 406, "message": "vehicle make id not be empty", "data": None}), 406

    carMakeId = request.form['makeid']
    delId = 0
    params =  [carMakeId,delId]
    modelQuery="select c.id, upper(c.carModel) as carModel from TBL_PREDICTION_OUTPUT a join TBL_CAR_MAKE b on a.make = b.id join TBL_CAR_MODEL c on a.model = c.id where a.prePrice != '' AND c.carMakeId = %s and c.delId= %s group by  c.carModel order by c.carModel asc"
    modelData = fetchAllPQuery(modelQuery,params)
    carData = []
    if len(modelData) > 0:
        for items in modelData:
            id = items[0]
            carmodel = items[1]
            datac = {
                "id": id,
                "model": carmodel
            }
            carData.append(datac)

        request_time = "%.2gs" % (time.process_time() - start)
        saveApiHit(data[0], request_time,200)
        return jsonify({"status":200, "message":"Data fetched successfully","data": carData}), 200
    else:
        request_time = "%.2gs" % (time.process_time() - start)
        saveApiHit(data[0], request_time,400)
        return jsonify({"status": 400, "message":"Some error getting data","data": None}), 400

@REQUEST_API.route('/getvehicleyear', methods=['POST'])
@token_required
def get_modelyear(data):
    start = time.process_time()
    if data[4] == 0:
        return jsonify({"status": 401,'message' : 'User unathorised to used API'}), 401

    userData = request.headers.get('User-Agent')
    parser = reqparse.RequestParser(bundle_errors=True)
    parser.add_argument('modelid', type=int, required=True, help = 'Please Enter vehicle make id')
    parser.add_argument('vcategory', type=str, required=True, help = 'Please Enter vehicle category type')
    args = parser.parse_args()
    if not args.modelid:
        return jsonify({"status": 406, "message": "vehicle make id not be empty", "data": None}), 406
    if not args.vcategory:
        return jsonify({"status": 406, "message": "vehicle category type not be empty", "data": None}), 406

    carModelId = args.modelid
    vehicleCategory = args.vcategory.upper()
    modelQuery=''
    delId = 0
    if vehicleCategory == '4W':
        params = [carModelId,delId]
        modelQuery="""Select distinct(carYear) as carYear from TBL_CAR_VARIANT where modelId=%s and delId=%s order by carYear desc"""
    else:
        params = [delId]
        modelQuery="""Select distinct(veh_year) as carYear from TBL_VEHICLE_MODEL_YEAR where delId=%s"""

    modelData = fetchAllPQuery(modelQuery,params)

    carData = []
    if len(modelData) > 0:
        for items in modelData:
            caryear = items[0]
            datac = {
                "id": caryear,
                "year": caryear
            }
            carData.append(datac)

        request_time = "%.2gs" % (time.process_time() - start)
        saveApiHit(data[0], request_time,200)
        return jsonify({"status":200, "message":"Data fetched successfully","data": carData}), 200
    else:
        request_time = "%.2gs" % (time.process_time() - start)
        saveApiHit(data[0], request_time,400)
        return jsonify({"status": 400, "message":"Some error getting data","data": None}), 400

@REQUEST_API.route('/gettopvehicleyear', methods=['POST'])
@token_required
def get_topmodelyear(data):
    start = time.process_time()
    if data[4] == 0:
        return jsonify({"status": 401,'message' : 'User unathorised to used API'}), 401

    userData = request.headers.get('User-Agent')
    # parser = reqparse.RequestParser(bundle_errors=True)
    # parser.add_argument('modelid', type=int, required=True, help = 'Please Enter vehicle make id')
    # parser.add_argument('vcategory', type=str, required=True, help = 'Please Enter vehicle category type')
    # args = parser.parse_args()
    # if not args.modelid:
    #     return jsonify({"status": 406, "message": "vehicle make id not be empty", "data": None}), 406
    # if not args.vcategory:
    #     return jsonify({"status": 406, "message": "vehicle category type not be empty", "data": None}), 406

    carModelId = request.form['modelid']
    vehicleCategory = request.form['vcategory'].upper()
    modelQuery=''
    delId = 0
    if vehicleCategory == '4W':
        params = [carModelId,delId]
        modelQuery="select d.carYear from TBL_PREDICTION_OUTPUT a left join TBL_CAR_MAKE b on a.make = b.id left join TBL_CAR_MODEL c on a.model = c.id left join TBL_CAR_VARIANT d on a.variant = d.id where a.prePrice != '' and d.modelId = %s and d.delId=%s group by d.carYear order by d.carYear asc"
    else:
        params = [delId]
        modelQuery="Select distinct(veh_year) as carYear from TBL_VEHICLE_MODEL_YEAR where delId=%s"

    
    modelData = fetchAllPQuery(modelQuery,params)
    carData = []
    if len(modelData) > 0:
        for items in modelData:
            caryear = items[0]
            datac = {
                "id": caryear,
                "year": caryear
            }
            carData.append(datac)

        request_time = "%.2gs" % (time.process_time() - start)
        saveApiHit(data[0], request_time,200)
        return jsonify({"status":200, "message":"Data fetched successfully","data": carData}), 200
    else:
        request_time = "%.2gs" % (time.process_time() - start)
        saveApiHit(data[0], request_time,400)
        return jsonify({"status": 400, "message":"Some error getting data","data": None}), 400
    

@REQUEST_API.route('/getvehiclevariant', methods=['POST'])
@token_required
def get_carvariant(data):
    try:
        start = time.process_time()
        if data[4] == 0:
            return jsonify({"status": 401,'message' : 'User unauthorized to use API'}), 401

        userData = request.headers.get('User-Agent')
        parser = reqparse.RequestParser(bundle_errors=True)
        parser.add_argument('modelid', type=int, required=True, help='Please enter the vehicle make id')
        parser.add_argument('caryear', type=str, required=True, help='Please enter the vehicle model year')
        parser.add_argument('vcategory', type=str, required=True, help='Please enter the vehicle category')
        args = parser.parse_args()

        if not args.modelid:
            return jsonify({"status": 406, "message": "Vehicle make id cannot be empty", "data": None}), 406
        if not args.caryear:
            return jsonify({"status": 406, "message": "Vehicle make year cannot be empty", "data": None}), 406
        if not args.vcategory:
            return jsonify({"status": 406, "message": "Vehicle category type cannot be empty", "data": None}), 406

        carModelId = args.modelid
        carYear = args.caryear
        vehicleCategory = args.vcategory.upper()
        delId = 0
        params = [carModelId,carYear,delId]
        if vehicleCategory == '4W':
            modelQuery = "Select id, carVariant from TBL_CAR_VARIANT where modelId=%s and carYear=%s and delId=%s order by carVariant asc"
        else:
            modelQuery = "Select id, carVariant from TBL_CAR_VARIANT where modelId=%s and carYear=%s and delId=%s order by carVariant asc"
  
        modelData = fetchAllPQuery(modelQuery,params)
        carData = []
        if len(modelData) > 0:
            for items in modelData:
                id = items[0]
                carvariant = items[1]
                datac = {
                    "id": id,
                    "variant": carvariant
                }
                carData.append(datac)

            request_time = "%.2gs" % (time.process_time() - start)
            saveApiHit(data[0], request_time, 200)
            return jsonify({"status": 200, "message": "Data fetched successfully...", "data": carData}), 200
        else:
            request_time = "%.2gs" % (time.process_time() - start)
            saveApiHit(data[0], request_time, 400)
            return jsonify({"status": 400, "message": "Some error getting data..", "data": None}), 400

    except Exception as e:
        # Handle the exception and return an error response
        return jsonify({"status": 500, "message": "An error occurred..", "data": None}), 500
    

@REQUEST_API.route('/gettopvehiclevariant', methods=['POST'])
@token_required
def get_topcarvariant(data):
    start = time.process_time()
    if data[4] == 0:
        return jsonify({"status": 401,'message' : 'User unathorised to used API'}), 401

    userData = request.headers.get('User-Agent')
    # parser = reqparse.RequestParser(bundle_errors=True)
    # parser.add_argument('modelid', type=int, required=True, help = 'Please Enter vehicle make id')
    # parser.add_argument('caryear', type=str, required=True, help = 'Please Enter vehicle model year')
    # parser.add_argument('vcategory', type=str, required=True, help = 'Please Enter vehicle category')
    # args = parser.parse_args()
    # if not args.modelid:
    #     return jsonify({"status": 406, "message": "vehicle make id not be empty", "data": None}), 406
    # if not args.caryear:
    #     return jsonify({"status": 406, "message": "vehicle make year not be empty", "data": None}), 406
    # if not args.vcategory:
    #     return jsonify({"status": 406, "message": "vehicle category type not be empty", "data": None}), 406

    carModelId = request.form['modelid']
    carYear = request.form['caryear']
    vehicleCategory = request.form['vcategory'].upper()
    delId = 0
    if vehicleCategory == '4W':
        params = [carModelId,carYear,delId]
        modelQuery="select d.id , upper(d.carVariant) carVariant from TBL_PREDICTION_OUTPUT a left join TBL_CAR_MAKE b on a.make = b.id left join TBL_CAR_MODEL c on a.model = c.id left join TBL_CAR_VARIANT d on a.variant = d.id where a.prePrice != '' and d.modelId = %s and d.carYear =%s and d.delId=%s group by d.carVariant order by carVariant asc"
    else:
        params = [carModelId,delId]
        modelQuery="select d.id , upper(d.carVariant) carVariant from TBL_PREDICTION_OUTPUT a left join TBL_CAR_MAKE b on a.make = b.id left join TBL_CAR_MODEL c on a.model = c.id left join TBL_CAR_VARIANT d on a.variant = d.id where a.prePrice != '' and d.modelId = %s and d.delId=%s group by d.carVariant order by carVariant asc"

    
    modelData = fetchAllPQuery(modelQuery,params)
    carData = []
    if len(modelData) > 0:
        for items in modelData:
            id = items[0]
            carvariant = items[1]
            datac = {
                "id": id,
                "variant": carvariant
            }
            carData.append(datac)

        request_time = "%.2gs" % (time.process_time() - start)
        saveApiHit(data[0], request_time,200)
        return jsonify({"status":200, "message":"Data fetched successfully","data": carData}), 200
    else:
        request_time = "%.2gs" % (time.process_time() - start)
        saveApiHit(data[0], request_time,400)
        return jsonify({"status": 400, "message":"Some error getting data","data": None}), 400

@REQUEST_API.route('/getvehiclefuel', methods=['POST'])
@token_required
def get_carfuel(data):
    start = time.process_time()
    if data[4] == 0:
        return jsonify({"status": 401,'message' : 'User unathorised to used API'}), 401

    userData = request.headers.get('User-Agent')
    parser = reqparse.RequestParser(bundle_errors=True)
    parser.add_argument('variantid', type=int, required=True, help = 'Please Enter vehicle variant id')
    args = parser.parse_args()
    if not args.variantid:
        return jsonify({"status": 406, "message": "vehicle variant id not be empty", "data": None}), 406

    carVariantId = args.variantid
    delId = 0
    params = [carVariantId,delId]
    modelQuery="Select a.fuelId as id,b.carFuel as carFuel from TBL_CAR_VARIANT a left join TBL_CAR_FUEL b on b.id=a.fuelId where a.id=%s and a.delId=%s"
    modelData = fetchAllPQuery(modelQuery,params)
    carData = []
    if len(modelData) > 0:
        for items in modelData:
            id = items[0]
            carfuel = items[1]
            datac = {
                "id": id,
                "fuel": carfuel
            }
            carData.append(datac)

        request_time = "%.2gs" % (time.process_time() - start)
        saveApiHit(data[0], request_time,200)
        return jsonify({"status":200, "message":"Data fetched successfully","data": carData}), 200
    else:
        request_time = "%.2gs" % (time.process_time() - start)
        saveApiHit(data[0], request_time,400)
        return jsonify({"status": 400, "message":"Some error getting data","data": None}), 400

@REQUEST_API.route('/gettopvehiclefuel', methods=['POST'])
@token_required
def get_topcarfuel(data):
    start = time.process_time()
    if data[4] == 0:
        return jsonify({"status": 401,'message' : 'User unathorised to used API'}), 401

    userData = request.headers.get('User-Agent')
    # parser = reqparse.RequestParser(bundle_errors=True)
    # parser.add_argument('variantid', type=int, required=True, help = 'Please Enter vehicle variant id')
    # args = parser.parse_args()
    # if not args.variantid:
    #     return jsonify({"status": 406, "message": "vehicle variant id not be empty", "data": None}), 406

    carVariantId = request.form['variantid']
    delId = 0
    params = [carVariantId,delId]
    modelQuery="select e.id , e.carFuel carFuel from TBL_PREDICTION_OUTPUT a left join TBL_CAR_MAKE b on a.make = b.id left join TBL_CAR_MODEL c on a.model = c.id left join TBL_CAR_VARIANT d on a.variant = d.id left join TBL_CAR_FUEL e on d.fuelId = e.id where a.prePrice != '' and d.id =%s and d.delId=%s group by e.carFuel order by e.carFuel asc";
    modelData = fetchAllPQuery(modelQuery,params)
    carData = []
    if len(modelData) > 0:
        for items in modelData:
            id = items[0]
            carfuel = items[1]
            datac = {
                "id": id,
                "fuel": carfuel
            }
            carData.append(datac)

        request_time = "%.2gs" % (time.process_time() - start)
        saveApiHit(data[0], request_time,200)
        return jsonify({"status":200, "message":"Data fetched successfully","data": carData}), 200
    else:
        request_time = "%.2gs" % (time.process_time() - start)
        saveApiHit(data[0], request_time,400)
        return jsonify({"status": 400, "message":"Some error getting data","data": None}), 400


#Update Prediction review update

import re

@REQUEST_API.route('/updatereview', methods=['POST'])
@token_required
def get_updatereview(data):
    start = time.process_time()

    if data[4] == 0:
        return jsonify({"status": 401, 'message': 'User unathorised to used API'}), 401

    userData = request.headers.get('User-Agent')
    parser = reqparse.RequestParser(bundle_errors=True)
    parser.add_argument('userreview', type=str, required=True, help='Please enter user review')
    parser.add_argument('hitid', type=str, required=True, help='Please enter hit ID')
    parser.add_argument('hitfrom', type=str, required=True, help='Please enter hit from')
    parser.add_argument('expectedprice', type=str, required=True, help='Please enter expected price')

    args = parser.parse_args()

    # Clean and validate inputs
    userReview = args.userreview.strip()
    hitId = args.hitid.strip()
    expectedPrice = args.expectedprice.strip()
    hitFrom = args.hitfrom.strip().upper()

    # Validate `hitid`
    if not hitId:
        return jsonify({"status": 406, "message": "Hit ID cannot be empty", "data": None}), 406

    # Validate `hitfrom`
    if not hitFrom or hitFrom not in ['WEB', 'MOBILE']:
        return jsonify({"status": 400, "message": "Only WEB and MOBILE value is allowed", "data": None}), 400

    # Validate `expectedPrice` (must be numeric)
    if not expectedPrice.isdigit():
        return jsonify({
            "status": 400,
            "message": "Expected price must be a numeric value.",
            "data": None
        }), 400

    # Validate `userReview` (block HTML tags)
    if re.search(r'<.*?>', userReview):
        return jsonify({
            "status": 400,
            "message": "HTML tags are not allowed in user review.",
            "data": None
        }), 400

    # Check if hitId exists and hasn't been reviewed yet
    fetchQuery = f"""
        SELECT id FROM TBL_PREDICTION_OUTPUT 
        WHERE hitId = '{hitId}' 
        AND userFeedback IS NULL 
        AND hitFrom IS NULL
    """
    fetchData = singleQuery(fetchQuery)

    if not fetchData:
        return jsonify({"status": 401, 'message': 'Hit id does not exist or review already updated'}), 401

    # Proceed with update
    updateQueryStr = f"""
        UPDATE TBL_PREDICTION_OUTPUT
        SET userFeedback = '{userReview}',
            hitFrom = '{hitFrom}',
            expectedPrice = '{expectedPrice}'
        WHERE hitId = '{hitId}'
    """

    updateData = updateQuery(updateQueryStr)

    request_time = "%.2gs" % (time.process_time() - start)

    if updateData[1] == 201:
        saveApiHit(data[0], request_time, 201)
        return jsonify({
            "status": 201,
            "message": "Data updated successfully",
            "data": None
        }), 201
    else:
        saveApiHit(data[0], request_time, 400)
        return jsonify({
            "status": 400,
            "message": "Some error occurred while updating data",
            "data": None
        }), 400


# @REQUEST_API.route('/updatereview', methods=['POST'])
# @token_required
# def get_updatereview(data):
#     start = time.process_time()
#     if data[4] == 0:
#         return jsonify({"status": 401,'message' : 'User unathorised to used API'}), 401

#     userData = request.headers.get('User-Agent')
#     parser = reqparse.RequestParser(bundle_errors=True)
#     parser.add_argument('userreview', type=str, required=True, help = 'Please Enter user review')
#     parser.add_argument('hitid', type=str, required=True, help = 'Please Enter hit id')
#     parser.add_argument('hitfrom', type=str, required=True, help = 'Please Enter hit from')
#     parser.add_argument('expectedprice', type=str, required=True, help = 'Please Enter hit from')
#     args = parser.parse_args()
#     if not args.hitid:
#         return jsonify({"status": 406, "message": "Hit Id cannot be empty", "data": None}), 406
#     if not args.hitfrom:
#         return jsonify({"status": 406, "message": "Hit From cannot be empty", "data": None}), 406

#     userReview = args.userreview
#     hitId = args.hitid
#     expectedPrice = args.expectedprice
#     hitFrom = args.hitfrom.upper()
#     fetchQuery = "Select id from TBL_PREDICTION_OUTPUT where hitId='"+ str(hitId) +"' and userFeedback is null and hitFrom is null"
#     fetchData = singleQuery(fetchQuery)
#     if not fetchData:
#         return jsonify({"status": 401,'message' : 'Hit id does not exist or review already updated'}), 401

#     if ((hitFrom == 'WEB') or (hitFrom == 'MOBILE')):
#         query = "UPDATE TBL_PREDICTION_OUTPUT SET userFeedback='"+ userReview +"', hitFrom='"+ hitFrom +"',expectedPrice='"+ expectedPrice +"' where hitId ="+hitId
#         updateData = updateQuery(query)
#         if updateData[1] == 201:
#             request_time = "%.2gs" % (time.process_time() - start)
#             saveApiHit(data[0], request_time,201)
#             return jsonify({"status":201, "message":"Data updated successfully","data": None}), 201
#         else:
#             request_time = "%.2gs" % (time.process_time() - start)
#             saveApiHit(data[0], request_time,400)
#             return jsonify({"status": 400, "message":"Some error occured while updating data","data": None}), 400
#     else:
#         return jsonify({"status": 400, "message":"Only WEB and MOBILE value is allowed","data": None}), 400



@REQUEST_API.route('/getsellersegment', methods=['GET'])
@token_required
def get_sellersegment(data):
    start = time.process_time()
    if data[4] == 0:
        return jsonify({"status": 401,'message' : 'User unathorised to used API'}), 401

    userData = request.headers.get('User-Agent')
    makeQuery="Select id, sellerSegment from TBL_SELLER_SEGMENT_MASTER where delId=0"
    makeData = fetchAllQuery(makeQuery)
    carData = []
    if len(makeData) > 0:
        for items in makeData:
            id = items[0]
            sellerSegment = items[1]
            dataC = {
                "id": id,
                "sellerSegment": sellerSegment
            }
            carData.append(dataC)
        request_time = "%.2gs" % (time.process_time() - start)
        saveApiHit(data[0], request_time,200)
        return jsonify({"status":200, "message":"Data feetched successfully","data": carData}), 200
    else:
        request_time = "%.2gs" % (time.process_time() - start)
        saveApiHit(data[0], request_time,400)
        return jsonify({"status": 400, "message":"Some error getting data","data": None}), 400
    

@REQUEST_API.route('/safe-redirect', methods=['GET'])
@token_required
def safe_redirect(authData):
    target = request.args.get('next')
    if not target or not target.startswith('/'):
        return jsonify({
            "status": 400,
            "message": "Unsafe redirection attempt blocked.",
            "data": None
        }), 400

    return redirect(target)




@REQUEST_API.after_request
def apply_security_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response




        

state_model = pickle.load(open('State_Prediction_Model_2.pkl','rb'))
#state_model = None


four_w_ncs = pickle.load(open('Final_4W_CS_1.pkl','rb'))                    
two_w_ncs = pickle.load(open('regressor_2w_ncs.pkl','rb'))
three_w_ncs=pickle.load(open('FInal_regressor_3w_CS.pkl','rb'))             
ce_ncs=pickle.load(open('FInal_regressor_CE_NCS.pkl','rb'))
cv_ncs=pickle.load(open('cv_ncs.pkl','rb'))
fe_ncs=pickle.load(open('regressor_FE_NCS.pkl','rb'))        




two_w_ncs_test = pickle.load(open('regressor_15may.pkl','rb'))    
two_w_cs_test = pickle.load(open('csregressor_15may.pkl','rb'))
cv_ncs_test = pickle.load(open('CV_JAN_To_May_NCS.pkl','rb'))
cv_cs_test = pickle.load(open('NEW_CV_JAN_To_May_Model_data_final_CV_CS.pkl','rb'))
fourw_ncs_test = pickle.load(open('NEW_4W_JAN_To_May_Model_data_final_4W_NCS.pkl','rb')) 
fourw_cs_test = pickle.load(open('NEW_4W_JAN_To_May_Model_data_final_4W_CS.pkl','rb'))
ce_ncs_test = pickle.load(open('NEW_CE_JAN_To_May_Model_data_final_CE_NCS.pkl','rb'))
ce_cs_test = pickle.load(open('NEW_CE_JAN_To_May_Model_data_final_CE_CS.pkl','rb'))
fe_cs_test = pickle.load(open('NEW_FE_JAN_To_May_Model_data_final_FE_CS.pkl','rb'))
fe_ncs_test = pickle.load(open('NEW_FE_JAN_To_May_Model_data_final_FE_NCS.pkl','rb'))
three_w_ncs_test = pickle.load(open('NEW_3W_JAN_To_May_Model_data_final_3W_NCS.pkl','rb'))
three_w_cs_test = pickle.load(open('NEW_3W_JAN_To_May_Model_data_final_3W_CS.pkl','rb'))

four_w_cs=pickle.load(open('Final_4W_CS_1.pkl','rb'))
cv_cs = pickle.load(open('regressor_CV_CS_1.pkl','rb'))
ce_cs=pickle.load(open('FInal_regressor_CE_CS_1.pkl','rb'))
two_w_cs=pickle.load(open('regressor_2w_cs.pkl','rb'))
three_w_cs=pickle.load(open('FInal_regressor_3w_CS.pkl','rb'))
fe_cs=pickle.load(open('regressor_fe_cs.pkl','rb'))