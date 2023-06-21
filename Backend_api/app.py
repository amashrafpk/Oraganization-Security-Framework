from matplotlib import use
import requests
from flask import Flask, request, jsonify,session
from flask_cors import CORS
from flask import jsonify
from itsdangerous import json
import pymongo
from pymongo import MongoClient
import jwt
from bson.objectid import ObjectId
from sqlalchemy import true
import re
import json
import random
import string

class policy:
    def __init__(self):
        password_policy = {}
    def __set_policy(self,d={"length":16,"special_char":True,"digits":True,"capitalize":True}):
        self.password_policy = d

class password_manager(policy):
    def __init__(self):
        password = ""
        policy.__init__(self)

    def validate(self,password):
        regex=re.compile('[@_!#$%^&*()<>?/\|}{~:]')
        if(not regex.search(password) and self.password_policy.get("special_char")):
            return False
        if(not re.search('\d',password) and self.password_policy.get("digits")):
            return False
        if(len(password) < self.password_policy.get("length")):
            return False
        return True

    def write_password(self,url,user,password):
        db = get_db()
        password_db = db["password"]
        password_db.insert_one({"username":user,"password":password,"url":url})
        print("err")

    def autogen(self):
        source_pool = []
        source_pool.append(string.ascii_letters)
        password_length = self.password_policy.get("length")
        if(self.password_policy.get("special_char")):
            source_pool.append('[@_!#$%^&*()<>?/\|}{~:]')
        if(self.password_policy.get("digits")):
            source_pool.append(string.digits)
        source_pool = "".join(source_pool)
        p = [0]*password_length
        for i in range(password_length):
            p[i]=random.choice(source_pool)
        if(self.password_policy.get("capitalize")):
            p[0]=random.choice(string.ascii_uppercase)
        password="".join(p)
        if(not self.validate(password)):
            self.autogen()
        self.password=password
        print(f"generated password: {password}",flush=True)

    def set_password(self):
        password=input("Enter password to be set:\n")
        while(not self.validate(password)):
            password=input("Password does not match the password policy\nPlease enter a new password:\n")
        self.password=password
        print("password set!")


app = Flask(__name__)
cors = CORS(app, resources={r"*": {"origins": "*"}})
app.config['SECRET_KEY'] = 'leavemealone'

fail={"status":"failed"}
passed={"status":"ok"}


def get_db():
    client = MongoClient(host='test_mongodb',
                         port=27017, 
                         username='root', 
                         password='pass',
                        authSource="admin")
    db = client["OSF"]
    return db

@app.route('/api/password_generator',methods=["POST"])
def generate_password():
    m=password_manager()
    m._policy__set_policy()
    input_json = request.get_json(force=True)
    if(input_json["password"]==''):
        m.autogen()
        pwd = m.password
        m.write_password(input_json["url"],input_json["username"],pwd)
        return passed
    else:
        if(m.validate(input_json["password"])):
            pwd = m.password
            m.write_password(input_json["url"],input_json["username"],pwd)
            return passed
        else:
            return fail
@app.route('/api/logs',methods=["POST"])
def logs():
    input_json = request.get_json(force=True)
    print(input_json)
    with open('network_logs.json', 'a') as json_file:
        json.dump(input_json,json_file)
        json_file.write('\n')
    return passed

@app.route('/api/get_logs',methods=["GET"])
def get_logs():
    f = open('network_logs.json')
    data=f.readlines()
    return {"data":data}

@app.route('/api/verify',methods=["POST"])
def verify_user():
    input_json = request.get_json(force=True)
    session={}
    try:
        session = jwt.decode(input_json['jwt_verify'],key = app.config['SECRET_KEY'], algorithms=['HS256'])
    except:
        print(fail)
    if session:
        print("passed")
        return passed
    else:
        print("failed")
        return fail

@app.route('/api/get_pass')
def hello_world():
    out=[]
    db=get_db()
    s=db.password
    for x in s.find():
        out.append(x)
    print(out)
    return json.dumps({"passwords":out}, default=str)
@app.route('/api/login',methods=["POST"])
def login():
    input_json = request.get_json(force=True)
    data={"email":input_json["email"],"password":input_json["password"]}
    db=get_db()
    user=db.users.find_one(data)
    if user:
        if user['email']==input_json['email'] and user['password']==input_json['password']:
            if(str(user['role']["organisation_id"]) != '-1'):
                user_jwt=jwt.encode({'id': str(user["_id"]),"email":user["email"],"org_id":str(user["role"]["organisation_id"]),"username":user["username"]},app.config['SECRET_KEY'], algorithm='HS256')
                org_details=db.organisation.find_one(user["role"]["organisation_id"])
                print(org_details['org_name'])
                return {"jwt":user_jwt,"org_present":1,"org_name":org_details['org_name']}
            else:
                user_jwt=jwt.encode({'id': str(user["_id"]),"email":user["email"],"username":user["username"]},app.config['SECRET_KEY'], algorithm='HS256')
                return {"jwt":user_jwt}
    else:
        return fail

@app.route('/api/register', methods=["POST"])
def registeruser():
     input_json = request.get_json(force=True)
     user_details={
        "username": input_json["username"],
        "email": input_json["email"],
        "password":input_json["password"],
        "role":{
            "isadmin":0,
            "organisation_id":-1
        }
     }
     print(user_details)
     db=get_db()
     db.users.create_index([('email', pymongo.ASCENDING)], unique=True)
     try:
         db.users.insert_one(user_details)
     except Exception as e:
         print(e)
         return jsonify(fail)
     return jsonify(passed)


@app.route('/api/org_register', methods = ["POST"])
def register_organisation():
    input_json = request.get_json(force = True)
    try:
        session = jwt.decode(input_json["session"],key = app.config['SECRET_KEY'], algorithms=['HS256'])
    except:
        return fail
    user_id = ObjectId(session["id"])
    input_json.pop("session")
    db = get_db()
    organisation = db["organisation"]
    db.organisation.create_index([('org_email', pymongo.ASCENDING)], unique=True)
    try:
        org_id = organisation.insert_one(input_json).inserted_id
        db.users.update_one({'_id':user_id},{'$set':{"role":{"isadmin":1,"organisation_id":org_id}}})

    except Exception as ae:
        print(ae)
        return jsonify(fail)

    users = db.users
    organisations = db.organisation

    for i in organisation.find():
        print(i,flush=True)

    for i in users.find():
        print(i,flush=True)
    return jsonify(passed)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000,debug = True)
