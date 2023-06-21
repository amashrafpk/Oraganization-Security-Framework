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
        try:
            with open("password.json","r") as ps:
                d=json.load(ps)
        except:
            d={}
        if(not d.get(url)):
            d[url]={user:password}
        else:
            d[url][user]=password

        with open("password.json","w+") as ps:
            json.dump(d,ps)

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
        print(f"generated password: {password}")
        decision=input("Confirm password? Y/N")
        if(decision == "Y" or decision=="y"):
            self.password = password
        else:
            self.autogen()

    def set_password(self):
        password=input("Enter password to be set:\n")
        while(not self.validate(password)):
            password=input("Password does not match the password policy\nPlease enter a new password:\n")
        self.password=password
        print("password set!")


m=password_manager()
m._policy__set_policy()
m.autogen()
pwd = m.password
m.write_password("google.com","sarang",pwd)
m.write_password("google.com","qwerty","password")
m.write_password("instagram.com","user","password123")
