import time
import requests
xxe="""<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY ent SYSTEM "file:///etc/shadow"> ]>
<userInfo>
 <firstName>John</firstName>
 <lastName>&ent;</lastName>
</userInfo>"""
while True:
    r=requests.get('http://0.0.0.0:8008/test?sqli=select*from users')
    print(r.status_code)
    time.sleep(3)
    r=requests.post('http://0.0.0.0:8008/test',data={"email":"sayoojbkumar@gmail.com","password":"' or 1-- -"})
    print(r.status_code)
    time.sleep(3)
    r=requests.get('http://0.0.0.0:8008/test?sqli=<script>alert(1)</script>')
    print(r.status_code)
    time.sleep(3)
    r=requests.post('http://0.0.0.0:8008/test',data={"email":"<script>alert(1)</script>","password":"<img onerror=alert(1)>"})
    print(r.status_code)
    time.sleep(3)
    r=requests.get('http://0.0.0.0:8008/test?test=../etc/passwd')
    print(r.status_code)
    time.sleep(3)
    r=requests.post('http://0.0.0.0:8008/test',data={"email":"../etc/passwd","password":"../etc/passwd"})
    print(r.status_code)
    time.sleep(3)
    r=requests.get('http://0.0.0.0:8008/test?test=ls -a')
    print(r.status_code)
    time.sleep(3)
    r=requests.post('http://0.0.0.0:8008/test',data={"email":"cat /etc/passwd","password":"ls"})
    print(r.status_code)
    time.sleep(3)
    r=requests.get('http://0.0.0.0:8008/test?test=127.0.0.1:80')
    print(r.status_code)
    time.sleep(3)
    r=requests.post('http://0.0.0.0:8008/test',data={"email":"127.0.0.1:80","password":"0.0.0.0:22"})
    print(r.status_code)
    time.sleep(3)
    r=requests.get('http://0.0.0.0:8008/test?test='+xxe)
    print(r.status_code)
    time.sleep(3)
    r=requests.post('http://0.0.0.0:8008/test',data={"email":"127.0.0.1:80","password":xxe})
    print(r.status_code)
    time.sleep(3)

