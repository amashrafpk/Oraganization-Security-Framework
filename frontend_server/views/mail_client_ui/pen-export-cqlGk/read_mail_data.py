from pathlib import Path
import json

for p in Path('../../../../mail_client/inbox/').glob('*.json'):
    with open("../../../../mail_client/inbox/"+str(p.name),"r") as file:
        data=json.load(file)
        print(data)

        date = data["Date"]
        sender = data["From"]
        snip = data["Message"]
        


