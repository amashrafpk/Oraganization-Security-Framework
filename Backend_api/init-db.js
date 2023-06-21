db = db.getSiblingDB("OSF");
db.users.drop();

db.users.insertOne(
    {
        "username": "test",
        "email": "test@gmail.com",
        "password":"test",
        "role":{
            "isadmin":"1",
            "organisation_id":125
        }
    }
);
