const express = require('express')
const dotenv = require('dotenv');
bodyParser = require('body-parser')
const axios = require('axios')
const frontend = express()
const path = require('path')
var cookieParser = require('cookie-parser');
const port = 8008
const fs = require('fs');

dotenv.config();

frontend.use(cookieParser());
frontend.use(bodyParser.urlencoded({ extended: true }));
frontend.use(express.static(__dirname + '/public'));
frontend.set('views',path.join(__dirname,"views"))
frontend.set("view engine","hbs")


function verified_user(jwt) {
  data={"jwt_verify":jwt}
  const promise = axios.post(`http://${process.env.HOST}:${process.env.PORT}/api/verify`,data) //use data destructuring to get data from the promise object
  const dataPromise = promise.then((response) => response.data)
  return dataPromise
}
/* for attack testing*/
frontend.post('/test',(req,res) => {
  console.log(req.body.email)
  res.sendStatus(200)
})

frontend.get('/test',(req,res) => {
  res.sendStatus(200)
})

frontend.get('/about',(req,res)=>{
  res.render('about')
})
frontend.get('/service',(req,res)=>{
  res.render('service')
})
frontend.get('/contact',(req,res)=>{
  res.render('contact')
})
frontend.get('/',(req,res)=>{
  res.render('index')
})

frontend.get('/password_manager',(req,res)=>{
  res.render('password')
})

frontend.get('/register', (req, res) => {
  res.render('register');
})

frontend.get('/org_register',(req,res) => {
  verified_user(req.cookies["jwt_session"]).then(data => {
    console.log(data)
    if(data["status"]=="ok"){
      console.log("yes")
      res.render('org_register');
    }
    else{
      console.log("no")
      res.render('session_err');
    }
  }).catch(err => console.log(err))

})

frontend.get('/network',(req,res) => {
  verified_user(req.cookies["jwt_session"]).then(data => {
    console.log(data)
    if(data["status"]=="ok"){
      axios.get(`http://${process.env.HOST}:${process.env.PORT}/api/get_logs`).then(res1 => {
        console.log(res1["data"]["data"][0])
        res.render('networks',{data:res1["data"]["data"]});
      })
    }
    else{
      console.log("no")
      res.render('session_err');
    }
  }).catch(err => console.log(err))

})

frontend.get('/stored_password',(req,res) => {
  verified_user(req.cookies["jwt_session"]).then(data => {
    console.log(data)
    if(data["status"]=="ok"){
      axios.get(`http://${process.env.HOST}:${process.env.PORT}/api/get_pass`).then(res1 => {
        res.render('list_password',{data:res1["data"]["passwords"]});
      })
    }
    else{
      console.log("no")
      res.render('session_err');
    }
  }).catch(err => console.log(err))

})

frontend.get('/compose',(req,res) => {
  res.render('compose');
})
frontend.get('/mail_client',(req,res) => {
    let mail_list = getmails();
    res.render('mail_client',{ mail: mail_list });
})

frontend.get("/spam",(req,res) =>{
    let mail_list = getspams();
    res.render('spam',{ mail : mail_list});
})

let getmails = () => {
    var list = [];
    try {
        const dir = '../mail_client/inbox';
        fs.readdir(dir, (err, files) => {
        if (err) {
            throw err;
        }
        console.log("Inside fn");
        files.forEach(file => {
            const data = fs.readFileSync(dir + '/' + file, 'utf8');

            const databases = JSON.parse(data);
    
            console.log(databases);
            list.push(databases);
            
        });
    }); 
    } catch (err) {
        console.log(`Error reading file from disk: ${err}`);
    }
    return list;
}

let getspams = () => {
    var list = [];
    try {
        const dir = '../mail_client/spam';
        fs.readdir(dir, (err, files) => {
        if (err) {
            throw err;
        }
        console.log("Inside fn");
        files.forEach(file => {
            const data = fs.readFileSync(dir + '/' + file, 'utf8');

            const databases = JSON.parse(data);
    
            console.log(databases);
            list.push(databases);
            
        });
    }); 
    } catch (err) {
        console.log(`Error reading file from disk: ${err}`);
    }
    return list;
}

frontend.post("/login",(req,res)=>{
  var data={
    email: req.body.email,password : req.body.password
  }
  axios.post(`http://${process.env.HOST}:${process.env.PORT}/api/login`,data).then(res1 => {
    console.log(res1.data)
    if(res1.data['jwt']){
      res.cookie('jwt_session',res1.data['jwt'], { maxAge: 900000, httpOnly: true ,sameSite:"lax"});
      if(res1.data['org_present']==1){
        res.render('admin',{name:res1.data['org_name']})
      }
      else{
        res.redirect('/org_register')
      }
    }
    if(res1.data["status"]=='failed'){
      res.render('login_err',{error:"Wrong username or password"})
    }
  })
  .catch(error => {
    console.error(error)
  })

})

frontend.post("/register",(req,res)=>{
  var data={
    email: req.body.email,username: req.body.username,password : req.body.password
  }
  axios.post(`http://${process.env.HOST}:${process.env.PORT}/api/register`,data).then(res1 => {
    console.log(res1)
    if(res1.data['status']=='ok'){
      res.redirect('/')
    }
    else{
      res.render('register_err',{error:"Username or email already in use"})
    }
  })
  .catch(error => {
    console.error(error)
  })

})
frontend.post("/org_register",(req,res)=>{
  verified_user(req.cookies["jwt_session"]).then(data => {
    console.log(data)
    if(data["status"] == "failed"){
      console.log("end_not logged")
      res.destroy()
    }
  }).catch(err => console.log(err))
  var data={
      org_email: req.body.org_email,org_name: req.body.org_name,org_decription : req.body.org_description,
    session : req.cookies["jwt_session"]
  } 
  const promise = axios.post(`http://${process.env.HOST}:${process.env.PORT}/api/org_register`,data) //use data destructuring to get data from the promise object
  const dataPromise = promise.then((response) => response.data)
  dataPromise.then(data => {
    if(data['status'] == 'ok'){
      res.render('admin',{name:req.body.org_name})
    }
    else{
      res.render('session_err')
    }
  })
})

frontend.post("/password_generator",(req,res)=>{
  verified_user(req.cookies["jwt_session"]).then(data => {
    console.log(data)
    if(data["status"] == "failed"){
      console.log("end_not logged")
      res.render('session_err')
    }
  }).catch(err => console.log(err))
  var data={
      username: req.body.username,password: req.body.password,url : req.body.URL,
      session : req.cookies["jwt_session"]
  }
  console.log(data)
  const promise = axios.post(`http://${process.env.HOST}:${process.env.PORT}/api/password_generator`,data) //use data destructuring to get data from the promise object
  const dataPromise = promise.then((response) => response.data)
  dataPromise.then(data => {
    if(data['status'] == 'ok'){
      res.redirect('/stored_password')
    }
    else{
      res.render('password',{msg:"Password fail to match policy"})
    }

  })
})

frontend.post("/send_mail",(req,res)=>{
    var data=req.body
    console.log(data)
    res.send(req.cookies)
    axios.post(`http://${process.env.HOST}:${process.env.PORT}/api/send_mail`,data).then(res =>{
        console.log(res)
    })
    .catch(error => {
        console.error(error)
    })
})

frontend.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})
