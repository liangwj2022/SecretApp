require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
// const encrypt = require("mongoose-encryption");
// const md5 = require("md5");
// const bcrypt = require('bcrypt');
// const saltRounds = 10;
const session = require('express-session');
const passport = require("passport");
//installing passport-local is because it is the dependency of passport-local-mongoose, no need to require here
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static("public"));

app.use(session({
  secret: 'This is good cat.',
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1:27017/userDB");

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// use static serialize and deserialize of model for passport session support
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID_GG,
    clientSecret: process.env.CLIENT_SECRET_GG,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    // console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.CLIENT_ID_FB,
    clientSecret: process.env.CLIENT_SECRET_FB,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    // console.log(profile);
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.serializeUser(function(user, done) {
    done(null, user.id);
    // if you use Model.id as your idAttribute maybe you'd want
    // done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

app.get("/", function(req, res) {
  res.render("home");
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] }));

app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
    function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
});

app.get("/auth/facebook",
  passport.authenticate("facebook"));

app.get("/auth/facebook/secrets",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
    function(req, res) {
      // Successful authentication, redirect home.
    res.redirect('/secrets');
});

app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/register", function(req, res) {
  res.render("register");
});

app.get("/secrets", function(req, res) {
  User.find({secret: {$ne: null}}, function(err,docs){
    if(err){
      console.log(err);
    }else{
      res.render("secrets", {usersWithSecrets: docs});
    }
  });
});

app.get("/submit", function(req,res){
  if(req.isAuthenticated()){
    res.render("submit");
  }else{
    res.redirect("/login");
  }
});

app.post("/submit", function(req,res){
  const submittedSecret = req.body.secret;
  //req.user --> current user object
  User.findById(req.user.id, function(err,doc){
    if(err){
      console.log(err);
    }else{
      doc.secret = submittedSecret;
      doc.save(function(){
        res.redirect("/secrets");
      });
    }
  });
});

app.get('/logout', function(req, res) {
  req.logout(function(err) {
    if (err) { console.log(err); }
    res.redirect('/');
  });
});

app.post("/register", function(req, res) {
  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
  //   // Store hash in your password DB.
  //   const newUser = new User({
  //     email: req.body.username,
  //     password: hash
  //     // password: md5(req.body.password)
  //   });
  //   newUser.save(function(err){
  //     if(err){
  //       res.send(err);
  //     }else{
  //       res.render("secrets");
  //     }
  //   });
  // });
  User.register({
    username: req.body.username,
    active: false
  }, req.body.password, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    }else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      });
    }
    });
});


app.post("/login", function(req, res) {
  // User.findOne(
  //   {email: req.body.username},
  //   function(err, doc){
  //     if(err){
  //       res.send(err);
  //     }else{
  //       if(doc){
  //         // if(doc.password === md5(req.body.password)){
  //         bcrypt.compare(req.body.password, doc.password, function(err, result) {
  //           // result == true
  //           if(result === true){
  //             res.render("secrets");
  //           }else{
  //             res.send("Password not match");
  //           }
  //         });
  //       }
  //     }
  //   }
  // );
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
    if(err){
      console.log(err);
    }else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      });
    }
  });
});

app.listen(3000, function() {
  console.log("Server started on port 3000");
});
