import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import env from "dotenv";
import uid from "uid-safe";
import GoogleStrategy from "passport-google-oauth2";

const app = express();
const port = 3000;
const saltRounds = 10;
let sessionStore = new session.MemoryStore();
env.config();

const genUID =  ()=>{
  return uid.sync(18);
}

app.use(
  session({
    genid:  function(req){
      return genUID();
    },
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    store: sessionStore
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
  console.log(sessionStore);
  console.log(req.session);
});

app.get("/auth/google",passport.authenticate("google",{
  scope:["profile","email"]
}))

app.get("/auth/google/secrets",passport.authenticate("google",{
  successRedirect:"/secrets",
  failureRedirect:"/login"
}));


app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/secrets", async (req, res) => {
   console.log(req.user);
   console.log(req.session);
   console.log("in secrets");
  //  console.log(req.session.views);
  //  req.session.views = 1;
   console.log(sessionStore);
  //  console.log(req.sessionID);
  if (req.isAuthenticated()) {
    try{
     const result = await db.query("SELECT * FROM secrets limit 4");
    res.render("secrets.ejs",{
      secrets: result.rows
    });
    }catch(e){
      console.log(e);
    }
  } else {
    res.redirect("/login");
  }
});
app.get("/ShareSecret",(req,res)=>{
  if (req.isAuthenticated()) {
  res.render("new_secret.ejs");
  } else {
    res.redirect("/login");
  }
})
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.get('/load-more-secrets', async (req, res) => {
  if(req.isAuthenticated()){
  const offset = parseInt(req.query.offset, 10);
  try {
    const secrets = await db.query('SELECT * FROM secrets LIMIT 4 OFFSET $1', [offset]);
    res.json({ secrets: secrets.rows });
  } catch (err) {
    console.error('Error loading more secrets:', err);
    res.status(500).send('Server error');
  }
}else{
  res.redirect("/login");
}
});

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      req.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/shareSecret",async (req,res)=>{
  if(req.isAuthenticated()){
    try{
    const response = db.query("insert into secrets (title,userId) values ($1,$2);",[
      req.body.title,req.user.id
    ]);
    res.redirect("/secrets");
  }catch(e){
    console.log(e);
    res.redirect("/secrets");
  }
  }else{

  }
})

passport.use("google",new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileURL: "https://googleapis.com/oauth2/v3/userinfo"
},async (accessToken,refreshToken,profile,cb)=>{
  console.log(profile);
  try{
    const result = await db.query("select * from users where email = $1",[profile.email]);
    if(result.rows.length === 0){
      const response = await db.query("insert into users (email , password) values ($1, $2) returning *",[profile.email,"google"+profile.id]);
      return cb(null,response.rows[0]);
    }else{
      return cb(null,result.rows[0]);
    }
  }catch(e){
    console.log(e);
  }
})
)

passport.use("local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            //Error with password check
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              console.log("valid");
              //Passed password check
              return cb(null, user);
            } else {
              //Did not pass password check
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.serializeUser((user, cb) => {
  cb(null, user.id);
});
passport.deserializeUser(async (id, cb) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      cb(null, user);
    } else {
      cb(null, false);
    }
  } catch (err) {
    cb(err);
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
