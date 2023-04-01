const express = require("express")
const app = express()
const hbs = require("hbs")
const path = require("path")
const bcrypt = require('bcrypt')
const jwt = require("jsonwebtoken");

require("./db/conn")
const Users = require("./db/models/Users")

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const partialPath = path.join(__dirname, "./components");
hbs.registerPartials(partialPath);

const cookieParser = require("cookie-parser");
app.use(cookieParser());

app.use("/css", express.static(path.join(__dirname, "./views/css")));
app.use("/images", express.static(path.join(__dirname, "./views/images")));

app.set("view engine", "hbs");

const mySecret = "भजेव्रजैकमण्डनंसमस्तपापखण्डनं"

const authenticate = async (req, res, next) => {
  try {
    const token = req.cookies.token;
    const email = jwt.verify(token, mySecret)

    if (email) {
      const allUser = await Users.findOne({ email: email.email })
      if (allUser === null) {
        req.user = false
      }
      else {
        req.user = allUser
      }
    }
    else {
      res.user = false
    }
  }
  catch (err) {
    req.user = false
    res.status(200)
  }
  next()
}

app.get("/", authenticate, async (req, res) => {
  try {
    if (req.user === false) {
      res.render("index", {
        login: req.user === false ? false : req.user,
      })
    }
    else {
      res.render("log", {
        login: req.user === false ? false : req.user,
      })
    }
  }
  catch (err) {
    console.log(err)
  }
})

app.get("/register", authenticate, (req, res) => {
  res.render("register", {
    login: req.user === false ? false : req.user,
  })
})

app.get("/signin", authenticate, (req, res) => {
  res.render("signin", {
    login: req.user === false ? false : req.user,
  })
})

app.post("/register", async (req, res) => {
  try {
    const { name, phone, email, password } = req.body
    if (name !== "" && phone !== "" && email !== "" && password !== "") {
      const data = await Users.findOne({ email })
      if (data === null) {
        let newPass = await bcrypt.hash(password, 10);
        const newUser = new Users({
          name, email, password: newPass, phone
        })
        await newUser.save();
        const token = jwt.sign({ email }, mySecret);
        res.cookie("token", token, {
          expires: new Date(Date.now() + 3000000000),
        });
        res.render("error", {
          err: "Successfully registered",
          color: "green",
          login: newUser,
          btn: true
        })
      }
      else {
        res.render("error", {
          err: "User already registered",
          color: "red"
        })
      }
    }
    else {
      res.render("error", {
        err: "Please fill all the fields",
        color: "red"
      })
    }
  }
  catch (err) {
    console.log(err)
  }
})

app.post("/signin", async (req, res) => {
  try {
    const { name, phone, email, password } = req.body
    if (name !== "" && phone !== "" && email !== "" && password !== "") {
      const data = await Users.findOne({ email })
      if (data !== null) {
        const isMatch = await bcrypt.compare(password, data.password);
        if (isMatch) {
          const token = jwt.sign({ email }, mySecret);
          res.cookie("token", token, {
            expires: new Date(Date.now() + 3000000000),
          });
          res.render("error", {
            err: "Successfully signed in",
            color: "green",
            login: data,
            btn: true
          })
        }
        else {
          res.render("error", {
            err: "Invalid Credentials",
            color: "red",
            btn: true
          })
        }
      }
      else {
        res.render("error", {
          err: "User is not registered",
          color: "red"
        })
      }
    }
    else {
      res.render("error", {
        err: "Please fill all the fields",
        color: "red"
      })
    }
  }
  catch (err) {
    console.log(err)
  }
})

app.get("/signout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/");
})

app.listen(5000)