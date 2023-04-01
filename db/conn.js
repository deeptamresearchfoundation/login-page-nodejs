const mongoose = require("mongoose")

mongoose.set('strictQuery', true);
mongoose.connect("mongodb://localhost:27017/iamyou", { useNewUrlParser: true, useUnifiedTopology: true, }).then(() => {console.log("connected")}).catch((err) => {console.log(err)})