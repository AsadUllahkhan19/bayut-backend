const mongoose = require("mongoose");

async function main() {
    try {
       res = await mongoose.connect('mongodb+srv://asad:asad@cluster0.rzcnxqe.mongodb.net/', { useNewUrlParser: true });
       console.log("Connected database")
    } catch (error) {
       console.log(error)
    }
   }

module.exports = main;