// 06-06-2025 06:40 pm

const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const userSchema = new Schema({
  Username: String,
  HashedPassword: String,
  codeforcesHandle: String,
  codeforcesRating: String,
  email: String,
  name: String,
  phoneNumber: String,
  profilePicture: String,
  role: String,
  location: String,

  //fields - make them arrays for consistency
  programmingLanguages: [{
    type: String
  }],


  skills: [{
    name: String,
    level: {
      type: Number,
      min: 0,
      max: 100,
      default: 80
    }
  }],

  // Add missing array fields
  degrees: [{
    title: String,
    institution: String
  }],

  experience: [{
    role: String,
    period: String,
    company: String
  }],

  languages: [{
    name: String,
    level: {
      type: Number,
      min: 0,
      max: 100,
      default: 0
    },
    fluency: String
  }]
}, {
  timestamps: true // Adds createdAt and updatedAt fields
});

const User = mongoose.model("User", userSchema, "users");

module.exports = User;
