const express = require("express");
const router = express.Router();
require("dotenv").config();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const mongoose = require('mongoose');
const User = require("../models/UserModel");
const auth = require("../middleware/auth");

router.post("/register/", async (request, response) => {
  const { username, password, email } = request.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const dbUsername = await User.find({ Username: username });
  const dbEmail = await User.find({ Email: email });
  if (dbUsername.length === 0 && dbEmail.length === 0) {
    if (password.length < 6) {
      response.status(400);
      response.send("Password is too short");
    } else {
      const newUser = new User({
        Username: username,
        HashedPassword: hashedPassword,
        email: email,
        codeforcesHandle: "",
        name: '',
        phoneNumber: '',
        profilePicture: 'https://static.vecteezy.com/system/resources/thumbnails/019/879/186/small_2x/user-icon-on-transparent-background-free-png.png',
        programmingLanguages: [],
        skills: [],
        role: '',
        location: '',
        degrees: [],
        experience: [],
        languages: [],
      });
      const dbResponse = await User.create(newUser);
      response.status(200);
      response.send(`User created successfully`);
    }
  } else {
    response.status(400);
    if (dbUsername.length !== 0) {
      response.send("Username already exists");
    } else if (dbEmail.length !== 0) {
      response.send("Email already exists");
    }
  }
});

router.post("/login/", async (req, res) => {
  const { username, password } = req.body;
  const dbuser = await User.findOne({ Username: username }); // Changed to findOne
  
  if (!dbuser) {
    return res.status(400).json({ error: "Invalid user" }); // Return JSON response
  }

  const checkPw = await bcrypt.compare(password, dbuser.HashedPassword);
  if (checkPw) {
    const payload = {
      username: username,
      user_id: dbuser._id.toString(), // Corrected to use dbuser._id
    };
    const jwtoken = jwt.sign(payload, "MY_SECRET_TOKEN");
    return res.json({ token: jwtoken }); // Return as JSON
  } else {
    return res.status(400).json({ error: "Invalid password" }); // Return JSON response
  }
});

router.get('/api/auth/me', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.user_id).select('-HashedPassword');
    // console.log(req.user.user_id);
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
