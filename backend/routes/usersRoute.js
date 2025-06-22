const bodyParser = require("body-parser");
const express = require("express");
const router = express.Router();
const User = require("../models/UserModel");
const mongoose = require("mongoose");

router.use(bodyParser.json({ limit: "100mb" }));

router.get("/:username", async (req, res) => {
  const { username } = req.params;
  if (!username || username.trim() === "") {
    return res.status(400).send([]);
  }
  try {
    const usersList = await User.find({
      Username: { $regex: `^${username}`, $options: "i" },
    }).select("_id Username profilePicture"); // Only select _id and Username fields

    if (usersList && usersList.length > 0) {
      // Map to return array of objects with id and username
      const result = usersList.map((user) => ({
        id: user._id,
        username: user.Username,
        profilePicture: user.profilePicture , // Default picture if not set
      }));
      res.status(200).send(result);
    } else {
      res.status(404).send("No users found!");
    }
  } catch (err) {
    res.status(500).send("Server error");
  }
});

module.exports = router;