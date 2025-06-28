// 06-06-2025 07:30 pm
const express = require("express");
const router = express.Router();
require("dotenv").config();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const mongoose = require("mongoose");
const User = require("../models/UserModel");
const bodyParser = require("body-parser");
const auth = require("../middleware/auth");

router.use(bodyParser.json({ limit: "100mb" }));

// UPDATE PROFILE ROUTE - CORRECTED
router.post("/profile/update", auth, async (req, res) => {
  try {
    const userId = req.user.user_id || req.user._id;

    // Update all fields at once using findByIdAndUpdate
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { $set: req.body }, // Update all fields sent in request body
      { new: true, runValidators: true } // Return updated doc and validate data
    );

    if (!updatedUser) {
      return res.status(404).json({ error: "User not found" });
    }

    res.status(200).json({
      message: "Profile updated successfully",
      user: updatedUser // Return complete updated user data
    });
  } catch (err) {
    console.error("Update error:", err);
    res.status(500).json({ error: "Failed to update profile" });
  }
});

// GET PROFILE ROUTE - CORRECTED
router.get("/profile", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.user_id)
      .select("-HashedPassword -__v"); // Exclude sensitive fields

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.status(200).json(user);
  } catch (err) {
    console.error("Profile fetch error:", err);
    res.status(500).json({ error: "Failed to fetch profile" });
  }
});

// GET USER BY ID - CORRECTED
router.get("/:id", async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select("-HashedPassword -__v -createdAt -updatedAt");

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.status(200).json(user);
  } catch (err) {
    console.error("User fetch error:", err);
    res.status(500).json({ error: "Failed to fetch user" });
  }
});

// PASSWORD UPDATE ROUTE (NO CHANGES NEEDED HERE)
router.post("/profile/update-password", auth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.user_id || req.user._id;

    const dbUser = await User.findById(userId);
    if (!dbUser) {
      return res.status(404).json({ error: "User not found" });
    }

    const isMatch = await bcrypt.compare(currentPassword, dbUser.HashedPassword);
    if (!isMatch) {
      return res.status(401).json({ error: "Current password is incorrect" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    dbUser.HashedPassword = hashedPassword;
    await dbUser.save();

    res.status(200).json({ message: "Password updated successfully" });
  } catch (err) {
    console.error("Password update error:", err);
    res.status(500).json({ error: "Failed to update password" });
  }
});

module.exports = router;
