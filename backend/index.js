// server.js
const express = require("express");
const http = require("http");
// const jwt = require("jsonwebtoken");
// const bcrypt = require("bcrypt");
const socketIo = require("socket.io");
const cors = require("cors");
// const Message = require("./models/messageModel.js");
const connectDB = require("./config/db");
const aiRoute = require("./routes/AskAI.js");
const loginRoute = require("./routes/LoginRoute.js");
const solutionsRoute = require("./routes/Solutions.js");
const profileRoute = require("./routes/Profile.js");
const socketHandler = require("./socketHandler");
const bookmarksRoute = require("./routes/Bookmarks.js");
const usersRoute = require("./routes/usersRoute.js");
const User = require("./models/UserModel.js");
const bodyParser = require("body-parser");
require("dotenv").config();

// Connect to MongoDB
connectDB();

const app = express();
app.use(bodyParser.json({ limit: "100mb" }));
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
  },
});

app.use(
  cors({
    origin: "*",
  })
);
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Headers", "Authorization, Content-Type");
  next();
});
app.use(express.json());

// routes
app.use("/api", aiRoute);
app.use("/", loginRoute);
app.use("/api/solutions", solutionsRoute);
app.use("/user", profileRoute);
app.use("/bookmarks", bookmarksRoute);
app.use("/users", usersRoute);
// app.get("/users/:username", async (req, res) => {
//   const { username } = req.params;
//   if (!username || username.trim() === "") {
//     return res.status(400).send([]);
//   }
//   try {
//     const usersList = await User.find({
//       Username: { $regex: `^${username}`, $options: "i" },
//     }).select("_id Username profilePicture"); // Only select _id and Username fields

//     if (usersList && usersList.length > 0) {
//       // Map to return array of objects with id and username
//       const result = usersList.map((user) => ({
//         id: user._id,
//         username: user.Username,
//         profilePicture: user.profilePicture , // Default picture if not set
//       }));
//       res.status(200).send(result);
//     } else {
//       res.status(404).send("No users found!");
//     }
//   } catch (err) {
//     res.status(500).send("Server error");
//   }
// });
app.get("/ping", (req, res) => {
  console.log(process.env.GROQ_API_KEY);
  res.json({ msg: "API is working !!" });
});

socketHandler(io);

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
