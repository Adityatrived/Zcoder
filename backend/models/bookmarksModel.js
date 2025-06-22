const mongoose = require("mongoose");

const bookmarks = new mongoose.Schema({
  username: {
    type: String,
    required: true,
  },
  bookmarks: {
    type: [String], // Array of problem slugs
    default: [],
  },
})

module.exports = mongoose.model("Bookmarks", bookmarks)