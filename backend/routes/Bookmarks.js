const express = require("express");
const router = express.Router();
const Bookmarks = require("../models/bookmarksModel");
const auth = require('../middleware/auth');

router.get('/', auth, async (req, res) => {
    try {
        const bookmarks = await Bookmarks.findOne({username: req.user.username});
        res.status(200).json(bookmarks);
    } catch (error) {
        console.error("Error fetching bookmarks:", error);
        res.status(500).json({ message: "Internal server error" });
    }
})

router.post('/toggle', auth, async (req, res) => {
  try {
    const { problemSlug } = req.body;
    const username = req.user.username;

    let userBookmarks = await Bookmarks.findOne({ username });

    if (!userBookmarks) {
      userBookmarks = new Bookmarks({ username, bookmarks: [problemSlug] });
    } else {
      const isBookmarked = userBookmarks.bookmarks.includes(problemSlug);
      if (isBookmarked) {
        userBookmarks.bookmarks = userBookmarks.bookmarks.filter(
          (slug) => slug !== problemSlug
        );
      } else {
        userBookmarks.bookmarks.push(problemSlug);
      }
    }

    await userBookmarks.save();
    res.status(200).json(userBookmarks);
  } catch (error) {
    console.error("Error toggling bookmark:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

module.exports = router;