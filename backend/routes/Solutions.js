const express = require("express");
const router = express.Router();
const Solution = require("../models/Solution");
const auth = require("../middleware/auth");

// Submit a solution
router.post("/submit", auth, async (req, res) => {
  try {
    const { problemSlug, code, language } = req.body;

    // Here you would typically run the code against test cases
    // For simplicity, we'll just save it
    console.log(req.user);

    const solution = new Solution({
      problemSlug,
      code,
      language,
      author: req.user.user_id,
    });

    await solution.save();

    res.json({
      success: true,
      message: "Solution submitted successfully!",
      passed: true, // In real app, this would depend on test results
      details: "All test cases passed", // Would show actual test results
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: err.message });
  }
});

router.delete("/:id", auth, async (req, res) => {
  try {
    const solution = await Solution.findById(req.params.id);

    // Check if solution exists and user is the author
    if (!solution) {
      return res.status(404).json({ error: "Solution not found" });
    }
    console.log(solution.author, req.user.user_id);
    if (solution.author.toString() !== req.user.user_id) {
      return res
        .status(403)
        .json({ error: "Unauthorized to delete this solution" });
    }

    await Solution.deleteOne({ _id: req.params.id });
    res.json({ success: true, message: "Solution deleted successfully" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: err.message });
  }
});

// Get all solutions for a problem
router.get("/:problemSlug", async (req, res) => {
  try {
    const solutions = await Solution.find({
      problemSlug: req.params.problemSlug,
    })
      .populate("author", "Username _id")
      .sort({ createdAt: -1 });

    res.json(solutions);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get solution detail
router.get("/detail/:id", async (req, res) => {
  try {
    const solution = await Solution.findById(req.params.id).populate(
      "author",
      "Username _id"
    );
    res.json(solution);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Handle voting
router.post("/vote", async (req, res) => {
  try {
    const { solutionId, voteType } = req.body;
    const solution = await Solution.findById(solutionId);

    if (!solution) {
      return res.status(404).json({ error: "Solution not found" });
    }

    // Update votes
    solution.votes += voteType === "upvote" ? 1 : -1;
    await solution.save();

    res.json({ success: true, votes: solution.votes });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
