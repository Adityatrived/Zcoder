const Groq = require("groq-sdk");
const express = require("express");
const router = express.Router();
require('dotenv').config();

// Initialize OpenAI with your API key
const groq = new Groq({
  apiKey: process.env.GROQ_API_KEY || "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",
});

async function getGroqChatCompletion(message) {
  return groq.chat.completions.create({
    messages: [
      {
        role: "user",
        content: message,
      },
    ],
    model: "llama-3.3-70b-versatile",
  });
}

router.post("/ask-ai", async (req, res) => {
  try {
    const { message } = req.body;
    const chatCompletion = await getGroqChatCompletion(message);
    let ans = chatCompletion.choices[0]?.message?.content || "";
    res.json({
      answer: ans,
    });
  } catch (error) {
    console.error("AI API error:", error);
    res.status(500).json({ error: "Failed to get AI response" });
  }
});

module.exports = router;
