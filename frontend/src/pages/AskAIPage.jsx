import React, { useState, useEffect } from "react";
import axios from "axios";
import ReactMarkdown from "react-markdown";
import { useNavigate } from "react-router-dom";
import "../styles/askAI.css";

function AskAIPage() {
  const [message, setMessage] = useState("");
  const [answer, setAnswer] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [conversation, setConversation] = useState([]);
  const navigate = useNavigate();

  useEffect(() => {
    // Redirect to the login page if the user is not authenticated
    const jwtoken = localStorage.getItem("jwtoken");
    if (jwtoken === null || jwtoken === undefined) {
      navigate("/login");
    }
  });

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!message.trim()) return;

    setIsLoading(true);
    try {
      // Add user message to conversation
      const userMessage = { sender: "user", text: message };
      setConversation((prev) => [...prev, userMessage]);

      const response = await axios.post(
        `${import.meta.env.VITE_BACKEND_URL}/api/ask-ai`,
        {
          message,
        }
      );

      // Add AI response to conversation
      const aiMessage = { sender: "ai", text: response.data.answer };
      setConversation((prev) => [...prev, aiMessage]);
      setAnswer(response.data.answer);
    } catch (error) {
      console.error("Error getting AI response:", error);
      setConversation((prev) => [
        ...prev,
        { sender: "ai", text: "Sorry, I encountered an error." },
      ]);
    } finally {
      setIsLoading(false);
      setMessage("");
    }
  };

  return (
    <div className="ask-ai-container">
      <h1>AI Assistant</h1>
      <div className="conversation">
        {conversation.map((msg, index) => (
          <div key={index} className={`message ${msg.sender}`}>
            <div className="message-content">
              {msg.sender === "ai" ? (
                <ReactMarkdown>{msg.text}</ReactMarkdown>
              ) : (
                msg.text
              )}
            </div>
          </div>
        ))}
        {isLoading && (
          <div className="message ai">
            <div className="message-content loading">Thinking...</div>
          </div>
        )}
      </div>
      <form onSubmit={handleSubmit} className="message-form">
        <input
          type="text"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Ask me anything..."
          disabled={isLoading}
        />
        <button type="submit" disabled={isLoading || !message.trim()}>
          {isLoading ? "Sending..." : "Send"}
        </button>
      </form>
    </div>
  );
}

export default AskAIPage;
