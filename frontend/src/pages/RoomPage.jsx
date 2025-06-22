import React, { useEffect, useRef, useState } from "react";
import { useLocation, useParams } from "react-router-dom";
import "../styles/rooms.css";
import io from "socket.io-client";
import SoloCodeEditor from "../components/SoloCodeEditor";

function RoomPage() {
  const location = useLocation();
  const username = location.state?.username;
  const { roomId } = useParams();
  const [message, setMessage] = useState("");
  const [messages, setMessages] = useState([]);
  const [users, setUsers] = useState([]);
  const [chatMode, setChatMode] = useState(true);
  const [sharedText, setSharedText] = useState("");
  const [sharedInput, setSharedInput] = useState("");
  const textAreaRef = useRef(null);
  const messagesEndRef = useRef(null);
  const socket = useRef();

  useEffect(() => {
    // Redirect to the login page if the user is not authenticated
    const jwtoken = localStorage.getItem("jwtoken");
    if (jwtoken === null || jwtoken === undefined) {
      navigate("/login");
    }
  });

  useEffect(() => {
    socket.current = io("http://localhost:3000");

    socket.current.emit("join-room", { roomId, username });

    // Add these listeners
    socket.current.on("user-joined", (username) => {
      setUsers((prev) => [...prev, username]);
    });

    socket.current.on("user-left", (username) => {
      setUsers((prev) => prev.filter((user) => user !== username));
    });

    socket.current.on("room-users", (userList) => {
      setUsers(userList);
    });

    socket.current.on("recieve-msg", (msg) => {
      setMessages((prev) => [...prev, msg]);
    });

    socket.current.on(
      "room-init",
      ({ users, sharedText, sharedInput, previousMessages }) => {
        setUsers(users);
        setSharedText(sharedText);
        setSharedInput(sharedInput || "");
        if (previousMessages) {
          setMessages(previousMessages);
        }
      }
    );

    socket.current.on("text-edit", (text) => {
      if (text !== sharedText) {
        setSharedText(text);
      }
    });

    socket.current.on("input-edit", (input) => {
      if (input !== sharedInput) {
        setSharedInput(input);
      }
    });

    return () => {
      socket.current.disconnect();
    };
  }, [username, roomId]);

  // Auto-scroll to bottom of messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const toggleEditor = () => {
    setChatMode(!chatMode);
    if (!chatMode && textAreaRef.current) {
      textAreaRef.current.focus();
    }
  };

  const handleTextChange = (newText) => {
    setSharedText(newText);
    socket.current.emit("text-edit", {
      roomId,
      text: newText,
    });
  };

  const sendMsg = (e) => {
    e.preventDefault();
    if (message.trim()) {
      socket.current.emit("send-msg", {
        roomId,
        message,
        username,
      });
      setMessage("");
    }
  };

  // Format timestamp
  const formatTime = (timestamp) => {
    return new Date(timestamp).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  return (
    <div className="room-container">
      <div className="left">
        <h2>Welcome to Room: {roomId}</h2>
        <hr />
        <h3>Users in the Room:</h3>
        <ul>
          {users.map((user, index) => (
            <li key={index}>{user}</li>
          ))}
        </ul>
      </div>
      <div className="right">
        <button onClick={toggleEditor} className="toggle-mode-btn">
          {chatMode ? "Switch to Editor" : "Switch to Chat"}
        </button>

        {chatMode ? (
          <div className="chat-container">
            <div className="title">
              <h3>Messages</h3>
              <hr />
            </div>
            <div className="messages">
              {messages.map((msg, index) => (
                <div key={index} className="message">
                  <div className="message-header">
                    <strong>{msg.username}</strong>
                    <span className="message-time">
                      {formatTime(msg.timestamp)}
                    </span>
                  </div>
                  <p>{msg.message}</p>
                </div>
              ))}
              <div ref={messagesEndRef} />
            </div>
            <form onSubmit={sendMsg} className="message-form">
              <input
                type="text"
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                placeholder="Type a message..."
              />
              <button type="submit">Send</button>
            </form>
          </div>
        ) : (
          <div className="editor-container">
            <div className="title">
              <h3>Collaborative Editor</h3>
              <hr />
            </div>
            <SoloCodeEditor
              value={sharedText}
              onChange={handleTextChange}
              inputValue={sharedInput}
              onInputChange={(newInput) => {
                setSharedInput(newInput);
                socket.current.emit("input-edit", {
                  roomId,
                  input: newInput,
                });
              }}
              height="70vh"
              width="100%"
            />
          </div>
        )}
      </div>
    </div>
  );
}

export default RoomPage;
