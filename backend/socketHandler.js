const Message = require("./models/messageModel.js");

let rooms = new Map();

function socketHandler(io) {
  io.on("connection", (socket) => {
    console.log("New client connected:", socket.id);

    let currentUsername, currentRoomId;

    socket.on("join-room", async ({ username, roomId }) => {
      currentUsername = username;
      currentRoomId = roomId;

      socket.join(roomId);

      if (!rooms.has(roomId)) {
        rooms.set(roomId, {
          users: new Set(),
          sharedText: "",
          sharedInput: "", // Add this line
        });
      }
      rooms.get(roomId).users.add(username);

      // Load previous messages from database
      try {
        const previousMessages = await Message.find({ roomId })
          .sort({ timestamp: 1 })
          .limit(100);

        socket.emit("room-init", {
          users: Array.from(rooms.get(roomId).users),
          sharedText: rooms.get(roomId).sharedText,
          sharedInput: rooms.get(roomId).sharedInput, // Add this line
          previousMessages,
        });
      } catch (err) {
        console.error("Error loading messages:", err);
      }

      socket.to(roomId).emit("user-joined", username);
      io.to(roomId).emit("room-users", Array.from(rooms.get(roomId).users));
    });

    socket.on("send-msg", async ({ roomId, message, username }) => {
      try {
        const newMessage = new Message({ roomId, username, message });
        await newMessage.save();

        io.to(roomId).emit("recieve-msg", {
          username,
          message,
          timestamp: newMessage.timestamp,
        });
      } catch (err) {
        console.error("Error saving message:", err);
      }
    });

    socket.on("text-edit", ({ roomId, text }) => {
      if (rooms.has(roomId)) {
        rooms.get(roomId).sharedText = text;
      }
      socket.to(roomId).emit("text-edit", text);
    });

    // Add this block for input sync
    socket.on("input-edit", ({ roomId, input }) => {
      if (rooms.has(roomId)) {
        rooms.get(roomId).sharedInput = input;
      }
      socket.to(roomId).emit("input-edit", input);
    });

    socket.on("disconnect", () => {
      console.log("Client disconnected:", socket.id);

      if (currentRoomId && currentUsername && rooms.has(currentRoomId)) {
        rooms.get(currentRoomId).users.delete(currentUsername);

        if (rooms.get(currentRoomId).users.size === 0) {
          rooms.delete(currentRoomId);
        } else {
          io.to(currentRoomId).emit("user-left", currentUsername);
          io.to(currentRoomId).emit(
            "room-users",
            Array.from(rooms.get(currentRoomId).users)
          );
        }
      }
    });
  });
}

module.exports = socketHandler;