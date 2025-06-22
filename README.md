# 🚀 ZCoder

**An Interactive Coding Community Platform to Practice and Scale Up Your Skills**

ZCoder is a comprehensive platform designed to help developers of all levels improve their coding skills through interactive challenges, community engagement, and real-time code execution.

---

## ✨ Features

- 💻 Interactive coding challenges  
- 🏆 Real-time code execution and testing  
- 👥 Community-driven learning environment  
- 📊 Progress tracking and skill assessment  
- 🎯 Multiple programming language support  

---

## 🛠️ Tech Stack

- **Frontend**: React.js with Vite  
- **Backend**: Node.js with Express  
- **Code Execution**: [Piston API](https://github.com/engineer-man/piston)  
- **Problem Database**: LeetCode API  
- **AI Integration**: Groq API  

---

## 📋 Prerequisites

Make sure you have the following installed:

- [Node.js (v16+)](https://nodejs.org/)  
- npm (comes with Node.js) or yarn  
- [Git](https://git-scm.com/downloads)  
- A code editor like [VS Code](https://code.visualstudio.com/)

### ✅ Check Your Setup

```bash
node --version
npm --version
git --version
```

---

## 🚀 Getting Started

### Step 1: Clone the Repository

```bash
git clone https://github.com/chethanreddy10/ZCoder.git
cd ZCoder
```

---

### Step 2: Set Up the Backend

```bash
cd backend
npm install
```

Create a `.env` file inside the `backend` directory:

```env
MONGODB_URI="connection-string of mongoDB"/Zcoder(so that if initailly not present then it will be created in your cluster).
PORT=3000
GROQ_API_KEY=

```

#### 🔑 To get your Groq API Key:

1. Visit [Groq Console](https://console.groq.com/)
2. Sign up or log in
3. Navigate to **API Keys**
4. Create a new API key
5. Copy and paste it into the `.env` file

Start the backend server:

```bash
nodemon index.js
```

✅ You should see: `Server running on port 3000`

---

### Step 3: Set Up the Frontend

In a **new terminal**:

```bash
cd frontend
npm install
```

Create a `.env` file inside the `frontend` directory:

```env
VITE_API_URL=https://leetcode-api-mu.vercel.app/
VITE_BACKEND_URL=http://localhost:3000
VITE_JUDGE=https://emkc.org/api/v2/piston/execute
```

Start the frontend server:

```bash
npm run dev
```

✅ You should see: `http://localhost:5173`

---

## 🌐 Access the Application

Visit in your browser: [http://localhost:5173](http://localhost:5173)

---

## 🐛 Troubleshooting

### ❌ "Command not found"

Ensure Node.js and npm are installed.  
Check with:
```bash
node --version
npm --version
```

---

### ❌ Port Already in Use

- For backend: Change port or kill process using port 3000  
- For frontend: Vite suggests an alternative port automatically

---

### ❌ Environment Variables Not Working

- Ensure files are named `.env`, not `.env.txt`
- Located in correct directories
- Restart both servers after creating

---

### ❌ Dependency Installation Fails

```bash
npm cache clean --force
rm -rf node_modules
npm install
```

---

### ❌ CORS Errors

- Make sure backend is running at `http://localhost:3000`
- Verify frontend `.env` has correct `VITE_BACKEND_URL`

---

## 📁 Project Structure

```
ZCoder/
├── backend/
│   ├── index.js
│   ├── package.json
│   ├── .env
│   └── ...
├── frontend/
│   ├── src/
│   ├── public/
│   ├── package.json
│   ├── .env
│   └── ...
└── README.md
```

---

## 🤝 Contributing

We welcome contributions!

```bash
# Fork the repository
# Create a new branch
git checkout -b feature/amazing-feature

# Make your changes
git commit -m 'Add amazing feature'

# Push and create a pull request
git push origin feature/amazing-feature
```

---

## 📞 Support

If you face issues:

- Review the [Troubleshooting](#-troubleshooting) section  
- Search or open an issue on GitHub  
- Include OS, Node.js version, and error logs for quicker help



## 🌟 Acknowledgments

- Thanks to all contributors 🙌  
- Special thanks to the open-source community ❤️  

---

**Happy Coding! 🎉**  
_Made with ❤️ by the ZCoder Team_
