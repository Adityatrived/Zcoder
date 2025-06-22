import React from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Home from "./pages/Home";
import RoomSelection from "./pages/RoomSelection";
import RoomPage from "./pages/RoomPage";
import AskAIPage from "./pages/AskAIPage";
import Calendar from "./pages/Calendar";
import LoginPage from "./pages/Login";
import RegisterPage from "./pages/Register";
import Dashboard from "./pages/Dashboard";
import ProblemDetail from "./pages/ProblemDetail";
import Discussions from "./pages/Discussion";
import SolutionDetail from "./pages/SolutionDetail";
import Header from "./components/Header";
import UserProfile from './pages/UserProfile';
import FriendsProfile from "./pages/FriendsProfile";
import Bookmarks from "./pages/Bookmarks";
import SoloCodeEditor from "./components/SoloCodeEditor";

function App() {
  return (
    <BrowserRouter>
      <Header />
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
        <Route path="/rooms" element={<RoomSelection />} />
        <Route path="/rooms/:roomId" element={<RoomPage />} />
        <Route path="/askAI" element={<AskAIPage />} />
        <Route path="/calendar" element={<Calendar />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/problem/:titleSlug" element={<ProblemDetail />} />
        <Route path="/discussions/:titleSlug" element={<Discussions />} />
        <Route path="/solution/:id" element={<SolutionDetail />} />
        <Route path="/profile" element={<UserProfile />} />
        <Route path="/user/:id" element={<FriendsProfile />} />
        <Route path="/bookmarks" element={<Bookmarks/>} />
        <Route path="/code-editor" element={<SoloCodeEditor />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
