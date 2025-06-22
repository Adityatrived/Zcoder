import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { LuGithub, LuArrowBigRightDash } from "react-icons/lu";
import "../styles/Home.css";
import logo from "../assets/logo-noBg.png";

function Home() {
  const navigate = useNavigate();
  const [users, setUsers] = useState([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [activeFeature, setActiveFeature] = useState(0);

  useEffect(() => {
    const jwtoken = localStorage.getItem("jwtoken");
    if (!jwtoken) {
      navigate("/login");
    }
  }, [navigate]);

  const searched = (e) => {
    const query = e.target.value;
    setSearchQuery(query);
    
    if (query.length > 0) {
      const searchTimer = setTimeout(async () => {
        try {
          const response = await fetch(`http://localhost:3000/users/${query}`);
          if(!response.ok) {
            setUsers('No users found');
          }else{
            const data = await response.json();
            setUsers(data);
          }
        } catch (error) {
          console.error("Search error:", error);
        }
      }, 1000);
      
      return () => clearTimeout(searchTimer);
    } else {
      setUsers([]);
    }
  };

  const features = [
    { 
      icon: "👤", 
      title: "Personal Profile", 
      desc: "Track your progress and showcase your coding achievements.",
      route: "/profile",
      color: "var(--feature-1)"
    },
    { 
      icon: "💬", 
      title: "Collaborative Rooms", 
      desc: "Real-time coding and chat with other developers.",
      route: "/rooms",
      color: "var(--feature-2)"
    },
    { 
      icon: "📅", 
      title: "Contest Calendar", 
      desc: "Never miss important coding competitions and hackathons.",
      route: "/calendar",
      color: "var(--feature-3)"
    },
    { 
      icon: "🤖", 
      title: "AI Assistant", 
      desc: "Get instant help with your coding questions.",
      route: "/askAI",
      color: "var(--feature-4)"
    },
    { 
      icon: "💻",
      title: "Inbuilt Code-Editor",
      desc: "Write, test, and debug your code directly in the browser.",
      route: "code-editor",
      color: "var(--feature-5)"
    }
  ];

  return (
    <>
    <div className="particle-container">
        {[...Array(25)].map((_, i) => (
          <div className="particle"
            key={i}
            style={{ width: Math.random() * 28 + "px", top: 10 + Math.random() * 90 + "vh", left: Math.random() * 100 + "vw", animationDelay: Math.random() * 5 + "s" }}
          >
          </div>
        ))}
      </div>
    <div className="home-page">
      {/* Hero Section */}
      <main className="main-content">
        <section className="hero-section">
          <div className="hero-text">
            <h1>
              <span className="highlight">Code</span> Without Limits
            </h1>
            <p className="subtitle">
              A streamlined platform for developers to learn, create, and connect.
            </p>
            <div className="cta-buttons">
              <button 
                className="primary-btn"
                onClick={() => navigate("/dashboard")}
              >
                Start Coding
              </button>
              <button 
                className="secondary-btn"
                onClick={() => navigate("/rooms")}
              >
                Join Rooms
              </button>
            </div>
          </div>
          <div className="user-search">
            <input type="search" placeholder="Search User" className="user-search-input" onChange={searched}/>
            <div className="search-results">
              {users==='No users found' ? users : (
                <ul className="user-list">
                  {users.map((user, index) => (
                    <li key={index} className="user-item">
                      <img src={user.profilePicture || "https://static.vecteezy.com/system/resources/thumbnails/019/879/186/small_2x/user-icon-on-transparent-background-free-png.png"}
                      alt={`${user.name}'s avatar`}
                      className="user-avatar" 
                      />
                      <span className="user-name">{user.username}</span>
                    </li>
                  ))}
                </ul>
              )}
              </div>
          </div>
        </section>

        {/* Features Section */}
        <section className="features-section" id="features">
          <h2 className="section-title">Core Features</h2>
          <div className="features-container">
            <div className="feature-tabs">
              {features.map((feature, index) => (
                <div 
                  key={index}
                  className={`feature-tab ${activeFeature === index ? 'active' : ''}`}
                  onClick={() => {
                    setActiveFeature(index);
                  }}
                  style={{ '--feature-color': feature.color }}
                >
                  <span className="feature-icon">{feature.icon}</span>
                  <span className="feature-title">{feature.title}</span>
                </div>
              ))}
            </div>
            <div className="feature-content">
              {activeFeature !== null && (
                <div className="feature-detail">
                  <h3>{features[activeFeature].title}</h3>
                  <p>{features[activeFeature].desc}</p>
                  <button 
                    className="explore-btn"
                    onClick={() => navigate(features[activeFeature].route)}
                    ><LuArrowBigRightDash className="right-arrow"/></button>
                </div>
              )}
            </div>
          </div>
        </section>

        {/* Stats Section */}
        <section className="stats-section">
          <div className="stats-box">
            <div className="stats-grid">
            <div className="stat-card">
              <h3>3000+</h3>
              <p>Problems</p>
            </div>
            <div className="stat-card">
              <h3>24/7</h3>
              <p>Rooms</p>
            </div>
            <div className="stat-card">
              <h3>Always</h3>
              <p>Updated</p>
            </div>
            <div className="stat-card">
              <h3>Instant</h3>
              <p>AI Help</p>
            </div>
            <div className="stat-card">
              <h3>3000+</h3>
              <p>Problems</p>
            </div>
            <div className="stat-card">
              <h3>24/7</h3>
              <p>Rooms</p>
            </div>
            <div className="stat-card">
              <h3>Always</h3>
              <p>Updated</p>
            </div>
            <div className="stat-card">
              <h3>Instant</h3>
              <p>AI Help</p>
            </div>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="site-footer">
        <div className="footer-content">
          <div className="footer-brand">
            <img src={logo} alt="Zcoder logo" />
          </div>
          <div className="footer-links">
            <button>About</button>
            <a href="#features"><button>Features</button></a>
            <button>Contact</button>
          </div>
          <div className="footer-social">
            <a href="https://github.com/chethanreddy10/ZCoder" target="_blank" rel="noreferrer">
              <LuGithub />
            </a>
          </div>
        </div>
        <div className="copyright">
          <p>© 2025 Zcoder. All rights reserved.</p>
        </div>
      </footer>
    </div>
    </>
  );
}

export default Home;
