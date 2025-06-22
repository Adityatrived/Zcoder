import React, { useState } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import "./Header.css";
import Logo from '../assets/logo-noBg.png';

function Header() {
  const navigate = useNavigate();
  const [menuOpen, setMenuOpen] = useState(false);

  const handleLogout = () => {
    localStorage.clear();
    navigate("/login");
  };

  const handleHamburgerClick = () => {
    setMenuOpen((prev) => !prev);
  };

  // Optional: close menu after clicking a link (especially on mobile)
  const handleLinkClick = () => {
    setMenuOpen(false);
  };

  const changeTheme = ()=>{
    const body = document.body;
    console.log(body);
    const currentTheme = localStorage.getItem("theme") || "style-1";
    const newTheme = "style-" + (currentTheme.split("-")[1] % 3 +1);
    localStorage.setItem("theme", newTheme);
    body.classList = newTheme;
  }

  return (
    <header className="navbar">
      <nav>
        <button
          className={`hamburger${menuOpen ? " active" : ""}`}
          aria-label="Toggle navigation menu"
          aria-expanded={menuOpen}
          onClick={handleHamburgerClick}
          type="button"
        >
          <span></span>
          <span></span>
          <span></span>
        </button>
        <ul className={`nav-links${menuOpen ? " show" : ""}`}>
          <li><NavLink to="/" onClick={handleLinkClick}>Home</NavLink></li>
          <li><NavLink to="/dashboard" onClick={handleLinkClick}>Dashboard</NavLink></li>
          <li><NavLink to="/rooms" onClick={handleLinkClick}>Rooms</NavLink></li>
          <li><NavLink to="/code-editor" onClick={handleLinkClick}>Online IDE</NavLink></li>
        </ul>
          <img src={Logo} alt="Logo" className="nav-logo" onClick={changeTheme}/>
        <ul className={`nav-links${menuOpen ? " show" : ""}`}>
          <li><NavLink to="/calendar" onClick={handleLinkClick}>Calender</NavLink></li>
          <li><NavLink to="/askAi" onClick={handleLinkClick}>Ask AI</NavLink></li>
          <li><NavLink to="/profile" onClick={handleLinkClick}>Profile</NavLink></li>
          <li className="logout-btn">
            <NavLink to="/login" onClick={() => { handleLogout(); handleLinkClick(); }}>Logout</NavLink>
          </li>
        </ul>
      </nav>
    </header>
  );
}

export default Header;
