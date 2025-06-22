import logo from "../assets/logo-bg.png";
import { useNavigate } from "react-router-dom";
import { useState } from "react";
import "../styles/Login.css";

function LoginPage() {
  const [hide, setHide] = useState(true);
  const navigate = useNavigate();
  const togglePassword = () => {
    setHide(!hide);
  };

  const formSubmitted = async (event) => {
    event.preventDefault();
    const form = document.getElementById("login-form");
    const formData = new FormData(form);
    const data = Object.fromEntries(formData.entries());
    form.reset();
    setHide(true);
    try {
      const response = await fetch(`http://localhost:3000/login/`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(data),
      });
      const result = await response.json(); // Parse JSON response

      if (response.ok) {
        localStorage.setItem("jwtoken", result.token); // Store token from response
        navigate("/");
      } else {
        console.error("Login failed:", result.error);
        alert(result.error || "Login failed");
      }
    } catch (error) {
      console.error("Network error:", error);
      alert("Network error, please try again later.");
    }
  };

  return (
    <div className="App">
      <div className="register-container">
        <div>
          <img src={logo} alt="Sholarseek Logo" className="logo" />
        </div>
        <form id="login-form" onSubmit={formSubmitted} >
          <div className="form-group">
            <label htmlFor="username" className="form-label">
              USERNAME
            </label>
            <input
              type="text"
              className="form-input"
              id="username"
              name="username"
              placeholder="Username"
              
              required
            />
          </div>
          <div className="form-group">
            <label htmlFor="password" className="form-label">
              PASSWORD
            </label>
            <input
              type={hide ? "password" : "text"}
              id="password"
              className="form-input"
              name="password"
              placeholder="Password"
              required
            />
          </div>
          <div className="checkbox-container" >
            <input
              type="checkbox"
              className="checkbox"
              id="showpassword"
              onChange={togglePassword}
            />
            <label htmlFor="showpassword" className="checkbox-label">
              Show Password
            </label>
          </div>
          <button type="Submit" className="login-button">
            Login
          </button>
        </form>
      </div>
      <div className="login-footer">
        <p>
          Don't have an account? <a href="/register">Register</a>
        </p>
      </div>
    </div>
  );
}

export default LoginPage;