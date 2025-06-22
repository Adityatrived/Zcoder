import { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import axios from "axios";
import "../styles/solutiondetail.css";

const SolutionDetail = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [solution, setSolution] = useState(null);
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [isDeleting, setIsDeleting] = useState(false);

  // Check authentication and fetch user data
  useEffect(() => {
    const jwtoken = localStorage.getItem("jwtoken");
    if (!jwtoken) {
      navigate("/login");
      return;
    }

    const fetchUser = async () => {
      try {
        const res = await axios.get(`${import.meta.env.VITE_BACKEND_URL}/api/auth/me`, {
          headers: { Authorization: `Bearer ${jwtoken}` },
        });
        setUser(res.data);
      } catch (err) {
        console.error("Failed to fetch user", err);
      }
    };
    fetchUser();
  }, [navigate]);

  // Fetch solution data
  useEffect(() => {
    const fetchSolution = async () => {
      try {
        const res = await axios.get(
          `${import.meta.env.VITE_BACKEND_URL}/api/solutions/detail/${id}`
        );
        setSolution(res.data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };
    
    if (id) {
      fetchSolution();
    }
  }, [id]);

  const handleDeleteSolution = async () => {
    if (!window.confirm("Are you sure you want to delete this solution?")) {
      return;
    }

    setIsDeleting(true);
    try {
      const token = localStorage.getItem("jwtoken");
      await axios.delete(`${import.meta.env.VITE_BACKEND_URL}/api/solutions/${id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      alert("Solution deleted successfully");
      navigate(-1); // Go back to previous page after deletion
    } catch (err) {
      console.error("Delete error:", err);
      alert(err.response?.data?.error || "Failed to delete solution");
    } finally {
      setIsDeleting(false);
    }
  };

  if (loading) return <div className="loading">Loading...</div>;
  if (error) return <div className="error">Error: {error}</div>;
  if (!solution) return <div className="not-found">Solution not found</div>;

  return (
    <div className="solution-detail">
      <div className="solution-actions">
        <button onClick={() => navigate(-1)} className="back-button">
          ← Back
        </button>
        {user && solution.author?._id === user._id && (
          <button 
            onClick={handleDeleteSolution} 
            className="delete-btn"
            disabled={isDeleting}
          >
            {isDeleting ? "Deleting..." : "Delete Solution"}
          </button>
        )}
      </div>
      
      <div className="solution-header">
        <h2>Solution by {solution.author?.Username || "Anonymous"}</h2>
        <span className="votes">Votes: {solution.votes || 0}</span>
      </div>
      
      <div className="solution-meta">
        <span>Language: {solution.language || "Not specified"}</span>
        <span>
          Posted: {solution.createdAt 
            ? new Date(solution.createdAt).toLocaleDateString() 
            : "Date not available"}
        </span>
      </div>
      
      <pre className="solution-code">
        <code>{solution.code || "No code available"}</code>
      </pre>
    </div>
  );
};

export default SolutionDetail;