// src/components/Discussions.js
import { useState, useEffect } from "react";
import { useNavigate, useParams } from "react-router-dom";
import axios from "axios";
// import Loader from "./Loader";
import "../styles/Discussion.css";
const backend = import.meta.env.VITE_BACKEND_URL ;

const Discussions = () => {
  const navigate = useNavigate();
  const { titleSlug } = useParams();
  const [solutions, setSolutions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const backend = import.meta.env.VITE_BACKEND_URL;

  useEffect(() => {
    // Redirect to the login page if the user is not authenticated
    const jwtoken = localStorage.getItem("jwtoken");
    if (jwtoken === null || jwtoken === undefined) {
      navigate("/login");
    }
  });

  useEffect(() => {
    const fetchSolutions = async () => {
      try {
        const res = await axios.get(`http://localhost:3000/api/solutions/${titleSlug}`);
        setSolutions(res.data);
      } catch (err) {
        setError(err.response?.data?.message || err.message);
      } finally {
        setLoading(false);
      }
    };
    fetchSolutions();
  }, [titleSlug]);

  const handleVote = async (solutionId, voteType) => {
    try {
      await axios.post(`http://localhost:3000/api/solutions/vote`, {
        solutionId,
        voteType,
      });
      setSolutions(
        solutions.map((sol) =>
          sol._id === solutionId
            ? {
                ...sol,
                votes: voteType === "upvote" ? sol.votes + 1 : sol.votes - 1,
              }
            : sol
        )
      );
    } catch (err) {
      setError(err.response?.data?.message || err.message);
    }
  };

  if (loading) return <>Loading...</>;
  if (error) return <div className="error-message">{error}</div>;

  return (
    <div className="discussions-container">
      <h1>Solutions for {titleSlug}</h1>
      <div className="solutions-list">
        {solutions.length === 0 ? (
          <p>No solutions submitted yet. Be the first one!</p>
        ) : (
          solutions.map((solution) => (
            <div
              key={solution._id}
              className="solution-card"
              onClick={() => navigate(`/solution/${solution._id}`)}
            >
              <div className="solution-header">
                <span className="author">{solution.author.Username}</span>
                <span className="votes">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      handleVote(solution._id, "upvote");
                    }}
                    className="vote-btn"
                  >
                    ↑
                  </button>
                  {solution.votes}
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      handleVote(solution._id, "downvote");
                    }}
                    className="vote-btn"
                  >
                    ↓
                  </button>
                </span>
                <span className="date">
                  {new Date(solution.createdAt).toLocaleDateString()}
                </span>
              </div>
              <pre className="solution-code">
                <code>{solution.code.substring(0, 20)}...</code>
              </pre>
              <div className="solution-footer">
                <span className="language">{solution.language}</span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default Discussions;
