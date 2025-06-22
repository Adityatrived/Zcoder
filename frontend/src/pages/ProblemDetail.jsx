import { useState, useEffect, useRef } from "react";
import { useParams, useNavigate } from "react-router-dom";
import axios from "axios";
import ProbCodeEditor from "../components/ProbCodeEditor";
import "../styles/ProblemDetail.css";
import { Bookmark, BookmarkCheck } from "lucide-react";

const ProblemDetail = () => {
  const { titleSlug } = useParams();
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [code, setCode] = useState("");
  const [input, setInput] = useState("");
  const [submissionResult, setSubmissionResult] = useState(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isBookmarked, setIsBookmarked] = useState(false);
  const [isResizing, setIsResizing] = useState(false);
  const [leftPanelWidth, setLeftPanelWidth] = useState(50); // Track width as percentage

  const backend = import.meta.env.VITE_BACKEND_URL || "http://localhost:3000";
  const LEETCODE_API = `https://leetcode-api-mu.vercel.app/select?titleSlug=${titleSlug}`;

  useEffect(() => {
    const jwtoken = localStorage.getItem("jwtoken");
    if (!jwtoken) navigate("/login");
  }, [navigate]);

  useEffect(() => {
    async function fetchProblem() {
      try {
        const res = await axios.get(LEETCODE_API);
        setData(res.data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }
    fetchProblem();
  }, [titleSlug]);

  useEffect(() => {
    const checkBookmark = async () => {
      try {
        const token = localStorage.getItem("jwtoken");
        const res = await axios.get(`${backend}/bookmarks`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        setIsBookmarked(res.data.bookmarks.includes(titleSlug));
      } catch (err) {
        console.error("Error checking bookmark:", err);
      }
    };
    checkBookmark();
  }, [titleSlug, backend]);

  const containerRef = useRef(null);

  useEffect(() => {
    if (!isResizing) return;

    const handleMouseMove = (e) => {
      if (!containerRef.current) return;
      
      const containerRect = containerRef.current.getBoundingClientRect();
      const newLeftWidth = ((e.clientX - containerRect.left) / containerRect.width) * 100;
      const constrainedWidth = Math.min(Math.max(newLeftWidth, 20), 80);
      
      setLeftPanelWidth(constrainedWidth);
    };

    const handleMouseUp = () => {
      setIsResizing(false);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };

    document.addEventListener("mousemove", handleMouseMove);
    document.addEventListener("mouseup", handleMouseUp);

    // Set cursor styles when resizing starts
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';

    return () => {
      document.removeEventListener("mousemove", handleMouseMove);
      document.removeEventListener("mouseup", handleMouseUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };
  }, [isResizing]);

  const handleDividerMouseDown = (e) => {
    e.preventDefault();
    setIsResizing(true);
  };

  const handleSubmit = async () => {
    if (!code) return;
    setIsSubmitting(true);
    try {
      const token = localStorage.getItem("jwtoken");
      if (!token) throw new Error("No authentication token found. Please login.");
      const response = await axios.post(
        `${backend}/api/solutions/submit`,
        {
          problemSlug: titleSlug,
          code,
          language: "javascript",
        },
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );
      setSubmissionResult(response.data);
    } catch (err) {
      setError(err.response?.data?.message || err.message);
      if (err.response?.status === 401) navigate("/login");
    } finally {
      setIsSubmitting(false);
    }
  };

  const toggleBookmark = async () => {
    try {
      const token = localStorage.getItem("jwtoken");
      await axios.post(
        `${backend}/bookmarks/toggle`,
        { problemSlug: titleSlug },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setIsBookmarked((prev) => !prev);
    } catch (err) {
      console.error("Error toggling bookmark:", err);
    }
  };

  const handleViewDiscussions = () => {
    navigate(`/discussions/${titleSlug}`);
  };

  const getDifficultyClass = (difficulty) => {
    switch (difficulty) {
      case "Easy": return "difficulty-easy";
      case "Medium": return "difficulty-medium";
      case "Hard": return "difficulty-hard";
      default: return "";
    }
  };

  if (loading) return <>Loading...</>;
  if (error) return <div className="error-message">{error}</div>;

  return (
    <div className="app-container">
      <div className={`resizable-container ${isResizing ? 'resizing' : ''}`} ref={containerRef}>
        <div 
          className="panel left-panel" 
          style={{ width: `${leftPanelWidth}%`, minWidth: '250px', maxWidth: '80%' }}
        >
          {data && (
            <>
              <div className="problem-header">
                <h1 className="problem-title">{data.questionTitle}</h1>
                
               <button className="discussions-button" onClick={handleViewDiscussions}>
                  Discussions
                 </button>
                 
                <button
                  onClick={toggleBookmark}
                  className={`bookmark-button ${isBookmarked ? "bookmarked" : ""}`}
                >
                  {isBookmarked ? <BookmarkCheck /> : <Bookmark />}
                </button>
              </div>

              <h2 className="difficulty-text">
                Difficulty: <span className={getDifficultyClass(data.difficulty)}>
                  {data.difficulty}
                </span>
              </h2>

              <div
                className="question-content"
                dangerouslySetInnerHTML={{ __html: data.question }}
              />

              <h3 className="sample-tests-title">Sample Test Cases</h3>
              <pre className="sample-tests-box">{data.exampleTestcases}</pre>

              <div className="tags-container">
                {data.topicTags.map(tag => (
                  <span key={tag.name} className="tag">{tag.name}</span>
                ))}
              </div>
            </>
          )}
        </div>

        <div 
          className={`divider ${isResizing ? 'resizing' : ''}`}
          onMouseDown={handleDividerMouseDown}
        />

        <div 
          className="panel right-panel" 
          style={{ width: `${100 - leftPanelWidth}%`, minWidth: '250px', maxWidth: '80%' }}
        >
          <ProbCodeEditor
            value={code}
            onChange={setCode}
            inputValue={input}
            onInputChange={setInput}
          />

          <div className="action-buttons">
            <button
              className="submit-button"
              onClick={handleSubmit}
              disabled={isSubmitting}
            >
              {isSubmitting ? "Submitting..." : "Submit"}
            </button>
            {/* 
            <button className="discussions-button" onClick={handleViewDiscussions}>
              Discussions
            </button> */}
          </div>

          {submissionResult && (
            <div className={`submission-result ${submissionResult.passed ? "success" : "error"}`}>
              <h3>Result</h3>
              <p>{submissionResult.message}</p>
              {submissionResult.details && <pre>{submissionResult.details}</pre>}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ProblemDetail;