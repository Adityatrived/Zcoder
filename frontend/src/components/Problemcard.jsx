import React, { useState, useEffect } from "react";
import axios from "axios";
import { Bookmark, BookmarkCheck } from "lucide-react";
import "./Problemcard.css";

const ProblemCard = ({
  id,
  title,
  platform,
  difficulty,
  Accuracy,
  locked,
  tags,
  onClick,
  titleSlug,
  onBookmarkToggle //NEW function props.
}) => {
  const [isBookmarked, setIsBookmarked] = useState(false);

  useEffect(() => {
    const checkBookmark = async () => {
      try {
        const response = await axios.get("http://localhost:3000/bookmarks", {
          headers: { Authorization: `Bearer ${localStorage.getItem("jwtoken")}` },
        });
        setIsBookmarked(response.data.bookmarks.includes(titleSlug));
      } catch (error) {
        console.error("Error checking bookmark:", error);
      }
    };
    checkBookmark();
  }, [titleSlug]);

  const toggleBookmark = async (e) => {
    e.stopPropagation();
    try {
      await axios.post(
        "http://localhost:3000/bookmarks/toggle",
        { problemSlug: titleSlug },
        { headers: { Authorization: `Bearer ${localStorage.getItem("jwtoken")}` } }
      );
      setIsBookmarked((prev) => !prev);
      if (onBookmarkToggle) onBookmarkToggle(titleSlug); // NEW
    } catch (error) {
      console.error("Error toggling bookmark:", error);
    }
  };

  const getDifficultyColor = (difficulty) => {
    switch (difficulty) {
      case "Easy":
        return "green";
      case "Medium":
        return "orange";
      case "Hard":
        return "red";
      default:
        return "gray";
    }
  };

  return (
    <div className="problem-card" onClick={onClick}>
      <div className="card-header">
        <button
          onClick={toggleBookmark}
          className={`bookmark-button ${isBookmarked ? "bookmarked" : ""}`}
        >
          {isBookmarked ? <BookmarkCheck className="icon" /> : <Bookmark className="icon" />}
        </button>
        <span className="problem-title">{title}</span>
        {locked && <span className="locked-icon">🔒</span>}
      </div>

      <div className="card-info">
        <span className="platform">{platform}</span>
        <span
          className="difficulty"
          style={{ color: getDifficultyColor(difficulty) }}
        >
          {difficulty}
        </span>
        <span className="accuracy">Accuracy: {Accuracy.toFixed(2)}%</span>
      </div>

      {tags && tags.length > 0 && (
        <div className="tags">
          {tags.map((tag, index) => (
            <span className="tag" key={index}>
              {tag}
            </span>
          ))}
        </div>
      )}
    </div>
  );
};

export default ProblemCard;
