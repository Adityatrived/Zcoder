import axios from "axios";
import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import ProblemCard from "../components/Problemcard";
import "../styles/Dashboard.css";

const STATIC_TAGS = [
  "Array",
  "String",
  "Hash Table",
  "Dynamic Programming",
  "Math",
  "Sorting",
  "Greedy",
  "Depth-First Search",
  "Binary Search",
  "Database",
  "Matrix",
  "Tree",
  "Breadth-First Search",
  "Bit Manipulation",
  "Two Pointers",
  "Prefix Sum",
  "Heap (Priority Queue)",
  "Simulation",
  "Binary Tree",
  "Stack",
  "Graph",
  "Counting",
  "Sliding Window",
  "Design",
  "Enumeration",
  "Backtracking",
  "Union Find",
  "Linked List",
  "Ordered Set",
  "Number Theory",
  "Monotonic Stack",
  "Segment Tree",
  "Trie",
  "Combinatorics",
  "Bitmask",
  "Queue",
  "Divide and Conquer",
  "Recursion",
  "Binary Indexed Tree",
  "Memoization",
  "Hash Function",
  "Geometry",
  "Binary Search Tree",
  "String Matching",
  "Topological Sort",
  "Shortest Path",
  "Rolling Hash",
  "Game Theory",
  "Interactive",
  "Data Stream",
  "Monotonic Queue",
  "Brainteaser",
  "Doubly-Linked List",
  "Randomized",
  "Merge Sort",
  "Counting Sort",
  "Iterator",
  "Concurrency",
  "Probability and Statistics",
  "Quickselect",
  "Suffix Array",
  "Line Sweep",
  "Bucket Sort",
  "Minimum Spanning Tree",
  "Shell",
  "Reservoir Sampling",
  "Strongly Connected Component",
  "Eulerian Circuit",
  "Radix Sort",
  "Rejection Sampling",
  "Biconnected Component",
];

function Bookmarks() {
  const navigate = useNavigate();
  const [problems, setProblems] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [selectedTags, setSelectedTags] = useState(() => {
    const saved = localStorage.getItem('selectedTags');
    return saved ? JSON.parse(saved) : [];
  });
  const [selectedDifficulties, setSelectedDifficulties] = useState(() => {
    const saved = localStorage.getItem('selectedDifficulties');
    return saved ? JSON.parse(saved) : [];
  });
  const [filterMode, setFilterMode] = useState(() => {
    return localStorage.getItem('filterMode') || 'OR';
  });
  const [searchQuery, setSearchQuery] = useState(() => {
    return localStorage.getItem('searchQuery') || '';
  });

  // Save to localStorage on state changes
  useEffect(() => {
    localStorage.setItem('selectedTags', JSON.stringify(selectedTags));
  }, [selectedTags]);

  useEffect(() => {
    localStorage.setItem('selectedDifficulties', JSON.stringify(selectedDifficulties));
  }, [selectedDifficulties]);

  useEffect(() => {
    localStorage.setItem('filterMode', filterMode);
  }, [filterMode]);

  useEffect(() => {
    localStorage.setItem('searchQuery', searchQuery);
  }, [searchQuery]);

  useEffect(() => {
    // Fetch bookmarks from the backend
    async function fetchBookmarks() {
      setIsLoading(true);
      try {
        const response = await fetch("http://localhost:3000/bookmarks", {
          method: "GET",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${localStorage.getItem("jwtoken")}`,
          },
        });
        const data = await response.json();
        const bookmarks = data.bookmarks;
        const resp = await axios.get(
          `https://leetcode-api-mu.vercel.app/problems?limit=500`
        );
        const allProblems = resp.data.problemsetQuestionList;
        const bookmarkedProblems = allProblems.filter(problem =>
          bookmarks.includes(problem.titleSlug)
        );
        setProblems(bookmarkedProblems);
      } catch (error) {
        console.error("Error fetching bookmarks:", error);
      } finally {
        setIsLoading(false);
      }
    }
    fetchBookmarks();
  }, []);

  useEffect(() => {
    // Redirect to the login page if the user is not authenticated
    const jwtoken = localStorage.getItem("jwtoken");
    if (!jwtoken) {
      navigate("/login");
    }
  }, [navigate]);

  const handleCardClick = (titleSlug) => {
    navigate(`/problem/${titleSlug}`);
  };

  const toggleTag = (tag) => {
    setSelectedTags((prev) =>
      prev.includes(tag) ? prev.filter((t) => t !== tag) : [...prev, tag]
    );
  };

  const toggleDifficulty = (difficulty) => {
    setSelectedDifficulties((prev) =>
      prev.includes(difficulty)
        ? prev.filter((d) => d !== difficulty)
        : [...prev, difficulty]
    );
  };

  const handleRandomProblem = () => {
    if (filteredProblems.length === 0) return;
    const randomIndex = Math.floor(Math.random() * filteredProblems.length);
    const randomProblem = filteredProblems[randomIndex];
    navigate(`/problem/${randomProblem.titleSlug}`);
  };

  const clearAllFilters = () => {
    setSelectedTags([]);
    setSelectedDifficulties([]);
    setFilterMode('OR');
    setSearchQuery('');
  };

  const filteredProblems = problems.filter((problem) => {
    const tagFilterPassed = 
      selectedTags.length === 0 || 
      (filterMode === "OR"
        ? selectedTags.some((tag) => problem.topicTags.some((t) => t.name === tag))
        : selectedTags.every((tag) => problem.topicTags.some((t) => t.name === tag)));
    
    const searchFilterPassed = 
      searchQuery === "" || 
      problem.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      problem.questionFrontendId.toLowerCase().includes(searchQuery.toLowerCase());
    
    const difficultyFilterPassed = 
      selectedDifficulties.length === 0 ||
      selectedDifficulties.includes(problem.difficulty);

    return tagFilterPassed && searchFilterPassed && difficultyFilterPassed;
  });

  return (
    <div className="dashboard-container">
      <h1>Bookmarked Problems</h1>

      <div className="search-bar-container">
        <input
          type="text"
          placeholder="Search bookmarks by title or ID..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="search-input"
        />
      </div>

      <div className="controls-section">
        <div className="filter-mode-toggle">
          <p>Filter Mode:</p>
          <button 
            onClick={() => setFilterMode((prev) => (prev === "OR" ? "AND" : "OR"))}
            className={`mode-button ${filterMode === 'OR' ? 'or-mode' : 'and-mode'}`}
          >
            {filterMode} (Click to toggle)
          </button>
        </div>

        <button 
          onClick={clearAllFilters}
          className="clear-filters-button"
        >
          Clear All Filters
        </button>
      </div>

      <div className="difficulty-filters">
        <p>Filter by Difficulty:</p>
        <div className="difficulty-container">
          {['Easy', 'Medium', 'Hard'].map((difficulty) => (
            <button
              key={difficulty}
              className={`difficulty-button ${selectedDifficulties.includes(difficulty) ? "selected" : ""} ${difficulty.toLowerCase()}`}
              onClick={() => toggleDifficulty(difficulty)}
            >
              {difficulty}
            </button>
          ))}
        </div>
      </div>

      <div className="tag-filters">
        <p>Filter by Tags:</p>
        <div className="tag-container">
          {STATIC_TAGS.map((tag) => (
            <button
              key={tag}
              className={`tag-button ${selectedTags.includes(tag) ? "selected" : ""}`}
              onClick={() => toggleTag(tag)}
            >
              {tag}
            </button>
          ))}
        </div>
      </div>

      <div className="random-problem-container">
        <button 
          onClick={handleRandomProblem}
          disabled={filteredProblems.length === 0}
          className="random-problem-button"
        >
          Pick Random Bookmarked Problem
        </button>
      </div>

      <div className="problems-container">
        {isLoading ? (
          <div className="loading">Loading bookmarks...</div>
        ) : filteredProblems.length > 0 ? (
          <ul className="problem-list">
            {filteredProblems.map((problem) => (
              <li key={problem.questionFrontendId} className="problem-card">
                <ProblemCard
                  id={problem.questionFrontendId}
                  title={problem.title}
                  platform="Leetcode"
                  difficulty={problem.difficulty}
                  Accuracy={problem.acRate}
                  locked={problem.isPaidOnly}
                  onClick={() => handleCardClick(problem.titleSlug)}
                  titleSlug={problem.titleSlug}
                  onBookmarkToggle={(slug) => {
                    setProblems((prev) => prev.filter((p) => p.titleSlug !== slug));
                  }}
                />
              </li>
            ))}
          </ul>
        ) : (
          <div className="no-problems">
            {problems.length === 0 
              ? "You haven't bookmarked any problems yet."
              : "No bookmarks found matching your criteria."}
          </div>
        )}
      </div>
    </div>
  );
}

export default Bookmarks;