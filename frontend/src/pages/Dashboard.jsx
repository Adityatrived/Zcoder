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

function Dashboard() {
  const navigate = useNavigate();
  const [problems, setProblems] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  // Initialize state from localStorage if not there initially then set defaults.

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

  const [problemLimit, setProblemLimit] = useState(() => {
    const saved = localStorage.getItem('problemLimit');
    return saved ? parseInt(saved) : 100;
  });

  const [searchQuery, setSearchQuery] = useState(() => {
    return localStorage.getItem('searchQuery') || '';
  });

  // below 6 useeffects.
  // Save to localStorage on state changes
  //so user can still have acccess to his recent 
  //filters.
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
    localStorage.setItem('problemLimit', problemLimit.toString());
  }, [problemLimit]);

  useEffect(() => {
    localStorage.setItem('searchQuery', searchQuery);
  }, [searchQuery]);

  // Fetch problems
  useEffect(() => {
    async function fetchProblems() {
      setIsLoading(true);
      try {
        const response = await axios.get(
          `https://leetcode-api-mu.vercel.app/problems?limit=${Math.min(problemLimit, 3000)}`
        );
        setProblems(response.data.problemsetQuestionList);
      } catch (error) {
        console.error("Error fetching problems:", error);
      } finally {
        setIsLoading(false);
      }
    }

    fetchProblems();
  }, [problemLimit]);

  // Validate JWT token
  useEffect(() => {
    const jwtoken = localStorage.getItem("jwtoken");
    if (!jwtoken) {
      navigate("/login");
    }
  }, [navigate]);
  
  //navigate to problem details
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

  const handleLimitChange = (e) => {
    const value = Math.min(Number(e.target.value), 3000);
    setProblemLimit(value);
  };

  const handleRandomProblem = () => {
    if (filteredProblems.length === 0) return;
    //select random problem
    const randomIndex = Math.floor(Math.random() * filteredProblems.length);
    const randomProblem = filteredProblems[randomIndex];
    navigate(`/problem/${randomProblem.titleSlug}`);
  };
  
  //reset all the filters.
  const clearAllFilters = () => {
    setSelectedTags([]);
    setSelectedDifficulties([]);
    setFilterMode('OR');
    setProblemLimit(100);
    setSearchQuery('');
  };

  const filteredProblems = problems.filter((problem) => {
    //filter by tags
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
      <h1>Problems</h1>

      <div className="search-bar-container">
        <input
          type="text"
          placeholder="Search problems by title or ID..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="search-input"
        />
      </div>

      <div className="controls-section">
        <div className="problem-limit-control">
          <label htmlFor="problemLimit">Number of Problems:</label>
          <input
            type="number"
            id="problemLimit"
            min="10"
            max="3000"
            value={problemLimit}
            onChange={handleLimitChange}
            className="limit-input"
          />
          <span>(Max: 3000)</span>
        </div>

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

        <button 
          onClick={()=>{
            navigate('/bookmarks')
          }}
          className="bookmarks"
        >
         Bookmarks
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
          Pick Random Problem
        </button>
      </div>

      <div className="problems-container">
        {isLoading ? (
          <div className="loading">Loading problems...</div>
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
                />
              </li>
            ))}
          </ul>
        ) : (
          <div className="no-problems">No problems found matching your criteria.</div>
        )}
      </div>
    </div>
  );
}

export default Dashboard;