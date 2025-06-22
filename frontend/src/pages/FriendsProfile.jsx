import React, { useState,useEffect } from 'react';
import '../styles/UserProfile.css';
import EditProfile from '../components/EditProfile';
import { useParams } from 'react-router-dom';

const FriendsProfile = () => {
  const [userData, setUserData] = useState({
    name: '',
    email: '',
    phoneNumber: '',
    profilePicture: '',
    codeforcesHandle: '',
    codeforcesRating: '',
    programmingLanguages: [],
    skills: []
  });
  const [cfInfo, setCfInfo] = useState(null);
  // Get query parameter from URL (e.g., ?id=123)
  const queryParams = new URLSearchParams(window.location.search);
  const {id} = useParams();
  const userId = id;

  // Fetch user data (replace with your actual API call)
  useEffect(() => {
    const fetchUserData = async () => {
      try {
        const res = await fetch(`http://localhost:3000/user/${userId}`,
          {
            method: 'GET',
            headers: {
              'Content-Type': 'application/json',
            },
          }
        );
        const data = await res.json();
        setUserData(data);
        if (data.codeforcesHandle) {
          fetchCodeforcesInfo(data.codeforcesHandle);
        }
      } catch (error) {
        console.error('Error fetching user data:', error);
      }
    };
    fetchUserData();
  }, []);

  // Fetch Codeforces info (handles array response)
  const fetchCodeforcesInfo = async (handle) => {
    try {
      const res = await fetch(`https://competeapi.vercel.app/user/codeforces/${handle}/`);
      const data = await res.json();
      // If data is an array, use first element; else use data itself
      const info = Array.isArray(data) ? data[0] : data;
      setCfInfo(info);
      // Optional: Also update codeforcesRating in userData if you want to store it
      // setUserData(prev => ({ ...prev, codeforcesRating: info?.rating ?? '' }));
    } catch (error) {
      console.error('Error fetching Codeforces info:', error);
      setCfInfo(null); // Clear on error
    }
  };

  return (
    <div className="profile-container">
      <h1 style={{ textAlign: 'center', marginBottom: '1.5rem' }}>Profile Page</h1>
      <div className="profile-box">
        <div className="profile-picture-box">
          <img
            src={
              userData.profilePicture && userData.profilePicture.trim() !== ""
                ? userData.profilePicture
                : "https://static.vecteezy.com/system/resources/thumbnails/019/879/186/small_2x/user-icon-on-transparent-background-free-png.png"
            }
            alt="Profile"
            className="profile-pic"
            onError={(e) => {
              e.target.onerror = null;
              e.target.src = "https://static.vecteezy.com/system/resources/thumbnails/019/879/186/small_2x/user-icon-on-transparent-background-free-png.png";
            }}
          />
        </div>
        <div className="info-box">
          <div className="user-details-box">
            <h2>{userData.name}</h2>
            <p>{userData.email}</p>
            <p>{userData.phoneNumber}</p>
          </div>
          <div className="codeforces-box">
            <h3>Codeforces Handle: {userData.codeforcesHandle || 'Not set'}</h3>
            <p>Rating: {cfInfo?.rating ?? 'N/A'}</p>
          </div>
          <div className="skills-box">
            <h3>Programming Languages</h3>
            {userData.programmingLanguages.length > 0 ? (
              <ul>
                {userData.programmingLanguages.map((lang, i) => (
                  <li key={i}>{lang}</li>
                ))}
              </ul>
            ) : <p>No languages listed</p>}
            <h3>Skills</h3>
            {userData.skills.length > 0 ? (
              <ul>
                {userData.skills.map((skill, i) => (
                  <li key={i}>{skill}</li>
                ))}
              </ul>
            ) : <p>No skills listed</p>}
          </div>
        </div>
      </div>
    </div>
  );
};

export default FriendsProfile;

