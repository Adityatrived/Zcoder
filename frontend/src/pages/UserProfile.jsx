// 06-06-2025 5:30 pm 
import React, { useState, useEffect } from 'react';
import '../styles/UserProfile.css';
import EditProfile from '../components/EditProfile';
import Toast from '../components/Toast';

const UserProfile = () => {

  const [userData, setUserData] = useState({
    name: '',
    email: '',
    phoneNumber: '',
    profilePicture: '',
    role: '',
    location: '',
    skills: [],
    degrees: [],
    experience: [],
    languages: [],
    codeforcesHandle: '',
  });

  const [cfInfo, setCfInfo] = useState(null);
  const [isEditing, setIsEditing] = useState(false);
  const [toastMessage, setToastMessage] = useState('');
  const [showToast, setShowToast] = useState(false);

  // Auto-dismiss toast after 3 seconds
  useEffect(() => {
    if (showToast) {
      const timer = setTimeout(() => setShowToast(false), 3000);
      return () => clearTimeout(timer);
    }
  }, [showToast]);

  // Fetch user profile data
  useEffect(() => {
    const fetchUserData = async () => {
      const jwtoken = localStorage.getItem('jwtoken');
      try {
        const res = await fetch('http://localhost:3000/user/profile', {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${jwtoken}`
          },
        });

        if (!res.ok) throw new Error('Failed to fetch profile');

        const data = await res.json();
        const receivedData = data.user || data;

        // Ensure all array fields exist and are arrays
        setUserData({
          name: receivedData.name || '',
          email: receivedData.email || '',
          phoneNumber: receivedData.phoneNumber || '',
          profilePicture: receivedData.profilePicture || '',
          role: receivedData.role || '',
          location: receivedData.location || '',
          skills: Array.isArray(receivedData.skills) ? receivedData.skills : [],
          degrees: Array.isArray(receivedData.degrees) ? receivedData.degrees : [],
          experience: Array.isArray(receivedData.experience) ? receivedData.experience : [],
          languages: Array.isArray(receivedData.languages) ? receivedData.languages : [],
          codeforcesHandle: receivedData.codeforcesHandle || '',
        });

        if (receivedData.codeforcesHandle) {
          fetchCodeforcesInfo(receivedData.codeforcesHandle);
        }
      } catch (error) {
        console.error('Error fetching user data:', error);
        setToastMessage('Failed to load profile data');
        setShowToast(true);
      }
    };

    fetchUserData();
  }, []);

  // Fetch Codeforces info
  const fetchCodeforcesInfo = async (handle) => {
    try {
      const res = await fetch(`https://competeapi.vercel.app/user/codeforces/${handle}/`);
      const data = await res.json();
      setCfInfo(Array.isArray(data) ? data[0] : data);
    } catch (error) {
      setCfInfo(null);
    }
  };

  // Edit profile
  const handleEdit = () => setIsEditing(true);

  // Update profile
  const handleProfileUpdate = async (updatedData) => {
    try {
      const jwtoken = localStorage.getItem('jwtoken');
      const res = await fetch('http://localhost:3000/user/profile/update', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${jwtoken}`,
        },
        body: JSON.stringify(updatedData),
      });
      if (!res.ok) throw new Error('Failed to update profile');
      const data = await res.json();
      const receivedData = data.user || data;
      setUserData({
        name: receivedData.name || '',
        email: receivedData.email || '',
        phoneNumber: receivedData.phoneNumber || '',
        profilePicture: receivedData.profilePicture || '',
        role: receivedData.role || '',
        location: receivedData.location || '',
        skills: Array.isArray(receivedData.skills) ? receivedData.skills : [],
        degrees: Array.isArray(receivedData.degrees) ? receivedData.degrees : [],
        experience: Array.isArray(receivedData.experience) ? receivedData.experience : [],
        languages: Array.isArray(receivedData.languages) ? receivedData.languages : [],
        codeforcesHandle: receivedData.codeforcesHandle || '',
      });
      setIsEditing(false);
      setToastMessage('Profile updated successfully!');
      setShowToast(true);
      if (receivedData.codeforcesHandle) {
        fetchCodeforcesInfo(receivedData.codeforcesHandle);
      }
    } catch (error) {
      setToastMessage('Failed to update profile. Please try again.');
      setShowToast(true);
    }
  };

  // Render EditProfile if editing
  if (isEditing) {
    return <EditProfile userData={userData} onUpdate={handleProfileUpdate} />;
  }

  // Render UserProfile
  return (
    <div className="profile-main-container">
      <div className="profile-header">
        <img
          src={
            userData.profilePicture && userData.profilePicture.trim() !== ""
              ? userData.profilePicture
              : "https://static.vecteezy.com/system/resources/thumbnails/019/879/186/small_2x/user-icon-on-transparent-background-free-png.png"
          }
          alt="Profile"
          className="profile-avatar"
        />
        <div className="profile-header-info">
          <h1>{userData.name || 'Your Name'}</h1>
          <h2>{userData.role || 'Your Role'}</h2>
          <div className="profile-contact">
            <span>{userData.email}</span>
            <span>{userData.phoneNumber}</span>
            <span>{userData.location}</span>
          </div>
        </div>
        <button className="edit-btn" onClick={handleEdit}>Edit Profile</button>
      </div>

      <div className="profile-sections">

        {/* Degrees Section */}
        <section className="profile-section degrees">
          <h3>Education</h3>
          <div className="degree-list">
            {userData.degrees.map((deg, idx) => (
              <div className="degree-card" key={idx}>
                {deg.title || 'Degree Title'}<br />
                <span>{deg.institution || 'Institution'}</span>
              </div>
            ))}
          </div>
        </section>


        {/* Skills Section */}
        <section className="profile-section skills">
          <h3>My Skills</h3>
          <ul>
            {userData.skills.map((skill, idx) => (
              <li key={idx}>
                <span>{skill.name || 'Skill Name'}</span>
                <div className="skill-bar">
                  <div className="skill-bar-fill" style={{ width: `${skill.level || 0}%` }}></div>
                </div>
              </li>
            ))}
          </ul>
        </section>

        {/* Experience Section */}
        <div className="experience-list">
          {userData.experience.map((exp, idx) => (
            <div className="exp-card" key={idx}>
              <h4>Experience #{idx + 1}</h4> {/* Add heading for each card */}
              <div>
                <strong>{exp.role || 'Role '}</strong>
                <span>{exp.period ? `${exp.period}` : ' '}</span>
              </div>
              <p>{exp.company || 'Company'}</p>
            </div>
          ))}
        </div>

        {/* Languages Section */}
        <section className="profile-section languages">
          <h3>Programming Languages</h3>
          <div className="languages-list">
            {userData.languages.map((lang, idx) => (
              <div className="language-card" key={idx}>
                <div className="lang-percentage">{lang.level || 0}%</div>
                <div className="lang-name">{lang.name || 'Language'}</div>
                <div className="lang-fluency">{lang.fluency || 'Fluency'}</div>
              </div>
            ))}
          </div>
        </section>

        {/* Codeforces Section */}
        {userData.codeforcesHandle && (
          <section className="profile-section codeforces">
            <h3>Codeforces Info</h3>
            {cfInfo ? (
              <div className="cf-info">
                <div><strong>Handle:</strong> <a href={`https://codeforces.com/profile/${userData.codeforcesHandle}`} target="_blank" rel="noopener noreferrer">{userData.codeforcesHandle}</a></div>
                <div><strong>Rating:</strong> {cfInfo.rating || 'N/A'}</div>
                <div><strong>Rank:</strong> {cfInfo.rank || 'N/A'}</div>
                <div><strong>Max Rating:</strong> {cfInfo.maxRating || 'N/A'}</div>
                <div><strong>Max Rank:</strong> {cfInfo.maxRank || 'N/A'}</div>
              </div>
            ) : (
              <div className="cf-info">No Codeforces data found.</div>
            )}
          </section>
        )}
      </div>

      {showToast && (
        <Toast message={toastMessage} onClose={() => setShowToast(false)} />
      )}
    </div>
  );
};

export default UserProfile;
