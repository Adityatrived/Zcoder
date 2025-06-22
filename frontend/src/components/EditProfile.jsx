// 06-06-2025 06:30 pm 

import React, { useState, useEffect } from 'react';

const EditProfile = ({ userData, onUpdate, showToast }) => {
  // Initialize form data with user info or defaults
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    phoneNumber: '',
    profilePicture: '',
    role: '',
    location: '',
    codeforcesHandle: '',
    skills: [],
    degrees: [],
    experience: [],
    languages: [],
    currentPassword: '',
    newPassword: '',
    confirmPassword: '',
  });

  // Fill form with user data on mount or when userData changes
  useEffect(() => {
    if (userData) {
      setFormData(prev => ({
        ...prev,
        ...userData,
        skills: userData.skills || [],
        degrees: userData.degrees || [],
        experience: userData.experience || [],
        languages: userData.languages || [],
        currentPassword: '',
        newPassword: '',
        confirmPassword: '',
      }));
    }
  }, [userData]);

  // Handle input changes for regular fields
  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  // --- Skill Management ---
  const addSkill = () => {
    setFormData(prev => ({
      ...prev,
      skills: [...prev.skills, { name: '', level: 80 }],
    }));
  };
  const removeSkill = (index) => {
    setFormData(prev => ({
      ...prev,
      skills: prev.skills.filter((_, i) => i !== index),
    }));
  };
  const handleSkillChange = (index, field, value) => {
    setFormData(prev => ({
      ...prev,
      skills: prev.skills.map((skill, i) =>
        i === index ? { ...skill, [field]: value } : skill
      ),
    }));
  };

  // --- Degree Management ---
  const addDegree = () => {
    setFormData(prev => ({
      ...prev,
      degrees: [...prev.degrees, { title: '', institution: '' }],
    }));
  };
  const removeDegree = (index) => {
    setFormData(prev => ({
      ...prev,
      degrees: prev.degrees.filter((_, i) => i !== index),
    }));
  };
  const handleDegreeChange = (index, field, value) => {
    setFormData(prev => ({
      ...prev,
      degrees: prev.degrees.map((deg, i) =>
        i === index ? { ...deg, [field]: value } : deg
      ),
    }));
  };

  // --- Experience Management ---
  const addExperience = () => {
    setFormData(prev => ({
      ...prev,
      experience: [...prev.experience, { role: '', period: '', company: '' }],
    }));
  };
  const removeExperience = (index) => {
    setFormData(prev => ({
      ...prev,
      experience: prev.experience.filter((_, i) => i !== index),
    }));
  };
  const handleExperienceChange = (index, field, value) => {
    setFormData(prev => ({
      ...prev,
      experience: prev.experience.map((exp, i) =>
        i === index ? { ...exp, [field]: value } : exp
      ),
    }));
  };

  // --- Language Management ---
  const addLanguage = () => {
    setFormData(prev => ({
      ...prev,
      languages: [...prev.languages, { name: '', level: 0, fluency: '' }],
    }));
  };
  const removeLanguage = (index) => {
    setFormData(prev => ({
      ...prev,
      languages: prev.languages.filter((_, i) => i !== index),
    }));
  };
  const handleLanguageChange = (index, field, value) => {
    setFormData(prev => ({
      ...prev,
      languages: prev.languages.map((lang, i) =>
        i === index ? { ...lang, [field]: value } : lang
      ),
    }));
  };

  // --- Handle Password Change ---

  const handlePasswordChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

 // Handle profile picture file input
  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = () => {
        setFormData((prev) => ({ ...prev, profilePicture: reader.result }));
      };
      reader.readAsDataURL(file);
    }
  };

  // --- Form Submission ---
  const handleSubmit = (e) => {
    e.preventDefault();
    onUpdate(formData);
  };

  // --- Render ---
  return (
    <div className="edit-profile-container">
      <h2>Edit Profile</h2>
      <form onSubmit={handleSubmit}>
        {/* Basic Info */}
        <div className="form-group">
          <label>Name</label>
          <input
            type="text"
            name="name"
            value={formData.name}
            onChange={handleInputChange}
          />
        </div>
        <div className="form-group">
          <label>Email</label>
          <input
            type="email"
            name="email"
            value={formData.email}
            onChange={handleInputChange}
          />
        </div>
        <div className="form-group">
          <label>Phone Number</label>
          <input
            type="text"
            name="phoneNumber"
            value={formData.phoneNumber}
            onChange={handleInputChange}
          />
        </div>
        <div className="form-group">
          <label>Profile Picture URL</label>
            <input type="file" accept="image/*" onChange={handleFileChange} />
        </div>
        <div className="form-group">
          <label>Role</label>
          <input
            type="text"
            name="role"
            value={formData.role}
            onChange={handleInputChange}
          />
        </div>
        <div className="form-group">
          <label>Location</label>
          <input
            type="text"
            name="location"
            value={formData.location}
            onChange={handleInputChange}
          />
        </div>
        <div className="form-group">
          <label>Codeforces Handle</label>
          <input
            type="text"
            name="codeforcesHandle"
            value={formData.codeforcesHandle}
            onChange={handleInputChange}
          />
        </div>

        {/* Skills */}
        <div className="form-group">
          <label>Skills</label>
          {formData.skills.map((skill, idx) => (
            <div key={idx} className="edit-array-item">
              <input
                type="text"
                placeholder="Skill Name"
                value={skill.name}
                onChange={(e) => handleSkillChange(idx, 'name', e.target.value)}
              />
              <input
                type="number"
                placeholder="Level (0-100)"
                min="0"
                max="100"
                value={skill.level}
                onChange={(e) => handleSkillChange(idx, 'level', e.target.value)}
              />
              <button type="button" className="remove-btn" onClick={() => removeSkill(idx)}>
                Remove
              </button>
            </div>
          ))}
          <button type="button" className="add-btn" onClick={addSkill}>
            Add Skill
          </button>
        </div>

        {/* Degrees */}
        <div className="form-group">
          <label>Degrees</label>
          {formData.degrees.map((deg, idx) => (
            <div key={idx} className="edit-array-item">
              <input
                type="text"
                placeholder="Title"
                value={deg.title}
                onChange={(e) => handleDegreeChange(idx, 'title', e.target.value)}
              />
              <input
                type="text"
                placeholder="Institution"
                value={deg.institution}
                onChange={(e) => handleDegreeChange(idx, 'institution', e.target.value)}
              />
              <button type="button" className="remove-btn" onClick={() => removeDegree(idx)}>
                Remove
              </button>
            </div>
          ))}
          <button type="button" className="add-btn" onClick={addDegree}>
            Add Degree
          </button>
        </div>

        {/* Experience */}
        <div className="form-group">
          <label>Experience</label>
          {formData.experience.map((exp, idx) => (
            <div key={idx} className="edit-array-item">
              <input
                type="text"
                placeholder="Role"
                value={exp.role}
                onChange={(e) => handleExperienceChange(idx, 'role', e.target.value)}
              />
              <input
                type="text"
                placeholder="Period"
                value={exp.period}
                onChange={(e) => handleExperienceChange(idx, 'period', e.target.value)}
              />
              <input
                type="text"
                placeholder="Company"
                value={exp.company}
                onChange={(e) => handleExperienceChange(idx, 'company', e.target.value)}
              />
              <button type="button" className="remove-btn" onClick={() => removeExperience(idx)}>
                Remove
              </button>
            </div>
          ))}
          <button type="button" className="add-btn" onClick={addExperience}>
            Add Experience
          </button>
        </div>

        {/* Languages */}
        <div className="form-group">
          <label>Languages</label>
          {formData.languages.map((lang, idx) => (
            <div key={idx} className="edit-array-item">
              <input
                type="text"
                placeholder="Language"
                value={lang.name}
                onChange={(e) => handleLanguageChange(idx, 'name', e.target.value)}
              />
              <input
                type="number"
                placeholder="Level (0-100)"
                min="0"
                max="100"
                value={lang.level}
                onChange={(e) => handleLanguageChange(idx, 'level', e.target.value)}
              />
              <input
                type="text"
                placeholder="Fluency"
                value={lang.fluency}
                onChange={(e) => handleLanguageChange(idx, 'fluency', e.target.value)}
              />
              <button type="button" className="remove-btn" onClick={() => removeLanguage(idx)}>
                Remove
              </button>
            </div>
          ))}
          <button type="button" className="add-btn" onClick={addLanguage}>
            Add Language
          </button>
        </div>

        {/* Change Password Section */}
        <div className="password-section">
          <h3>CHANGE PASSWORD</h3>
          <br></br>
          <div className="form-group">
            <label>Current Password</label>
            <input
              type="password"
              name="currentPassword"
              value={formData.currentPassword}
              onChange={handlePasswordChange}
            />
          </div>
          <div className="form-group">
            <label>New Password</label>
            <input
              type="password"
              name="newPassword"
              value={formData.newPassword}
              onChange={handlePasswordChange}
            />
          </div>
          <div className="form-group">
            <label>Confirm New Password</label>
            <input
              type="password"
              name="confirmPassword"
              value={formData.confirmPassword}
              onChange={handlePasswordChange}
            />
          </div>
        </div>

        {/* Submit Button */}
        <button type="submit" className="update-btn">
          Save Profile
        </button>
      </form>
    </div>
  );
};

export default EditProfile;
