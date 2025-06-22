import React from 'react';
import { LANGUAGE_VERSIONS } from './constants';
import './LanguageSelector.css';

export default function LanguageSelector({ language, setLanguage }) {
  return (
    <select
      value={language}
      onChange={(e) => setLanguage(e.target.value)}
      className="language-selector"
    >
      {Object.keys(LANGUAGE_VERSIONS).map((lang) => (
       <option key={lang} value={lang}>
          {lang} ({LANGUAGE_VERSIONS[lang]})
       </option>

      ))}
    </select>
  );
}
