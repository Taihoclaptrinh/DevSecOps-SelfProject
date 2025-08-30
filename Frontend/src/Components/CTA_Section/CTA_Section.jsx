import React, { useState, useEffect } from "react";
import "./CTA_Section.css";
import Pop_up from "../Popup/Popup.jsx"
export default function CTA_Section() {
  const CTA_Background = "https://minoshoesstorage.blob.core.windows.net/minoshoesbackground/jordan-giay.jpg"
  const [isLoggedIn, setIsLoggedIn] = useState(false); // Replace this with actual login check logic
  const [showPopup, setShowPopup] = useState(false);

  const handleSignUpClick = () => {
    if (isLoggedIn) {
      setShowPopup(true);
    } else {
      window.location.href = '/login';
    }
  };

  const handleClosePopup = () => {
    setShowPopup(false);
  };

  useEffect(() => {
    // Check login status based on token in localStorage
    const token = localStorage.getItem('token');
    if (token) {
      setIsLoggedIn(true);
    }
  }, []);

  return (
    <div className="CTA-layout">
      <div className="CTA-background">
        <div class="CTA_container">
            <span class="gradient-text top">Stay Updated with Our </span>
            <span class="gradient-text bottom">Newsletter</span>
            <p className="format-text">Register to receive the latest news, events, products, and exclusive sale offers.</p>
          
        </div>
        <img src={CTA_Background} alt=""/>
        <div className="CTA-button">
          <div className="CTA_left-section" onClick={handleSignUpClick}>
            Sign Up
          </div>
          <div className="CTA_right-section" onClick={() => window.location.href = '/new-arrivals'}>
            Learn More
          </div> 
        </div>
      </div>
      {showPopup && 
          <Pop_up 
              isSuccess={false} 
              review="You already logged in!" 
              message="Click the button below to back to the landing page" 
              confirm="Back to HomePage"
              href="/"
          />
      }
    </div>
  )
}
