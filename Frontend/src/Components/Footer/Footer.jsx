import React from "react";
import "./Footer.css";


const Footer = () => {
    return (
        <div className="footer">
            <div className="footer-left">
                &copy; 2024 Relume. All rights reserved.
            </div>
            <div className="footer-right">
                <a href="/agreement-service/privacy-policy">Privacy Policy</a>
                <a href="/agreement-service/term-of-service">Terms of Service</a>
                <a href="/agreement-service/cookies-setting">Cookies Settings</a>
            </div>
        </div> 
    );
};

export default Footer;
