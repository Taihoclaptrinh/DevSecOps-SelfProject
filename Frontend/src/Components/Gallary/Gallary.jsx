import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import "./Gallary.css";
import { Link } from "react-router-dom";
import Pop_up from "../Popup/Popup";
import ProductSlider from "./ProductSlider";

const Gallary = () => {

  const hotshoe4 = "https://minoshoesstorage.blob.core.windows.net/minoshoesbackground/jordan-ng.jpeg";

  return (
    <div className="layout">
      <div className="layout-trending">
        <h1 className="trending-qoute">SEASONAL FOCUS</h1>
        <div className="trending-img">
          <img src={hotshoe4} alt="" className="img-format4" />
          <ProductSlider />
        </div>
        <div className="trending-button">
          <Link to="/new-arrivals" className="Gal_left-section">
            Shop
          </Link>
          <Link to="/new-arrivals" className="Gal_right-section" >
            Explore
          </Link>
        </div>
      </div>
    </div>
  );
};

export default Gallary;
