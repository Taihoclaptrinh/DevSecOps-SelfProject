import React from "react"
import "./Contact_info.css"

export default function Contact_info(){
  const logo = "https://minoshoesstorage.blob.core.windows.net/minoshoesbackground/logo.jpg"
  const map = "https://minoshoesstorage.blob.core.windows.net/minoshoesbackground/map.jpeg"

  return (
    <div className="Contact-layout">
      <div className="Contact-container">
        <div className="address-img">
          <img src={map} alt="" />
        </div>
        <div className="nav-logo" >
          <img src={logo} alt="" style={{ height: "100px" }} />
        </div>

        <div className="text">
          <h1 className="h-top">Address:</h1>
          <h2 className="h-bottom">227 Nguyen Van Cu, Ward 4, District 5, HCMC</h2>
          <h1 className="h-top" style={{paddingTop:"25%"}}>Contact:</h1>
          <h2 className="h-bottom">minoshoestore@gmail.com</h2>
        </div>
      </div> 
    </div>
  )
}