import React from "react"
import Hero from "../Components/Hero/Hero.jsx"
import Gallary from "../Components/Gallary/Gallary.jsx"
import Bestseller from "../Components/Bestseller/Bestseller.jsx"
import Reviews from "../Components/Reviews/Reviews.jsx"
import Footer from "../Components/Footer/Footer.jsx"
import CTA_Section from "../Components/CTA_Section/CTA_Section.jsx"
import Brand_Section from "../Components/Brand_Section/Brand_Section.jsx"
import Contact_info from "../Components/Contact_info/Contact_info.jsx"
import "./CSS/Shop.css"
import "../Components/Hero/Hero.css";
const Shop = () => {
    return (
        <div className="landing-page"> 
            <div className="landing-background">
                <Hero />
            </div>
            <div className="landing-main-content">
                <div className="container">
                    <Gallary />
                    <Bestseller />
                    <Reviews />
                    <CTA_Section />
                    <Brand_Section />
                    <Contact_info />
                    <Footer />
                </div>
            </div>

        </div>
    )
}

export default Shop