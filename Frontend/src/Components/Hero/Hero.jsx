import React, { useState, useEffect } from "react";
import "./Hero.css";

const images = [
    "https://minoshoesstorage.blob.core.windows.net/minoshoesbackground/bg.png",
    "https://minoshoesstorage.blob.core.windows.net/minoshoesbackground/bg1.jpg",
    "https://minoshoesstorage.blob.core.windows.net/minoshoesbackground/bg2.jpg"
];

const Hero = () => {
    const [currentIndex, setCurrentIndex] = useState(0);

    useEffect(() => {
        const interval = setInterval(() => {
            setCurrentIndex((prevIndex) => (prevIndex + 1) % images.length);
        }, 5000);

        return () => clearInterval(interval);
    }, []);

    return (
        <div className="hero">
            {images.map((image, index) => (
                <img
                    key={index}
                    src={image}
                    alt={`Slide ${index}`}
                    className={`hero-image ${index === currentIndex ? "active" : ""}`}
                />
            ))}
            <div className="hero-dots">
                {images.map((_, index) => (
                    <span
                        key={index}
                        className={index === currentIndex ? "dot active" : "dot"}
                        onClick={() => setCurrentIndex(index)}
                    ></span>
                ))}
            </div>
        </div>
    );
};

export default Hero;
