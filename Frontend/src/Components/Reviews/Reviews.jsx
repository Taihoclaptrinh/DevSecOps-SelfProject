import React, { useEffect, useState } from 'react';
import "./Reviews.css"
import "../Bestseller/Bestseller.css"
import Carousel from "react-multi-carousel";
import "react-multi-carousel/lib/styles.css";

const Reviews = () => {
  const im_src1 = "https://minoshoesstorage.blob.core.windows.net/minoshoesbackground/rv1.jpg"
  const im_src2 = "https://minoshoesstorage.blob.core.windows.net/minoshoesbackground/rv2.jpeg"
  const responsive = {
    superLargeDesktop: {
      // the naming can be any, depends on you.
      breakpoint: { max: 4000, min: 1024 },
      items: 1,
      slidesToSlide: 1,
    },
    desktop: {
      breakpoint: { max: 1024, min: 800 },
      items: 1,
    },
    tablet: {
      breakpoint: { max: 800, min: 464 },
      items: 1,
    },
    mobile: {
      breakpoint: { max: 464, min: 0 },
      items: 1,
    },
  };
  return (
    <div className="reviews-container">
      <div className="head"> REVIEWS </div>
      <Carousel showDots={true} responsive={responsive}>
        <div className="reviews">
          <div className="feedback">
            <img className="feedback--image" src={im_src1} alt="feedback image" />
            <div className="feedback--content">
              <div className="feedback--content-font">
                <p style={{textAlign: "justify"}}>
                  The variety of shoes available was impressive, with a wide range of styles, sizes, and brands to choose from. The quality of the shoes is top-notch, and I can tell they are made to last. The store itself was clean, well-organized, and had a welcoming atmosphere.
                </p>
                <p className="feedback--author-font">Phan Vo Minh Tue</p>
                <p className="feedback--role-font">Binh Chanh, Ho Chi Minh City </p>
              </div>
            </div>
          </div>
        </div>
        <div className="reviews">
          <div className="feedback">
            <img className="feedback--image" src={im_src2} alt="feedback image" />
            <div className="feedback--content">
              <div>
                <div className="feedback--content-font">
                  <p style={{textAlign: "justify"}}>
                    I am thoroughly impressed with the entire experience. The website is user-friendly, making it easy to browse through a wide variety of stylish and high-quality shoes. The detailed product descriptions and multiple photos for each item helped me make an informed decision.                </p>
                  <p className="feedback--author-font">Lam Tai Chi</p>
                  <p className="feedback--role-font">Cai Be, Tien Giang</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </Carousel>
    </div>


  )

}

export default Reviews;
