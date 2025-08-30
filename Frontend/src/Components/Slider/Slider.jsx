import React, { useEffect, useState } from "react";
import Carousel from "react-multi-carousel";
import "react-multi-carousel/lib/styles.css";
import Product from "./Product";
import Loader from "../Loader/Loading";
import "./Slider.css"
import { get, post, put, del } from '../../config/api';

const Slider = () => {
  const [productData, setProductData] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchProducts = async () => {
      try {
        const response = await get("/api/v1/auth/products");
        setProductData(response.data);
      } catch (error) {
        console.error("Error fetching products:", error);
      } finally {
        setLoading(false);
      }
    };
    fetchProducts();
  }, []);

  if (loading) {
    return (
      <div style={{  display: "flex", justifyContent: "center", alignItems: "center", height:"100%"  }}>
        <Loader />
      </div>
    )
  }
  
  return (
    <Carousel 
      showDots={false} 
      responsive={responsive}
      className="carousel-item"
    > 
      {productData.map((item) => (
        <Product
          key={item._id} 
          name={item.name}
          url={item.images.length > 0 ? item.images[0] : 'default-image-url'} // Handle image array
          price={item.price}
        />
      ))}
    </Carousel>
  );
};

export default Slider;

const responsive = {
  superLargeDesktop: {
    breakpoint: { max: 4000, min: 1024 },
    items: 4,
    slidesToSlide: 1,
  },
  desktop: {
    breakpoint: { max: 1024, min: 800 },
    items: 3,
  },
  tablet: {
    breakpoint: { max: 800, min: 464 },
    items: 2,
  },
  mobile: {
    breakpoint: { max: 464, min: 0 },
    items: 1,
  },
};

/* Carousel Custom*/
const CustomLeftArrow = ({ onClick }) => {
  return (
    <button className="custom-arrow left-arrow" onClick={onClick}>
      &#8249;
    </button>
  );
};

const CustomRightArrow = ({ onClick }) => {
  return (
    <button className="custom-arrow right-arrow" onClick={onClick}>
      &#8250;
    </button>
  );
};
