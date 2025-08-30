import React, { useEffect, useState } from 'react';
import { get, post, put, del } from '../../config/api';
import Carousel from 'react-multi-carousel';
import { useNavigate } from 'react-router-dom';
import 'react-multi-carousel/lib/styles.css';
import "./Gallary.css";
import "../Bestseller/Bestseller.css";
import Loader from "../Loader/Loading.jsx"

const ProductSlider = () => {
  const responsive1 = {
    superLargeDesktop: {
      breakpoint: { max: 4000, min: 1024 },
      items: 1, // Chỉ hiển thị 1 nhóm mỗi lần
      slidesToSlide: 1,
    },
    desktop: {
      breakpoint: { max: 1024, min: 768 },
      items: 1, // Chỉ hiển thị 1 nhóm mỗi lần
      slidesToSlide: 1,
    },
    tablet: {
      breakpoint: { max: 768, min: 464 },
      items: 1, // Chỉ hiển thị 1 nhóm mỗi lần
      slidesToSlide: 1,
    },
    mobile: {
      breakpoint: { max: 464, min: 0 },
      items: 1, // Chỉ hiển thị 1 nhóm mỗi lần
      slidesToSlide: 1,
    },
  };

  const [products, setProducts] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate(); // Khai báo useNavigate

  useEffect(() => {
    const fetchProducts = async () => {
      try {
        const response = await get('/api/v1/auth/products'); 
        setProducts(response.data);
        setLoading(false);
      } catch (error) {
        console.error('Error fetching products:', error);
        setLoading(false);
      }
    };

    fetchProducts();
  }, []);

  const handleProductClick = (productName) => {
    navigate(`/product?name=${encodeURIComponent(productName)}`);
  };

  if (loading) {
    return (
      <div style={{  display: "flex", justifyContent: "center", alignItems: "center", height:"100%", width:"100%", marginTop: "25%"  }}>
        <Loader />
      </div>
    )
  }

  const productChunks = [];
  const data = [...products]; // Clone the array if necessary
  for (let i = 0; i < data.length; i += 4) {
    productChunks.push(data.slice(i, i + 4));
  }

  return (
    <div className="nproduct_slider">
      <Carousel responsive={responsive1}>
        {productChunks.map((chunk, index) => (
          <div key={index} className="product-group">
            <div className="product-row">
              {chunk.slice(0, 2).map(product => (
                <div key={product._id} className="nproduct-card"
                onClick={() => handleProductClick(product.name)}>
                  <div className="nproduct_image">
                    <img src={product.images[0]} alt={product.name} className="nproduct_image" />
                  </div>
                  <h3>{product.name}</h3>
                  <button>Buy Now</button>
                </div>
              ))}
            </div>
            <div className="product-row">
              {chunk.slice(2, 4).map(product => (
                <div key={product._id} className="nproduct-card"
                onClick={() => handleProductClick(product.name)}>
                  <div className="nproduct_image">
                    <img src={product.images[0]} alt={product.name} className="nproduct_image" />
                  </div>
                  <h3>{product.name}</h3>
                  <button>Buy Now</button>
                </div>
              ))}
            </div>
          </div>
        ))}
      </Carousel>
    </div>
  );
};

export default ProductSlider;
