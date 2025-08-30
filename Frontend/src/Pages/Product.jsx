import React, { useEffect, useState, useContext } from "react";
import "./CSS/Product.css";
import { get, post } from '../config/api';
import { useLocation, useNavigate } from "react-router-dom";
import { UserContext } from '../UserContext';
import ShoppingCartOutlinedIcon from '@mui/icons-material/ShoppingCartOutlined';
import FavoriteBorderOutlinedIcon from '@mui/icons-material/FavoriteBorderOutlined';
import Slider from "../Components/Slider/Slider.jsx";
import Footer from "../Components/Footer/Footer.jsx";
import Loader from "../Components/Loader/Loading.jsx";
import Pop_up from "../Components/Popup/Popup.jsx"
import Swal from 'sweetalert2';
// Review Form component
const ReviewForm = ({ onClose, onSubmit }) => {
    const [rating, setRating] = useState(0);
    const [comment, setComment] = useState("");

    const handleSubmit = (e) => {
        e.preventDefault();
        onSubmit({ rating, comment });
    };

    return (
        <div className="review-form-popup">
            <form onSubmit={handleSubmit}>
                <h1 style={{marginBottom:"0rem", justifyContent:"center", display:"flex"}}>Leave a Review</h1>
                <div className="rating-input">
                    {[1, 2, 3, 4, 5].map((star) => (
                        <span
                            key={star}
                            className={star <= rating ? "star filled" : "star empty"}
                            onClick={() => setRating(star)}
                        >
                            ★
                        </span>
                    ))}
                </div>
                <textarea
                    value={comment}
                    onChange={(e) => setComment(e.target.value)}
                    placeholder="Write your review here..."
                    required
                    style={{ width: "95%", height: "150px", resize:"none", fontFamily:"sans-serif", fontSize:"1.2rem", padding:"10px" }}
                />
                <div className="form-buttons">
                    <button type="submit">Submit</button>
                    <button type="button" onClick={onClose}>Cancel</button>
                </div>
            </form>
        </div>
    );
};

const Product = () => {
    const [productData, setProductData] = useState(null);
    const [reviews, setReviews] = useState([]);
    const [averageRating, setAverageRating] = useState(0);
    const [reviewCount, setReviewCount] = useState(0);
    const [selectedSize, setSelectedSize] = useState(null);
    const [isDescriptionExpanded, setIsDescriptionExpanded] = useState(false);
    const [currentPage, setCurrentPage] = useState(1);
    const [cartCount, setCartCount] = useState(0);
    const [showReviewForm, setShowReviewForm] = useState(false);
    const [showNoSizeSelectedPopup, setShowNoSizeSelectedPopup] = useState(false);
    const [showNoSizesStockPopup, setShowNoSizesStockPopup] = useState(false);
    const [showAddToCartSuccessPopup, setShowAddToCartSuccessPopup] = useState(false);
    const [showAddToCartFailedPopup, setShowAddToCartFailurePopup] = useState(false);
    const { user } = useContext(UserContext);

    const reviewsPerPage = 5;
    const location = useLocation();
    const navigate = useNavigate();

    useEffect(() => {
        fetchProductData();
    }, [location.search]);

    useEffect(() => {
        const fetchCartCount = async () => {
            const token = localStorage.getItem('token');
            if (token) {
                try {
                    const response = await get('/api/v1/auth/cart/count', {
                        headers: {
                            'Authorization': `Bearer ${token}`
                        }
                    });
                    setCartCount(response.data.totalQuantity);
                } catch (error) {
                    console.error('Error fetching cart count:', error);
                }
            }
        };
        fetchCartCount();
    }, []);

    const onAddtoCartHandler = async (product) => {
        const token = localStorage.getItem('token');
        if (!token) {
            navigate('/login');
            return;
        }
    
        if (!selectedSize) {
            setShowNoSizeSelectedPopup(true)
            return;
        }
    
        // Kiểm tra số lượng tồn kho
        const sizeIndex = product.sizes.indexOf(selectedSize);
        if (sizeIndex === -1) {
            setShowNoSizesStockPopup(true)
            return;
        }
    
        const stockAvailable = product.stocks[sizeIndex];
        if (stockAvailable <= 0) {
            setShowNoSizesStockPopup(true);
            return;
        }
    
        try {
            const response = await post('/api/v1/auth/cart/add-to-cart', {
                productId: product._id,
                quantity: 1,
                price: product.price,
                size: selectedSize
            }, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
    
            if (response.status === 200) {
                setShowAddToCartSuccessPopup(true);
                const newCartCount = response.data.totalQuantity;
                setCartCount(response.data.totalQuantity);
            }
        } catch (error) {
            setShowAddToCartFailurePopup(true);
        }
    };

    const handleAddToWishlist = async (product) => {
        try {
          const token = localStorage.getItem('token');
          if (!token) {
            Swal.fire('Error', 'Please login to add items to your wishlist', 'error');
            return;
          }
    
          const response = await post(
            `/api/v1/auth/users/${user._id}/wishlist/${product._id}`,
            {},
            {
              headers: { Authorization: `Bearer ${token}` }
            }
          );
    
          if (response.status === 200) {
            Swal.fire('Success', 'Product added to wishlist', 'success');
          } else {
            throw new Error(response.data.message || 'Failed to add product to wishlist');
          }
        } catch (error) {
          console.error('Error adding product to wishlist:', error.response?.data || error.message);
          if (error.response?.status === 401) {
            Swal.fire('Error', 'Your session has expired. Please login again.', 'error');
          } else {
            Swal.fire('Error', 'Failed to add product to wishlist. Please try again.', 'error');
          }
        }
    };

    const handleClosePopup = () => {
        setShowNoSizeSelectedPopup(false);
        setShowNoSizesStockPopup(false);
        setShowAddToCartSuccessPopup(false);
        setShowAddToCartFailurePopup(false);
    };

    const renderStars = (rating) => {
        const fullStars = Math.floor(rating);
        const halfStar = rating % 1 !== 0;
        const emptyStars = 5 - fullStars - (halfStar ? 1 : 0);
        return (
            <>
                {[...Array(fullStars)].map((_, index) => (
                    <span key={index} className="star filled">★</span>
                ))}
                {halfStar && <span className="star half">★</span>}
                {[...Array(emptyStars)].map((_, index) => (
                    <span key={index} className="star empty">☆</span>
                ))}
            </>
        );
    };

    const handleLeaveReview = () => {
        const token = localStorage.getItem('token');
        if (!token) {
            navigate('/login');
            return;
        }
        setShowReviewForm(true);
    };

    const handleSubmitReview = async (reviewData) => {
        const token = localStorage.getItem('token');
        try {
            const response = await post('/api/v1/auth/reviews', {
                productId: productData._id,
                userId: localStorage.getItem('userId'),
                rating: reviewData.rating,
                comment: reviewData.comment
            }, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (response.status === 201) {
                alert('Review submitted successfully!');
                setShowReviewForm(false);
                fetchProductData();
            }
        } catch (error) {
            console.error('Error submitting review:', error);
            alert('Failed to submit review. Please try again.');
        }
    };

    const fetchProductData = async () => {
        const query = new URLSearchParams(location.search);
        const productName = query.get('name');

        if (productName) {
            try {
                const response = await get(`/api/v1/auth/products/${encodeURIComponent(productName)}`);
                setProductData(response.data);
                window.scrollTo(0, 0);

                // Fetch reviews and average rating
                const reviewsResponse = await get(`/api/v1/auth/reviews/product/:${response.data._id}`);
                setReviews(reviewsResponse.data.reviews);
                setAverageRating(reviewsResponse.data.averageRating);
                setReviewCount(reviewsResponse.data.reviewCount);
            } catch (error) {
                console.error("Error fetching product data:", error);
            }
        }
    };

    const handleSizeClick = (size) => {
        setSelectedSize(size);
    };

    const toggleDescription = () => {
        setIsDescriptionExpanded(!isDescriptionExpanded);
    };

    const handlePageChange = (direction) => {
        if (direction === "prev" && currentPage > 1) {
            setCurrentPage(currentPage - 1);
        } else if (direction === "next" && currentPage < totalPages) {
            setCurrentPage(currentPage + 1);
        }
    };

    const renderDescription = () => {
        if (!productData) return "";
        const descriptionLines = productData.description.split("\n");
        if (descriptionLines.length <= 5 || isDescriptionExpanded) {
            return descriptionLines.join("\n");
        } else {
            return descriptionLines.slice(0, 5).join("\n") + "...";
        }
    };

    if (!productData) {
        return <div style={{ display: "flex", justifyContent: "center", alignItems: "center", height: "100vh" }}>
            <Loader />
        </div>;
    }

    const indexOfLastReview = currentPage * reviewsPerPage;
    const indexOfFirstReview = indexOfLastReview - reviewsPerPage;
    const currentReviews = reviews.slice(indexOfFirstReview, indexOfLastReview);
    const totalPages = Math.ceil(reviews.length / reviewsPerPage);

    return (
        <div className="product-page">
            <div className="product-page-layout" style={{marginTop:"2rem"}}>
                <div className="main-container">
                    <div className="product-section">
                        <div className="product-image-list">
                            <div className="image-grid">
                                {productData.images && productData.images.length > 0 ? (
                                    productData.images.map((image, index) => (
                                        <img className="image-item" src={image} alt={`product-${index}`} key={index} />
                                    ))
                                ) : (
                                    <p>No images available</p>
                                )}
                            </div>
                        </div>
                        <div className={`product-description ${isDescriptionExpanded ? "expanded" : ""}`}>
                            <h1>Product Description:</h1>
                            <p style={{textAlign: "justify"}}>{renderDescription()}</p>
                            {productData.description.split("\n").length > 5 && (
                                <span className="show-more" onClick={toggleDescription}>
                                    {isDescriptionExpanded ? "Show Less" : "Show More"}
                                </span>
                            )}
                        </div>
                    </div>
                    <div className="info-section">
                        <div className="text-group">
                            <p style={{ fontSize: "1.8rem" }}>{productData.category}</p>
                            <h1>{productData.name}</h1>
                            <h2>{productData.price.toLocaleString('vi-VN')} VND</h2>
                        </div>

                        <h2 style={{ marginTop: "3rem" }}>Main colours</h2>
                        <div className="button-grid">
                            {productData.color && productData.color.length > 0 ? (
                                productData.color.map((color, index) => (
                                    <div key={index} className="color-box">
                                        {color}
                                        <div
                                            className="color-circle"
                                            style={{ backgroundColor: color.toLowerCase() }} // Chuyển màu thành định dạng chữ thường để sử dụng trong style
                                        ></div>
                                    </div>
                                ))
                            ) : (
                                <p>No colors available</p>
                            )}
                        </div>


                        <h2>Sizes</h2>
                        <div className="button-grid">
                            {productData.sizes && productData.sizes.length > 0 ? (
                                productData.sizes.map((size, index) => (
                                    <button
                                        key={index}
                                        className={selectedSize === size ? "selected" : ""}
                                        onClick={() => handleSizeClick(size)}
                                    >
                                        {size}
                                    </button>
                                ))
                            ) : (
                                <p>No sizes available</p>
                            )}
                        </div>

                        <div className="adding-button-container">
                            <button onClick={() => onAddtoCartHandler(productData)} className="add-to-bag">
                                <ShoppingCartOutlinedIcon
                                className="icon"
                                style={{
                                    backgroundColor: "unset",
                                    color: "white",
                                    width: "40px",
                                }}
                                />
                                ADD TO CART
                            </button>
                            <button onClick={() => handleAddToWishlist(productData)} className="add-to-bag">
                                <FavoriteBorderOutlinedIcon
                                className="icon"
                                style={{
                                    backgroundColor: "unset",
                                    color: "white",
                                    width: "40px",
                                }}
                                />
                                ADD TO WISHLIST
                            </button>
                        </div>
                    </div>
                </div>

                <div className="related-product">
                    <h1>Related Products:</h1>
                    <div className="related-product-slider">
                        <Slider />
                    </div>
                </div>

                <div className="review-section">
                    <div className="reviews">
                        <div className="overall-rating">
                            <h1>Reviews:</h1>
                            <div className="rating">
                                <span id="rating-score" className="rating-score">{averageRating}</span>
                                <span id="overall-stars" className="stars">{renderStars(averageRating)}</span>
                                <span id="review-count" className="review-count">{reviewCount} reviews</span>
                            </div>
                        </div>
                        <div id="reviews">
                            {currentReviews.length > 0 ? (
                                currentReviews.map((review, index) => (
                                    <div key={index} className="review show">
                                        <h3>{review.name}</h3>
                                        <div className="stars">{renderStars(review.rating)}</div>
                                        <p style={{textAlign: "justify"}}>{review.comment}</p>
                                    </div>
                                ))
                            ) : (
                                <p>No reviews available</p>
                            )}
                        </div>

                        <div className="leave-review-button-container">
                            <button onClick={handleLeaveReview} className="leave-review-button">Leave a Review</button>
                        </div>

                        {showReviewForm && (
                            <div className="review-form-overlay">
                                <ReviewForm
                                    onClose={() => setShowReviewForm(false)}
                                    onSubmit={handleSubmitReview}
                                />
                            </div>
                        )}

                        {totalPages > 1 && (
                            <div className="review-pagination">
                                <span
                                    className={`arrow ${currentPage === 1 ? "disabled" : ""}`}
                                    onClick={() => handlePageChange("prev")}
                                >
                                    &lt;
                                </span>
                                <span className="page-number">{currentPage}</span>
                                <span
                                    className={`arrow ${currentPage === totalPages ? "disabled" : ""}`}
                                    onClick={() => handlePageChange("next")}
                                >
                                    &gt;
                                </span>
                            </div>
                        )}
                        <div className="review-pagination">
                            <span
                                className={`arrow ${currentPage === 1 ? "disabled" : ""}`}
                                onClick={() => handlePageChange("prev")}
                            >
                                &lt;
                            </span>
                            <span className="page-number">{currentPage}</span>
                            <span
                                className={`arrow ${currentPage === totalPages ? "disabled" : ""}`}
                                onClick={() => handlePageChange("next")}
                            >
                                &gt;
                            </span>
                        </div>
                    </div>
                </div>
                <Footer />
            </div>
            {showNoSizeSelectedPopup && 
                <Pop_up 
                isSuccess={false} 
                review="No Size is Selected!" 
                message="Please select a size before adding to cart" 
                confirm="Confirm"
                onClose={handleClosePopup}
                />
            }
            {showNoSizesStockPopup && 
                <Pop_up 
                isSuccess={false} 
                review="Out of Stock!" 
                message="Sorry, this product is out of stock for the selected size." 
                confirm="Confirm"
                onClose={handleClosePopup}
                />
            }
            {showAddToCartSuccessPopup && 
                <Pop_up 
                isSuccess={true} 
                review="Add to Cart Success!" 
                message="Product added to cart successfully!" 
                confirm="Confirm"
                onClose={handleClosePopup}
                />
            }
            {showAddToCartFailedPopup && 
                <Pop_up 
                isSuccess={false} 
                review="Add to Cart Failure !" 
                message="Failed to add product to cart. Please try again!" 
                confirm="Confirm"
                onClose={handleClosePopup}
                />
            }
        </div>
    );
};

export default Product;