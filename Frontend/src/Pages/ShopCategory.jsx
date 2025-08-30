import React, { useState, useEffect, useCallback, useContext } from 'react';
import { UserContext } from '../UserContext';
import { get, post, put, del } from '../config/api';
import './CSS/ProductCategory.css';
import Footer from '../Components/Footer/Footer';
import { useNavigate, useLocation } from 'react-router-dom';
import Loader from "../Components/Loader/Loading.jsx";
import Swal from 'sweetalert2';

const ProductCategory = () => {
  const [productData, setProductData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [priceRange, setPriceRange] = useState([0, 5000000]);
  const [sortedBy, setSortedBy] = useState([]);
  const [selectedSizes, setSelectedSizes] = useState([]);
  const [selectedColors, setSelectedColors] = useState([]);
  const [selectedBrands, setSelectedBrands] = useState([]);
  const [selectedGender, setSelectedGender] = useState([]);
  const [currentPage, setCurrentPage] = useState(1);
  const [openBrands, setOpenBrands] = useState([]);
  const [maxPrice, setMaxPrice] = useState(5000000);
  const [totalPages, setTotalPages] = useState(1);
  const [searchCompleted, setSearchCompleted] = useState(false);
  const [filteredAndSortedProducts, setFilteredAndSortedProducts] = useState([]);
  const [noProductsFound, setNoProductsFound] = useState(false);

  const location = useLocation();
  const navigate = useNavigate();
  const productsPerPage = 12;
  const searchQuery = new URLSearchParams(location.search).get('query');
  const { user } = useContext(UserContext);

  const [isSalePage, setIsSalePage] = useState(false);

  const formatPrice = (price) => {
    return price.toLocaleString('vi-VN') + " VND";
  };

  const fetchProducts = async () => {
  setLoading(true);
  try {
    let response;
    if (searchQuery) {
      response = await get(`/api/v1/auth/products/search`, {
        params: { query: searchQuery },
      });
    } else {
      response = await get(`/api/v1/auth/products`, {
        params: {
          size: selectedSizes.join(','),
          brand: selectedBrands.join(','),
          gender: selectedGender.length > 0 ? selectedGender[0] : undefined,
          minPrice: priceRange[0],
          maxPrice: priceRange[1],
          sale: isSalePage ? true : undefined, // Thêm tham số này
        },
      });
    }
    setProductData(response.data);
    setTotalPages(Math.ceil(response.data.length / productsPerPage));
    setNoProductsFound(response.data.length === 0);
  } catch (error) {
    console.error('Error fetching products:', error);
    setNoProductsFound(true);
  } finally {
    setLoading(false);
  }
};

  useEffect(() => {
    fetchProducts();
  }, [searchQuery, selectedColors, selectedSizes, selectedBrands, selectedGender, priceRange, sortedBy, currentPage]);


  useEffect(() => {
    const filtered = filterProducts(productData);
    const sorted = sortProducts(filtered);
    const start = (currentPage - 1) * productsPerPage;
    const end = start + productsPerPage;
    const sliced = sorted.slice(start, end);
    setFilteredAndSortedProducts(sliced);
    setNoProductsFound(sliced.length === 0);
  }, [productData, selectedColors, selectedSizes, selectedBrands, selectedGender, priceRange, sortedBy, currentPage]);

  useEffect(() => {
    if (location.pathname === '/new-arrivals' && !location.search && !location.hash) {
      setSortedBy(['Newest']);
    }
  }, [location.pathname, location.search, location.hash]);
  

  useEffect(() => {
    const pathname = location.pathname;
    setIsSalePage(pathname === '/sale');
    
    // Reload products when navigating to the sale page
    if (pathname === '/sale') {
      setSortedBy([]);
      fetchProducts();
    }
  }, [location.pathname]);


  const handlePriceChange = (e) => {
    const value = Number(e.target.value);
    setMaxPrice(value);
    setPriceRange([priceRange[0], value]);
    setCurrentPage(1); 
  };

  const handleSortChange = (sortOption) => {
    setSortedBy([sortOption]);
    setCurrentPage(1); 
  };

  const handleSizeChange = (size) => {
    setSelectedSizes((prevSelectedSizes) =>
      prevSelectedSizes.includes(size)
        ? prevSelectedSizes.filter((s) => s !== size)
        : [...prevSelectedSizes, size]
    );
    setCurrentPage(1); 
  };
  const handleBrandChange = (brand) => {
    setSelectedBrands((prevSelectedBrands) =>
      prevSelectedBrands.includes(brand)
        ? prevSelectedBrands.filter((b) => b !== brand)
        : [...prevSelectedBrands, brand]
    );
    setCurrentPage(1); 
  };

  const handleGenderChange = (gender) => {
    setSelectedGender((prevSelectedGender) =>
      prevSelectedGender.includes(gender)
        ? prevSelectedGender.filter((g) => g !== gender)
        : [...prevSelectedGender, gender]
    );
    setCurrentPage(1); 
  };

  const filterProducts = (products) => {
    return products.filter((product) => {
      const brandMatch = selectedBrands.length === 0 || selectedBrands.includes(product.brand);
      const sizeMatch = selectedSizes.length === 0 || selectedSizes.some(size => product.sizes.includes(size));
      const priceMatch = product.price >= priceRange[0] && product.price <= priceRange[1];
      const saleMatch = isSalePage ? product.sale === true : true; // Thêm điều kiện này

      let genderSizeMatch = true;
      if (selectedGender.includes('Women')) {
        genderSizeMatch = product.sizes.some(size => parseFloat(size) <= 5);
      } else if (selectedGender.includes('Men')) {
        genderSizeMatch = product.sizes.some(size => parseFloat(size) > 5);
      }
      return priceMatch && sizeMatch && brandMatch && genderSizeMatch && saleMatch;

    })
  };

  const sortProducts = (products) => {
    return sortedBy.reduce((sortedProducts, sortOption) => {
      switch (sortOption) {
        case 'Price (Low - High)':
          return sortedProducts.sort((a, b) => a.price - b.price);
        case 'Price (High - Low)':
          return sortedProducts.sort((a, b) => b.price - a.price);
        case 'Newest':
          return sortedProducts.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
        case 'Best Seller':
          return sortedProducts.sort((a, b) => b.sales - a.sales);
        default:
          return sortedProducts;
      }
    }, [...products]);
  };

  const handlePageChange = (direction) => {
    setCurrentPage((prevPage) => {
      if (direction === 'up' && prevPage < totalPages) {
        return prevPage + 1;
      } else if (direction === 'down' && prevPage > 1) {
        return prevPage - 1;
      }
      return prevPage;
    });
  };

  const handleProductClick = (productName) => {
    navigate(`/product?name=${encodeURIComponent(productName)}`);
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

  return (
    <div className="product-category">
      <header className="header">
        <h1 className="title">Category</h1>
        <h2 className="subtitle">Products</h2>
      </header>
      <div className="main-content">
        <section className="products">
          {loading ? (
            <div style={{ display: "flex", justifyContent: "center", alignItems: "center", marginTop: "10%" }}>
              <Loader />
            </div>
          ) : noProductsFound ? (
            <div className="no-results">
              <p style={{ color: "red", fontSize: "1.5rem" }}>
                Sorry, we don't have the product you are looking for :(
              </p>
            </div>
          ) : (
            <div className="products-grid">
              {filteredAndSortedProducts.map((product) => (
                <div key={product._id} className={`product-item ${isSalePage ? 'sale-item' : ''}`}>
                <button className="add-to-wishlist-btn" onClick={() => handleAddToWishlist(product)}>
                  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" className="heart-icon">
                    <path d="M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z" />
                  </svg>
                </button>
                <img
                  src={product.images[0]}
                  alt={product.name}
                  onClick={() => handleProductClick(product.name)}
                  className="product-image"
                />
                <div
                  className="product-name"
                  onClick={() => handleProductClick(product.name)}
                >
                  {product.name}
                </div>
                <div className="product-price-container">
                  {isSalePage && product.sale ? (
                    <>
                      <div className="product-price sale-price" onClick={() => handleProductClick(product.name)}>
                        {formatPrice(product.price)}
                      </div>
                      <div className="product-previous-price"> {formatPrice(product[`previous-price`])}
                      </div>
                    </>
                  ) : (
                    <div className="product-price" onClick={() => handleProductClick(product.name)}>
                      {formatPrice(product.price)}
                    </div>
                  )}
                </div>
              </div>
              ))}
            </div>
          )}
        </section>
        <aside className="filters sticky">
          <div className="filter-section">
            <p id="FilterAndSort">Filter & Sort</p>
            <input type="reset" value="clear all" id="clear-all" onClick={() => {
              setPriceRange([0, 5000000]);
              setSortedBy([]);
              setSelectedSizes([]);
              setSelectedColors([]);
              setSelectedBrands([]);
              setSelectedGender([]);
              setMaxPrice(5000000);
            }} />
            <div className="price-filter">
              <label>Price</label>
              <input
                id="range"
                type="range"
                min="0"
                max="5000000"
                value={maxPrice}
                onChange={handlePriceChange}
              />
              <span>{`${formatPrice(priceRange[0])} - ${formatPrice(priceRange[1])}`}</span>
            </div>
            <div className="sort-options">
              {['Price (Low - High)', 'Price (High - Low)', 'Newest', 'Best Seller'].map((option) => (
                <button
                  key={option}
                  onClick={() => handleSortChange(option)}
                  className={sortedBy.includes(option) ? 'active' : ''}
                >
                  {option}
                </button>
              ))}
            </div>
            <div className="gender-filter">
              <h3>Gender</h3>
              <div>
                {['Men', 'Women'].map((gender) => (
                  <label key={gender}>
                    <input
                      type="checkbox"
                      checked={selectedGender.includes(gender)}
                      onChange={() => handleGenderChange(gender)}
                    />
                    {gender}
                  </label>
                ))}
              </div>
            </div>
            <div className="size-filter">
              <h3>Sizes (UK)</h3>
              <div>
                {['4.0', '5.0', '8.0', '8.5', '9.0', '9.5'].map((size) => (
                  <label key={size}>
                    <input
                      type="checkbox"
                      checked={selectedSizes.includes(size)}
                      onChange={() => handleSizeChange(size)}
                    />
                    {size}
                  </label>
                ))}
              </div>
            </div>
            <div className="brand-filter">
              <h3>Brands</h3>
              <div>
                {['Adidas', 'Nike', 'Asics', 'Vans', 'Puma'].map((brand) => (
                  <label key={brand}>
                    <input
                      type="checkbox"
                      checked={selectedBrands.includes(brand)}
                      onChange={() => handleBrandChange(brand)}
                    />
                    {brand}
                  </label>

                ))}
              </div>
            </div>
          </div>
        </aside>
      </div>
      <div className="Category-pagination">
        <span
          className={`arrow ${currentPage === 1 ? "disabled" : ""}`}
          onClick={() => handlePageChange('down')}
        >
          &lt;
        </span>
        <span className="page-number">{currentPage}</span>
        <span
          className={`arrow ${currentPage === totalPages ? "enabled" : ""}`}
          onClick={() => handlePageChange('up')}
        >
          &gt;
        </span>
      </div>
      <Footer />
    </div>
  );
};

export default ProductCategory;
