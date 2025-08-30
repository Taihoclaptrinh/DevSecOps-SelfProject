import React, { useState } from "react";
import "./CSS/AdminNew.css";
import { post } from '../config/api'; // Ensure this path is correct
import { productInputs } from '../formSource'; // Import the productInputs configuration
import { useNavigate } from 'react-router-dom'; // Import useNavigate

const AdminNew = ({ title, formType }) => {
  // Initialize formData from productInputs
  const [formData, setFormData] = useState(() =>
    productInputs.reduce((acc, input) => ({
      ...acc,
      [input.id]: input.type === "file" ? [] : "",
    }), {})
  );

  const [previewImages, setPreviewImages] = useState([]);
  const navigate = useNavigate(); // Initialize useNavigate

  // Handle input changes
  const handleInputChange = (id, value) => {
    setFormData((prevData) => ({ ...prevData, [id]: value }));
  };

  // Handle file input changes
  const handleFileChange = (e, id) => {
    const files = e.target.files;
    setFormData((prevData) => ({ ...prevData, [id]: files }));

    const fileArray = Array.from(files);
    const imageUrls = fileArray.map((file) => URL.createObjectURL(file));
    setPreviewImages(imageUrls);
  };

  // Handle form submission
  const handleSubmit = async (e) => {
    e.preventDefault();
  
    try {
      if (formData.productImages.length > 0) {
        const fileData = new FormData();
        Array.from(formData.productImages).forEach((file) => {
          fileData.append('images', file);
        });
  
        // Upload images
        const uploadResponse = await post('/api/v1/auth/upload', fileData, {
          headers: {
            'Content-Type': 'multipart/form-data',
          },
        });
        const { imageUrls } = uploadResponse.data;
  
        // Prepare other product data
        const productData = {
          code: formData.productCode,
          name: formData.productName,
          description: formData.productDescription,
          price: Number(formData.productPrice),
          brand: formData.productBrand,
          category: formData.productCategory,
          sizes: formData.productSizes.split(',').map(size => size.trim()),
          color: formData.productColor.split(',').map(color => color.trim()),
          stocks: formData.productStocks.split(',').map(stock => Number(stock.trim())),
          images: imageUrls,
        };
  
        // Submit product data
        const response = await post('/api/v1/auth/products', productData);
        console.log('Product created successfully:', response.data);
        navigate('/admin/products');
      } else {
        alert("Please upload at least one image.");
      }
    } catch (error) {
      console.error('Error creating product:', error);
    }
  };
  

  return (
    <div className="AdminNew">
      <div className="newContainer">
        <div className="top">
          <h1>{title}</h1>
        </div>
        <div className="bottom">
          <div className="left">
            {formType === "product" && previewImages.length > 0 ? (
              <div className="imagePreviewContainer">
                {previewImages.map((image, index) => (
                  <img
                    key={index}
                    src={image}
                    alt={`Preview ${index}`}
                    className="imagePreview"
                  />
                ))}
              </div>
            ) : (
              <div className="imagePreviewContainer">
                <img
                  src="https://icon-library.com/images/no-image-icon/no-image-icon-0.jpg"
                  alt="No Preview"
                  className="imagePreview"
                />
              </div>
            )}
          </div>
          <div className="right">
            <form onSubmit={handleSubmit}>
              {productInputs.map((input) => (
                <div className="formInput" key={input.id}>
                  <label>{input.label}</label>
                  {input.type === "file" ? (
                    <input
                      type={input.type}
                      placeholder={input.placeholder}
                      onChange={(e) => handleFileChange(e, input.id)}
                      multiple={input.multiple}
                    />
                  ) : (
                    <input
                      type={input.type}
                      placeholder={input.placeholder}
                      value={formData[input.id]}
                      onChange={(e) => handleInputChange(input.id, e.target.value)}
                      min={input.min} // Add min for number inputs
                    />
                  )}
                </div>
              ))}
              <button type="submit">Submit</button>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AdminNew;
