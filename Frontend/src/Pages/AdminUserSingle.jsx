import React, { useState, useEffect } from "react";
import "./CSS/AdminSingle.css";
import { useParams } from "react-router-dom";
import { get } from '../config/api';

const AdminUserSingle = () => {
  const { userId } = useParams();
  const [formData, setFormData] = useState(null);
  const [previewImages, setPreviewImages] = useState([]);


  useEffect(() => {
    const fetchUserData = async () => {
      try {
        const response = await get(`/api/v1/admin/get-user/${userId}`);
        const user = response.data.user;
        setFormData({
          id: user._id || "N/A",
          name: user.name || "N/A",
          email: user.email || "N/A",
          phone: user.phone || "N/A",
          address: user.address || "N/A",
          totalSpent: user.totalSpent || "N/A",
          role: user.role || "N/A",
          createAt: new Date(user.createdAt).toLocaleString() || "Invalid Date",
          images: ["https://minoshoesstorage.blob.core.windows.net/minoshoesbackground/people.jpg"]
        });
        setPreviewImages(["https://minoshoesstorage.blob.core.windows.net/minoshoesbackground/people.jpg"]);
      } catch (error) {
        console.error("Error fetching user data:", error);
      }
    };
  
    fetchUserData();
  }, [userId]);
  

  const handleInputChange = (e) => {
    const { name, value, files } = e.target;

    if (files && files.length > 0) {
      handleImageChange(files);
    } else {
      setFormData((prevData) => ({
        ...prevData,
        [name]: value,
      }));
    }
  };

  const handleImageChange = (files) => {
    const fileArray = Array.from(files);
    const imageUrls = fileArray.map((file) => URL.createObjectURL(file));

    setPreviewImages(imageUrls);
    setFormData((prevData) => ({
      ...prevData,
      images: imageUrls,
    }));
  };

  if (!formData) return <div>Data not found</div>;

  return (
    <div className="AdminSingle">
      <div className="singleContainer">
        <div className="top">
          <div className="left">
            <div className="buttonContainer">
            </div>
            <h1 className="title">User Information</h1>
            <div className="item">
              <div className="imagePreviewContainer">
                {previewImages.length > 0 ? (
                  previewImages.map((image, index) => (
                    <img
                      key={index}
                      src={image}
                      alt={`Preview ${index}`}
                      className="itemImg"
                    />
                  ))
                ) : (
                  <img
                    src="https://via.placeholder.com/150"
                    alt="No Preview"
                    className="itemImg"
                  />
                )}
              </div>
              <div className="details">
                <h1 className="itemTitle">{formData.name}</h1>
                <form>
                  {Object.keys(formData).map((key) => (
                    key !== 'images' && (
                      <div key={key} className="detailItem">
                        <label className="itemKey" htmlFor={key}>
                          {key.charAt(0).toUpperCase() + key.slice(1)}:
                        </label>
                        <span className="itemValue">
                          {formData[key] || "N/A"}
                        </span>
                      </div>
                    )
                  ))}
                </form>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AdminUserSingle;
