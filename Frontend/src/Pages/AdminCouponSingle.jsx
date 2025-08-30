import React, { useState, useEffect } from "react";
import "./CSS/AdminCouponSingle.css";
import { useParams } from "react-router-dom";
import { get, put } from '../config/api';

const AdminCouponSingle = () => {
  const { couponId } = useParams();
  const [formData, setFormData] = useState(null);
  const [isEditing, setIsEditing] = useState(false);
  const [error, setError] = useState(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchCouponData = async () => {
      setIsLoading(true);
      setError(null);
      try {
        const response = await get(`/api/v1/admin/coupons/${couponId}`);
        console.log("API Response:", response); 

        if (!response || !response.data) {
          throw new Error("No data received from API");
        }

        const coupon = response.data.coupon || response.data;
        console.log("Coupon data:", coupon); 

        if (!coupon || typeof coupon !== 'object') {
          throw new Error("Invalid coupon data structure");
        }

        setFormData({
          id: coupon._id || coupon.id || "N/A",
          code: coupon.code || "N/A",
          discountValue: coupon.discountValue || "N/A",
          startDate: coupon.startDate ? new Date(coupon.startDate).toLocaleDateString() : "Invalid Date",
          endDate: coupon.endDate ? new Date(coupon.endDate).toLocaleDateString() : "Invalid Date",
          usageCount: coupon.usageCount || "N/A",
          usageLimit: coupon.usageLimit || "N/A",
        });
      } catch (error) {
        console.error("Error fetching coupon data:", error);
        setError(error.message || "Failed to fetch coupon data");
      } finally {
        setIsLoading(false);
      }
    };

    fetchCouponData();
  }, [couponId]);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData((prevData) => ({
      ...prevData,
      [name]: value,
    }));
  };

  const toggleEditMode = () => {
    setIsEditing(!isEditing);
  };

  const saveChanges = async () => {
    try {
      const response = await put(`/api/v1/admin/coupons/${couponId}`, formData);
      console.log("Update response:", response);
      toggleEditMode();
    } catch (error) {
      console.error("Error saving changes:", error);
      setError("Failed to save changes. Please try again.");
    }
  };

  if (isLoading) return <div>Loading...</div>;
  if (error) return <div>Error: {error}</div>;
  if (!formData) return <div>No coupon data available</div>;

  return (
    <div className="admin-coupon-single">
      <div className="single-container">
        <div className="top">
          <div className="left">
            <div className="button-container">
              <button className="edit-button" onClick={toggleEditMode}>
                {isEditing ? "Cancel" : "Edit"}
              </button>
              {isEditing && (
                <button className="save-button" onClick={saveChanges}>
                  Save
                </button>
              )}
            </div>
            <h1 className="Coupon_single_title">Coupon Information</h1>
            <div className="Coupon_single_details">
              <form>
                {Object.entries(formData).map(([key, value]) => (
                  <div key={key} className="Coupon_single_detail-item">
                    <label htmlFor={key}>
                      <span className="Coupon_single_item-key">
                        {key.charAt(0).toUpperCase() + key.slice(1)}:
                      </span>
                      {isEditing ? (
                        <input
                          type={['discountValue', 'usageCount', 'usageLimit'].includes(key) ? 'number' : 'text'}
                          id={key}
                          name={key}
                          value={value}
                          onChange={handleInputChange}
                          className="Coupon_single_item-value"
                        />
                      ) : (
                        <span className="Coupon_single_item-value">{value}</span>
                      )}
                    </label>
                  </div>
                ))}
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AdminCouponSingle;