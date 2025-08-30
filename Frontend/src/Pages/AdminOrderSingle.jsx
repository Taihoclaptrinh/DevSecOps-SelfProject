import React, { useState, useEffect } from "react";
import { useParams } from "react-router-dom";
import { get, put } from '../config/api';
import "./CSS/AdminOrderSingle.css";

const AdminOrderSingle = () => {
  const { orderId } = useParams(); // Get the orderId from the URL parameters
  const [orderData, setOrderData] = useState(null);
  const [isEditing, setIsEditing] = useState(false); // Kiểm soát chế độ chỉnh sửa
  const [status, setStatus] = useState(""); // Trạng thái đơn hàng

  const formatPrice = (price) => {
    return price.toLocaleString('vi-VN') + " VND";
  };

  useEffect(() => {
    const fetchOrderData = async () => {
      try {
        const response = await get(`/api/v1/admin/orders/${orderId}`);
        const order = response.data.order;
        setOrderData({
          id: order._id || "N/A",
          userId: order.user._id || "N/A",
          userEmail: order.user.email || "N/A",
          orderItems: order.orderItems || [],
          shippingAddress: order.shippingAddress || {},
          paymentMethod: order.paymentMethod || "N/A",
          totalPrice: order.totalPrice || "N/A",
          status: order.status || "N/A",
          createdAt: new Date(order.createdAt).toLocaleString() || "Invalid Date",
          updatedAt: new Date(order.updatedAt).toLocaleString() || "Invalid Date",
        });
        setStatus(order.status || "N/A");
      } catch (error) {
        console.error("Error fetching order data:", error);
      }
    };

    fetchOrderData();
  }, [orderId]);


  const handleInputChange = (e) => {
    setStatus(e.target.value);
  };

  const toggleEditMode = () => {
    setIsEditing(!isEditing); 
  };

  const saveChanges = async () => {
    try {
      const token = localStorage.getItem('token');
      const updatedData = { status }; // Chỉ gửi trạng thái mới
      alert(status)
      const response = await put(`/api/v1/orders/${orderId}/status`, {
        status: status,
        }, { 
        headers: { Authorization: `Bearer ${token}` }
      });
  
      console.log('Order status updated successfully:', response.data);
  
      setOrderData((prevData) => ({
        ...prevData,
        status: status,
      }));
      setIsEditing(false);
    } catch (error) {
      console.error('Error updating order status:', error.response ? error.response.data : error.message);
      alert('Failed to update order status. Check console for details.');
    }
  };
  

  if (!orderData) return <div>Data not found</div>;

  return (
    <div className="admin-order-single">
      <div className="single-container">
        <div className="top">
          <div className="left">
            <h1 className="title">Order Information</h1>
            <div className="Order_Single_detail-item">
            <button className="edit-button"  onClick={toggleEditMode}>
              {isEditing  ? "Cancel" : "Edit"}
            </button>
            {isEditing  && (
                <button className="save-button" type="button" onClick={saveChanges}>Save</button>
            )}
            </div>
            <div className="item">
              <div className="Order_Single_details">
                <form>
                  <div className="Order_Single_detail-item">
                    <label >
                      <span className="Order_Single_item-key">Order ID:</span>
                      <span className="Order_Single_item-value">{orderData.id}</span>
                    </label>
                  </div>
                  <div className="Order_Single_detail-item">
                    <label >
                      <span className="Order_Single_item-key">User ID: </span>
                      <span className="Order_Single_item-value">{orderData.userId}</span>
                    </label>
                  </div>
                  <div className="Order_Single_detail-item">
                    <label >
                      <span className="Order_Single_item-key">User Email:</span>
                      <span className="Order_Single_item-value">{orderData.userEmail}</span>
                    </label>
                  </div>
                  <div className="Order_Single_detail-item">
                    <label >
                      <span className="Order_Single_item-key">Payment Method:</span>
                      <span className="Order_Single_item-value">{orderData.paymentMethod}</span>
                    </label>
                  </div>
                  <div className="Order_Single_detail-item">
                    <label>
                      <span className="Order_Single_item-key">Total Price:</span>
                      <span className="Order_Single_item-value">{formatPrice(orderData.totalPrice)}</span>
                    </label>
                  </div>
                  <div className="Order_Single_detail-item">
                    <label>
                      <span className="Order_Single_item-key">Status:</span>
                      {isEditing ? (
                        <select
                          id="status"
                          name="status"
                          value={status}
                          onChange={handleInputChange}
                          className="item-value"
                        >
                          <option value="Pending">Pending</option>
                          <option value="Delivered">Delivered</option>
                        </select>
                      ) : (
                        <span className="Order_single_item-value">{orderData.status}</span>
                      )}
                    </label>
                  </div>
                  <div className="Order_Single_detail-item">
                    <label >
                      <span className="Order_Single_item-key">Created At:</span>
                      <span className="Order_Single_item-value">{orderData.createdAt}</span>
                    </label>
                  </div>
                  <div className="Order_Single_detail-item">
                    <label >
                      <span className="Order_Single_item-key">Updated At:</span>
                      <span className="Order_Single_item-value">{orderData.updatedAt}</span>
                    </label>
                  </div>
                  <div className="Order_Single_detail-item">
                    <label >
                      <span className="Order_Single_item-key">Shipping Address:</span>
                      <span className="Order_Single_item-value ">
                        <ul>{orderData.shippingAddress.fullName}</ul>
                        <ul>{orderData.shippingAddress.address}</ul>
                        <ul>{orderData.shippingAddress.phoneNumber}</ul>
                      </span>
                    </label>
                  </div>
                  <div className="Order_Single_detail-item">
                    <div className="Order_Single_item-key">Order Items:</div>
                    <div className="Order_Single_table-container" style={{justifyContent:"center", display:"flex"}}>
                      <table className="Order_Single_item-value">
                        <thead>
                          <tr>
                            <th>Product</th>
                            <th>Quantity</th>
                            <th>Price</th>
                            <th>Size</th>
                          </tr>
                        </thead>
                        <tbody>
                          {orderData.orderItems.map((item, index) => (
                            <tr key={index}>
                              <td>{item.name}</td>
                              <td>{item.quantity}</td>
                              <td>{formatPrice(item.price)}</td>
                              <td>{item.size}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </form>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AdminOrderSingle;
