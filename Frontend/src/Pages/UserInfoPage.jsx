import React, { useState, useEffect, useContext } from 'react';
import UserInfo from '../Components/UserInfo/UserInfo';
import { useNavigate } from "react-router-dom";
import { UserContext } from '../UserContext';
import './CSS/UserInfoPage.css';
import { get, put, del } from '../config/api';

const UserInfoPage = () => {
  const [activeSection, setActiveSection] = useState('details');
  const { user, updateUser, logout } = useContext(UserContext);
  const [localUser, setLocalUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [orders, setOrders] = useState([]); // Trạng thái để lưu trữ đơn hàng
  const [wishlist, setWishlist] = useState([]);
  const [error, setError] = useState(null);
  const [reloadOrders, setReloadOrders] = useState(false); // Trạng thái để trigger reload đơn hàng
  const [reloadWishlist, setReloadWishlist] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchUserData = async () => {
      try {
        const response = await get(`/api/v1/auth/users/${user._id}`);
        setLocalUser(response.data);
      } catch (error) {
        console.error('Error fetching user data:', error.response?.data || error.message);
        setError('Failed to fetch user data. Please try again.');
      } finally {
        setLoading(false);
      }
    };

    const fetchUserWishlist = async () => {
      try {
        const response = await get(`/api/v1/auth/users/${user._id}/wishlist`, { headers: { Authorization: `Bearer ${localStorage.getItem('token')}` } });
        setWishlist(response.data);
      } catch (error) {
        console.error('Error fetching user wishlist:', error.response?.data || error.message);
        setError('Failed to fetch user wishlist. Please try again.');
      }
    };

    const fetchUserOrders = async () => {
      try {
        const response = await get(`/api/v1/orders/user-orders/${user._id}`);
        setOrders(response.data);
      } catch (error) {
        console.error('Error fetching user orders:', error.response?.data || error.message);
        setError('Failed to fetch user orders. Please try again.');
      }
    };

    if (user?._id) {
      fetchUserData();
      fetchUserWishlist();
      fetchUserOrders();
    } else {
      setLoading(false);
    }
  }, [user, reloadWishlist]);

  useEffect(() => {
    if (reloadOrders) {
      setReloadOrders(false);
      const fetchUserOrders = async () => {
        try {
          const response = await get(`/api/v1/orders/user-orders/${user._id}`);
          setOrders(response.data);
        } catch (error) {
          console.error('Error fetching user orders:', error.response?.data || error.message);
          setError('Failed to fetch user orders. Please try again.');
        }
      };

      fetchUserOrders();
    }
  }, [reloadOrders]);

  useEffect(() => {
    if (reloadWishlist) {
      setReloadWishlist(false);
      const fetchUserWishlist = async () => {
        try {
          const response = await get(`/api/v1/auth/users/${user._id}/wishlist`, { headers: { Authorization: `Bearer ${localStorage.getItem('token')}` } });
          setWishlist(response.data);
        } catch (error) {
          console.error('Error fetching user wishlist:', error.response?.data || error.message);
          setError('Failed to fetch user wishlist. Please try again.');
        }
      };

      fetchUserWishlist();
    }
  }, [reloadWishlist]);

  const handleUpdateUser = async (updatedUser) => {
    if (!updatedUser._id) {
      console.error('No user ID found');
      setError('No user ID found. Cannot update user.');
      return;
    }
    try {
      await put(`/api/v1/auth/users/${updatedUser._id}`, updatedUser);
      updateUser(updatedUser);
      setLocalUser(updatedUser);

      if (updatedUser.address) {
        await put(`/api/v1/orders/update-address/${updatedUser._id}`, {
          newAddress: updatedUser.address
        });
        setReloadOrders(true);
      }
    } catch (error) {
      console.error('Error updating user data:', error.response?.data || error.message);
    }
  };

  const handleDeleteWishlistItem = async (itemId) => {
    try {
      const token = localStorage.getItem('token');
      const item = wishlist.find(item => item._id === itemId);
      const productId = item.product._id
      // Kiểm tra token
      if (!token) {
        throw new Error('No authentication token found');
      }
  
      // Gọi API để xóa sản phẩm khỏi wishlist
      const response = await del(`/api/v1/auth/users/${user._id}/wishlist/${productId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
  
      if (response.status === 200) {
        // Cập nhật state để xóa sản phẩm khỏi wishlist ngay lập tức
        setWishlist(prevWishlist => prevWishlist.filter(item => item._id !== itemId));
      } else {
        // Xử lý các mã trạng thái khác và thông báo lỗi
        const errorMessage = response.data?.message || 'Failed to delete item from wishlist';
        throw new Error(errorMessage);
      }
    } catch (error) {
      console.error('Error deleting wishlist item:', error.message);
      setError('Failed to delete item from wishlist. Please try again.');
    }
  };
  
  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const handleCancelOrder = async (cancelDetails) => {
    try {
      setLoading(true);
      const orderId = cancelDetails.orderId;
      const token = localStorage.getItem('token');

      const response = await put(`/api/v1/orders/${orderId}/status`, {
        status: 'Cancelled',
        cancellationReason: cancelDetails.reason,
        ...cancelDetails
      }, { headers: { Authorization: `Bearer ${token}` } });

      if (response.status === 200) {
        // Update the local orders state
        setOrders(prevOrders =>
          prevOrders.map(order =>
            order._id === orderId
              ? { ...order, status: 'Cancelled' }
              : order
          )
        );
        setReloadOrders(true); // Trigger a reload of orders
      } else {
        throw new Error(response.data.message || 'Failed to cancel order');
      }
    } catch (error) {
      console.error('Error cancelling order:', error.response?.data || error.message);
      setError('Failed to cancel order. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleMoveToCart = async (itemId) => {
    try {
      // Find the wishlist item with the provided itemId
      const item = wishlist.find(item => item._id === itemId);
  
      if (!item) {
        throw new Error('Item not found in wishlist');
      }
  
      // Use the product name to construct the query parameter
      const productName = encodeURIComponent(item.name);
  
      // Navigate to the product page with the query parameter
      navigate(`/product?name=${productName}`);
  
      // Make API call to add the item to the cart
      const response = await fetch('/api/v1/auth/cart/add-to-cart', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ itemId }), // Pass the itemId to the API
      });
  
      if (response.ok) {
        // If the request was successful, remove the item from the wishlist
        await handleDeleteWishlistItem(itemId);
      } else {
        throw new Error('Failed to add item to cart');
      }
    } catch (error) {
      console.error('Error moving item to cart:', error.message);
      setError('Failed to move item to cart. Please try again.');
    }
  };

  const transformWishlistData = (wishlist) => {
    return wishlist.map((item) => ({
      id: item._id,
      name: item.name,
      price: item.price,
      images: item.images,
    }));
  };

  // Hàm transform dữ liệu đơn hàng
  const transformOrderData = (orders) => {
    return orders.map((order) => ({
      id: order._id,
      productName: order.orderItems.map(item => item.name).join(', '),
      quantity: order.orderItems.map(item => item.quantity).join(', '),
      price: order.orderItems.map(item => item.price).join(', '),
      shippingAddress: order.shippingAddress.address,
      name: order.shippingAddress.fullName,
      phone: order.shippingAddress.phoneNumber,
      paymentMethod: order.paymentMethod,
      shippingPrice: order.shippingPrice,
      totalPrice: order.totalPrice,
      status: order.status,
      createAt: new Date(order.createdAt).toLocaleString(),
      updateAt: new Date(order.updatedAt).toLocaleString(),
    }));
  };

  // Cấu trúc cột của bảng hiển thị đơn hàng
  const orderColumns = [
    { field: "productName", headerName: "Product Name", width: 200 },
    { field: "quantity", headerName: "Quantity", width: 100 },
    { field: "totalPrice", headerName: "Total Price", width: 150 },
    { field: "shippingAddress", headerName: "Shipping Address", width: 300 },
    { field: "phone", headerName: "Phone", width: 150 },
    { field: "paymentMethod", headerName: "Payment Method", width: 150 },
    { field: "status", headerName: "Status", width: 150 },
  ];

  const renderSection = () => {
    if (loading) {
      return <div>Loading...</div>;
    }

    if (error) {
      return <div>{error}</div>;
    }

    if (!localUser) {
      return <div>No user data available</div>;
    }

    switch (activeSection) {
      case 'details':
        return <UserInfo.Section type="details" user={localUser} onUpdateUser={handleUpdateUser} />;
      case 'wishlist':
        return (
          <UserInfo.Section
            type="wishlist"
            wishlist={transformWishlistData(wishlist)}
            onMoveToCart={handleMoveToCart}
            onRemoveFromWishlist={handleDeleteWishlistItem}
          />
        );
      case 'orders':
        return (
          <UserInfo.Section
            type="orders"
            orders={transformOrderData(orders)}
            orderColumns={orderColumns}
            onCancelOrder={handleCancelOrder}
          />
        );
      default:
        return <UserInfo.Section type="details" user={localUser} onUpdateUser={handleUpdateUser} />;
    }
  };

  return (
    <div className="user-info-page">
      <h1>HI, {localUser?.name}</h1>
      <h2>ACCOUNT OVERVIEW</h2>
      <div className="content">
        <div className="sidebar">
          <ul>
            <li onClick={() => setActiveSection('details')}>Details</li>
            <li onClick={() => setActiveSection('wishlist')}>Wishlist</li>
            <li onClick={() => setActiveSection('orders')}>Your Orders</li>
            <li onClick={handleLogout}>Log Out</li>
          </ul>
        </div>
        <div className="UserInfo-main-content">{renderSection()}</div>
      </div>
    </div>
  );
};

export default UserInfoPage;
