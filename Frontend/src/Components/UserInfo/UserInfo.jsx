import React, { useState } from 'react';
import { DataGrid } from '@mui/x-data-grid';
import { Delete as DeleteIcon, ShoppingCart as CartIcon } from '@mui/icons-material';
import './UserInfo.css';
import Swal from 'sweetalert2';
import { post } from '../../config/fetchConfig'
// import AddressSelector from '../Address/Address'; // Import the AddressSelector component

const UserInfo = ({ user, type, orders, orderColumns, onUpdateUser, onCancelOrder, wishlist, onMoveToCart, onRemoveFromWishlist }) => {
  const [isEditing, setIsEditing] = useState(false);
  const [updatedUser, setUpdatedUser] = useState(user);
  const [cancellingOrderId, setCancellingOrderId] = useState(null);
  const [cancelReason, setCancelReason] = useState('');
  const [paymentMethod, setPaymentMethod] = useState('COD');
  const [bankAccount, setBankAccount] = useState('');
  const [bankName, setBankName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isModalOpen, setIsModalOpen] = useState(false);
  const formatPrice = (price) => {
    return price.toLocaleString('vi-VN') + " VND";
  };
  const handleEdit = () => setIsEditing(true);
  const handleSave = () => {
    if (validateUser()) {
      onUpdateUser(updatedUser);
      setIsEditing(false);
    }
  };

  const validateUser = () => {
    const { email, phone } = updatedUser;
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const phoneRegex = /^[0-9]{10}$/;

    if (!emailRegex.test(email)) {
      alert('Please enter a valid email address.');
      return false;
    }

    if (!phoneRegex.test(phone)) {
      alert('Please enter a valid phone number (10 digits).');
      return false;
    }

    return true;
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setUpdatedUser({ ...updatedUser, [name]: value });
  };

  const handleCancel = async (orderId, status) => {
    if (status !== 'Pending') {
      Swal.fire('Error', 'Product can only be cancelled while pending.', 'error');
      return;
    }
    setCancellingOrderId(orderId);

    setIsModalOpen(true); // Open the modal
  };

  const updateProductStock = async (orderItems) => {
    try {
      for (const item of orderItems) {
        const response = await fetch(`/api/v1/auth/products/${item.product}/update-stock`, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${localStorage.getItem('token')}`,
          },
          body: JSON.stringify({
            quantity: item.quantity,
            size: item.size,
            operation: 'increase'
          }),
        });

        if (!response.ok) {
          throw new Error(`Failed to update stock for product ${item.product}`);
        }
      }
    } catch (error) {
      console.error('Error updating product stock:', error);
      throw error;
    }
  };

  const handleCancelConfirm = async () => {
    try {
      const localUser = JSON.parse(localStorage.getItem('user'));
      const correct_email = localUser.email;

      // Validate password (you'd need to implement this check against your backend)
      const isValidCredentials = await validateCredentials(correct_email, email, password);

      if (!isValidCredentials) {
        Swal.fire('Error', 'Invalid email or password. Try again!', 'error');
        return;
      }

      // Validate payment method
      const orderResponse = await fetch(`/api/v1/orders/get-order/${cancellingOrderId}`, {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('token')}`
        }
      });

      if (!orderResponse.ok) {
        throw new Error('Failed to fetch order details');
      }

      const orderData = await orderResponse.json();

      if (orderData.paymentMethod !== paymentMethod) {
        Swal.fire('Error', 'Selected payment method does not match the order\'s payment method.', 'error');
        return;
      }

      const result = await Swal.fire({
        title: 'Are you sure?',
        text: 'You won\'t be able to revert this!',
        icon: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#3085d6',
        cancelButtonColor: '#d33',
        confirmButtonText: 'Yes, cancel it!'
      });

      if (result.isConfirmed) {
        // Get the order details
        const orderResponse = await fetch(`/api/v1/orders/get-order/${cancellingOrderId}`, {
          headers: {
            Authorization: `Bearer ${localStorage.getItem('token')}`
          }
        });

        if (orderResponse.status === 401) {
          throw new Error('Unauthorized');
        }

        if (!orderResponse.ok) {
          throw new Error('Failed to fetch order details');
        }
        const orderData = await orderResponse.json();

        // Update the stock for each product in the order
        await updateProductStock(orderData.orderItems);

        // Call the onCancelOrder function passed as prop
        await onCancelOrder({
          orderId: cancellingOrderId,
          reason: cancelReason + (paymentMethod === 'E-Banking' ? ` | Bank Name: ${bankName} | Bank Account: ${bankAccount}` : ''),
          paymentMethod,
          bankName: paymentMethod === 'E-Banking' ? bankName : undefined,
          bankAccount: paymentMethod === 'E-Banking' ? bankAccount : undefined
        });

        Swal.fire('Cancelled!', 'Your order has been cancelled.', 'success');
        setCancellingOrderId(null);
        setCancelReason('');
        setPaymentMethod('COD');
        setBankName('');
        setBankAccount('');
        setPassword('');
      }

      setIsModalOpen(false); // Close the modal after confirming cancellation

    } catch (error) {
      console.error('Error cancelling order:', error);
      Swal.fire('Error', 'An error occurred while cancelling the order.', 'error');
    }
  };



  const validateCredentials = async (correct_email, email, password) => {
    try {
      const response = await post(
        '/api/v1/auth/validateCredentials',
        { correct_email, email, password }
      );

      return response.isValid;
    } catch (error) {
      console.error('Error validating credentials:', error);
      return false;
    }
  };


  const renderDetails = () => (
    <>
      <div className="details-header">
        <h2>DETAILS</h2>
      </div>
      <div className="details-content">
        <div className="avatar">
          <img
            src="https://minoshoesstorage.blob.core.windows.net/minoshoesbackground/people.jpg"
            alt="Avatar"
          />
        </div>
        {isEditing ? (
          <form>
            <label>
              Name:
              <input
                type="text"
                name="name"
                value={updatedUser.name}
                onChange={handleChange}
              />
            </label>
            <label>
              Email:
              <input
                type="email"
                name="email"
                value={updatedUser.email}
                onChange={handleChange}
              />
            </label>
            <label>
              Phone Number:
              <input
                type="text"
                name="phone"
                value={updatedUser.phone}
                onChange={handleChange}
              />
            </label>
            <label>
              Address:
              <input
                type="text"
                name="address"
                value={updatedUser.address}
                onChange={handleChange}
              />
            </label>
            <button type="button" onClick={handleSave} className="save">
              Save
            </button>
          </form>
        ) : (
          <>
            <p>
              <strong>Name:</strong> {user.name}
            </p>
            <p>
              <strong>Email:</strong> {user.email}
            </p>
            <p>
              <strong>Phone Number:</strong> {user.phone}
            </p>
            <p>
              <strong>Address:</strong> {user.address}
            </p>
            <button onClick={handleEdit} className="edit">
              Edit
            </button>
          </>
        )}
      </div>
    </>
  );

  const renderWishlist = () => (
    <>
      <div className="details-header">
        <h2>YOUR WISHLIST</h2>
      </div>
      <div className="wishlist-content">
        {wishlist.map((item) => (
          <div key={item.id} className="wishlist-item">
            <img src={item.images[0]} alt={item.name} className="product-image-wishlist" />
            <div className="product-info-wishlist">
              <h3>{item.name}</h3>
              <p>{formatPrice(item.price)}</p>
            </div>
            <div className="product-actions">
              <CartIcon
                onClick={() => onMoveToCart(item.id)}
                className="cart-icon"
                style={{ cursor: 'pointer', color: '#4caf50' }}
              />
              <DeleteIcon
                onClick={() => onRemoveFromWishlist(item.id)}
                className="delete-icon"
                style={{ cursor: 'pointer', color: '#e57373' }}
              />
            </div>
          </div>
        ))}
      </div>
    </>
  );

  const renderOrders = () => (
    <>
      <div className="details-header">
        <h2>YOUR ORDERS</h2>
      </div>
      <div className="orders-content">
        <DataGrid
          className="order-table"
          rows={orders}
          columns={[
            ...orderColumns,
            {
              field: 'cancel',
              headerName: 'Cancel',
              width: 150,
              renderCell: (params) => (
                <DeleteIcon
                  onClick={() => handleCancel(params.row.id, params.row.status)}
                  className="cancel-icon"
                  style={{ cursor: 'pointer', color: '#e57373' }}
                />
              ),
            },
          ]}
          pageSize={5}
          rowsPerPageOptions={[5, 10, 20]}
          autoHeight
        />
        <Modal isOpen={isModalOpen} onClose={() => setIsModalOpen(false)}>
          <div className="cancel-form">
            <h3>Cancel Order</h3>
            <form onSubmit={(e) => { e.preventDefault(); handleCancelConfirm(); }}>
              <label>
                Email:
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </label>
              <label>
                Password:
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </label>
              <label>
                Reason for Cancellation:
                <input
                  type="text"
                  value={cancelReason}
                  onChange={(e) => setCancelReason(e.target.value)}
                  required
                />
              </label>
              <label>
                Payment Method:
                <select
                  value={paymentMethod}
                  onChange={(e) => setPaymentMethod(e.target.value)}
                >
                  <option value="COD">COD</option>
                  <option value="E-Banking">E-Banking</option>
                </select>
              </label>
              {paymentMethod === 'E-Banking' && (
                <>
                  <label>
                    Bank Name:
                    <input
                      type="text"
                      value={bankName}
                      onChange={(e) => setBankName(e.target.value)}
                      required
                    />
                  </label>
                  <label>
                    Bank Account:
                    <input
                      type="text"
                      value={bankAccount}
                      onChange={(e) => setBankAccount(e.target.value)}
                      required
                    />
                  </label>
                </>
              )}
              <button
                type="submit"
                className="confirm-cancel"
              >
                Confirm
              </button>
              <button
                type="button"
                onClick={() => [setCancellingOrderId(null), setIsModalOpen(false)]}
                className="cancel-cancel"
              >
                Cancel
              </button>
            </form>
          </div>
        </Modal>
      </div>
    </>
  );



  const renderSection = () => {
    switch (type) {
      case 'details':
        return renderDetails();
      case 'wishlist':
        return renderWishlist();
      case 'orders':
        return renderOrders();
      default:
        return renderDetails();
    }
  };

  return <div className="user-info">{renderSection()}</div>;
};

const Modal = ({ isOpen, onClose, children }) => {
  if (!isOpen) return null;

  return (
    <div className="cancel_order-modal-overlay" onClick={onClose}>
      <div className="cancel_order-modal-content" onClick={(e) => e.stopPropagation()}>
        {/* <button className="close-button" onClick={onClose}>×</button> */}
        {children}
      </div>
    </div>
  );
};

UserInfo.Section = UserInfo;

export default UserInfo;
