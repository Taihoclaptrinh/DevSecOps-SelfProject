import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { post, del } from './config/api';

const PaymentSuccess = () => {
  const [error, setError] = useState(null);
  const [showPopup, setShowPopup] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    const handlePaymentCompletion = async () => {
      const urlParams = new URLSearchParams(window.location.search);
      const status = urlParams.get('status');
      const orderCode = urlParams.get('orderCode');

      if (status === 'PAID' && orderCode) {
        const pendingOrder = JSON.parse(localStorage.getItem('pendingOrder'));
        if (pendingOrder) {
          try {
            const token = localStorage.getItem('token');
            const response = await post('/api/v1/orders/create-order', pendingOrder, {
              headers: { Authorization: `Bearer ${token}` }
            });

            if (response.status === 201) {
              const cleared = await clearCart();
              if (cleared) {
                setShowPopup(true);
                localStorage.removeItem('pendingOrder');
                setTimeout(() => {
                  navigate('/');
                }, 3000);
              } else {
                setError('Order created but failed to clear cart. Please refresh the page.');
              }
            } else {
              throw new Error('Failed to create order after successful payment');
            }
          } catch (error) {
            console.error('Error creating order after payment:', error);
            setError('Payment successful but failed to create order. Please contact support.');
          }
        }
      } else {
        setError('Payment failed or no order code provided.');
      }
    };

    const clearCart = async () => {
      const token = localStorage.getItem('token');
      try {
        const response = await del('/api/v1/auth/cart/clear', {
          headers: { Authorization: `Bearer ${token}` }
        });
        return response.status === 200;
      } catch (error) {
        console.error('Error clearing cart:', error);
        return false;
      }
    };

    handlePaymentCompletion();
  }, [navigate]);

  return (
    <div className="payment-success-container">
      {showPopup && (
        <div className="popup-success">
          <h2>Payment Successful!</h2>
          <p>Your order has been placed successfully.</p>
          <button onClick={() => navigate('/')}>Back to Home Page</button>
        </div>
      )}
      {error && (
        <div className="error-message">
          <h2>Error</h2>
          <p>{error}</p>
        </div>
      )}
    </div>
  );
};

export default PaymentSuccess;