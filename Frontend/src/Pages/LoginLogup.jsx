import React, { useState, useContext } from "react";
import "./CSS/LoginLogup.css";
import AddressSelector from "../Components/Address/Address.jsx"
import { get, post } from '../config/api';
import { useNavigate } from 'react-router-dom';
import { UserContext } from '../UserContext.js';

const LoginLogup = () => {
    const [showSignIn, setShowSignIn] = useState(true);
    const [showSignUp, setShowSignUp] = useState(false);
    const [showPassword, setShowPassword] = useState(false);
    const [showForgotPassword, setShowForgotPassword] = useState(false);
    const [email, setEmail] = useState('');
    const [verificationCode, setVerificationCode] = useState('');
    const [providedCode, setProvidedCode] = useState('');
    const [password, setPassword] = useState('');
    const [name, setName] = useState('');
    const [phone, setPhone] = useState('');
    const [address, setAddress] = useState({city: '', district: '', ward: ''});
        const [error, setError] = useState('');
    const [success, setSuccess] = useState('');
    const { login } = useContext(UserContext);

    const navigate = useNavigate();

    const handleEmailChange = (e) => setEmail(e.target.value);

    const handleEmailSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setSuccess('');

        try {
            const response = await post('/api/v1/auth/check-email', { email });
            if (response.data.userExists) {
                setShowPassword(true);
                setShowSignIn(false);
            } else {
                setVerificationCode(response.data.verificationCode);
                setShowSignUp(true);
                setShowSignIn(false);
            }
        } catch (error) {
            console.error('Error checking email:', error);
            setError('An error occurred while checking the email.');
        }
    };

    const handleSignUpSubmit = async (e) => {
        e.preventDefault();
        setError(''); 
        setSuccess(''); 
    
        // Kiểm tra mã xác thực
        if (verificationCode !== providedCode) {
            setError('Verification code is incorrect.'); 
            return;
        }
        
        // Kiểm tra các trường thông tin
        if (!name || !phone || !address || !password) {
            setError('All fields are required.'); // Hiển thị lỗi nếu có trường thông tin thiếu
            return;
        }
        const fullAddress = `${address.street}, ${address.ward}, ${address.district}, ${address.city}`;

        try {
            // Gửi yêu cầu đăng ký đến API
            const response = await post('/api/v1/auth/register', {
                name,
                email,
                password,
                phone,
                address: fullAddress,
                verificationCode,
                providedCode
            });
    
            // Xử lý kết quả trả về từ API
            if (response.data.success) {
                setSuccess('Registration successful! You can now sign in.'); // Hiển thị thông báo thành công
                setShowSignIn(true); // Hiển thị form đăng nhập
                setShowSignUp(false); // Ẩn form đăng ký
            } else {
                setError(response.data.message || 'Registration failed. Please try again.'); // Hiển thị lỗi từ API hoặc thông báo lỗi chung
            }
        } catch (error) {
            console.error('Error registering:', error); // Ghi log lỗi ra console
            setError(error.response?.data?.message || 'An error occurred while registering. Please try again later.'); // Hiển thị thông báo lỗi
        }
    };
    

    const handleLoginSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setSuccess('');
    
        if (!email || !password) {
            setError('Email and password are required.');
            return;
        }
    
        try {
            const response = await post('/api/v1/auth/login', { email, password });
            if (response.data.success) {
                const token = response.data.token;
                localStorage.setItem('token', token);
    
                // Fetch full user data based on ID
                const userResponse = await get(`/api/v1/auth/users/${response.data.user._id}`, {
                    headers: { Authorization: `Bearer ${token}` }
                });
    
                const user = userResponse.data;
                login(user); // Store user data in context and localStorage
                navigate('/');
            } else {
                setError('Login failed. Please check your email and password.');
            }
        } catch (error) {
            console.error('Error logging in:', error);
            setError('Your email/password is incorrect!');
        }
    };
    
    const handleSendResetCode = async () => {
        setError('');
        setSuccess('');
    
        if (!email) {
            setError('Email is required.');
            return false; // Indicate failure
        }
    
        try {
            const response = await post('/api/v1/auth/send-reset-code', { email });
    
            if (response.data.success) {
                const token = response.data.resetToken;
                localStorage.setItem('resetToken', token);
                setSuccess('Reset code sent to email.');
                return true; // Indicate success
            } else {
                setError(response.data.message || 'Failed to send reset code. Please try again.');
                return false; // Indicate failure
            }
        } catch (error) {
            setError('An error occurred while sending the reset code. Please try again later.');
            console.error('Error sending reset code:', error);
            return false; // Indicate failure
        }
    };

    const handleForgotPasswordSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setSuccess('');
    
        const resetToken = localStorage.getItem('resetToken');
    
        if (!providedCode || !password) {
            setError('Verification code and new password are required.');
            return;
        }
    
        try {
            const response = await post('/api/v1/auth/reset-password', {
                email,
                resetCode: providedCode, 
                newPassword: password,
                resetToken
            });
    
            if (response.data.success) {
                setSuccess('Password reset successful! You can now sign in with your new password.');
                setShowSignIn(true);
                setShowForgotPassword(false);
            } else {
                setError(response.data.message || 'Password reset failed. Please try again.');
            }
        } catch (error) {
            console.error('Error resetting password:', error);
            setError(error.response?.data?.message || 'An error occurred while resetting password. Please try again later.');
        }
    };

    const showForgotPasswordForm = async () => {
        setShowForgotPassword(true);
        setShowSignIn(false);
        setShowPassword(false);
        
        // Send the reset code immediately after showing the forgot password form
        const success = await handleSendResetCode();
        if (!success) {
            setError('Please try again.');
        }
    };
    const handleAddressChange = (newAddress) => {
        setAddress(prevAddress => ({
            ...prevAddress,
            city: newAddress.city,
            district: newAddress.district,
            ward: newAddress.ward
        }));
    };
    return (
        <div className="login-logup">
            {showSignIn && (
                <div className="login-container">
                    <h1>WELCOME</h1>
                    <h2 style={{fontWeight:"normal"}}>Enter your email to join us or sign in.</h2>
                    <form id="email-form" onSubmit={handleEmailSubmit}>
                        <div className="input-container">
                            <input
                                type="email"
                                placeholder="Enter your email"
                                required
                                value={email}
                                onChange={handleEmailChange}
                            />
                        </div>
                        {error && <p className="error-message">{error}</p>}
                        <button type="submit" style={{ marginTop: "4rem" }}>CONTINUE</button>
                    </form>
                </div>
            )}

            {showPassword && (
                <div className="login-container">
                    <h1>WELCOME</h1>
                    <form id="password-form" onSubmit={handleLoginSubmit}>
                        <div className="input-container">
                            <input
                                type="password"
                                placeholder="Enter your password"
                                required
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                            />
                        </div>
                        {error && <p className="error-message">{error}</p>}
                        <div className="forgot-password">
                            <a type="button" onClick={showForgotPasswordForm}>Forgot password?</a>
                        </div>
                        <button type="submit">CONTINUE</button>
                    </form>
                </div>
            )}

            {showForgotPassword && (
                <div className="login-container">
                    <h1>VERIFICATION</h1>
                    <p>Verify your email and enter a new password</p>
                    <form id="verification-form" onSubmit={handleForgotPasswordSubmit}>
                        <div className="input-container">
                            <input
                                type="text"
                                placeholder="Verification Code*"
                                required
                                value={providedCode}
                                onChange={(e) => setProvidedCode(e.target.value)}
                            />
                        </div>
                        <div className="input-container">
                            <input style={{ marginBottom: "1rem" }}
                                type="password"
                                placeholder="New Password*"
                                required
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                            />
                        </div>
                        {error && <p className="error-message">{error}</p>}
                        {success && <p className="success-message">{success}</p>}
                        <button type="submit">CONFIRM</button>
                    </form>
                </div>
            )}

        {showSignUp && (
                <div className="signup-container">
                    <h1>LET’S MAKE YOU A MEMBER</h1>
                    <form id="signup-form" onSubmit={handleSignUpSubmit}>
                        <div className="signup-input-container">
                            <input
                                type="text"
                                placeholder="Name"
                                required
                                value={name}
                                onChange={(e) => setName(e.target.value)}
                            />
                        </div>
                        <div className="signup-input-container">
                            <input
                                type="text"
                                placeholder="Phone"
                                required
                                value={phone}
                                onChange={(e) => setPhone(e.target.value)}
                            />
                        </div>
                        <AddressSelector onAddressChange={handleAddressChange} />
                        <div className="signup-input-container">
                            <input
                                type="text"
                                placeholder="Street Address"
                                required
                                value={address.street}
                                onChange={(e) => setAddress(prevAddress => ({ ...prevAddress, street: e.target.value }))}
                            />
                        </div>
                        <div className="signup-input-container">
                            <input
                                type="password"
                                placeholder="Password"
                                required
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                            />
                        </div>
                        <div className="signup-input-container">
                            <input
                                type="text"
                                placeholder="Verification Code"
                                required
                                value={providedCode}
                                onChange={(e) => setProvidedCode(e.target.value)}
                            />
                        </div>
                        {error && <p className="error-message">{error}</p>}
                        {success && <p className="success-message">{success}</p>}
                        <button type="submit">REGISTER</button>
                    </form>
                </div>
            )}
        </div>
    );
};

export default LoginLogup;
