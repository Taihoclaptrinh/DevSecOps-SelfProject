import React, { createContext, useState, useEffect } from 'react';
import { put } from './config/api';

export const UserContext = createContext();

export const UserProvider = ({ children }) => {
    const [user, setUser] = useState(null);

    useEffect(() => {
        // Check localStorage when component mounts
        const storedUser = localStorage.getItem('user');
        if (storedUser) {
            const parsedUser = JSON.parse(storedUser);
            if (parsedUser && parsedUser._id) { // Use _id instead of id
                setUser(parsedUser);
                console.log('User data loaded from localStorage:', parsedUser);
            }
        }
    }, []);

    const login = (userData) => {
        if (userData && userData._id) { // Check _id instead of id
            setUser(userData);
            localStorage.setItem('user', JSON.stringify(userData));
            console.log('User logged in:', userData);
            // Store token in localStorage if available
            if (userData.token) {
                localStorage.setItem('token', userData.token);
            }
        } else {
            console.error('User data does not contain _id');
        }
    };
    
    const logout = () => {
        setUser(null);
        localStorage.removeItem('user');
        localStorage.removeItem('token');
    };

    // Function to update user information
    const updateUser = async (newUserData) => {
        try {
            // Use the user's _id to make a request to the update API
            const response = await put(`/api/v1/auth/users/${user._id}`, newUserData, {
                headers: {
                    Authorization: `Bearer ${localStorage.getItem('token')}`
                }
            });
            const updatedUser = response.data.user;
            if (updatedUser && updatedUser._id) { // Check _id instead of id
                setUser(updatedUser);
                localStorage.setItem('user', JSON.stringify(updatedUser));
                console.log('User updated:', updatedUser);
            } else {
                console.error('Updated user data does not contain _id');
            }
        } catch (error) {
            console.error('Error updating user data:', error);
        }
    };

    return (
        <UserContext.Provider value={{ user, login, logout, updateUser }}>
            {children}
        </UserContext.Provider>
    );
};
