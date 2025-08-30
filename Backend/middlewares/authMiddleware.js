import JWT from 'jsonwebtoken';
import userModel from '../models/userModel.js';

// Middleware kiểm tra token xác thực
export const requireSignIn = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).send({ message: 'No token provided' });
  }

  JWT.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).send({ message: 'Invalid token' });
    }
    req.user = decoded;
    next();
  });
};

// Middleware kiểm tra quyền quản trị viên
export const isAdmin = async (req, res, next) => {
  try {
    const user = await userModel.findById(req.user._id);
    if (!user) {
      return res.status(404).send({
        success: false,
        message: 'User not found',
      });
    }

    if (user.role !== 1) {
      return res.status(403).send({
        success: false,
        message: 'Unauthorized access',
      });
    }

    next();
  } catch (error) {
    console.error('Error in admin middleware:', error);
    res.status(500).send({
      success: false,
      message: 'Error in admin middleware',
    });
  }
};

export const checkLoggedIn = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (token) {
    JWT.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        return next(); // Token không hợp lệ, tiếp tục đến trang login
      }
      req.user = decoded;
      return res.status(200).send({
        success: true,
        message: 'You are already logged in!',
      });
    });
  } else {
    return next(); // Không có token, tiếp tục đến trang login
  }
};