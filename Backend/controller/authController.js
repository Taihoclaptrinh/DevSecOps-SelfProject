import userModel from '../models/userModel.js';
import { comparePassword, hashPassword } from './../helpers/authHelper.js';
import JWT from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
dotenv.config();
const EMAIL_USERNAME = process.env.EMAIL_USERNAME;
const EMAIL_PASSWORD = process.env.EMAIL_PASSWORD;


const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: EMAIL_USERNAME,
    pass: EMAIL_PASSWORD,
  },
});

const sendVerificationCode = async (email, verificationCode) => {
  const mailOptions = {
    from: EMAIL_USERNAME,
    to: email,
    subject: 'Your Confirmation Code for Mino Shoes Store',
    text: `Dear ${email},
Thank you for creating an account with Mino Shoes Store. To complete your registration and ensure the security of your account, please use the following confirmation code: 
${verificationCode}

Please enter this code on our website to verify your email address and activate your account. This code will expire in 24 hours for security reasons.
If you didn't request this code or need any assistance, please contact our customer support team at minoshoesstore@gmail.com.

We're excited to have you join our community of shoe enthusiasts! Once your account is verified, you'll be able to:

- Browse our latest shoe collections
- Save your favorite styles
- Receive exclusive offers and updates
- Enjoy a seamless shopping experience

Thank you for choosing Mino Shoes Store for your footwear needs.

Best regards,
Mino Shoes Team`,
  };

  try {
    await transporter.sendMail(mailOptions);
    return true;
  } catch (error) {
    console.error('Error sending email:', error);
    return false;
  }
};

// Kiểm tra email
export const checkEmailController = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).send({ message: 'Email is required' });
    }

    // Kiểm tra tính hợp lệ của email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).send({ message: 'Invalid email address' });
    }

    const existingUser = await userModel.findOne({ email });
    if (existingUser) {
      return res.status(200).send({ userExists: true });
    } else {
      const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
      const success = await sendVerificationCode(email, verificationCode);
      if (!success) {
        return res.status(500).send({ message: 'Failed to send verification code' });
      }
      return res.status(200).send({ userExists: false, verificationCode });
    }
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: 'Error in checking email',
      error,
    });
  }
};

// Đăng ký người dùng
export const registerController = async (req, res) => {
  try {
    const { name, email, password, phone, address, verificationCode, providedCode } = req.body;
    if (!verificationCode || verificationCode !== providedCode) {
      return res.status(400).send({ message: 'Invalid verification code' });
    }

    if (!name || !email || !password || !address) {
      return res.status(400).send({ message: 'All fields are required' });
    }

    const existingUser = await userModel.findOne({ email });
    if (existingUser) {
      return res.status(200).send({
        success: false,
        message: 'Already registered, please login',
      });
    }

    const hashedPassword = await hashPassword(password);
    const user = await new userModel({ name, email, phone, address, password: hashedPassword }).save();

    res.status(201).send({
      success: true,
      message: 'User registered successfully',
      user,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: 'Error in registration',
      error,
    });
  }
};


// Đăng nhập người dùng
export const loginController = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).send({
        success: false,
        message: 'Invalid email or password!',
      });
    }

    const user = await userModel.findOne({ email });
    if (!user) {
      return res.status(404).send({
        success: false,
        message: 'Email does not exist!',
      });
    }

    const match = await comparePassword(password, user.password);
    if (!match) {
      return res.status(401).send({
        success: false,
        message: 'Invalid password!',
      });
    }

    const token = JWT.sign({ _id: user._id }, process.env.JWT_SECRET, {
      expiresIn: '7d',
    });
    console.log('Generated Token:', token);

    res.status(200).send({
      success: true,
      message: 'Login successfully!',
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        address: user.address,
      },
      token,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: 'Error in login',
      error,
    });
  }
};


// Test controller
export const testController = (req, res) => {
  try {
    res.send('Protected Routes');
  } catch (error) {
    console.log(error);
    res.send({ error });
  }
};

// Create user
export const createUser = async (req, res) => {
  try {
    const { name, email, password, phone, address } = req.body;
    const hashedPassword = await hashPassword(password);
    const user = await new userModel({ name, email, password: hashedPassword, phone, address }).save();
    res.status(201).send({
      success: true,
      message: 'User created successfully',
      user,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: 'Error in creating user',
      error,
    });
  }
};

// Read all users
export const readUsers = async (req, res) => {
  try {
    const users = await userModel.find({});
    res.status(200).send(users);
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: 'Error in reading users',
      error,
    });
  }
};

// Delete user
export const deleteUser = async (req, res) => {
  try {
    await userModel.findByIdAndDelete(req.params.id);
    res.status(200).send({
      success: true,
      message: 'User deleted successfully',
    });
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: 'Error in deleting user',
      error,
    });
  }
};

// Find user (ID, mail, name)
export const findUser = async (req, res) => {
  try {
    const { search } = req.query;
    const user = await userModel.find({
      $or: [
        { _id: search },
        { email: search },
        { name: { $regex: search, $options: 'i' } },
      ],
    });
    res.status(200).send(user);
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: 'Error in finding user',
      error,
    });
  }
};

// Show all users
export const showAllUsers = async (req, res) => {
  try {
    const users = await userModel.find({});
    res.status(200).send(users);
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: 'Error in showing all users',
      error,
    });
  }
};

// Đặt lại mật khẩu
export const resetPasswordController = async (req, res) => {
  try {
    const { email, resetCode, newPassword, resetToken } = req.body;

    if (!email || !resetCode || !newPassword || !resetToken) {
      return res.status(400).send({ message: 'All fields are required' });
    }

    let decoded;
    try {
      decoded = JWT.verify(resetToken, process.env.JWT_SECRET);
    } catch (error) {
      return res.status(400).send({ message: 'Invalid or expired reset token' });
    }

    if (decoded.email !== email || decoded.resetCode !== resetCode) {
      return res.status(400).send({ message: 'Invalid reset code' });
    }

    const existingUser = await userModel.findOne({ email });
    if (!existingUser) {
      return res.status(404).send({ message: 'Email does not exist' });
    }

    existingUser.password = await hashPassword(newPassword);
    await existingUser.save();

    res.status(200).send({
      success: true,
      message: 'Password reset successfully',
    });
  } catch (error) {
    console.log('Error in resetting password:', error);
    res.status(500).send({
      success: false,
      message: 'Error in resetting password',
      error,
    });
  }
};
// Hàm gửi mã reset mật khẩu
export const sendResetCode = async (email, resetCode) => {
  const mailOptions = {
    from: process.env.EMAIL_USERNAME,
    to: email,
    subject: 'Password Reset Code for Mino Shoes Store',
    text: `Dear ${email},

We received a request to reset the password for your account at Mino Shoes Store. To proceed with resetting your password, please use the following code:

${resetCode}

Enter this code on our password reset page to verify your identity and create a new password. This code will expire in 1 hour for security reasons.

If you didn't request a password reset, please disregard this email and ensure your account is secure. If you have any concerns, contact our support team immediately at minoshoesstore@gmail.com.

Thank you for being a valued customer of Mino Shoes Store.

Best regards,
Mino Shoes Store Security Team`,
  };

  try {
    await transporter.sendMail(mailOptions); // Đảm bảo gọi hàm sendMail
    return true;
  } catch (error) {
    console.error('Error sending email:', error);
    return false;
  }
};


// Gửi mã reset qua email
export const sendResetCodeController = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).send({ message: 'Email is required' });
    }

    const existingUser = await userModel.findOne({ email });
    if (!existingUser) {
      return res.status(404).send({ message: 'Email does not exist' });
    }

    const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
    const resetToken = JWT.sign({ email, resetCode }, process.env.JWT_SECRET, { expiresIn: '15m' });

    const success = await sendResetCode(email, resetCode);
    if (!success) {
      return res.status(500).send({ message: 'Failed to send reset code' });
    }

    res.status(200).send({
      success: true,
      message: 'Reset code sent to email',
      resetToken,
    });
  } catch (error) {
    console.log(error);
    res.status(500).send({
      success: false,
      message: 'Error in sending reset code',
      error,
    });
  }
};

export const validateCredentials = async (req, res) => {
  try {
    const { correct_email, email, password } = req.body;

    // Check if the email is correct
    if (email !== correct_email) {
      return res.status(400).json({ isValid: false, message: 'Invalid email' });
    }

    // Find the user by email
    const user = await userModel.findOne({ email });

    if (!user) {
      return res.status(400).json({ isValid: false, message: 'User not found' });
    }

    // Compare the plain text password from the request with the stored hashed password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (isPasswordValid) {
      res.json({ isValid: true, message: 'Credentials are valid' });
    } else {
      res.status(400).json({ isValid: false, message: 'Invalid credentials' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ isValid: false, message: 'Server error' });
  }
}
export const sendCancellationEmail = async (recipientEmail, order) => {
  try {
      const mailOptions = {
          from: EMAIL_USERNAME, // Địa chỉ email của bạn
          to: order.email, // Địa chỉ email người nhận
          subject: 'Order Cancellation Confirmation',
          text: `Your order with ID ${order._id} has been cancelled. Reason: ${order.cancellationReason}`,
      };
      console.log('Mail options:', mailOptions);

      await transporter.sendMail(mailOptions);
      return true;
  } catch (error) {
      console.error('Error sending cancellation email:', error);
      return false;
  }
};