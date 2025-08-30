import User from '../models/userModel.js'; // Import User model
import { Order } from '../models/orderModel.js'; // Import Order model
import Product from '../models/productModel.js'; // Import Product model
import Coupon from '../models/couponModel.js'; // Import Coupon model

// Function to count all users
export const countAllUsers = async (req, res) => {
    try {
        const userCount = await User.countDocuments(); // Count all user documents
        res.status(200).json({
            success: true,
            count: userCount // Send the count as part of the response
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Error occurred while counting users',
            error: error.message // Send error message if something goes wrong
        });
    }
};

// Function to count all orders
export const countAllOrders = async (req, res) => {
    try {
        const orderCount = await Order.countDocuments(); // Count all order documents
        res.status(200).json({
            success: true,
            count: orderCount // Send the count as part of the response
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Error occurred while counting orders',
            error: error.message // Send error message if something goes wrong
        });
    }
};
export const getLatestOrder = async (req, res) => {
    try {
        // Truy vấn để lấy 2 order mới nhất
        const orders = await Order.find({})
            .sort({ createdAt: -1 }) // Sắp xếp theo createdAt giảm dần (mới nhất trước)
            .limit(2); // Giới hạn chỉ lấy 2 đơn hàng

        res.status(200).json({ orders });
    } catch (error) {
        console.error('Error fetching orders:', error);
        res.status(500).json({ message: 'Failed to fetch orders' });
    }
};
export const getAllUsers = async (req, res) => {
    try {
        const users = await User.find(); // Fetch all users

        res.status(200).json({
            success: true,
            users // Send the user data as part of the response
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Error occurred while retrieving users',
            error: error.message // Send error message if something goes wrong
        });
    }
};

// Function to get a single user by ID
export const getUserById = async (req, res) => {
    try {
        const { userId } = req.params; // Extract userId from request parameters
        const user = await User.findById(userId); // Find user by ID

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found',
            });
        }

        res.status(200).json({
            success: true,
            user // Send the user data as part of the response
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Error occurred while retrieving user',
            error: error.message // Send error message if something goes wrong
        });
    }
};

export const getAllProducts = async (req, res) => {
    try {
        const products = await Product.find(); // Fetch all products

        res.status(200).json({
            success: true,
            products // Send the product data as part of the response
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Error occurred while retrieving products',
            error: error.message // Send error message if something goes wrong
        });
    }
};

export const getProductById = async (req, res) => {
    try {
        const { productId } = req.params; // Extract productId from request parameters
        const product = await Product.findById(productId); // Find product by ID

        if (!product) {
            return res.status(404).json({
                success: false,
                message: 'Product not found',
            });
        }

        res.status(200).json({
            success: true,
            product // Send the product data as part of the response
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Error occurred while retrieving product',
            error: error.message // Send error message if something goes wrong
        });
    }
};

// Function to delete a product by ID
export const deleteProductById = async (req, res) => {
    try {
        const { productId } = req.params; // Extract productId from request parameters
        const product = await Product.findByIdAndDelete(productId); // Find and delete product by ID

        if (!product) {
            return res.status(404).json({
                success: false,
                message: 'Product not found',
            });
        }

        res.status(200).json({
            success: true,
            message: 'Product deleted successfully',
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Error occurred while deleting product',
            error: error.message,
        });
    }
};

export const getAllOrders = async (req, res) => {
    try {
        const orders = await Order.find().populate('user', 'email');
        res.json({ orders });
    } catch (error) {
        console.error("Error fetching orders:", error);
        res.status(500).json({ error: "Internal server error", details: error.message });
    }
};

export const getOrderById = async (req, res) => {
    try {
        const { orderId } = req.params; // Lấy orderId từ tham số request
        const order = await Order.findById(orderId).populate('user', 'name email'); // Tìm đơn hàng theo ID và populate thông tin người dùng

        if (!order) {
            return res.status(404).json({
                success: false,
                message: 'Order not found',
            });
        }

        res.status(200).json({
            success: true,
            order // Trả về dữ liệu đơn hàng
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Error occurred while retrieving order',
            error: error.message // Trả về thông báo lỗi nếu có
        });
    }
};

export const deleteOrderById = async (req, res) => {
    try {
        const { orderId } = req.params; // Extract productId from request parameters
        const order = await Order.findByIdAndDelete(orderId); // Find and delete product by ID

        if (!order) {
            return res.status(404).json({
                success: false,
                message: 'Order not found',
            });
        }

        res.status(200).json({
            success: true,
            message: 'Order deleted successfully',
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Error occurred while deleting Order',
            error: error.message,
        });
    }
};

export const createCoupon = async (req, res) => {
    try {
        const { code, discountValue, startDate, endDate, usageCount, usageLimit } = req.body;
        const coupon = new Coupon({
            code,
            discountValue,
            startDate,
            endDate,
            usageCount: 0,
            usageLimit,
        });

        const createdCoupon = await coupon.save();

        res.status(201).json(createdCoupon);
    } catch (error) {
        res.status(500).json({ message: 'Failed to create coupon', error: error.message });
    }
};

// Function to get all coupons
export const getAllCoupons = async (req, res) => {
    try {
        const coupons = await Coupon.find();

        res.status(200).json(coupons);
    } catch (error) {
        res.status(500).json({ message: 'Failed to retrieve coupons', error: error.message });
    }
};

// Function to get a single coupon by ID
export const getCouponById = async (req, res) => {
    try {
        const { couponId } = req.params;
        const coupon = await Coupon.findById(couponId);

        if (!coupon) {
            return res.status(404).json({ message: 'Coupon not found' });
        }

        res.status(200).json(coupon);
    } catch (error) {
        res.status(500).json({ message: 'Failed to retrieve coupon', error: error.message });
    }
};

// Function to update a coupon
export const updateCoupon = async (req, res) => {
    try {
        const { code, discountValue, startDate, endDate, usageLimit } = req.body;
        const coupon = await Coupon.findById(req.body.couponId);

        if (!coupon) {
            return res.status(404).json({ message: 'Coupon not found' });
        }

        coupon.code = code;
        coupon.discountValue = discountValue;
        coupon.startDate = startDate;
        coupon.endDate = endDate;
        coupon.usageLimit = usageLimit;

        const updatedCoupon = await coupon.save();
        res.status(200).json(updatedCoupon);
    }
    catch (error) {
        res.status(500).json({ message: 'Failed to update coupon', error: error.message });
    }
}

// Function to delete a coupon
export const deleteCoupon = async (req, res) => {
    try {
        const { couponId } = req.params;
        const coupon = await Coupon.findById(couponId);

        if (!coupon) {
            return res.status(404).json({ message: 'Coupon not found' });
        }

        await coupon.remove();
        res.status(200).json({ message: 'Coupon deleted successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Failed to delete coupon', error: error.message });
    }
}