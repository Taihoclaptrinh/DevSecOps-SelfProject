import express from 'express';
import {
    deleteProductById,
    getProductById, getAllProducts,
    getUserById, getAllUsers,
    countAllUsers, countAllOrders,
    getAllOrders, getOrderById,
    getLatestOrder,
    deleteOrderById, createCoupon,
    getAllCoupons, getCouponById,
    updateCoupon, deleteCoupon
} from '../controller/adminController.js'; // Ensure this path is correct

const router = express.Router();

// Route to count all users
router.get('/products', getAllProducts);
router.get('/products/:productId', getProductById);
router.delete('/products/:productId', deleteProductById);
router.get('/count-user', countAllUsers);
router.get('/get-user/:userId', getUserById);
router.get('/count-order', countAllOrders);
router.get('/orders', getAllOrders);
router.get('/orders/:orderId', getOrderById);
router.delete('/orders/:orderId', deleteOrderById);
router.get('/get2orders', getLatestOrder)
router.get('/get-user', getAllUsers);

// Route related to coupons
router.post('/coupons', createCoupon);
router.get('/coupons', getAllCoupons);
router.get('/coupons/:couponId', getCouponById);
router.put('/coupons/:couponId', updateCoupon);
router.delete('/coupons/:couponId', deleteCoupon);

export default router;