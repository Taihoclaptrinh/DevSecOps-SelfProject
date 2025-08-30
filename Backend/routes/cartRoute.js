import express from 'express';
import { requireSignIn, isAdmin } from '../middlewares/authMiddleware.js';
import { clearCart, countCart, addToCart, getCart, updateCart, removeFromCart, applyCoupon } from '../controller/cartController.js';

const router = express.Router();

router.get('/count', requireSignIn, countCart);
router.get('/get-cart', requireSignIn, getCart);
router.post('/add-to-cart', requireSignIn, addToCart);
router.put('/update-cart', requireSignIn, updateCart);
router.delete('/clear', requireSignIn, clearCart);
router.delete('/remove-from-cart/', requireSignIn, removeFromCart);
router.post('/apply-coupon', requireSignIn, applyCoupon);

// router.post('/admin-route', requireSignIn, isAdmin, (req, res) => {
//   res.send('Admin access granted');
// });

export default router;
