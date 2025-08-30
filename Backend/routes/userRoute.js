import express from 'express';
import {
    updateUser, findUserById, getSummary, addProductToWishlist,
    getUserWishlist, removeProductFromWishlist,
} from '../controller/userController.js'; // Adjust path as needed
import { requireSignIn } from '../middlewares/authMiddleware.js';

const router = express.Router();

router.get('/summary', getSummary);
router.get('/users/:id', findUserById);
router.put('/users/:id', updateUser); // Route for updating user

// Add product to wishlist
router.post('/users/:id/wishlist/:productId', requireSignIn, addProductToWishlist);
router.get('/users/:id/wishlist', requireSignIn, getUserWishlist);
router.delete('/users/:id/wishlist/:productId', requireSignIn, removeProductFromWishlist);

export default router;