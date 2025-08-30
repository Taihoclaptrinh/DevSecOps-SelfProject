import express from 'express';
import {
    createReview,
    getReviewsByUserId,
    deleteReview,
    getReviewsAndAverageRating
} from '../controller/reviewController.js';
import { requireSignIn } from '../middlewares/authMiddleware.js';

const router = express.Router();

// Create a new review
router.post('/', requireSignIn, createReview);

// Get all reviews by a specific user
router.get('/user/:userId', getReviewsByUserId);

// Get Reviews And Average Rating for a product
router.get('/product/:productId', getReviewsAndAverageRating);

// Delete a review
router.delete('/', requireSignIn, deleteReview);

export default router;
