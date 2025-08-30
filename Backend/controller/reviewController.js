import Review from "../models/reviewModel.js";
import Users from "../models/userModel.js";
import { Order } from "../models/orderModel.js";
import mongoose from "mongoose";

// List of offensive words
const offensiveWords = ['fuck', 'cunt', 'whore', 'slut', 'bitch', 'shit', 'damn', 'pussy', 'ass'];
const offensiveRegex = new RegExp(offensiveWords.join('|'), 'i');

// Create a new review
export const createReview = async (req, res) => {
    try {
        const { productId, rating, comment } = req.body;
        const userId = req.user._id; // Extract userId from the authenticated user object

        if (!userId) {
            return res.status(401).json({ message: "User not authenticated" });
        }

        if (!productId || !rating || !comment) {
            return res.status(400).json({ message: "Missing required fields" });
        }

        // Check if the user has already purchased the product
        const hasPurchased = await Order.exists({
            user: userId,
            'orderItems.product': productId,
            status: 'Delivered'
        });

        if (!hasPurchased) {
            return res.status(400).json({ message: "You must purchase the product before leaving a review" });
        }

        // Check if the user has already created a review for the product
        const existingReview = await Review.findOne({ productId, userId });
        if (existingReview) {
            return res.status(400).json({ message: "User has already created a review for this product" });
        }

        // Check if the content of review has offensive words
        if (offensiveRegex.test(comment)) {
            return res.status(400).json({ message: "Your review contains unsuitable words and we do not accept it" });
        }

        const review = new Review({ productId, userId, rating, comment });
        const savedReview = await review.save();

        res.status(201).json(savedReview);
    } catch (error) {
        console.error("Error in createReview:", error);
        res.status(500).json({ message: "Server error while creating review", error: error.message });
    }
};

// Get all reviews for a product
// export const getReviewsByProductId = async (req, res) => {
//     try {
//         const { productId } = req.params;
//         const reviews = await Review.find({ productId }).populate('userId', 'name');
//         res.status(200).json(reviews);
//     } catch (error) {
//         res.status(500).json({ message: "Server error while fetching reviews", error: error.message });
//     }
// };

// Get all reviews by a user
export const getReviewsByUserId = async (req, res) => {
    try {
        const { userId } = req.params;
        const reviews = await Review.find({ userId }).populate('productId', 'name');
        res.status(200).json(reviews);
    } catch (error) {
        res.status(500).json({ message: "Server error while fetching reviews", error: error.message });
    }
};

// Delete a review by user id and product id
export const deleteReview = async (req, res) => {
    try {
        const { productId } = req.body;
        const userId = req.user._id;

        const review = await Review.findOneAndDelete
            ({ productId, userId });

        if (!review) {
            return res.status(404).json({ message: "Review not found" });
        }

        res.status(200).json({ message: "Review deleted successfully" });
    }
    catch (error) {
        res.status(500).json({ message: "Server error while deleting review", error: error.message });
    }
};

// Get a specific review
// export const getReviewById = async (req, res) => {
//     try {
//         const { id } = req.params;
//         const review = await Review.findById(id).populate('userId', 'name').populate('productId', 'name');
//         if (!review) {
//             return res.status(404).json({ message: "Review not found" });
//         }
//         res.status(200).json(review);
//     } catch (error) {
//         res.status(500).json({ message: "Server error while fetching review", error: error.message });
//     }
// };


// Get reviews and average ratings for a product
export const getReviewsAndAverageRating = async (req, res) => {
    try {
        let { productId } = req.params;

        productId = productId.replace(/:/g, '');

        // Check if the product id is valid
        if (!mongoose.Types.ObjectId.isValid(productId)) {
            return res.status(400).json({ message: "Invalid productId format" });
        }

        // Fetch reviews for the product
        const reviews = await Review.find({ productId })
            .populate('userId', 'name')
            .sort({ createdAt: -1 });

        // Calculate average rating
        const totalRating = reviews.reduce((sum, review) => sum + review.rating, 0);
        const averageRating = reviews.length > 0 ? (totalRating / reviews.length).toFixed(1) : 0;

        // Prepare the response
        const response = {
            reviews: reviews.map(review => ({
                id: review._id,
                name: review.userId ? review.userId.name : 'Anonymous',
                rating: review.rating,
                comment: review.comment,
                createdAt: review.createdAt
            })),
            averageRating: parseFloat(averageRating),
            reviewCount: reviews.length
        };

        res.status(200).json(response);
    } catch (error) {
        console.error("Error in getReviewsAndAverageRating:", error);
        res.status(500).json({ message: "Server error while fetching reviews and average rating", error: error.message });
    }
};