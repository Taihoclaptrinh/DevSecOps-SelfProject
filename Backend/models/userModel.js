import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true,
    },
    phone: {
        type: String,
        required: true
    },
    address: {
        type: String,
        required: true
    },
    totalSpent: {
        type: Number,
        default: 0
    },
    role: {
        type: Number,
        default: 0
    },
    wishlist: [
        {
            product: { type: mongoose.Schema.Types.ObjectId, ref: "Product", required: true },
            name: { type: String, required: true },
            price: { type: Number, required: true, min: 1 },
            images: { type: [String], required: true }
        },
    ],
}, { timestamps: true });

export default mongoose.model("User", userSchema, "users");
