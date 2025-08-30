import mongoose from "mongoose";

const couponSchema = new mongoose.Schema({
    code: { type: String, required: true },
    discountValue: { type: Number, required: true },
    startDate: { type: Date, required: true },
    endDate: { type: Date, required: true },
    usageCount: { type: Number, required: true },
    usageLimit: { type: Number, required: true },
}, { timestamps: true });

export default mongoose.model("Coupon", couponSchema, "coupons");