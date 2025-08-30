import mongoose from 'mongoose';
import User from './userModel.js';
import Coupon from './couponModel.js';

export const orderItemSchema = new mongoose.Schema({
    product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
    name: { type: String, required: true },
    quantity: { type: Number, required: true },
    price: { type: Number, required: true },
    size: { type: String, required: true },
}, { _id: false });

export const shippingAddressSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    address: { type: String, required: true },
    phoneNumber: { type: String, required: true },
}, { _id: false });

export const paymentResultSchema = new mongoose.Schema({
    transactionId: { type: String },
    status: { type: String },
    paymentTime: { type: Date },
}, { _id: false });

export const orderSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    email: { type: String, required: true },
    orderItems: [orderItemSchema],
    shippingAddress: shippingAddressSchema,
    paymentMethod: { type: String, required: true },
    paymentResult: paymentResultSchema,
    shippingPrice: { type: Number, required: true, default: 0.0 },
    totalPrice: { type: Number, required: true, default: 0.0 },
    status: { type: String, required: true, default: 'Pending' },
    deliveredAt: { type: Date },
    canceledAt: { type: Date }, 
    cancellationReason: { type: String },  
    coupon: { type: mongoose.Schema.Types.ObjectId, ref: 'Coupon' }
}, { timestamps: true });


export const Order = mongoose.model('Order', orderSchema, 'orders');