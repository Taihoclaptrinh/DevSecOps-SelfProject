import mongoose from 'mongoose';

const productSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    code: { type: String, required: true },
    description: { type: String, required: true, default: "No description" },
    price: { type: Number, required: true },
    brand: { type: String, required: true },
    category: { type: String, required: true, default: "Uncategorized" },
    sizes: { type: [String], required: true },
    color: { type: [String], required: true },
    stocks: { type: [Number], required: true },
    images: { type: [String], required: true }
}, { timestamps: true });

// Create a compound index on the 'code' field
productSchema.index({ code: 1 });

// If you need text search capabilities on other fields:
productSchema.index({ name: 'text', description: 'text' });

export default mongoose.model('Product', productSchema, 'products');