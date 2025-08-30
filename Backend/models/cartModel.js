import mongoose from "mongoose";

const cartSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  cartItems: [
    {
      product: { type: mongoose.Schema.Types.ObjectId, ref: "Product", required: true },
      quantity: { type: Number, required: true, min: 1 },
      price: { type: Number, required: true, min: 1 },
      size: { type: String, required: true } // Add the size field here
    },
  ],
}, { timestamps: true });

// Method to calculate the total price of the cart
cartSchema.methods.calculateTotalPrice = function() {
  return this.cartItems.reduce((total, item) => total + item.quantity * item.price, 0);
};

// Method to add an item to the cart
cartSchema.methods.addItemToCart = async function(productId, quantity, price, size) { // Add size as a parameter
  const cart = this;
  const existingItemIndex = cart.cartItems.findIndex(item => 
    item.product.toString() === productId.toString() && item.size === size // Match by both product and size
  );
  
  if (existingItemIndex >= 0) {
    // The product with the same size already exists in the cart
    cart.cartItems[existingItemIndex].quantity += quantity;
    cart.cartItems[existingItemIndex].price = price; // Update price
  } else {
    // Add new product with size to the cart
    cart.cartItems.push({ product: productId, quantity, price, size });
  }

  return cart.save();
};

export default mongoose.model('Cart', cartSchema, 'carts');
