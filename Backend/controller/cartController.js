import cartModel from '../models/cartModel.js';
import couponModel from '../models/couponModel.js';
import jwt from 'jsonwebtoken'; // Đảm bảo rằng import này có trong file của bạn

// Get cart items
export const getCart = async (req, res) => {
  try {
    const userId = req.user._id;
    const cart = await cartModel.findOne({ user: userId }).populate('cartItems.product');
    if (!cart) {
      return res.status(404).send({ message: 'Cart not found' });
    }
    res.status(200).send(cart);
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Error getting cart', error });
  }
};

// Add item to cart
export const addToCart = async (req, res) => {
  try {
    const { productId, quantity, price, size } = req.body; // Add size to the request body
    const userId = req.user._id;
    let cart = await cartModel.findOne({ user: userId });

    if (!cart) {
      cart = new cartModel({ user: userId, cartItems: [] });
    }

    // Ensure `addItemToCart` is a method on your cartModel
    await cart.addItemToCart(productId, quantity, price, size); // Pass size as an argument
    await cart.save(); // Ensure you save the cart after modifications
    res.status(200).send(cart);
  } catch (error) {
    console.error('Error adding to cart:', error);
    res.status(500).send({ message: 'Error adding to cart', error });
  }
};

// Update cart item quantity
export const updateCart = async (req, res) => {
  try {
    const { productId, quantity, price, size } = req.body; // Add size to the request body
    const userId = req.user._id;

    // Validate input
    if (typeof quantity !== 'number' || quantity < 0) {
      return res.status(400).send({ message: 'Invalid quantity' });
    }
    if (typeof price !== 'number' || price <= 0) {
      return res.status(400).send({ message: 'Invalid price' });
    }

    // Find user's cart
    const cart = await cartModel.findOne({ user: userId });
    if (!cart) {
      return res.status(404).send({ message: 'Cart not found' });
    }

    // Find the item to update (match by product ID and size)
    const existingItemIndex = cart.cartItems.findIndex(item =>
      item.product.toString() === productId.toString() && item.size === size
    );

    if (existingItemIndex >= 0) {
      if (quantity === 0) {
        // Remove item from cart if quantity is 0
        cart.cartItems.splice(existingItemIndex, 1);
      } else {
        // Update item quantity and price
        cart.cartItems[existingItemIndex].quantity = quantity;
        cart.cartItems[existingItemIndex].price = price;
      }

      // Save changes
      await cart.save();
      res.status(200).send(cart);
    } else {
      return res.status(404).send({ message: 'Product with specified size not found in cart' });
    }
  } catch (error) {
    console.error('Error updating cart:', error);
    res.status(500).send({ message: 'Error updating cart', error });
  }
};


export const removeFromCart = async (req, res) => {
  try {
    const { productId, size } = req.body; // Lấy productId và size từ body yêu cầu
    const token = req.headers.authorization.split(' ')[1]; // Lấy token từ header
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET); // Giải mã token

    if (!decodedToken) {
      return res.status(401).send({ message: 'Unauthorized' });
    }

    const userId = decodedToken._id; // Lấy userId từ token

    // Tìm giỏ hàng của người dùng
    const cart = await cartModel.findOne({ user: userId });

    if (!cart) {
      return res.status(404).send({ message: 'Cart not found' });
    }

    // Xóa sản phẩm theo productId và size
    const initialCartItemsLength = cart.cartItems.length;
    cart.cartItems = cart.cartItems.filter(item =>
      item.product.toString() !== productId.toString() || item.size !== size
    );

    // Kiểm tra nếu không có sản phẩm nào bị xóa
    if (cart.cartItems.length === initialCartItemsLength) {
      return res.status(404).send({ message: 'Product not found in cart' });
    }

    // Lưu giỏ hàng sau khi đã xóa sản phẩm
    const updatedCart = await cart.save();

    // Trả về giỏ hàng đã được cập nhật
    res.status(200).send({ message: 'Item removed successfully', cart: updatedCart });
  } catch (error) {
    console.error('Error removing from cart:', error);
    res.status(500).send({ message: 'Error removing from cart', error: error.message });
  }
};

// Count total items in cart
export const countCart = async (req, res) => {
  try {
    const userId = req.user._id;
    const cart = await cartModel.findOne({ user: userId });

    if (!cart) {
      return res.status(404).send({ message: 'Cart not found' });
    }

    const totalQuantity = cart.cartItems.reduce((accum, item) => accum + item.quantity, 0);

    res.status(200).send({ totalQuantity });
  } catch (error) {
    console.error('Error counting cart items:', error);
    res.status(500).send({ message: 'Error counting cart items', error });
  }
};
// Clear entire cart
export const clearCart = async (req, res) => {
  try {
    const userId = req.user._id;
    const cart = await cartModel.findOne({ user: userId });

    if (!cart) {
      return res.status(404).send({ message: 'Cart not found' });
    }

    // Clear all items from the cart
    cart.cartItems = [];
    await cart.save();

    res.status(200).send({ message: 'Cart cleared successfully' });
  } catch (error) {
    console.error('Error clearing cart:', error);
    res.status(500).send({ message: 'Error clearing cart', error });
  }
};

// Apply coupon to cart
export const applyCoupon = async (req, res) => {
  try {
    const { couponCode } = req.body;
    const userId = req.user._id;

    // Find the user's cart
    const cart = await cartModel.findOne({ user: userId });
    if (!cart) {
      return res.status(404).send({ message: 'Cart not found' });
    }

    // Find the coupon (case-insensitive)
    const coupon = await couponModel.findOne({ code: new RegExp(`^${couponCode}$`, 'i') });
    if (!coupon) {
      return res.status(404).send({ message: 'Coupon not found' });
    }

    // Check if the coupon is valid (within date range)
    const currentDate = new Date();
    if (currentDate < coupon.startDate) {
      return res.status(400).send({ message: 'Coupon is not yet valid.' });
    } else if (currentDate > coupon.endDate) {
      return res.status(400).send({ message: 'Coupon has expired.' });
    }

    // Check if the coupon has reached its usage limit
    if (coupon.usageCount >= coupon.usageLimit) {
      return res.status(400).send({ message: 'Coupon usage limit has been reached' });
    }

    // Calculate the discount
    const cartTotal = cart.cartItems.reduce((total, item) => total + item.price * item.quantity, 0);
    const discountAmount = Math.min(coupon.discountValue, cartTotal); // Ensure discount doesn't exceed cart total

    // Apply the discount to the cart
    cart.discount = discountAmount;
    cart.couponApplied = couponCode;
    await cart.save();

    // Update coupon usage count atomically
    await couponModel.updateOne({ code: couponCode }, { $inc: { usageCount: 1 } });

    res.status(200).send({
      message: 'Coupon applied successfully',
      cart: cart,
      discountAmount: discountAmount
    });

  } catch (error) {
    console.error('Error applying coupon:', error.message);
    res.status(500).send({ message: 'Error applying coupon', error: error.message });
  }
};
