import Product from '../models/productModel.js';

// Tạo mới sản phẩm
export const createProduct = async (req, res) => {
    try {
        const product = new Product(req.body);
        const savedProduct = await product.save();
        res.status(201).json(savedProduct);
    } catch (error) {
        res.status(500).json({ message: "Server error while creating product", error });
    }
};

// Lấy thông tin sản phẩm theo ID
export const getProductByName = async (req, res) => {
    try {
        const productName = req.params.name;
        const product = await Product.findOne({ name: productName });
        if (!product) {
            return res.status(404).json({ message: 'Product not found' });
        }
        res.status(200).json(product);
    } catch (error) {
        res.status(500).json({ message: 'Server error while fetching product', error: error.message });
    }
};
// Cập nhật thông tin sản phẩm theo ID
export const updateProduct = async (req, res) => {
    try {
        const updatedProduct = await Product.findByIdAndUpdate(req.params.id, req.body, { new: true });
        if (!updatedProduct) {
            return res.status(404).json({ message: "Product not found" });
        }
        res.status(200).json(updatedProduct);
    } catch (error) {
        res.status(500).json({ message: "Server error while updating product", error });
    }
};

// Xoá sản phẩm theo ID
export const deleteProduct = async (req, res) => {
    try {
        const deletedProduct = await Product.findByIdAndDelete(req.params.id);
        if (!deletedProduct) {
            return res.status(404).json({ message: "Product not found" });
        }
        res.status(200).json({ message: "Product deleted successfully" });
    } catch (error) {
        res.status(500).json({ message: "Server error while deleting product", error });
    }
};

// Lấy danh sách các sản phẩm liên quan
export const getRelatedProducts = async (req, res) => {
    try {
        const { productId } = req.params;

        // Lấy thông tin sản phẩm hiện tại
        const currentProduct = await Product.findById(productId);
        if (!currentProduct) {
            return res.status(404).json({ message: "Product not found" });
        }

        // Lấy danh sách các sản phẩm liên quan
        const relatedProducts = await Product.find({
            category: currentProduct.category,
            _id: { $ne: currentProduct._id }
        }).limit(5);

        res.status(200).json(relatedProducts);
    } catch (error) {
        res.status(500).json({ message: "Server error while fetching related products", error });
    }
};
export const searchProducts = async (req, res) => {
    const { query } = req.query;
    try {
        if (!query) {
            return res.status(400).json({ message: 'Query parameter is required' });
        }

        const products = await Product.find({
            $or: [
                { name: { $regex: query, $options: 'i' } },
                { category: { $regex: query, $options: 'i' } },
                { brand: { $regex: query, $options: 'i' } }  // Ensure 'brand' is a field in your Product model
            ]
        });

        res.json(products);
    } catch (error) {
        console.error('Error searching products:', error);
        res.status(500).json({ message: 'Server error while fetching products', error: error.message });
    }
};


export const getProducts = async (req, res) => {
    try {
        const { size, brand, gender, minPrice, maxPrice, sale } = req.query;
        const filters = {};

        // Add filters based on query parameters
        if (size) {
            filters.sizes = { $in: size.split(',') };
        }

        if (gender) {
            if (gender === 'Women') {
                filters.sizes = { $in: [1.0, 2.0, 2.5, 3.0, 3.5, 4.0, 4.5, 5] }; // Sizes for women
            } else if (gender === 'Men') {
                filters.sizes = { $in: [5.5, 6.0, 6.5, 7, 7.5, 8, 8.5, 9, 9.5, 10, 10, 11, 12] }; // Sizes for men
            }
        }

        if (brand) {
            filters.brand = { $in: brand.split(',') };
        }

        if (minPrice || maxPrice) {
            filters.price = {};
            if (minPrice) filters.price.$gte = Number(minPrice);
            if (maxPrice) filters.price.$lte = Number(maxPrice);
        }

        // Add sale filter if provided
        if (sale !== undefined) {
            filters.sale = sale === 'true';
        }

        // Fetch products from the database with the applied filters
        const products = await Product.find(filters);

        res.status(200).json(products);
    } catch (error) {
        console.error('Server error while fetching products:', error);
        res.status(500).json({ message: "Server error while fetching products", error });
    }
};


export const checkout = async (req, res) => {
    try {
        const userId = req.user._id; // Đảm bảo req.user có _id

        // Lấy giỏ hàng của người dùng
        const cart = await cartModel.findOne({ user: userId }).populate('cartItems.product');

        if (!cart) {
            return res.status(404).json({ message: "Cart not found" });
        }

        // Cập nhật số lượng tồn kho cho mỗi sản phẩm trong giỏ hàng
        for (let item of cart.cartItems) {
            const product = item.product; // Kiểm tra nếu trường đúng là `product`

            if (!product) {
                throw new Error(`Product is missing for item ${item._id}`);
            }

            if (!product._id) {
                throw new Error(`Product ID is missing for item ${item._id}`);
            }

            const sizeIndex = product.sizes.indexOf(item.size);

            if (sizeIndex === -1) {
                throw new Error(`Invalid size ${item.size} for product ${product._id}`);
            }

            if (product.stocks[sizeIndex] < item.quantity) {
                throw new Error(`Not enough stock for product ${product._id}, size ${item.size}`);
            }

            // Giảm số lượng tồn kho
            product.stocks[sizeIndex] -= item.quantity;
            await product.save();
        }

        // Xóa giỏ hàng sau khi thanh toán
        await cartModel.findByIdAndDelete(cart._id);

        res.status(200).json({ message: "Checkout successful" });
    } catch (error) {
        res.status(500).json({ message: "Server error during checkout", error: error.message });
    }
};
export const searchProductsByColor = async (req, res) => {
    // Get the color query parameter; it can be an array if multiple values are provided
    const { color } = req.query;

    try {
        // If color is not provided or is an empty string, return an error
        if (!color || (Array.isArray(color) && color.length === 0)) {
            return res.status(400).json({ message: 'Valid color query parameter is required' });
        }

        // Convert color to an array if it's a string
        const colorArray = Array.isArray(color)
            ? color.map(c => c.trim().toLowerCase())
            : color.split(',').map(c => c.trim().toLowerCase()).filter(c => c !== '');

        // Ensure that we have at least one valid color
        if (colorArray.length === 0) {
            return res.status(400).json({ message: 'At least one valid color must be provided' });
        }

        // Find products where the 'color' array field contains at least one of the specified colors
        const products = await Product.find({
            color: { $in: colorArray.map(c => new RegExp(`^${c}$`, 'i')) } // Use regex for exact matching
        });

        res.status(200).json(products);
    } catch (error) {
        console.error('Error searching products by color:', error);
        res.status(500).json({ message: 'Server error while searching products by color', error: error.message });
    }
};

// Cập nhật số lượng tồn kho của sản phẩm
export const updateProductStock = async (req, res) => {
    try {
        const { id } = req.params;
        const { quantity, size, operation } = req.body;

        const product = await Product.findById(id);
        if (!product) {
            return res.status(404).json({ message: 'Product not found' });
        }

        const sizeIndex = product.sizes.indexOf(size);
        if (sizeIndex === -1) {
            return res.status(400).json({ message: 'Size not found for this product' });
        }

        if (operation === 'increase') {
            product.stocks[sizeIndex] += quantity;
        } else if (operation === 'decrease') {
            if (product.stocks[sizeIndex] < quantity) {
                return res.status(400).json({ message: 'Not enough stock' });
            }
            product.stocks[sizeIndex] -= quantity;
        } else {
            return res.status(400).json({ message: 'Invalid operation' });
        }

        await product.save();

        res.status(200).json({ message: 'Stock updated successfully' });
    } catch (error) {
        console.error('Error updating product stock:', error);
        res.status(500).json({ message: 'Server error' });
    }
};