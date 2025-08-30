import express from 'express';
import {
        searchProductsByColor, checkout, createProduct,
        getProductByName, updateProduct,
        deleteProduct, getRelatedProducts,
        searchProducts, getProducts, updateProductStock
} from '../controller/productController.js';
import { requireSignIn } from '../middlewares/authMiddleware.js';

const router = express.Router();

router.post('/', createProduct);
router.get('/', getProducts);
router.get('/search', searchProducts); 
router.get('/color', searchProductsByColor);
router.post('/checkout', checkout);
router.get('/:name', getProductByName);
router.put('/:id', updateProduct);
router.delete('/:id', deleteProduct);
router.get('/:productId/related', getRelatedProducts);
// Update stock
router.put('/:id/update-stock', requireSignIn, updateProductStock);

export default router;