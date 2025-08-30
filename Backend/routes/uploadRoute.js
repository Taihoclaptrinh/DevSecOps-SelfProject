import express from 'express';
import { uploadImage, uploadMiddleware } from '../controller/uploadController.js';

const router = express.Router();

router.post('/upload', uploadMiddleware, uploadImage);

export default router;
