import express from 'express';
import {
    checkEmailController,
    registerController,
    loginController,
    sendResetCodeController,
    resetPasswordController,
    testController,
    validateCredentials,
} from "../controller/authController.js";
import { isAdmin, requireSignIn } from '../middlewares/authMiddleware.js';

//router object
const router = express.Router();

// Check Email || method POST
router.post("/check-email", checkEmailController);

// Register || method POST
router.post("/register", registerController);

// Login || method POST
router.post("/login", loginController);

// Test routes
router.get('/test', requireSignIn, isAdmin, testController);

// Send Reset Code || method POST
router.post('/send-reset-code', sendResetCodeController);

// Reset Password || method POST
router.post('/reset-password', resetPasswordController);

// Validate Credentials || method POST
router.post('/validateCredentials', validateCredentials);


export default router;
