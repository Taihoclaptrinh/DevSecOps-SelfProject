import express from 'express';
const router = express.Router();
import Botchat from '../models/botchatModel.js';

router.post('/ask', async (req, res) => {
    try {
        const { question } = req.body;

        // Split the question into an array of keywords
        const keywords = question.split(' ').map(keyword => keyword.trim()).filter(keyword => keyword.length > 0);

        // Create a regex to match any of the keywords
        const regex = new RegExp(keywords.join('|'), 'i');

        // Find the chat message by matching keywords in the 'chatbot' collection
        const chatMessage = await Botchat.findOne({ keywords: { $regex: regex } });

        if (chatMessage) {
            res.json({ answer: chatMessage.answer });
        } else {
            res.json({ answer: "Sorry, I don't understand your question." });
        }
    } catch (error) {
        console.error("Error occurred:", error);  // Debug log for errors
        res.status(500).json({ message: "Internal server error" });
    }
});

export default router;