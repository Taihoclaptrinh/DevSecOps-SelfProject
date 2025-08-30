import mongoose from 'mongoose';

const botchatSchema = new mongoose.Schema({
    keywords: [String],
    answer: String
}, {
    collection: 'botchat'
});

export default mongoose.model('Botchat', botchatSchema);