import mongoose from "mongoose";
import colors from "colors";

const connectDB = async () => {
    try {
        console.log('MONGO_URL:', process.env.MONGO_URL);
        const conn = await mongoose.connect(process.env.MONGO_URL);
        console.log(`Connected to MongoDB Database ${conn.connection.host}`);

        // Lấy danh sách các collection từ đối tượng kết nối
        const collections = await conn.connection.db.listCollections().toArray();

        // Hiển thị tên của từng collection
        console.log("Collections:");
        collections.forEach(collection => console.log(`- ${collection.name}`));
    } catch (error) {
        console.log(`Error connecting to MongoDB: ${error}`.bgRed.white);
    }
};

export default connectDB;