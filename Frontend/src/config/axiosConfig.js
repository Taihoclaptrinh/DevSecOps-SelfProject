// axiosConfig.js
import axios from 'axios';

const axiosInstance = axios.create({
  baseURL: process.env.APP_API_BASE_URL, // Base URL cho các API
  headers: {
    'Content-Type': 'application/json', // Loại nội dung mặc định cho tất cả các yêu cầu
  },
});

// Thêm interceptors để xử lý trước và sau khi gửi yêu cầu
axiosInstance.interceptors.request.use(
  (config) => {
    // Thực hiện các thay đổi trước khi gửi yêu cầu đi, nếu cần
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

axiosInstance.interceptors.response.use(
  (response) => {
    // Thực hiện xử lý dữ liệu khi nhận phản hồi, nếu cần
    return response;
  },
  (error) => {
    return Promise.reject(error);
  }
);

export default axiosInstance;
