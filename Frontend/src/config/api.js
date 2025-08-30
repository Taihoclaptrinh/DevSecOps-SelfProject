import axiosInstance from './axiosConfig';

// Hàm GET
export const get = (url, config = {}) => axiosInstance.get(url, config);

// Hàm POST
export const post = (url, data, config = {}) => axiosInstance.post(url, data, config);

// Hàm PUT
export const put = (url, data, config = {}) => axiosInstance.put(url, data, config);

// Hàm DELETE
export const del = (url, config = {}) => axiosInstance.delete(url, config);
