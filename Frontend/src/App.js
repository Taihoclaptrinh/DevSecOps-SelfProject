import React from 'react';
import "./App.css";
import { BrowserRouter, Routes, Route } from "react-router-dom";

import SearchResults from './Pages/SearchResult';
import { UserProvider } from './UserContext';
import PrivacyPolicy from "./Components/Docs/privacy_policy";
import CookiesSetting from "./Components/Docs/cookies_setting";
import TermOfService from "./Components/Docs/term_of_service";

// Admin Components
import AdminNavbar from "./Components/AdminNavbar/AdminNavbar";
import AdminSidebar from "./Components/AdminSidebar/AdminSidebar";
import AdminHome from "./Pages/AdminHome";
import AdminUserList from "./Pages/AdminUserList";
import AdminProductList from "./Pages/AdminProductList";
import AdminNotificationList from "./Pages/AdminNotificationList";
import AdminOrderList from "./Pages/AdminOrderList";
import AdminCouponList from "./Pages/AdminCouponList";
import AdminUserSingle from "./Pages/AdminUserSingle";
import AdminProductSingle from "./Pages/AdminProductSingle";
import AdminOrderSingle from "./Pages/AdminOrderSingle";
import AdminCouponSingle from "./Pages/AdminCouponSingle";
import AdminNotificationSingle from "./Pages/AdminNotificationSingle";

import AdminNewCoupon from "./Pages/AdminNewCoupon"
import AdminNew from "./Pages/AdminNew";

// Shop Components
import Navbar from "./Components/Navbar/Navbar";
import Shop from "./Pages/Shop";
import ShopCategory from "./Pages/ShopCategory";
import Cart from "./Pages/Cart";
import LoginLogup from "./Pages/LoginLogup";
import Product from "./Pages/Product";
import UserInfo from "./Pages/UserInfoPage";

// Botchat Component
import Botchat from "./Components/Botchat/Botchat";

// Admin App Component
const AdminApp = () => (
  <div className="AdminApp">
    <AdminNavbar />
    <div className="layout">
      <AdminSidebar />
      <div className="mainContent">
        <Routes>
          <Route path="/" element={<AdminHome />} />
          <Route path="users">
            <Route index element={<AdminUserList />} />
            <Route path=":userId" element={<AdminUserSingle />} />
            <Route path="new" element={<AdminNew title="Add New User" formType="user" />} />
          </Route>
          <Route path="products">
            <Route index element={<AdminProductList />} />
            <Route path=":productId" element={<AdminProductSingle />} />  {/* Correctly render AdminProductSingle */}
            <Route path="new" element={<AdminNew title="Add New Product" formType="product" />} />
          </Route>
          <Route path="orders">
            <Route index element={<AdminOrderList />} />
            <Route path=":orderId" element={<AdminOrderSingle />} />  {/* Assuming AdminUserSingle handles orders too */}
          </Route>
          <Route path="coupons">
            <Route index element={<AdminCouponList />} />
            <Route path=":couponId" element={<AdminCouponSingle />} />
            <Route path="new" element={<AdminNewCoupon title="Add New Coupon" formType="coupon" />} />
          </Route>
          <Route path="notifications">
            <Route index element={<AdminNotificationList />} />
            <Route path=":notificationId" element={<AdminNotificationSingle />} /> {/* Tạo AdminNotificationSingle để xem chi tiết */}
          </Route>
        </Routes>
      </div>
    </div>
  </div>
);

// Shop App Component
const ShopApp = () => (
  <div className="ShopApp">
    <Navbar />
    <Routes>
      <Route path="/" element={<Shop />} />
      <Route path="/men" element={<ShopCategory category="men" />} />
      <Route path="/women" element={<ShopCategory category="women" />} />
      <Route path="/brands" element={<ShopCategory category="brands" />} />
      <Route path="/new-arrivals" element={<ShopCategory category="new-arrivals" />} />
      <Route path="/sale" element={<ShopCategory category="sale" />} />
      <Route path="/cart" element={<Cart />} />
      <Route path="/login" element={<LoginLogup />} />
      <Route path="/product" element={<Product />} />
      <Route path="/userinfo" element={<UserInfo />} />
      <Route path="/search" element={<SearchResults />} />
    </Routes>
    <Botchat />
  </div>
);

// Main App Component
function App() {
  return (
    <UserProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/admin/*" element={<AdminApp />} />
          <Route path="/*" element={<ShopApp />} />
          <Route path="/agreement-service/privacy-policy" element={<PrivacyPolicy />} />
          <Route path="/agreement-service/term-of-service" element={<TermOfService />} />
          <Route path="/agreement-service/cookies-setting" element={<CookiesSetting />} />
        </Routes>
      </BrowserRouter>
    </UserProvider>

  );
}


export default App;