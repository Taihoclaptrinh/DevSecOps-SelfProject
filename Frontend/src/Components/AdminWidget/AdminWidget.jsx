import React, { useEffect, useState } from "react";
import "./AdminWidget.css";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import PersonOutlinedIcon from "@mui/icons-material/PersonOutlined";
import ShoppingCartOutlinedIcon from "@mui/icons-material/ShoppingCartOutlined";
import MonetizationOnOutlinedIcon from "@mui/icons-material/MonetizationOnOutlined";
import { Link } from "react-router-dom"; // Import Link
import { get, post, put, del } from '../../config/api';

const AdminWidget = ({ type }) => {
  const [data, setData] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        let response;
        if (type === "user") {
          response = await get('/api/v1/admin/count-user');
        } else if (type === "order") {
          response = await get('/api/v1/admin/count-order');
        }

        if (response && response.data.success) {
          setData({
            ...data,
            count: response.data.count,
            diff: 20 // You can set diff to some meaningful value if needed
          });
        }
      } catch (error) {
        console.error("Error fetching data:", error);
      }
    };

    fetchData();
  }, [type]);

  if (!data) return null;

  const { count, diff } = data;

  const widgetData = {
    user: {
      title: "USERS",
      isMoney: false,
      link: "See all users",
      path: "/admin/users",
      icon: (
        <PersonOutlinedIcon
          className="icon"
          style={{
            color: "crimson",
            backgroundColor: "rgba(255, 0, 0, 0.2)",
          }}
        />
      ),
    },
    order: {
      title: "ORDERS",
      isMoney: false,
      link: "View all orders",
      path: "/admin/orders",
      icon: (
        <ShoppingCartOutlinedIcon
          className="icon"
          style={{
            backgroundColor: "rgba(218, 165, 32, 0.2)",
            color: "goldenrod",
          }}
        />
      ),
    },
    earning: {
      title: "EARNINGS",
      isMoney: true,
      link: "View net earnings",
      icon: (
        <MonetizationOnOutlinedIcon
          className="icon"
          style={{
            backgroundColor: "rgba(0, 128, 0, 0.2)",
            color: "green",
          }}
        />
      ),
    },
  };

  const { title, isMoney, link, path, icon } = widgetData[type] || {};

  return (
    <div className="AdminWidget">
      <div className="left">
        <span className="title">{title}</span>
        <span className="counter">
          {isMoney && "$"} {count}
        </span>
        {path ? (
          <Link to={path} className="link">
            {link}
          </Link>
        ) : (
          <span className="link">{link}</span>
        )}
      </div>
      <div className="right">
        <div className="percentage positive">
          <KeyboardArrowUpIcon />
          {diff} %
        </div>
        {icon}
      </div>
    </div>
  );
};

export default AdminWidget;
