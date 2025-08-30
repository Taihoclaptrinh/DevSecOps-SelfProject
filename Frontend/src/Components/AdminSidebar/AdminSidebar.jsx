import "./AdminSidebar.css";
import DashboardIcon from "@mui/icons-material/Dashboard";
import PersonOutlineIcon from "@mui/icons-material/PersonOutline";
import CreditCardIcon from "@mui/icons-material/CreditCard";
import StoreIcon from "@mui/icons-material/Store";
import ExitToAppIcon from "@mui/icons-material/ExitToApp";
import DiscountIcon from '@mui/icons-material/Discount';
import NotificationsNoneIcon from "@mui/icons-material/NotificationsNone";
import { Link } from "react-router-dom";

const AdminSidebar = () => {
  return (
    <div className="AdminSidebar">
      <div className="center">
        <ul>
          <p className="title">MAIN</p>
          <li>
            <DashboardIcon className="icon" />
            <Link to="/admin" style={{ textDecoration: "none" }}>
              <span>Dashboard</span>
            </Link>
          </li>
          <p className="title">LISTS</p>
          <Link to="/admin/users" style={{ textDecoration: "none" }}>
            <li>
              <PersonOutlineIcon className="icon" />
              <span>Users</span>
            </li>
          </Link>
          <Link to="/admin/products" style={{ textDecoration: "none" }}>
            <li>
              <StoreIcon className="icon" />
              <span>Products</span>
            </li>
          </Link>
          <Link to="/admin/orders" style={{ textDecoration: "none" }}>
            <li>
              <CreditCardIcon className="icon" />
              <span>Orders</span>
            </li>
          </Link>
          <Link to="/admin/coupons" style={{ textDecoration: "none" }}>
            <li>
              <DiscountIcon className="icon" />
              <span>Coupons</span>
            </li>
          </Link>
          <p className="title">USEFUL</p>
          <Link to="/admin/notifications" style={{ textDecoration: "none" }}>
            <li>
              <NotificationsNoneIcon className="icon" />
              <span>Notifications</span>
            </li>
          </Link>
          <li>
            <ExitToAppIcon className="icon" />
            <span>Logout</span>
          </li>
        </ul>
      </div>
    </div>
  );
};

export default AdminSidebar;
