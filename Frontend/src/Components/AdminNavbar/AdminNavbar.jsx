import "./AdminNavbar.css";
import NotificationsNoneOutlinedIcon from "@mui/icons-material/NotificationsNoneOutlined";
import ChatBubbleOutlineOutlinedIcon from "@mui/icons-material/ChatBubbleOutlineOutlined";
import ListOutlinedIcon from "@mui/icons-material/ListOutlined";
import { Link } from "react-router-dom";

const AdminNavbar = () => {
  const logo = "https://minoshoesstorage.blob.core.windows.net/minoshoesbackground/logo.jpg";
  return (
    <div className="AdminNavbar">
      <div className="wrapper">
        <div className="search">
          <div className="nav-logo">
            <Link to='/'><img src={logo} alt="" style={{ height: "80px", marginLeft:"-13px" }} /></Link>
          </div>
        </div> 
        
      </div>
    </div>
  );
};

export default AdminNavbar;
