import "./CSS/AdminList.css";
import AdminNotificationDatatable from "../Components/AdminDatatable/AdminNotificationDatatable";

const AdminNotificationList = () => {
  return (
    <div className="AdminList">
      <div className="listContainer">
        <AdminNotificationDatatable />
      </div>
    </div>
  );
};

export default AdminNotificationList;
