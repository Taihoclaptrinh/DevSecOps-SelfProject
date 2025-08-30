import "./CSS/AdminList.css";
import AdminOrderDatatable from "../Components/AdminDatatable/AdminOrderDatatable";

const AdminOrderList = () => {
  return (
    <div className="AdminList">
      <div className="listContainer">
        <AdminOrderDatatable />
      </div>
    </div>
  );
};

export default AdminOrderList;
