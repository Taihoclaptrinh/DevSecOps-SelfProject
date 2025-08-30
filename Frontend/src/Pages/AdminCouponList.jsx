import "./CSS/AdminList.css";
import AdminCouponDatatable from "../Components/AdminDatatable/AdminCouponDatatable";

const AdminCouponList = () => {
  return (
    <div className="AdminList">
      <div className="listContainer">
        <AdminCouponDatatable />
      </div>
    </div>
  );
};

export default AdminCouponList;