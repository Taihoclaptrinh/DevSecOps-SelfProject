import "./CSS/AdminList.css";
import AdminProductDatatable from "../Components/AdminDatatable/AdminProductDatatable"; // Import ProductDatatable component

const AdminProductList = () => {
  return (
    <div className="AdminList">
      <div className="listContainer">
        <AdminProductDatatable />
      </div>
    </div>
  );
};

export default AdminProductList;