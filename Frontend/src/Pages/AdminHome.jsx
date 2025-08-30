import "./CSS/AdminHome.css";
import AdminWidget from "../Components/AdminWidget/AdminWidget";
import AdminFeatured from "../Components/AdminFeatured/AdminFeatured";
import AdminList from "../Components/AdminChart/AdminChart";
import AdminTable from "../Components/AdminTable/AdminTable";

const AdminHome = () => {
  return (
    <div className="AdminHome">
      <div className="homeContainer">
        <div className="widgets">
          <AdminWidget type="user" />
          <AdminWidget type="order" />
          <AdminWidget type="earning" />
        </div>
        <div className="charts">
          <AdminFeatured />
          <AdminList title="Last Month (Revenue)" aspect={2 / 1} />
        </div>
        <div className="listContainer">
          <div className="listTitle">Latest Orders</div>
          <AdminTable />
        </div>
      </div>
    </div>
  );
};

export default AdminHome;
