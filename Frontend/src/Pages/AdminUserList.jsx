import "./CSS/AdminList.css"
import AdminDatatable from "../Components/AdminDatatable/AdminUserDatatable"

const AdminUserList = () => {
  return (
    <div className="AdminList">
      <div className="listContainer">
        <AdminDatatable/>
      </div>
    </div>
  )
}

export default AdminUserList