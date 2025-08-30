import "./AdminDatatable.css";
import { DataGrid } from "@mui/x-data-grid";
// import { userColumns } from "../../datatablesource.js"; // Adjust the path as needed
import { Link } from "react-router-dom";
import { useState, useEffect } from "react";
import { get, post, put, del } from '../../config/api';

const AdminUserDatatable = () => {
  const [data, setData] = useState([]); // Initialize state with an empty array

  const userColumns = [
    { field: "id", headerName: "ID", width: 150 },
    { field: "name", headerName: "Name", width: 200 },
    { field: "email", headerName: "Email", width: 200 },
    { field: "phone", headerName: "Phone", width: 150 },
    { field: "totalSpent", headerName: "Total Spent", width: 120 },
    { field: "role", headerName: "Role", width: 120 },
  ];

  useEffect(() => {
    // Fetch user data from API when the component mounts
    const fetchUsers = async () => {
      try {
        const response = await get('/api/v1/admin/get-user'); // Adjust the API endpoint as needed
        const users = response.data.users; // Adjust based on your API response structure

        // Transform data to match DataGrid format
        const formattedData = users.map(user => ({
          id: user._id,
          name: user.name,
          email: user.email,
          phone: user.phone,
          address: user.address,
          totalSpent: user.totalSpent,
          role: user.role,
          createAt: new Date(user.createdAt).toLocaleString(), // Format date if needed
          updateAt: new Date(user.updatedAt).toLocaleString(), // Format date if needed
        }));

        setData(formattedData);
      } catch (error) {
        console.error('Error fetching users:', error);
      }
    };

    fetchUsers();
  }, []); // Empty dependency array means this effect runs once on mount

  const handleDelete = (id) => {
    setData(data.filter((item) => item.id !== id));
  };

  const actionColumn = [
    {
      field: "action",
      headerName: "Action",
      width: 200,
      renderCell: (params) => (
        <div className="cellAction">
          <Link to={`/admin/users/${params.row.id}`} className="viewButton">
            View
          </Link>
          <div
            className="deleteButton"
            onClick={() => handleDelete(params.row.id)}
          >
            Delete
          </div>
        </div>
      ),
    },
  ];

  return (
    <div className="AdminDatatable">
      <div className="datatableTitle">
        Users
      </div>
      <DataGrid
        className="datagrid"
        rows={data}
        columns={userColumns.concat(actionColumn)}
        pageSize={9}
        rowsPerPageOptions={[9]}
        checkboxSelection
      />
    </div>
  );
};

export default AdminUserDatatable;
