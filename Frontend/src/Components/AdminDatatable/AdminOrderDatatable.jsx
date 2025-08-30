import "./AdminDatatable.css";
import { DataGrid } from "@mui/x-data-grid";
import { Link } from "react-router-dom";
import { useState, useEffect } from "react";
import Swal from 'sweetalert2';
import { get, post, put, del } from '../../config/api';
const AdminOrderDatatable = () => {
  const [data, setData] = useState([]);

  const orderColumns = [
    { field: 'id', headerName: 'Order ID', width: 200 },
    { field: 'userEmail', headerName: 'User Email', width: 250 },
    { field: 'totalItems', headerName: 'Total Items', width: 150 },
    { field: 'address', headerName: 'Address', width: 400 },
    { field: 'phoneNumber', headerName: 'Phone Number', width: 150 },
    { field: 'paymentMethod', headerName: 'Payment Method', width: 150 },
    { field: 'totalPrice', headerName: 'Total Price', width: 150 },
    { field: 'status', headerName: 'Status', width: 150 },
    { field: 'createdAt', headerName: 'Created At', width: 200 },
  ];

  useEffect(() => {
    const fetchOrders = async () => {
      try {
        const response = await get('/api/v1/admin/orders');
        const orders = response.data.orders.map(order => ({
          id: order._id,
          userId: order.user._id,
          userEmail: order.user.email,
          address: order.shippingAddress.address || '',
          phoneNumber: order.shippingAddress.phoneNumber || '',
          paymentMethod: order.paymentMethod,
          totalPrice: order.totalPrice,
          totalItems: order.orderItems.reduce((total, item) => total + item.quantity, 0), // Compute total items
          status: order.status,
          createdAt: new Date(order.createdAt).toLocaleString(),
        }));
        setData(orders);
      } catch (error) {
        console.error("Error fetching orders:", error);
      }
    };

    fetchOrders();
  }, []);

  const handleDelete = async (id) => {
    const result = await Swal.fire({
      title: 'Are you sure?',
      text: 'You won\'t be able to revert this!',
      icon: 'warning',
      showCancelButton: true,
      confirmButtonColor: '#3085d6',
      cancelButtonColor: '#d33',
      confirmButtonText: 'Yes, delete it!'
    });

    if (result.isConfirmed) {
      try {
        await del(`/api/v1/admin/orders/${id}`);
        setData(data.filter((item) => item.id !== id));
        Swal.fire('Deleted!', 'The order has been deleted.', 'success');
      } catch (error) {
        console.error('Error deleting order:', error);
        Swal.fire('Error!', 'There was a problem deleting the order.', 'error');
      }
    }
  };

  const actionColumn = [
    {
      field: "action",
      headerName: "Action",
      width: 200,
      renderCell: (params) => (
        <div className="cellAction">
          <Link to={`/admin/orders/${params.row.id}`} className="viewButton">
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
        Orders
      </div>
      <DataGrid
        className="datagrid"
        rows={data}
        columns={orderColumns.concat(actionColumn)}
        pageSize={9}
        rowsPerPageOptions={[9]}
        checkboxSelection
      />
    </div>
  );
};

export default AdminOrderDatatable;
