import "./AdminDatatable.css";
import { DataGrid } from "@mui/x-data-grid";
import { Link } from "react-router-dom";
import { useState, useEffect } from "react";
import Swal from 'sweetalert2';
import { get, post, put, del } from '../../config/api';
const AdminNotificationDatatable = () => {
  const [data, setData] = useState([]);

  const orderColumns = [
    { field: 'id', headerName: 'Order ID', width: 200 },
    { field: 'userEmail', headerName: 'User Email', width: 250 },
    { field: 'totalItems', headerName: 'Total Items', width: 150 },
    { field: 'paymentMethod', headerName: 'Payment Method', width: 150 },
    { field: 'totalPrice', headerName: 'Total Price', width: 150 },
    { field: 'status', headerName: 'Status', width: 150 },
    { field: 'canceledAt', headerName: 'Canceled At', width: 200 },
    { field: 'cancellationReason', headerName: 'Reason', width: 200 },
  ];

  const fetchOrders = async () => {
    try {
      const response = await get('/api/v1/admin/orders');
      
      // Lọc các đơn hàng có trạng thái là 'Cancelled'
      const cancelledOrders = response.data.orders
        .filter(order => order.status === 'Cancelled')
        .map(order => ({
          id: order._id,
          userId: order.user._id,
          userEmail: order.user.email,
          paymentMethod: order.paymentMethod,
          totalPrice: order.totalPrice,
          totalItems: order.orderItems.reduce((total, item) => total + item.quantity, 0), // Compute total items
          status: order.status,
          canceledAt: new Date(order.canceledAt).toLocaleString(),
          cancellationReason: order.cancellationReason
        }));

      setData(cancelledOrders);
    } catch (error) {
      console.error("Error fetching orders:", error);
    }
  };

  useEffect(() => {
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
        Notifications
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

export default AdminNotificationDatatable;
