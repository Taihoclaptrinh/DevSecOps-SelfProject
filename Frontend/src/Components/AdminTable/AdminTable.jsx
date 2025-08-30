import "./AdminTable.css";
import Table from "@mui/material/Table";
import TableBody from "@mui/material/TableBody";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import TableHead from "@mui/material/TableHead";
import TableRow from "@mui/material/TableRow";
import Paper from "@mui/material/Paper";
import { useNavigate } from "react-router-dom";
import { useState, useEffect } from "react";
import { get, post, put, del } from '../../config/api';

const AdminList = () => {
  const navigate = useNavigate();
  const [orders, setOrders] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);

  const orderColumns = [
    { field: 'id', headerName: 'Order ID', width: 100 },
    { field: 'userEmail', headerName: 'User Email', width: 200 },
    { field: 'totalItems', headerName: 'Total Items', width: 150 },
    { field: 'address', headerName: 'Address', width: 400 },
    { field: 'phoneNumber', headerName: 'Phone Number', width: 150 },
    { field: 'paymentMethod', headerName: 'Payment Method', width: 150 },
    { field: 'totalPrice', headerName: 'Total Price', width: 150 },
    { field: 'status', headerName: 'Status', width: 150 },
    { field: 'createdAt', headerName: 'Created At', width: 200 },
  ];

  const fetchOrders = async () => {
    try {
      const response = await get('/api/v1/admin/get2orders'); // Update with your API endpoint
      let orders = response.data.orders.map(order => ({
        id: order._id,
        userEmail: order.email,
        address: order.shippingAddress.address || '',
        phoneNumber: order.shippingAddress.phoneNumber || '',
        paymentMethod: order.paymentMethod,
        totalPrice: order.totalPrice,
        totalItems: order.orderItems.reduce((total, item) => total + item.quantity, 0), // Compute total items
        status: order.status,
        createdAt: new Date(order.createdAt).toLocaleString(),
      }));

      // Sort orders by createdAt in descending order and take the first 2
      orders = orders.sort((a, b) => b.createdAt - a.createdAt).slice(0, 2);
      orders = orders.map(order => ({
        ...order,
        createdAt: order.createdAt.toLocaleString(),
      }));
      setOrders(orders);
    } catch (error) {
      setError('Failed to fetch orders');
      console.error("Error fetching orders:", error);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchOrders(); // Fetch orders when component mounts
    const intervalId = setInterval(fetchOrders, 30000); // Poll every 30 seconds

    return () => clearInterval(intervalId); // Clean up the interval on component unmount
  }, []);

  const handleRowClick = (id) => {
    navigate(`/admin/orders/${id}`);
  };

  if (isLoading) return <div>Loading...</div>;
  if (error) return <div>{error}</div>;

  return (
    <TableContainer component={Paper} className="AdminTable">
      <Table sx={{ minWidth: 650 }} aria-label="simple table">
        <TableHead>
          <TableRow>
            {orderColumns.map(column => (
              <TableCell key={column.field} className="tableCell">
                {column.headerName}
              </TableCell>
            ))}
          </TableRow>
        </TableHead>
        <TableBody>
          {orders.map((row) => (
            <TableRow 
              key={row.id} 
              onClick={() => handleRowClick(row.id)} 
              className="clickableRow"
              hover
            >
              {orderColumns.map(column => (
                <TableCell key={column.field} className="tableCell">
                  {row[column.field]}
                </TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
};

export default AdminList;
