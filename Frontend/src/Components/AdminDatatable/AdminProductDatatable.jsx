import "./AdminDatatable.css";
import { DataGrid } from "@mui/x-data-grid";
// import { productColumns } from "../../datatablesource.js"; // Adjust the path as needed
import { Link } from "react-router-dom";
import { useState, useEffect } from "react";
import { get, post, put, del } from '../../config/api';
import Swal from 'sweetalert2';

const AdminProductDatatable = () => {
  const [data, setData] = useState([]);

  const productColumns = [
    { field: "id", headerName: "ID", width: 150 },
    { field: "name", headerName: "Name", width: 200 },
    { field: "price", headerName: "Price", width: 100 },
    {
      field: "images",
      headerName: "Images",
      width: 300,
      renderCell: (params) => (
        <div>
          {params.value.map((image, index) => (
            <img key={index} src={image} alt={`Product ${index}`} style={{ width: 50, height: 50, margin: 2 }} />
          ))}
        </div>
      ),
    },
    {
      field: "stocks",
      headerName: "Total Stock",
      width: 200,
      renderCell: (params) => {
        const totalStock = params.value.reduce((total, stock) => total + stock, 0); // Tính tổng của mảng stocks
        return <div>{`Total: ${totalStock} units`}</div>;
      },
    },
  ];


  useEffect(() => {
    const fetchProducts = async () => {
      try {
        const response = await get('/api/v1/admin/products'); // Adjust the API endpoint as necessary
        const products = response.data.products.map(product => ({
          id: product._id,
          name: product.name,
          price: product.price,
          brand: product.brand,
          category: product.category,
          sizes: product.sizes,
          color: product.color,
          stocks: product.stocks,
          images: product.images,
          createdAt: new Date(product.created_at).toLocaleString(),
        }));
        setData(products);
      } catch (error) {
        console.error("Error fetching products:", error);
      }
    };

    fetchProducts();
  }, []);

  const handleDelete = async (id) => {
    const result = await Swal.fire({
      title: 'Are you sure?',
      text: "Do you want to delete this product?",
      icon: 'warning',
      showCancelButton: true,
      confirmButtonColor: '#3085d6',
      cancelButtonColor: '#d33',
      confirmButtonText: 'Yes, delete it!'
    });
  
    if (result.isConfirmed) {
      try {
        await del(`/api/v1/admin/products/${id}`); // Gửi yêu cầu xóa đến API
        setData(data.filter((item) => item.id !== id)); // Xóa sản phẩm khỏi bảng trên web
        Swal.fire(
          'Deleted!',
          'The product has been deleted.',
          'success'
        );
      } catch (error) {
        Swal.fire(
          'Error!',
          'Failed to delete the product.',
          'error'
        );
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
          <Link to={`/admin/products/${params.row.id}`} className="viewButton">
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
        Products
        <Link to="/admin/products/new" className="link">
          Add New
        </Link>
      </div>  
      <DataGrid
        className="datagrid"
        rows={data}
        columns={productColumns.concat(actionColumn)}
        pageSize={9}
        rowsPerPageOptions={[9]}
        checkboxSelection
      />
    </div>
  );
};

export default AdminProductDatatable;
