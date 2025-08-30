import "./AdminDatatable.css";
import { DataGrid } from "@mui/x-data-grid";
import { Link } from "react-router-dom";
import { useState, useEffect } from "react";
import { get, del } from '../../config/api';

const AdminCouponDatatable = () => {
    const [data, setData] = useState([]);

    const couponColumns = [
        { field: 'id', headerName: 'Coupon ID', width: 200 },
        { field: 'code', headerName: 'Code', width: 250 },
        { field: 'discountValue', headerName: 'Discount Value', width: 150 },
        { field: 'startDate', headerName: 'Start Date', width: 200 },
        { field: 'endDate', headerName: 'End Date', width: 200 },
        { field: 'usageCount', headerName: 'Usage Count', width: 150 },
        { field: 'usageLimit', headerName: 'Usage Limit', width: 150 },
        { field: 'createdAt', headerName: 'Created At', width: 200 },
    ];

    useEffect(() => {
        const fetchCoupons = async () => {
            try {
                const response = await get('/api/v1/admin/coupons');

                // Extract the coupons data from the response
                let coupons = [];
                if (response && response.data && Array.isArray(response.data)) {
                    coupons = response.data;
                } else if (response && response.data && Array.isArray(response.data.coupons)) {
                    coupons = response.data.coupons;
                } else {
                    console.error("Unexpected response structure:", response);
                    return;
                }

                // Transform data to match DataGrid format
                const formattedData = coupons.map(coupon => ({
                    id: coupon._id,
                    code: coupon.code,
                    discountValue: coupon.discountValue,
                    startDate: new Date(coupon.startDate).toLocaleString(),
                    endDate: new Date(coupon.endDate).toLocaleString(),
                    usageCount: coupon.usageCount,
                    usageLimit: coupon.usageLimit,
                    createdAt: new Date(coupon.createdAt).toLocaleString(),
                }));

                console.log("Formatted Coupon Data:", formattedData);
                setData(formattedData);
            } catch (error) {
                console.error("Error fetching coupons:", error);
            }
        };

        fetchCoupons();
    }, []);

    const handleDelete = async (id) => {
        try {
            await del(`/api/v1/admin/coupons/${id}`);
            setData(data.filter((item) => item.id !== id));
        } catch (error) {
            console.error('Error deleting coupon:', error);
        }
    };

    const actionColumn = [
        {
            field: "action",
            headerName: "Action",
            width: 200,
            renderCell: (params) => (
                <div className="cellAction">
                    <Link to={`/admin/coupons/${params.row.id}`} className="viewButton">
                        View
                    </Link>
                    <div className="deleteButton" onClick={() => handleDelete(params.row.id)}>
                        Delete
                    </div>
                </div>
            ),
        },
    ];

    return (
        <div className="AdminDatatable">
            <div className="datatableTitle">
                Coupons
                <Link to="/admin/coupons/new" className="link">
                    Add New
                </Link>
            </div>
            <DataGrid
                className="datagrid"
                rows={data}
                columns={couponColumns.concat(actionColumn)}
                pageSize={9}
                rowsPerPageOptions={[9]}
                checkboxSelection
            />
        </div>
    );
};

export default AdminCouponDatatable;