export const userInputs = [
  {
    id: 'userImage', // Unique ID
    label: "Images",
    type: "file",
    placeholder: "Upload images",
    multiple: false,
  },
  {
    id: 'userName', // Unique ID
    label: "Name",
    type: "text",
    placeholder: "John Doe",
  },
  {
    id: 'userEmail', // Unique ID
    label: "Email",
    type: "email",
    placeholder: "john.doe@example.com",
  },
  {
    id: 'userPassword', // Unique ID
    label: "Password",
    type: "password",
    placeholder: "Enter password",
  },
  {
    id: 'userPhone', // Unique ID
    label: "Phone",
    type: "tel",
    placeholder: "123-456-7890",
  },
  {
    id: 'userAddress', // Unique ID
    label: "Address",
    type: "text",
    placeholder: "123 Main St, Anytown, USA",
  },
  {
    id: 'userTotalSpent', // Unique ID
    label: "Total Spent",
    type: "number",
    placeholder: "0",
    min: 0, // Ensure non-negative values
  },
  {
    id: 'userRole', // Unique ID
    label: "Role",
    type: "text",
    placeholder: "Admin",
  },
  {
    id: 'userCreateAt', // Unique ID
    label: "Created At",
    type: "date",
  },
  {
    id: 'userUpdateAt', // Unique ID
    label: "Updated At",
    type: "date",
  },
];
export const productInputs = [
  {
    id: 'productCode',
    label: "Code",
    type: "text",
    placeholder: "Product Code",
  },
  {
    id: 'productName', // Unique ID
    label: "Name",
    type: "text",
    placeholder: "Product Name",
  },
  {
    id: 'productDescription', // Unique ID
    label: "Description",
    type: "text",
    placeholder: "Description of the product",
  },
  {
    id: 'productPrice', // Unique ID
    label: "Price",
    type: "number",
    placeholder: "100",
    min: 0, // Ensure non-negative values
  },
  {
    id: 'productBrand', // Unique ID
    label: "Brand",
    type: "text",
    placeholder: "Brand Name",
  },
  {
    id: 'productCategory', // Unique ID
    label: "Category",
    type: "text",
    placeholder: "Product Category",
  },
  {
    id: 'productSizes', // Unique ID
    label: "Sizes",
    type: "text",
    placeholder: "S, M, L",
  },
  {
    id: 'productColor', // Unique ID
    label: "Colors",
    type: "text",
    placeholder: "Red, Blue",
  },
  {
    id: 'productStocks', // Unique ID
    label: "Stocks",
    type: "text",
    placeholder: "10, 20, 15",
  },
  {
    id: 'productImages', // Unique ID
    label: "Images",
    type: "file",
    placeholder: "Upload images",
    multiple: true,
  },
  // {
  //   id: 'productCreateAt', // Unique ID
  //   label: "Created At",
  //   type: "date",
  // },
  // {
  //   id: 'productUpdateAt', // Unique ID
  //   label: "Updated At",
  //   type: "date",
  // },
];
export const orderInputs = [
  {
    id: 'userId',
    label: "User ID",
    type: "text",
    placeholder: "Enter User ID",
    maxLength: 20, // Example maxLength
  },
  {
    id: 'orderItems', // Unique ID
    label: "Items",
    type: "text",
    placeholder: "Product ID: 1, Quantity: 2, Price: 200",
  },
  {
    id: 'orderShippingAddress', // Unique ID
    label: "Shipping Address",
    type: "text",
    placeholder: "123 Main St, Anytown, USA",
  },
  {
    id: 'orderPaymentMethod', // Unique ID
    label: "Payment Method",
    type: "text",
    placeholder: "Credit Card",
  },
  {
    id: 'orderPaymentStatus', // Unique ID
    label: "Payment Status",
    type: "text",
    placeholder: "Paid",
  },
  {
    id: 'orderDeliveryStatus', // Unique ID
    label: "Delivery Status",
    type: "text",
    placeholder: "Shipped",
  },
  {
    id: 'orderCreateAt', // Unique ID
    label: "Created At",
    type: "date",
  },
  {
    id: 'orderUpdateAt', // Unique ID
    label: "Updated At",
    type: "date",
  },
];
export const couponInputs = [
  {
    id: 'couponCode',
    label: "Code",
    type: "text",
    placeholder: "Enter coupon code",
  },
  {
    id: 'discountValue',
    label: "Discount Value",
    type: "number",
    placeholder: "Enter discount value",
    min: 0, // Ensure non-negative values
  },
  {
    id: 'startDate',
    label: "Start Date",
    type: "date",
  },
  {
    id: 'endDate',
    label: "End Date",
    type: "date",
  },
  {
    id: 'usageCount',
    label: "Usage Count",
    type: "number",
    placeholder: "Enter usage count",
    default: 0, // Default value
    min: 0, // Ensure non-negative values
  },
  {
    id: 'usageLimit',
    label: "Usage Limit",
    type: "number",
    placeholder: "Enter usage limit",
    min: 0, // Ensure non-negative values
  },
];