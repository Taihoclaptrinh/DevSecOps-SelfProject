export const userRows = [
  {
    id: 1,
    name: "John Doe",
    email: "john.doe@example.com",
    password: "password123",
    phone: "123-456-7890",
    address: "123 Main St, Anytown, USA",
    totalSpent: 1200,
    role: "Admin",
    createAt: "2023-01-01",
    updateAt: "2023-01-15",
  },
  // More user data...
];

export const productRows = [
  {
    id: 1,
    name: "Product 1",
    description: "Description of product 1",
    price: 100,
    brand: "Brand A",
    category: "Category 1",
    sizes: ["S", "M", "L"],
    color: ["Red", "Blue"],
    stocks: [10, 20, 15],
    images: ["img1.jpg", "img2.jpg"],
    createAt: "2023-01-01",
    updateAt: "2023-01-15",
  },
  {
    id: 2,
    name: "Product 2",
    description: "Description of product 2",
    price: 200,
    brand: "Brand B",
    category: "Category 2",
    sizes: ["S", "M", "L"],
    color: ["Red", "Blue"],
    stocks: [10, 20, 15],
    images: ["img1.jpg", "img2.jpg"],
    createAt: "2023-01-01",
    updateAt: "2023-01-15",
  },
  // More product data...
];

export const orderRows = [
  {
    id: 1,
    userID: 1,
    items: [
      { productId: 1, quantity: 2, price: 200 },
      { productId: 2, quantity: 1, price: 100 },
    ],
    shippingAddress: '123 Main St, Anytown, USA',
    paymentMethod: 'Credit Card',
    paymentStatus: 'Paid',
    orderStatus: 'Shipped',
    createAt: '2023-01-01',
    updateAt: '2023-01-15',
  },
  {
    id: 2,
    userID: 1,
    items: [
      { productId: 3, quantity: 1, price: 150 },
      { productId: 4, quantity: 3, price: 50 },
    ],
    shippingAddress: '456 Elm St, Othertown, USA',
    paymentMethod: 'PayPal',
    paymentStatus: 'Pending',
    orderStatus: 'Processing',
    createAt: '2023-02-10',
    updateAt: '2023-02-15',
  },
];

export const orderColumns = [
  { field: "id", headerName: "ID", width: 90 },
  { field: "userID", headerName: "User ID", width: 150 },
  {
    field: "items",
    headerName: "Items",
    width: 250,
    renderCell: (params) => (
      <div>
        {params.value.map((item, index) => (
          <div key={index}>
            Product ID: {item.productId}, Quantity: {item.quantity}, Price: {item.price}
          </div>
        ))}
      </div>
    ),
  },
  { field: "shippingAddress", headerName: "Shipping Address", width: 200 },
  { field: "paymentMethod", headerName: "Payment Method", width: 150 },
  { field: "paymentStatus", headerName: "Payment Status", width: 150 },
  { field: "orderStatus", headerName: "Order Status", width: 150 },
  { field: "createAt", headerName: "Created At", width: 150 },
  { field: "updateAt", headerName: "Updated At", width: 150 },
];

export const productColumns = [
  { field: "id", headerName: "ID", width: 90 },
  { field: "name", headerName: "Name", width: 150 },
  { field: "description", headerName: "Description", width: 200 },
  { field: "price", headerName: "Price", width: 100 },
  { field: "brand", headerName: "Brand", width: 100 },
  { field: "category", headerName: "Category", width: 100 },
  {
    field: "sizes",
    headerName: "Sizes",
    width: 150,
    renderCell: (params) => params.value.join(", "),
  },
  {
    field: "color",
    headerName: "Colors",
    width: 150,
    renderCell: (params) => params.value.join(", "),
  },
  {
    field: "stocks",
    headerName: "Stocks",
    width: 150,
    renderCell: (params) => params.value.join(", "),
  },
  {
    field: "images",
    headerName: "Images",
    width: 200,
    renderCell: (params) => (
      <div>
        {params.value.map((image, index) => (
          <img key={index} src={image} alt={`Product ${index}`} style={{ width: 50, height: 50, margin: 2 }} />
        ))}
      </div>
    ),
  },
  { field: "createAt", headerName: "Created At", width: 150 },
  { field: "updateAt", headerName: "Updated At", width: 150 },
];

export const userColumns = [
  { field: "id", headerName: "ID", width: 90 },
  { field: "name", headerName: "Name", width: 150 },
  { field: "email", headerName: "Email", width: 150 },
  { field: "phone", headerName: "Phone", width: 150 },
  { field: "address", headerName: "Address", width: 200 },
  { field: "totalSpent", headerName: "Total Spent", width: 120 },
  { field: "role", headerName: "Role", width: 120 },
  { field: "createAt", headerName: "Created At", width: 150 },
  { field: "updateAt", headerName: "Updated At", width: 150 },
];


