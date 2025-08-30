import PayOS from '@payos/node';

const payos = new PayOS(
  '165040ef-2353-4643-9378-c897156a5bb8',
  '696628be-b9ee-4965-94b1-e694dc8157de',
  'd9e4c705b499d53fad53c5a42ca385a2153a632042f0c9ca4182b9e59eb4a4d4'
);

export const createPaymentLink = async (req, res) => {
  try {
    const { amount, description } = req.body;
    const orderCode = Math.floor(Math.random() * 9000000000000);
    const order = {
      amount,
      description,
      orderCode,
      returnUrl: process.env.URL,
      cancelUrl: process.env.URL
    };
    const paymentLink = await payos.createPaymentLink(order);
    res.json({ checkoutUrl: paymentLink.checkoutUrl });
  } catch (error) {
    console.error('Error creating payment link:', error);
    res.status(500).send('Failed to create payment link');
  }
};
