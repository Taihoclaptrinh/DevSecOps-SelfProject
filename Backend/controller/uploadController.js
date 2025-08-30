import multer from 'multer';
import { BlobServiceClient } from '@azure/storage-blob';
import dotenv from 'dotenv';

dotenv.config();

const AZURE_STORAGE_ACCOUNT = process.env.AZURE_STORAGE_ACCOUNT;
const AZURE_SAS_URL = process.env.AZURE_SAS_URL;
const blobServiceClient = new BlobServiceClient(AZURE_SAS_URL);
const CONTAINER_NAME='minoshoesprods';
const FOLDER_NAME = 'main2';

// Configure multer for file upload
const storage = multer.memoryStorage();
const upload = multer({ storage });

// Middleware for handling multiple file uploads
export const uploadMiddleware = upload.array('images', 10); // 'images' should match the field name in your form

export const uploadImage = async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).send({ message: 'No files uploaded' });
    }

    const containerClient = blobServiceClient.getContainerClient(FOLDER_NAME);
    const uploadPromises = req.files.map(async (file) => {
      const blobName = file.originalname;
      console.log('Uploading blob:', blobName);

      const blockBlobClient = containerClient.getBlockBlobClient(blobName);

      // Define Content-Type based on file extension
      let contentType = 'application/octet-stream';
      if (file.originalname.endsWith('.jpg') || file.originalname.endsWith('.jpeg')) {
        contentType = 'image/jpeg';
      } else if (file.originalname.endsWith('.png')) {
        contentType = 'image/png';
      }

      // Upload the file with Content-Type
      const uploadBlobResponse = await blockBlobClient.upload(file.buffer, file.size, {
        blobHTTPHeaders: { blobContentType: contentType }
      });
      console.log(`Upload block blob ${blobName} successfully`, uploadBlobResponse.requestId);

      // Create URL for the image without SAS token
      const imageUrl = `https://${AZURE_STORAGE_ACCOUNT}.blob.core.windows.net/${CONTAINER_NAME}/${FOLDER_NAME}/${blobName}`;

      return imageUrl;
    });

    const imageUrls = await Promise.all(uploadPromises);

    res.status(200).send({ message: 'Files uploaded successfully', imageUrls });
  } catch (error) {
    console.log('Error uploading files:', error);
    res.status(500).send({ message: 'Error uploading files', error });
  }
};

export const deleteImage = async (req, res) => {
  try {
    const blobName = req.params.blobName; // Get blob name from URL parameter

    const containerClient = blobServiceClient.getContainerClient(CONTAINER_NAME);
    const blockBlobClient = containerClient.getBlockBlobClient(blobName);

    // Delete blob
    await blockBlobClient.delete();
    console.log(`Deleted block blob ${blobName} successfully`);

    res.status(200).send({ message: 'File deleted successfully', blobName });
  } catch (error) {
    console.log('Error deleting file:', error);
    res.status(500).send({ message: 'Error deleting file', error: error.message });
  }
};
