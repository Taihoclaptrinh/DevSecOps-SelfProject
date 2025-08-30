import React from 'react';
import "./Brand_Section.css"

export default function Brand_Section() {
  const images = [
    "https://minoshoesstorage.blob.core.windows.net/minoshoesbackground/adidas.jpg",
    "https://minoshoesstorage.blob.core.windows.net/minoshoesbackground/vans.jpg",
    "https://minoshoesstorage.blob.core.windows.net/minoshoesbackground/puma.jpg",
    "https://minoshoesstorage.blob.core.windows.net/minoshoesbackground/asics.jpg",
    "https://minoshoesstorage.blob.core.windows.net/minoshoesbackground/nike.jpg"  
  ];
  return (
    <div className='Logo-container'>
      <h3>Discover top shoe brands trusted by millions worldwide </h3>
      
      <div className='Logo-images'>
        {images.map((image, index) => (
          <img key={index} src={image} alt={`Brand logo ${index + 1}`} />
        ))}
      </div>
    </div>
  );
};