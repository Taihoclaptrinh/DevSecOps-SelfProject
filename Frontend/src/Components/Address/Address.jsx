import React, { useState, useEffect } from 'react';
import { get, post, put, del } from '../../config/api';
import "./Address.css";

const AddressSelector = ({ onAddressChange }) => {
  const [cities, setCities] = useState([]);
  const [districts, setDistricts] = useState([]);
  const [wards, setWards] = useState([]);

  const [selectedCity, setSelectedCity] = useState('');
  const [selectedDistrict, setSelectedDistrict] = useState('');
  const [selectedWard, setSelectedWard] = useState('');

  useEffect(() => {
    const fetchCities = async () => {
      try {
        const response = await get('https://raw.githubusercontent.com/kenzouno1/DiaGioiHanhChinhVN/master/data.json');
        setCities(response.data);
      } catch (error) {
        console.error('Error fetching cities:', error);
      }
    };
    fetchCities();
  }, []);

  useEffect(() => {
    if (onAddressChange) {
      const city = cities.find(city => city.Id === selectedCity);
      const district = city?.Districts.find(district => district.Id === selectedDistrict);
      const ward = district?.Wards.find(ward => ward.Id === selectedWard);

      onAddressChange({
        city: city?.Name || '',
        district: district?.Name || '',
        ward: ward?.Name || '',
      });
    }
  }, [selectedCity, selectedDistrict, selectedWard, cities, onAddressChange]);

  const handleCityChange = (e) => {
    const cityId = e.target.value;
    setSelectedCity(cityId);
    setDistricts([]);
    setWards([]);
    setSelectedDistrict('');
    setSelectedWard('');

    if (cityId) {
      const city = cities.find(city => city.Id === cityId);
      if (city) {
        setDistricts(city.Districts);
      }
    }
  };

  const handleDistrictChange = (e) => {
    const districtId = e.target.value;
    setSelectedDistrict(districtId);
    setWards([]);
    setSelectedWard('');

    if (districtId) {
      const district = districts.find(district => district.Id === districtId);
      if (district) {
        setWards(district.Wards);
      }
    }
  };
  return (
    <div className='address-container'>
        <div>
            <select
                id="city"
                value={selectedCity}
                onChange={handleCityChange}
                className='address-selector'
                style={{width:"100%"}}
            >
                <option value="" selected>Select City/Province</option>
                {cities.map(city => (
                <option key={city.Id} value={city.Id}>{city.Name}</option>
                ))}
            </select>
        </div>
        <select
                id="district"
                value={selectedDistrict}
                onChange={handleDistrictChange}
                className='address-selector'
                style={{width:"50%"}}
            >
                <option value="" selected>Select District/City</option>
                {districts.map(district => (
                <option key={district.Id} value={district.Id}>{district.Name}</option>
                ))}
            </select>
        <select
            id="ward"
            value={selectedWard}
            onChange={(e) => setSelectedWard(e.target.value)}
            className='address-selector'     
            style={{width:"50%"}} 
        >
            <option value="" selected>Select Ward</option>
            {wards.map(ward => (
            <option key={ward.Id} value={ward.Id}>{ward.Name}</option>
            ))}
        </select>
        
    </div>
  );
};

export default AddressSelector;
