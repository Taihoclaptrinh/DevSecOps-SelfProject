import React, { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import "./CSS/SearchResults.css";
import Footer from "../Components/Footer/Footer.jsx";
import Loader from "../Components/Loader/Loading.jsx";

const SearchResults = () => {
    const [loading, setLoading] = useState(true);
    const location = useLocation();
    const navigate = useNavigate();

    useEffect(() => {
        setLoading(true);
        const searchQuery = new URLSearchParams(location.search).get('query');
        if (searchQuery) {
            navigate(`/new-arrivals?query=${encodeURIComponent(searchQuery)}`);
        }
    }, [location.search, navigate]);

    if (loading) {
        return <div style={{ display: "flex", justifyContent: "center", alignItems: "center", height: "100vh" }}>
            <Loader />
        </div>;
    }

    return (
        <div>
            <Footer />
        </div>
    );
};

export default SearchResults;
