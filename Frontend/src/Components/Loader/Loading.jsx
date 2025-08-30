import React from 'react';
import './Loading.css';

const Loader = () => {
    const loaderGif = "https://minoshoesstorage.blob.core.windows.net/minoshoesbackground/Intersection.gif"
    return (
        <div>
            <img style={{width: "80px"}} src={loaderGif} alt="Loading..." className="loader-gif" />
        </div>
    );
};
export default Loader;
