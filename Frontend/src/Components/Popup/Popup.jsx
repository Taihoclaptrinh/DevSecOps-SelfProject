import React from 'react';
import PropTypes from 'prop-types';
import './Popup.css';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCircleCheck, faTimes } from '@fortawesome/free-solid-svg-icons';

const Pop_up = ({ isSuccess, review, message, confirm, href, onClose  }) => {
    const handleConfirmClick = () => {
        if (href) {
            window.location.href = href;
        } else if (onClose) {
            onClose();
        }
    };

    return (
        <div className="overlay active">
            <div className="popup active">
                <div className="modalbox center">
                    {isSuccess === true ? (
                        <FontAwesomeIcon 
                            icon={faCircleCheck} 
                            style={{ fontSize: '40px', color: "#50c878" }}
                        />
                        ):(
                        <div className='circle_faTime'>
                            <div className='cf1'>
                                <FontAwesomeIcon 
                                icon={faTimes} 
                                style={{ fontSize: "30px", color: "red" }}
                                />
                            </div>
                        </div>
                    )}

                    <h1 style={{ color: isSuccess ? "#50c878" : "#ff0000" }}>{review}</h1>
                    <p style={{ marginBottom: "50px" }}>{message}</p>
                    <div className="btnback" style={{cursor: "pointer"}}>
                        <a className='btn' onClick={handleConfirmClick}>{confirm}</a>
                    </div>
                </div>
            </div>
        </div>
    );
};

Pop_up.propTypes = {
    isSuccess: PropTypes.bool.isRequired, // Determines icon and color
    review: PropTypes.string.isRequired, // Main message to display
    message: PropTypes.string.isRequired, // Additional message to display
    confirm: PropTypes.string.isRequired, // Show confirm context
    href: PropTypes.string, // Redirect link
    onClose: PropTypes.func // Function to call when closing popup
};

export default Pop_up;
