import React, { useState, useEffect } from 'react';
import "./Botchat.css";
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faComments, faPaperPlane, faTimes } from '@fortawesome/free-solid-svg-icons';
import { get, post, put, del } from '../../config/api';

const Botchat = () => {
    const [isOpen, setIsOpen] = useState(false);
    const [question, setQuestion] = useState('');
    const [messages, setMessages] = useState([
        { type: 'bot', content: "Hi, I am Mino. What can I help you?" }
    ]);

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!question.trim()) return;

        setMessages(prev => [...prev, { type: 'user', content: question }]);
        setQuestion('');

        try {
            const response = await post('/api/v1/botchat/ask', { question });
            setMessages(prev => [...prev, { type: 'bot', content: response.data.answer }]);
        } catch (error) {
            console.error('Error:', error);
            setMessages(prev => [...prev, { type: 'bot', content: 'Error occurred while fetching answer' }]);
        }
    };

    return (
        <div className="botchat-container">
            {!isOpen && (
                <button className="botchat-button" onClick={() => setIsOpen(true)}>
                    <FontAwesomeIcon icon={faComments} />
                </button>
            )}
            {isOpen && (
                <div className="botchat-window">
                    <div className="botchat-header">
                        <h3>Chat with Mino</h3>
                        <button onClick={() => setIsOpen(false)}>
                            <FontAwesomeIcon icon={faTimes} />
                        </button>
                    </div>
                    <div className="botchat-messages">
                        {messages.map((message, index) => (
                            <div key={index} className={`message ${message.type}`}>
                                {message.content}
                            </div>
                        ))}
                    </div>
                    <form onSubmit={handleSubmit} className="botchat-input">
                        <input
                            type="text"
                            value={question}
                            onChange={(e) => setQuestion(e.target.value)}
                            placeholder="Enter your question"
                        />
                        <button type="submit">
                            <FontAwesomeIcon icon={faPaperPlane} />
                        </button>
                    </form>
                </div>
            )}
        </div>
    );
};

export default Botchat;