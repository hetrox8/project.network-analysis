import React, { useEffect, useState } from 'react';
import axios from 'axios';

const PacketLog = () => {
    const [packets, setPackets] = useState([]);

    const fetchPackets = async () => {
        const response = await axios.get('http://localhost:5000/api/packets');
        setPackets(response.data.packets);
    };

    useEffect(() => {
        fetchPackets();
        const interval = setInterval(fetchPackets, 5000); // Poll every 5 seconds
        return () => clearInterval(interval);
    }, []);

    return (
        <div>
            <h2>Captured Packets</h2>
            <ul>
                {packets.map((packet, index) => (
                    <li key={index}>{packet}</li>
                ))}
            </ul>
        </div>
    );
};

export default PacketLog;
