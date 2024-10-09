import React, { useEffect, useState } from 'react';
import axios from 'axios';
import PacketLog from './PacketLog';
import DeviceMonitor from './DeviceMonitor';

const Dashboard = () => {
    const [bandwidth, setBandwidth] = useState({});
    const [alert, setAlert] = useState('');

    const fetchBandwidth = async () => {
        const response = await axios.get('http://localhost:5000/api/bandwidth');
        setBandwidth(response.data);
    };

    const startSniffing = async () => {
        await axios.post('http://localhost:5000/api/start-sniffing');
        setAlert('Packet sniffing started.');
    };

    useEffect(() => {
        fetchBandwidth();
        const interval = setInterval(fetchBandwidth, 5000); // Poll every 5 seconds
        return () => clearInterval(interval);
    }, []);

    return (
        <div>
            <h1>Network Analysis Dashboard</h1>
            <button onClick={startSniffing}>Start Sniffing</button>
            {alert && <p>{alert}</p>}

            <h2>Bandwidth Usage</h2>
            <ul>
                {Object.entries(bandwidth).map(([ip, usage]) => (
                    <li key={ip}>{ip}: {usage} bytes</li>
                ))}
            </ul>

            <PacketLog />
            <DeviceMonitor />
        </div>
    );
};

export default Dashboard;
