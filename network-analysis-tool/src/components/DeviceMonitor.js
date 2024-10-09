import React, { useEffect, useState } from 'react';
import axios from 'axios';

const DeviceMonitor = () => {
    const [devices, setDevices] = useState([]);
    const [blacklist, setBlacklist] = useState([]);
    const [whitelist, setWhitelist] = useState([]);

    const fetchDevices = async () => {
        const response = await axios.get('http://localhost:5000/api/devices');
        setDevices(response.data.devices);
    };

    const addToBlacklist = async (ip) => {
        await axios.post(`http://localhost:5000/api/blacklist`, { ip });
        setBlacklist([...blacklist, ip]);
    };

    const addToWhitelist = async (ip) => {
        await axios.post(`http://localhost:5000/api/whitelist`, { ip });
        setWhitelist([...whitelist, ip]);
    };

    useEffect(() => {
        fetchDevices();
        const interval = setInterval(fetchDevices, 5000); // Poll every 5 seconds
        return () => clearInterval(interval);
    }, []);

    return (
        <div>
            <h2>Connected Devices</h2>
            <ul>
                {devices.map((device, index) => (
                    <li key={index}>
                        {device} 
                        <button onClick={() => addToBlacklist(device)}>Blacklist</button>
                        <button onClick={() => addToWhitelist(device)}>Whitelist</button>
                    </li>
                ))}
            </ul>
        </div>
    );
};

export default DeviceMonitor;
