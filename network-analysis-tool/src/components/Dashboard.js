import React, { useEffect, useState } from 'react';
import axios from 'axios';
import PacketLog from './PacketLog';
import DeviceMonitor from './DeviceMonitor';
import Blacklist from './Blacklist'; // Import your blacklist component
import Whitelist from './Whitelist'; // Import your whitelist component

const Dashboard = () => {
    const [bandwidth, setBandwidth] = useState({});
    const [devices, setDevices] = useState([]);
    const [blacklist, setBlacklist] = useState([]);
    const [whitelist, setWhitelist] = useState([]);
    const [alert, setAlert] = useState('');

    // Fetch bandwidth data
    const fetchBandwidth = async () => {
        try {
            const response = await axios.get('http://localhost:5000/api/bandwidth');
            setBandwidth(response.data);
        } catch (error) {
            console.error('Error fetching bandwidth data:', error);
        }
    };

    // Fetch devices
    const fetchDevices = async () => {
        try {
            const response = await axios.get('http://localhost:5000/api/devices');
            setDevices(response.data.devices);
        } catch (error) {
            console.error('Error fetching devices:', error);
        }
    };

    // Fetch blacklist
    const fetchBlacklist = async () => {
        try {
            const response = await axios.get('http://localhost:5000/api/blacklist');
            setBlacklist(response.data.blacklist);
        } catch (error) {
            console.error('Error fetching blacklist:', error);
        }
    };

    // Fetch whitelist
    const fetchWhitelist = async () => {
        try {
            const response = await axios.get('http://localhost:5000/api/whitelist');
            setWhitelist(response.data.whitelist);
        } catch (error) {
            console.error('Error fetching whitelist:', error);
        }
    };

    const startSniffing = async () => {
        await axios.post('http://localhost:5000/api/start-sniffing');
        setAlert('Packet sniffing started.');
    };

    useEffect(() => {
        fetchBandwidth();
        fetchDevices();
        fetchBlacklist();
        fetchWhitelist();

        const interval = setInterval(() => {
            fetchBandwidth();
            fetchDevices();
        }, 5000); // Poll every 5 seconds

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

            <h2>Connected Devices</h2>
            <ul>
                {devices.map(device => (
                    <li key={device}>{device}</li>
                ))}
            </ul>

            <h2>Blacklist</h2>
            <Blacklist blacklist={blacklist} />

            <h2>Whitelist</h2>
            <Whitelist whitelist={whitelist} />

            <PacketLog />
            <DeviceMonitor />
        </div>
    );
};

export default Dashboard;
