import React, { useState, useEffect } from 'react';
import { LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { Shield, AlertTriangle, Terminal, RefreshCw, Calendar, Clock } from 'lucide-react';
import './App.css';

function App() {
  const [logData, setLogData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [portStats, setPortStats] = useState([]);
  const [payloadStats, setPayloadStats] = useState([]);
  const [timelineData, setTimelineData] = useState([]);
  const [attackerScore, setAttackerScore] = useState(0);
  const [lastUpdated, setLastUpdated] = useState('');
  const [totalAttacks, setTotalAttacks] = useState(0);
  
  const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884d8', '#DE3163'];
  
  useEffect(() => {
    // In a real application, this would fetch data from your backend API
    // For this demo, we'll use the static data analyzed from the honeypot logs
    const fetchData = async () => {
      setLoading(true);
      
      try {
        // Try to fetch from API, but fall back to mock data if API is not available
        let data;
        try {
          const response = await fetch('http://localhost:5000/api/honeypot-data');
          if (response.ok) {
            data = await response.json();
          } else {
            throw new Error('API not available');
          }
        } catch (error) {
          console.log('Using mock data instead of API:', error.message);
          // Using mock data based on the sample analysis file
          data = {
            timestamp: new Date().toISOString(),
            totalAttacks: 356,
            attackerScore: 20.4,
            portStats: [
              { port: 21, name: "FTP", attacks: 188, uniquePayloads: 11 },
              { port: 22, name: "SSH", attacks: 125, uniquePayloads: 18 },
              { port: 80, name: "HTTP", attacks: 43, uniquePayloads: 3 }
            ],
            payloadStats: [
              { name: "USER admin", count: 46 },
              { name: "USER root", count: 35 },
              { name: "USER user", count: 35 },
              { name: "USER test", count: 35 },
              { name: "admin:password123", count: 16 },
              { name: "GET / HTTP", count: 15 }
            ],
            // Create hourly attack distribution for the last 24 hours
            timelineData: Array.from({ length: 24 }, (_, i) => {
              // Add a spike around hour 23 to match the honeypot data
              const baseValue = 5;
              const value = i === 23 ? 356 : Math.floor(Math.random() * 10) + baseValue;
              return {
                hour: i,
                attacks: value
              };
            })
          };
        }
        
        setPortStats(data.portStats);
        setPayloadStats(data.payloadStats);
        setTimelineData(data.timelineData);
        setAttackerScore(data.attackerScore);
        setLastUpdated(new Date().toLocaleString());
        setTotalAttacks(data.totalAttacks);
        setLogData(data);
        
      } catch (error) {
        console.error("Error fetching honeypot data:", error);
      } finally {
        setLoading(false);
      }
    };
    
    fetchData();
    
    // Refresh data every 5 minutes
    const interval = setInterval(fetchData, 300000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="loading-container">
        <div className="loading-box">
          <RefreshCw className="loading-icon" />
          <h2 className="loading-text">Loading honeypot data...</h2>
        </div>
      </div>
    );
  }

  // Calculate threat level based on attack sophistication score
  const getThreatLevel = (score) => {
    if (score >= 15) return { level: 'High', color: 'text-red' };
    if (score >= 8) return { level: 'Medium', color: 'text-yellow' };
    return { level: 'Low', color: 'text-green' };
  };

  const threatLevel = getThreatLevel(attackerScore);

  return (
    <div className="dashboard-container">
      {/* Header */}
      <div className="dashboard-header">
        <div className="header-content">
          <div className="header-title">
            <Shield className="header-icon" />
            <h1 className="dashboard-title">Honeypot Attack Dashboard</h1>
          </div>
          <div className="header-meta">
            <div className="meta-item">
              <Calendar className="meta-icon" />
              <span>Last updated: {lastUpdated}</span>
            </div>
            <div className="meta-item">
              <Clock className="meta-icon" />
              <span>Analysis period: last 24 hours</span>
            </div>
          </div>
        </div>
      </div>

      {/* Stats Overview */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-content">
            <div>
              <p className="stat-label">Total Attacks</p>
              <h2 className="stat-value">{totalAttacks}</h2>
            </div>
            <AlertTriangle className="stat-icon warning" />
          </div>
        </div>
        
        <div className="stat-card">
          <div className="stat-content">
            <div>
              <p className="stat-label">Attack Sophistication</p>
              <h2 className={`stat-value ${threatLevel.color}`}>{attackerScore.toFixed(1)}</h2>
            </div>
            <div className={`threat-badge ${threatLevel.level.toLowerCase()}`}>
              {threatLevel.level} Threat
            </div>
          </div>
        </div>
        
        <div className="stat-card">
          <div className="stat-content">
            <div>
              <p className="stat-label">Unique Ports Targeted</p>
              <h2 className="stat-value">{portStats.length}</h2>
            </div>
            <Terminal className="stat-icon primary" />
          </div>
        </div>
      </div>

      {/* Attack Timeline */}
      <div className="widget-card">
        <div className="widget-header">
          <h2 className="widget-title">Attack Timeline (24 Hours)</h2>
        </div>
        <div className="widget-body">
          <div className="chart-container">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart
                data={timelineData}
                margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
              >
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="hour" label={{ value: 'Hour of Day', position: 'insideBottom', offset: -5 }} />
                <YAxis label={{ value: 'Attack Count', angle: -90, position: 'insideLeft' }} />
                <Tooltip formatter={(value) => [`${value} attacks`, 'Count']} />
                <Legend />
                <Line type="monotone" dataKey="attacks" stroke="#8884d8" activeDot={{ r: 8 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Attack Distribution by Port & Top Payloads */}
      <div className="charts-grid">
        <div className="widget-card">
          <div className="widget-header">
            <h2 className="widget-title">Attack Distribution by Port</h2>
          </div>
          <div className="widget-body">
            <div className="chart-container">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={portStats}
                    cx="50%"
                    cy="50%"
                    labelLine={true}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="attacks"
                    nameKey="name"
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  >
                    {portStats.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip formatter={(value, name, props) => [`${value} attacks`, props.payload.name]} />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        <div className="widget-card">
          <div className="widget-header">
            <h2 className="widget-title">Top Attack Payloads</h2>
          </div>
          <div className="widget-body">
            <div className="chart-container">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={payloadStats}
                  layout="vertical"
                  margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
                >
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis type="number" />
                  <YAxis type="category" dataKey="name" width={100} />
                  <Tooltip formatter={(value) => [`${value} occurrences`, 'Count']} />
                  <Legend />
                  <Bar dataKey="count" fill="#8884d8">
                    {payloadStats.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      </div>

      {/* Recommendations */}
      <div className="widget-card">
        <div className="widget-header">
          <h2 className="widget-title">Security Recommendations</h2>
        </div>
        <div className="widget-body">
          <div className="alert info">
            <div className="alert-content">
              <h3 className="alert-title">Strengthen FTP Authentication</h3>
              <div className="alert-message">
                <p>High number of FTP brute force attempts detected. Consider implementing rate limiting and fail2ban.</p>
              </div>
            </div>
          </div>
          
          <div className="alert success">
            <div className="alert-content">
              <h3 className="alert-title">Ongoing Threat Intelligence</h3>
              <div className="alert-message">
                <p>Consider expanding honeypot deployment to detect more sophisticated attacks and collect additional TTPs.</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Detailed Port Analysis */}
      <div className="widget-card">
        <div className="widget-header">
          <h2 className="widget-title">Detailed Port Analysis</h2>
        </div>
        <div className="widget-body">
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Port</th>
                  <th>Service</th>
                  <th className="right-align">Attack Count</th>
                  <th className="right-align">Unique Payloads</th>
                  <th className="right-align">Risk Level</th>
                </tr>
              </thead>
              <tbody>
                {portStats.map((port, index) => (
                  <tr key={index} className="table-row">
                    <td className="cell-port">{port.port}</td>
                    <td className="cell-service">{port.name}</td>
                    <td className="cell-count right-align">{port.attacks}</td>
                    <td className="cell-payloads right-align">{port.uniquePayloads}</td>
                    <td className="cell-risk right-align">
                      <span className={`risk-badge ${
                        port.attacks > 150 ? 'high' : 
                        port.attacks > 75 ? 'medium' : 'low'
                      }`}>
                        {port.attacks > 150 ? 'High' : port.attacks > 75 ? 'Medium' : 'Low'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table> 
          </div> 
        </div>
      </div>
    </div>
  );
}

export default App;