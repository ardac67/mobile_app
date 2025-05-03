import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Dashboard from './Dashboard';
import Reports from './Reports';
import Logs from './Logs';
import Installation from './Installation';
import Navbar from './Navbar';

function App() {
  return (
    <Router>
      <Navbar />
      <div style={{ padding: '10px',margin:'auto',maxWidth:'80%' }}>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/logs" element={<Logs />} />
          <Route path="/installation" element={<Installation />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
