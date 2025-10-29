import { useEffect, useState } from 'react'
import FingerprintJS from '@fingerprintjs/fingerprintjs'
import {Routes, Route, useNavigate} from 'react-router-dom';
import './App.css'

// Routes
import Login from './pages/login';
import Landing from './pages/landing';

// API
import { postFingerprint } from './utils/api';
import Register from './pages/register';

function App() {
  const [visitorId, setVisitorId] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      const fp = await FingerprintJS.load();
      const { visitorId } = await fp.get();
      setVisitorId(visitorId);

      const res = await postFingerprint(visitorId);
    if (res.status !== 200) {
      document.open();
      document.write("<h1>Access Denied</h1>");
      document.close();
    }



    })();
  }, []);


  return (
    <>
      <Routes>
        <Route path="/" element={<Landing />}></Route>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register/>} />
      </Routes>
    </>
  )
}

export default App;