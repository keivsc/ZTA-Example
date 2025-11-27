import { useEffect, useState } from 'react'
import FingerprintJS from '@fingerprintjs/fingerprintjs'
import {Routes, Route, useNavigate} from 'react-router-dom';
import Cookies from 'js-cookie';


import './App.css'

// Routes
import Login from './pages/login';
import Landing from './pages/landing';

// API
import { checkDevice, registerDevice } from './utils/api';
import Register from './pages/register';
import { bufferToHex, generateDeviceKey, hexToBuffer } from './utils/crypto';
import { LocalDB } from './utils/localDB';

function App() {
  const [visitorId, setVisitorId] = useState<string | null>(null);

  useEffect(() => {
(async () => {
  const db = new LocalDB('ZTA-Example');

  // Try to get existing key
  const existingKey:any = await db.getItem('deviceKeys', 'myDevice');

  let deviceKeysHex: { publicKey: string; privateKey: string };
  let privateKey:CryptoKey;

  if (existingKey) {
    // Key exists, reuse
    deviceKeysHex = {
      publicKey: existingKey.publicKey,
      privateKey: existingKey.privateKey
    };

    const deviceCheck = await checkDevice();

    if (deviceCheck.status == 200){
      return;
    }

    privateKey = await crypto.subtle.importKey('pkcs8', hexToBuffer(existingKey.privateKey), {name:"Ed25519"}, true, ['sign']);
    
  } else {
    // Generate new key pair
    const deviceKeys = await generateDeviceKey();
    privateKey = deviceKeys.privateKey;

    const rawPrivateKey = await crypto.subtle.exportKey("pkcs8", deviceKeys.privateKey);
    const rawPublicKey = await crypto.subtle.exportKey("raw", deviceKeys.publicKey);

    const privateKeyHex = bufferToHex(rawPrivateKey);
    const publicKeyHex = bufferToHex(rawPublicKey);

    deviceKeysHex = { privateKey: privateKeyHex, publicKey: publicKeyHex };

    await db.addItem('deviceKeys', { id: 'myDevice', value: deviceKeysHex });
  }

  const res = await registerDevice(deviceKeysHex.publicKey, privateKey);

  if (res.status === 401){
    Cookies.remove('x-device-id');
    window.location.reload();
  }
  else if (res.status !== 200) {
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