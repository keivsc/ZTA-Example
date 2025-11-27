import { useEffect, useState } from 'react'
import {Routes, Route, useNavigate} from 'react-router-dom';
import Cookies from 'js-cookie';


import './App.css'

// Routes
import Login from './pages/login';
import Landing from './pages/landing';
import Register from './pages/register';
import Explorer from './pages/explorer'
import FilePage from './pages/file';

// API
import { checkDevice, registerDevice } from './utils/api';
import { bufferToHex, generateDeviceKey, hexToBuffer } from './utils/crypto';
import { LocalDB } from './utils/localDB';

function App() {
useEffect(() => {
  (async () => {
    try {
      const db = new LocalDB('ZTA-Example');
      const existingKey:any = await db.getItem('deviceKeys', 'myDevice');

      let deviceKeysHex: { publicKey: string; privateKey: string };
      let privateKey: CryptoKey;

      if (existingKey) {
        deviceKeysHex = {
          publicKey: existingKey.publicKey,
          privateKey: existingKey.privateKey
        };

        const deviceCheck = await checkDevice();
        if (deviceCheck.status === 200) return;

        privateKey = await crypto.subtle.importKey(
          'pkcs8', 
          hexToBuffer(existingKey.privateKey), 
          { name:"Ed25519" }, 
          true, 
          ['sign']
        );

      } else {
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
      } else if (res.status !== 200) {
        document.open();
        document.write("<h1>Access Denied</h1>");
        document.close();
      }

    } catch (err) {
      console.error('Error in device init:', err);
    }
  })();
}, []);



  return (
    <>
      <Routes>
        <Route path="/" element={<Landing />}></Route>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register/>} />
        <Route path="/explorer" element={<Explorer/>} />
        <Route path="/file" element={<Explorer/>}/>
        <Route path="/file/:id" element={<FilePage/>} />
      </Routes>
    </>
  )
}

export default App;