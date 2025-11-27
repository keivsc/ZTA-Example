import express from 'express';
import Logger from '../src/logging.js';
import { verifyToken } from '../services/session.js';
import { getFile, updateFile, deleteFile, createFile, updatePermissions, getAllFiles } from '../services/file.js';

const router = express.Router();
const logger = new Logger('api');

router.use(async (req, res, next)=>{
    const sessionToken = req.cookies['session'];
    const deviceId = req.cookies['x-device-id'];

    if (!sessionToken || !deviceId){
        return res.status(401).json({error:"Missing authentication cookies."})
    }

    const userId = await verifyToken(sessionToken, deviceId);
    if (!userId){
        return res.status(401).json({error:"Invalid Session."});
    }
    req.userId = userId;
    next();
})

router.post('/create', async(req, res)=>{
    const {filename, users} = req.body;
    if (!filename){
        return res.status(400).json({error:"Missing file name."});
    }
    const file = createFile(filename, req.userId, users);
    return res.status(200).json(file);
})

router.delete('/delete/:fileId', async (req, res)=>{
    const fileId = req.params.fileId;
    if (!fileId){
        return res.status(400).json({error:"Missing file id."});
    }
    const file = deleteFile(fileId, req.userId);
    if (!file.success){
        return res.status(404).json(file);
    }
    return res.status(200).json(file);
})

router.put('/modify/:fileId', async (req, res)=>{
    const fileId = req.params.fileId;
    const {content} = req.body;
    if (!fileId || !content){
        return res.status(400).json({error:"Missing body."});
    }
    const file = await updateFile(fileId, req.userId, content);
    if (!file.success){
        return res.status(400).json(file);
    }
    return res.status(200).json(file);
})

router.put('/perms/:fileId', async (req, res)=>{
    const fileId = req.params.fileId;
    const {users} = req.body;
    if (!fileId || !users){
        return res.status(400).json({error:"Missing body."});
    }
    const perms = await updatePermissions(fileId, users);
    if (!perms.success){
        return res.status(400).json(perms);
    }
    return res.status(200).json(perms);
})

router.get('/all', async (req, res) => {
    const fileArray = await getAllFiles(req.userId);
    return res.status(200).json({ files: Array.isArray(fileArray) ? fileArray : [] });
});

router.get('/:fileId', async (req, res)=>{

    const file = await getFile(req.params.fileId, req.userId);
    if (!file){
        return res.status(404).json({error:"File not found."});
    }
    return res.status(200).json(file);

})
export default router;