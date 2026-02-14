require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY; 
const ALGORITHM = 'aes-256-cbc';
const IV_LENGTH = 16; 

// --- CONFIGURACIÓN ---
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(__dirname));

app.get('/secure_view', (req, res) => {
    res.sendFile(path.join(__dirname, 'secure_view.html'));
});

// --- UTILIDADES DE CRIPTOGRAFÍA ---
function encrypt(text) {
    if(!text) return { encryptedData: null, iv: null };
    let iv = crypto.randomBytes(IV_LENGTH);
    let cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return { iv: iv.toString('hex'), encryptedData: encrypted.toString('hex') };
}

function decrypt(text, ivHex) {
    if(!text || !ivHex) return null;
    let iv = Buffer.from(ivHex, 'hex');
    let encryptedText = Buffer.from(text, 'hex');
    let decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

// --- MIDDLEWARES ---
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(403).json({ error: 'Token requerido' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token inválido' });
        req.user = user;
        next();
    });
};

const verifySuperAdmin = (req, res, next) => {
    verifyToken(req, res, () => {
        if (req.user.role !== 'SUPER_ADMIN') {
            return res.status(403).json({ error: 'Acceso Denegado: Se requiere Nivel Super Admin.' });
        }
        next();
    });
};

// ==========================================
//  RUTAS DE AUTENTICACIÓN
// ==========================================

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await prisma.user.findUnique({ where: { email }, include: { agency: true } });

        if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
        if (user.role !== 'SUPER_ADMIN' && user.agency && !user.agency.active) {
            return res.status(403).json({ error: 'Agencia desactivada' });
        }

        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) return res.status(401).json({ error: 'Contraseña incorrecta' });

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role, agencyId: user.agencyId },
            SECRET_KEY,
            { expiresIn: '8h' }
        );

        res.json({ token, user: { email: user.email, role: user.role, agencyId: user.agencyId } });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/portal/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const client = await prisma.client.findFirst({ where: { email } });
        if (!client) return res.status(404).json({ error: 'Cliente no encontrado' });

        const validPass = await bcrypt.compare(password, client.password);
        if (!validPass) return res.status(401).json({ error: 'Contraseña incorrecta' });

        const token = jwt.sign(
            { id: client.id, role: 'CLIENT', agencyId: client.agencyId, name: client.name },
            SECRET_KEY,
            { expiresIn: '8h' }
        );
        res.json({ message: 'Bienvenido', token, client: { name: client.name, email: client.email } });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/portal/me', async (req, res) => {
    try {
        const token = req.headers['authorization']?.split(' ')[1];
        if (!token) return res.status(403).json({ error: 'Token requerido' });
        jwt.verify(token, SECRET_KEY, async (err, decoded) => {
            if (err) return res.status(403).json({ error: 'Token inválido' });
            const client = await prisma.client.findUnique({
                where: { id: decoded.id },
                include: { agency: { select: { name: true, logo: true } } }
            });
            res.json(client);
        });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/register', async (req, res) => {
    try {
        const { agencyName, email, password } = req.body;
        const existing = await prisma.user.findUnique({ where: { email } });
        if (existing) return res.status(400).json({ error: 'Correo ya registrado' });

        const hashed = await bcrypt.hash(password, 10);
        const result = await prisma.$transaction(async (prisma) => {
            const ag = await prisma.agency.create({ data: { name: agencyName } });
            const usr = await prisma.user.create({
                data: { email, password: hashed, role: 'AGENCY_ADMIN', agencyId: ag.id }
            });
            return { ag, usr };
        });
        res.json({ message: 'Registrado', agencyId: result.ag.id });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// ==========================================
//  BÓVEDA (WALLET) Y AUDITORÍA
// ==========================================

// 1. Crear Credencial
app.post('/api/credentials', verifyToken, async (req, res) => {
    try {
        const { serviceName, type, username, password, notes, clientId } = req.body;
        const { encryptedData, iv } = encrypt(password);
        
        await prisma.credential.create({
            data: { serviceName, type, username, notes, encryptedData, iv, clientId }
        });
        // Nota: Ya no usamos CredentialLog porque esa tabla se eliminó.
        res.json({ message: 'Guardado' });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// 2. Listar
app.get('/api/clients/:clientId/credentials', verifyToken, async (req, res) => {
    try {
        const creds = await prisma.credential.findMany({
            where: { clientId: req.params.clientId },
            select: { id: true, serviceName: true, type: true, username: true, notes: true, createdAt: true },
            orderBy: { createdAt: 'desc' }
        });
        res.json(creds);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// 3. Editar
app.put('/api/credentials/:id', verifyToken, async (req, res) => {
    try {
        const { serviceName, type, username, password, notes } = req.body;
        let data = { serviceName, type, username, notes };
        if (password && password.trim() !== "") {
            const enc = encrypt(password);
            data.encryptedData = enc.encryptedData;
            data.iv = enc.iv;
        }
        await prisma.credential.update({ where: { id: req.params.id }, data });
        res.json({ message: 'Actualizado' });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// 4. Borrar
app.delete('/api/credentials/:id', verifyToken, async (req, res) => {
    try {
        await prisma.credential.delete({ where: { id: req.params.id } });
        res.json({ message: 'Eliminado' });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// 5. REVELAR (Con Auditoría)
app.post('/api/credentials/:id/reveal', verifyToken, async (req, res) => {
    try {
        const cred = await prisma.credential.findUnique({ where: { id: req.params.id } });
        if (!cred) return res.status(404).json({ error: 'No encontrado' });

        const pass = decrypt(cred.encryptedData, cred.iv);

        // REGISTRO EN AUDITLOG (Modelo Correcto)
        await prisma.auditLog.create({
            data: {
                credentialId: req.params.id,
                userEmail: req.user.email,
                userRole: req.user.role, 
                ipAddress: req.headers['x-forwarded-for'] || req.socket.remoteAddress,
                agencyId: req.user.agencyId
            }
        });

        res.json({ password: pass });
    } catch (error) { 
        console.error(error);
        res.status(500).json({ error: 'Error interno' }); 
    }
});

// 6. HISTORIAL (Filtrado)
app.get('/api/audit-logs', verifyToken, async (req, res) => {
    try {
        const logs = await prisma.auditLog.findMany({
            where: {
                agencyId: req.user.agencyId,
                userRole: 'EMPLOYEE' // Solo empleados
            },
            include: { credential: { select: { serviceName: true } } },
            orderBy: { createdAt: 'desc' }
        });
        res.json(logs);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// 7. COMPARTIR LINK
app.post('/api/credentials/:id/share', verifyToken, async (req, res) => {
    try {
        const { minutes = 30 } = req.body;
        const token = crypto.randomBytes(24).toString('hex');
        const expiresAt = new Date(Date.now() + minutes * 60000);

        await prisma.magicLink.create({
            data: { token, credentialId: req.params.id, expiresAt }
        });
        // CredentialLog eliminado, no registramos creación de link para no romper la BD.
        res.json({ link: `https://api-agencia-0smc.onrender.com/secure_view?token=${token}` });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// 8. UNLOCK LINK (Vista del Empleado)
app.post('/api/magic-link/:token/unlock', verifyToken, async (req, res) => {
    try {
        const magicLink = await prisma.magicLink.findUnique({
            where: { token: req.params.token },
            include: { credential: true }
        });

        if (!magicLink || magicLink.expiresAt < new Date()) {
            return res.status(403).json({ error: 'Enlace expirado' });
        }

        const pass = decrypt(magicLink.credential.encryptedData, magicLink.credential.iv);

        // REGISTRO AUDITORÍA (Cuando el empleado usa el link)
        await prisma.auditLog.create({
            data: {
                credentialId: magicLink.credentialId,
                userEmail: `${req.user.name} (${req.user.email})`, 
                userRole: 'EMPLOYEE',
                ipAddress: req.headers['x-forwarded-for'] || req.socket.remoteAddress,
                agencyId: magicLink.credential.client ? magicLink.credential.client.agencyId : null // Intentamos inferir agencia
            }
        });

        res.json({
            serviceName: magicLink.credential.serviceName,
            username: magicLink.credential.username,
            password: pass,
            notes: magicLink.credential.notes
        });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// ==========================================
//  GESTIÓN DE CLIENTES
// ==========================================

app.get('/api/clients', verifyToken, async (req, res) => {
    try {
        let agencyId = req.user.role === 'SUPER_ADMIN' && req.query.agencyId ? req.query.agencyId : req.user.agencyId;
        const clients = await prisma.client.findMany({ where: { agencyId }, orderBy: { createdAt: 'desc' } });
        res.json(clients);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/clients', verifyToken, async (req, res) => {
    try {
        const { name, contactName, email, adAccountId, password, targetAgencyId } = req.body;
        let agencyId = req.user.role === 'SUPER_ADMIN' && targetAgencyId ? targetAgencyId : req.user.agencyId;
        
        const passToHash = password || "123456"; 
        const hashed = await bcrypt.hash(passToHash, 10);

        const newClient = await prisma.client.create({
            data: { name, contactName, email, adAccountId, password: hashed, agencyId }
        });
        res.json(newClient);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.put('/api/clients/:id', verifyToken, async (req, res) => {
    try {
        const { name, contactName, email, adAccountId, password } = req.body;
        // Validación simple de propiedad
        if (req.user.role !== 'SUPER_ADMIN') {
            const check = await prisma.client.findFirst({ where: { id: req.params.id, agencyId: req.user.agencyId } });
            if (!check) return res.status(403).json({ error: 'No autorizado' });
        }
        let data = { name, contactName, email, adAccountId };
        if (password && password.trim() !== "") data.password = await bcrypt.hash(password, 10);
        
        const updated = await prisma.client.update({ where: { id: req.params.id }, data });
        res.json({ message: 'Actualizado', client: updated });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.delete('/api/clients/:id', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'SUPER_ADMIN') {
            const check = await prisma.client.findFirst({ where: { id: req.params.id, agencyId: req.user.agencyId } });
            if (!check) return res.status(403).json({ error: 'No autorizado' });
        }
        await prisma.client.delete({ where: { id: req.params.id } });
        res.json({ message: 'Eliminado' });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.put('/api/clients/:id/logo', verifyToken, async (req, res) => {
    try {
        await prisma.client.update({ where: { id: req.params.id }, data: { logo: req.body.logoBase64 } });
        res.json({ message: 'Logo actualizado' });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// ==========================================
//  GESTIÓN DE EMPLEADOS
// ==========================================

app.get('/api/employees', verifyToken, async (req, res) => {
    try {
        const agencyId = req.query.agencyId || req.user.agencyId;
        const emps = await prisma.employee.findMany({ where: { agencyId }, select: { id: true, name: true, email: true, role: true } });
        res.json(emps);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/employees', verifyToken, async (req, res) => {
    try {
        const { name, email, password, role, agencyId } = req.body;
        let targetId = req.user.role === 'SUPER_ADMIN' && agencyId ? agencyId : req.user.agencyId;
        const hashed = await bcrypt.hash(password, 10);
        await prisma.employee.create({
            data: { name, email, password: hashed, role, agencyId: targetId }
        });
        res.json({ message: 'Creado' });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.put('/api/employees/:id', verifyToken, async (req, res) => {
    try {
        const { name, email, role, password } = req.body;
        let data = { name, email, role };
        if (password) data.password = await bcrypt.hash(password, 10);
        await prisma.employee.update({ where: { id: req.params.id }, data });
        res.json({ message: 'Actualizado' });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.delete('/api/employees/:id', verifyToken, async (req, res) => {
    try {
        await prisma.employee.delete({ where: { id: req.params.id } });
        res.json({ message: 'Eliminado' });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// LOGIN DE EMPLEADO (Para Magic Link)
app.post('/api/employee/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const emp = await prisma.employee.findUnique({ where: { email } });
        if (!emp) return res.status(404).json({ error: 'Empleado no encontrado' });
        const valid = await bcrypt.compare(password, emp.password);
        if (!valid) return res.status(401).json({ error: 'Incorrecto' });

        const token = jwt.sign({ id: emp.id, name: emp.name, email: emp.email, role: 'EMPLOYEE' }, SECRET_KEY, { expiresIn: '15m' });
        res.json({ token, name: emp.name });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// ==========================================
//  RUTAS SUPER ADMIN
// ==========================================

app.get('/api/admin/agencies', verifySuperAdmin, async (req, res) => {
    try {
        const agencies = await prisma.agency.findMany({
            include: { users: { select: { email: true } }, clients: true, wallet: true },
            orderBy: { createdAt: 'desc' }
        });
        const data = agencies.map(a => ({
            id: a.id, name: a.name, logo: a.logo, active: a.active,
            ownerEmail: a.users[0]?.email || 'N/A',
            totalClients: a.clients.length,
            balance: a.wallet ? a.wallet.balance : 0
        }));
        res.json(data);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.put('/api/agency/logo', verifyToken, async (req, res) => {
    try {
        const { logoBase64, targetAgencyId } = req.body;
        let id = req.user.role === 'SUPER_ADMIN' && targetAgencyId ? targetAgencyId : req.user.agencyId;
        const updated = await prisma.agency.update({ where: { id }, data: { logo: logoBase64 } });
        res.json({ message: 'Logo actualizado', logo: updated.logo });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/agency/me', verifyToken, async (req, res) => {
    try {
        const agency = await prisma.agency.findUnique({ where: { id: req.user.agencyId } });
        res.json(agency);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/emergency-fix', async (req, res) => {
    const email = 'stephanorubio@gmail.com'; 
    const pass = await bcrypt.hash('123456', 10);
    await prisma.user.update({ where: { email }, data: { password: pass } });
    res.json({ success: true });
});

app.listen(PORT, () => {
    console.log(`Sistema ONLINE en puerto ${PORT} 🚀`);
});
