require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto'); // Importamos crypto aquí

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET;

// --- CONFIGURACIÓN DE APP ---
app.use(cors());
// Límite de carga aumentado para imágenes
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// --- UTILIDADES DE CRIPTOGRAFÍA (Movidass al lugar correcto) ---
const ALGORITHM = 'aes-256-cbc';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY; 
const IV_LENGTH = 16; 

function encrypt(text) {
    if(!text) return { encryptedData: null, iv: null };
    let iv = crypto.randomBytes(IV_LENGTH);
    let cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return { 
        iv: iv.toString('hex'), 
        encryptedData: encrypted.toString('hex') 
    };
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

// --- MIDDLEWARE DE SEGURIDAD ---
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

// --- RUTA: LOGIN (CON VERIFICACIÓN DE ESTADO DE AGENCIA) ---
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // 1. Buscar usuario E INCLUIR DATOS DE SU AGENCIA
        const user = await prisma.user.findUnique({ 
            where: { email },
            include: { agency: true } 
        });

        if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

        // 2. CHECK DE SEGURIDAD: ¿La agencia está activa?
        if (user.role !== 'SUPER_ADMIN' && user.agency && !user.agency.active) {
            return res.status(403).json({ 
                error: 'ACCESO BLOQUEADO: Su agencia ha sido desactivada. Por favor, contacte con el Administrador del sistema.' 
            });
        }

        // 3. Verificar contraseña
        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) return res.status(401).json({ error: 'Contraseña incorrecta' });

        // 4. Generar Token
        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role, agencyId: user.agencyId },
            process.env.JWT_SECRET,
            { expiresIn: '8h' }
        );

        res.json({
            message: 'Bienvenido',
            token,
            user: {
                id: user.id,
                email: user.email,
                role: user.role,
                agencyId: user.agencyId
            }
        });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// --- LOGIN PARA CLIENTES (PORTAL) ---
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

        res.json({
            message: 'Bienvenido al Portal',
            token,
            client: {
                id: client.id,
                name: client.name,
                email: client.email,
                role: 'CLIENT'
            }
        });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// OBTENER MIS DATOS (Para el Dashboard del Cliente)
app.get('/api/portal/me', async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        if (!token) return res.status(403).json({ error: 'Token requerido' });

        jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
            if (err) return res.status(403).json({ error: 'Token inválido' });

            const client = await prisma.client.findUnique({
                where: { id: decoded.id },
                include: { agency: { select: { name: true, logo: true } } }
            });

            if (!client) return res.status(404).json({ error: 'Cliente no encontrado' });
            res.json(client);
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// REGISTRO DE AGENCIA
app.post('/api/register', async (req, res) => {
    try {
        const { agencyName, email, password } = req.body;

        const existingUser = await prisma.user.findUnique({ where: { email } });
        if (existingUser) return res.status(400).json({ error: 'El correo ya está registrado' });

        const hashedPassword = await bcrypt.hash(password, 10);

        const result = await prisma.$transaction(async (prisma) => {
            const newAgency = await prisma.agency.create({ data: { name: agencyName } });
            const newUser = await prisma.user.create({
                data: {
                    email,
                    password: hashedPassword,
                    role: 'AGENCY_ADMIN',
                    agencyId: newAgency.id
                }
            });
            await prisma.wallet.create({ data: { agencyId: newAgency.id } });
            return { agency: newAgency, user: newUser };
        });

        res.json({ message: 'Agencia registrada exitosamente', agencyId: result.agency.id });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==========================================
//  RUTAS DE LA BÓVEDA (WALLET) - ¡AHORA SÍ EN EL LUGAR CORRECTO!
// ==========================================

// 1. GUARDAR NUEVA CREDENCIAL (Encriptando)
app.post('/api/credentials', verifyToken, async (req, res) => {
    try {
        const { serviceName, type, username, password, notes, clientId } = req.body;
        
        const { encryptedData, iv } = encrypt(password);

        const cred = await prisma.credential.create({
            data: {
                serviceName, type, username, notes,
                encryptedData, iv,
                clientId
            }
        });

        await prisma.credentialLog.create({
            data: {
                action: 'CREATED',
                userEmail: req.user.email || 'Sistema',
                credentialId: cred.id
            }
        });

        res.json({ message: 'Credencial guardada seguramente' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 2. LISTAR CREDENCIALES
app.get('/api/clients/:clientId/credentials', verifyToken, async (req, res) => {
    try {
        const { clientId } = req.params;
        const credentials = await prisma.credential.findMany({
            where: { clientId },
            select: { id: true, serviceName: true, type: true, username: true, notes: true, createdAt: true },
            orderBy: { createdAt: 'desc' }
        });
        res.json(credentials);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 3. REVELAR CONTRASEÑA
app.post('/api/credentials/:id/reveal', verifyToken, async (req, res) => {
    try {
        const { id } = req.params;
        const cred = await prisma.credential.findUnique({ where: { id } });

        if (!cred) return res.status(404).json({ error: 'No encontrado' });

        const decryptedPassword = decrypt(cred.encryptedData, cred.iv);

        await prisma.credentialLog.create({
            data: {
                action: 'VIEW_REVEALED',
                userEmail: req.user.email || 'Usuario',
                ipAddress: req.ip,
                credentialId: id
            }
        });

        res.json({ password: decryptedPassword });
    } catch (error) {
        res.status(500).json({ error: 'Error de desencriptado' });
    }
});

// 4. GENERAR LINK TEMPORAL
app.post('/api/credentials/:id/share', verifyToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { minutes = 30 } = req.body;

        const token = crypto.randomBytes(24).toString('hex');
        const expiresAt = new Date(Date.now() + minutes * 60000);

        await prisma.magicLink.create({
            data: { token, credentialId: id, expiresAt }
        });

        await prisma.credentialLog.create({
            data: {
                action: `SHARED_LINK_${minutes}MIN`,
                userEmail: req.user.email,
                credentialId: id
            }
        });

        res.json({ link: `https://api-agencia-0smc.onrender.com/secure_view.html?token=${token}` });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==========================================
//  RUTAS DE CLIENTES
// ==========================================

app.get('/api/clients', verifyToken, async (req, res) => {
    try {
        let targetAgencyId = req.user.agencyId;
        if (req.user.role === 'SUPER_ADMIN' && req.query.agencyId) {
            targetAgencyId = req.query.agencyId;
        }

        const clients = await prisma.client.findMany({
            where: { agencyId: targetAgencyId },
            orderBy: { createdAt: 'desc' }
        });
        res.json(clients);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/clients', verifyToken, async (req, res) => {
    try {
        const { name, contactName, email, adAccountId, password, targetAgencyId } = req.body;
        
        let agencyId = req.user.agencyId;
        if (req.user.role === 'SUPER_ADMIN' && targetAgencyId) {
            agencyId = targetAgencyId;
        }

        const passToHash = password || "123456"; 
        const hashedPassword = await bcrypt.hash(passToHash, 10);

        const newClient = await prisma.client.create({
            data: {
                name, contactName, email, adAccountId,
                password: hashedPassword,
                agencyId
            }
        });
        res.json(newClient);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/clients/:id', verifyToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { name, contactName, email, adAccountId, password } = req.body;

        if (req.user.role !== 'SUPER_ADMIN') {
            const check = await prisma.client.findFirst({ where: { id, agencyId: req.user.agencyId } });
            if (!check) return res.status(403).json({ error: 'No tienes permiso' });
        }

        const updateData = { name, contactName, email, adAccountId };

        if (password && password.trim() !== "") {
            updateData.password = await bcrypt.hash(password, 10);
        }

        const updated = await prisma.client.update({
            where: { id },
            data: updateData
        });

        res.json({ message: 'Cliente actualizado', client: updated });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/clients/:id', verifyToken, async (req, res) => {
    try {
        const { id } = req.params;

        if (req.user.role !== 'SUPER_ADMIN') {
            const check = await prisma.client.findFirst({ where: { id, agencyId: req.user.agencyId } });
            if (!check) return res.status(403).json({ error: 'No tienes permiso' });
        }

        await prisma.client.delete({ where: { id } });
        res.json({ message: 'Cliente eliminado' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/clients/:id/logo', verifyToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { logoBase64 } = req.body;

        const client = await prisma.client.findUnique({ where: { id } });
        if (!client) return res.status(404).json({ error: 'Cliente no encontrado' });

        let allowed = false;
        if (req.user.role === 'SUPER_ADMIN') allowed = true;
        else if (req.user.role === 'CLIENT' && req.user.id === id) allowed = true;
        else if (req.user.agencyId === client.agencyId) allowed = true;

        if (!allowed) return res.status(403).json({ error: 'No tienes permiso para editar este logo' });

        const updated = await prisma.client.update({
            where: { id },
            data: { logo: logoBase64 }
        });

        res.json({ message: 'Logo actualizado', logo: updated.logo });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==========================================
//  RUTAS SUPER ADMIN
// ==========================================

app.get('/api/admin/agencies', verifySuperAdmin, async (req, res) => {
    try {
        const agencies = await prisma.agency.findMany({
            include: { 
                users: { select: { email: true } },
                clients: true,
                wallet: true
            },
            orderBy: { createdAt: 'desc' }
        });
        
        const data = agencies.map(agency => ({
            id: agency.id,
            name: agency.name,
            logo: agency.logo,
            ownerEmail: agency.users[0]?.email || 'Sin Dueño',
            totalClients: agency.clients.length,
            balance: agency.wallet ? agency.wallet.balance : 0,
            active: agency.active
        }));

        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/admin/agencies/:id/toggle', verifySuperAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const agency = await prisma.agency.findUnique({ where: { id } });
        if (!agency) return res.status(404).json({ error: 'Agencia no encontrada' });

        const updated = await prisma.agency.update({
            where: { id },
            data: { active: !agency.active }
        });

        res.json({ message: 'Estado actualizado', agency: updated });
    } catch (error) {
        res.status(500).json({ error: 'Error interno al cambiar estado' });
    }
});

app.delete('/api/admin/agencies/:id', verifySuperAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        await prisma.client.deleteMany({ where: { agencyId: id } });
        await prisma.user.deleteMany({ where: { agencyId: id } });
        await prisma.wallet.deleteMany({ where: { agencyId: id } });
        await prisma.agency.delete({ where: { id } });
        res.json({ message: 'Agencia eliminada permanentemente' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/agency/logo', verifyToken, async (req, res) => {
    try {
        const { logoBase64, targetAgencyId } = req.body;
        if (!logoBase64) return res.status(400).json({ error: 'Falta la imagen' });

        let idToUpdate = req.user.agencyId;
        if (req.user.role === 'SUPER_ADMIN' && targetAgencyId) {
            idToUpdate = targetAgencyId;
        }

        const updatedAgency = await prisma.agency.update({
            where: { id: idToUpdate },
            data: { logo: logoBase64 }
        });

        res.json({ message: 'Logo actualizado', logo: updatedAgency.logo });
    } catch (error) {
        res.status(500).json({ error: 'Error al guardar el logo' });
    }
});

app.get('/api/agency/me', verifyToken, async (req, res) => {
    try {
        const agency = await prisma.agency.findUnique({
            where: { id: req.user.agencyId },
            select: { id: true, name: true, logo: true, active: true }
        });
        res.json(agency);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/admin/agencies/:id/update', verifySuperAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { name, ownerEmail, password } = req.body;

        await prisma.agency.update({ where: { id }, data: { name } });

        const userUpdateData = { email: ownerEmail };
        if (password && password.trim() !== "") {
            userUpdateData.password = await bcrypt.hash(password, 10);
        }

        const firstUser = await prisma.user.findFirst({ where: { agencyId: id } });
        if(firstUser) {
            await prisma.user.update({
                where: { id: firstUser.id },
                data: userUpdateData
            });
        }

        res.json({ message: 'Agencia y credenciales actualizadas correctamente' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});
// --- RUTA DE EMERGENCIA: RESETEAR SUPER ADMIN ---
// Visita esta ruta desde el navegador para arreglar tu usuario
app.get('/api/emergency-fix', async (req, res) => {
    try {
        const email = 'stephanorubio@gmail.com'; // <--- TU CORREO EXACTO
        const newPassword = '123456';
        
        // 1. Encriptar con la librería interna del servidor (100% compatible)
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        
        // 2. Actualizar en BD
        const user = await prisma.user.update({
            where: { email },
            data: { password: hashedPassword }
        });
        
        res.json({ 
            success: true, 
            message: 'Contraseña reseteada correctamente', 
            user: user.email,
            new_hash: user.password 
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});
// INICIAR SERVIDOR
app.listen(PORT, () => {
    console.log(`Sistema SaaS ONLINE en puerto ${PORT} 🚀`);
});
