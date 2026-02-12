const crypto = require('crypto');

// --- UTILIDADES DE CRIPTOGRAFÍA ---
const ALGORITHM = 'aes-256-cbc';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY; // Debe ser de 32 chars
const IV_LENGTH = 16; // AES block size

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
// --- RUTAS DE LA BÓVEDA (WALLET) ---

// 1. GUARDAR NUEVA CREDENCIAL (Encriptando)
app.post('/api/credentials', verifyToken, async (req, res) => {
    try {
        const { serviceName, type, username, password, notes, clientId } = req.body;
        
        // Encriptamos la contraseña ANTES de tocar la base de datos
        const { encryptedData, iv } = encrypt(password);

        const cred = await prisma.credential.create({
            data: {
                serviceName, type, username, notes,
                encryptedData, iv,
                clientId
            }
        });

        // Log de creación
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

// 2. LISTAR CREDENCIALES DE UN CLIENTE (Sin revelar contraseña)
app.get('/api/clients/:clientId/credentials', verifyToken, async (req, res) => {
    try {
        const { clientId } = req.params;
        // Solo devolvemos metadatos, NUNCA la password aquí
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

// 3. REVELAR CONTRASEÑA (Alta Seguridad + Log)
app.post('/api/credentials/:id/reveal', verifyToken, async (req, res) => {
    try {
        const { id } = req.params;
        const cred = await prisma.credential.findUnique({ where: { id } });

        if (!cred) return res.status(404).json({ error: 'No encontrado' });

        // Desencriptamos
        const decryptedPassword = decrypt(cred.encryptedData, cred.iv);

        // --- TRAZABILIDAD OBLIGATORIA ---
        // Guardamos quién pidió ver esto
        await prisma.credentialLog.create({
            data: {
                action: 'VIEW_REVEALED',
                userEmail: req.user.email || 'Usuario', // Tu token debe traer email
                ipAddress: req.ip,
                credentialId: id
            }
        });

        res.json({ password: decryptedPassword });
    } catch (error) {
        res.status(500).json({ error: 'Error de desencriptado' });
    }
});

// 4. GENERAR LINK TEMPORAL (Para empleados)
app.post('/api/credentials/:id/share', verifyToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { minutes = 30 } = req.body; // Dura 30 mins por defecto

        // Crear token único
        const token = crypto.randomBytes(24).toString('hex');
        const expiresAt = new Date(Date.now() + minutes * 60000);

        await prisma.magicLink.create({
            data: {
                token,
                credentialId: id,
                expiresAt
            }
        });

        // Log de que se creó un link
        await prisma.credentialLog.create({
            data: {
                action: `SHARED_LINK_${minutes}MIN`,
                userEmail: req.user.email,
                credentialId: id
            }
        });

        res.json({ link: `https://tusitio.com/secure_view.html?token=${token}` });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET;

app.use(cors());
// AUMENTAMOS EL LÍMITE DE CARGA A 50MB PARA LAS IMÁGENES
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

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

        // 1. Buscar usuario E INCLUIR DATOS DE SU AGENCIA para ver el estado
        const user = await prisma.user.findUnique({ 
            where: { email },
            include: { agency: true } // <--- CRÍTICO: Traemos los datos de la agencia
        });

        if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

        // 2. CHECK DE SEGURIDAD: ¿La agencia está activa?
        // Si el usuario NO es Super Admin y su agencia está desactivada... ¡BLOQUEADO!
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

        // 1. Buscamos en la tabla CLIENT (no en User)
        // Nota: Asumimos que el email es único. Si no lo es, esto podría dar problemas.
        const client = await prisma.client.findFirst({ where: { email } });

        if (!client) return res.status(404).json({ error: 'Cliente no encontrado' });

        // 2. Verificar contraseña
        const validPass = await bcrypt.compare(password, client.password);
        if (!validPass) return res.status(401).json({ error: 'Contraseña incorrecta' });

        // 3. Generar Token (Rol especial: CLIENT)
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

            // Buscamos al cliente Y su agencia (para mostrar el logo de la agencia en el portal)
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


// REGISTRO DE AGENCIA (Ahora devuelve JSON limpio)
app.post('/api/register', async (req, res) => {
    try {
        const { agencyName, email, password } = req.body;

        const existingUser = await prisma.user.findUnique({ where: { email } });
        if (existingUser) return res.status(400).json({ error: 'El correo ya está registrado' });

        const hashedPassword = await bcrypt.hash(password, 10);

        // Transacción: Crea Agencia + Usuario + Wallet a la vez
        const result = await prisma.$transaction(async (prisma) => {
            const newAgency = await prisma.agency.create({
                data: { name: agencyName }
            });

            const newUser = await prisma.user.create({
                data: {
                    email,
                    password: hashedPassword,
                    role: 'AGENCY_ADMIN',
                    agencyId: newAgency.id
                }
            });

            await prisma.wallet.create({
                data: { agencyId: newAgency.id }
            });

            return { agency: newAgency, user: newUser };
        });

        res.json({ message: 'Agencia registrada exitosamente', agencyId: result.agency.id });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==========================================
//  RUTAS DE CLIENTES (AGENCIA)
// ==========================================

// OBTENER CLIENTES (Con soporte para "Ver Como" del Super Admin)
app.get('/api/clients', verifyToken, async (req, res) => {
    try {
        // Por defecto, carga la agencia del usuario
        let targetAgencyId = req.user.agencyId;

        // SI es Super Admin y pide ver otra agencia, cambiamos el objetivo
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

// CREAR CLIENTE (Actualizado con Password)
app.post('/api/clients', verifyToken, async (req, res) => {
    try {
        const { name, contactName, email, adAccountId, password, targetAgencyId } = req.body;
        
        let agencyId = req.user.agencyId;
        if (req.user.role === 'SUPER_ADMIN' && targetAgencyId) {
            agencyId = targetAgencyId;
        }

        // Si no mandan contraseña, asignamos "123456" por defecto
        const passToHash = password || "123456"; 
        const hashedPassword = await bcrypt.hash(passToHash, 10);

        const newClient = await prisma.client.create({
            data: {
                name, contactName, email, adAccountId,
                password: hashedPassword, // <--- Guardamos la contraseña encriptada
                agencyId
            }
        });
        res.json(newClient);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// EDITAR CLIENTE
// EDITAR CLIENTE (Con soporte para cambio de contraseña)
app.put('/api/clients/:id', verifyToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { name, contactName, email, adAccountId, password } = req.body;

        // Verificaciones de seguridad (igual que antes)
        if (req.user.role !== 'SUPER_ADMIN') {
            const check = await prisma.client.findFirst({ where: { id, agencyId: req.user.agencyId } });
            if (!check) return res.status(403).json({ error: 'No tienes permiso' });
        }

        // Preparamos los datos a actualizar
        const updateData = { name, contactName, email, adAccountId };

        // SI mandaron contraseña nueva, la encriptamos y la agregamos al paquete
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

// ELIMINAR CLIENTE
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

// --- ACTUALIZAR LOGO DE CLIENTE ---
app.put('/api/clients/:id/logo', verifyToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { logoBase64 } = req.body;

        // 1. Buscar el cliente
        const client = await prisma.client.findUnique({ where: { id } });
        if (!client) return res.status(404).json({ error: 'Cliente no encontrado' });

        // 2. Verificar Permisos (Seguridad estricta)
        let allowed = false;

        if (req.user.role === 'SUPER_ADMIN') allowed = true; // Dios puede todo
        else if (req.user.role === 'CLIENT' && req.user.id === id) allowed = true; // El cliente puede editarse a sí mismo
        else if (req.user.agencyId === client.agencyId) allowed = true; // La agencia dueña puede editar

        if (!allowed) return res.status(403).json({ error: 'No tienes permiso para editar este logo' });

        // 3. Actualizar
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
//  RUTAS SUPER ADMIN (GOD MODE)
// ==========================================

// RUTA: VER TODAS LAS AGENCIAS (Para el dueño del SaaS)
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
        
        // Formateamos la data
        const data = agencies.map(agency => ({
            id: agency.id,
            name: agency.name,
            logo: agency.logo, // <--- ¡AQUÍ ESTABA EL CULPABLE! FALTABA ESTA LÍNEA
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

// --- RUTA: ACTIVAR / DESACTIVAR AGENCIA ---
app.put('/api/admin/agencies/:id/toggle', verifySuperAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        
        // 1. Buscamos la agencia actual
        const agency = await prisma.agency.findUnique({ where: { id } });
        
        if (!agency) return res.status(404).json({ error: 'Agencia no encontrada' });

        // 2. Invertimos su estado (Si es true -> false, Si es false -> true)
        const updated = await prisma.agency.update({
            where: { id },
            data: { active: !agency.active } // <--- Aquí ocurre la magia
        });

        res.json({ message: 'Estado actualizado', agency: updated });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error interno al cambiar estado' });
    }
});

// BORRAR AGENCIA DEFINITIVAMENTE
app.delete('/api/admin/agencies/:id', verifySuperAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        
        // Limpieza en cascada manual
        await prisma.client.deleteMany({ where: { agencyId: id } });
        await prisma.user.deleteMany({ where: { agencyId: id } });
        await prisma.wallet.deleteMany({ where: { agencyId: id } });
        await prisma.agency.delete({ where: { id } });

        res.json({ message: 'Agencia eliminada permanentemente' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// --- RUTA: SUBIR LOGO (CORREGIDA PARA MODO DIOS) ---
app.put('/api/agency/logo', verifyToken, async (req, res) => {
    try {
        const { logoBase64, targetAgencyId } = req.body;
        
        if (!logoBase64) return res.status(400).json({ error: 'Falta la imagen' });

        // POR DEFECTO: Actualizo mi propia agencia
        let idToUpdate = req.user.agencyId;

        // PERO: Si soy Super Admin y me dicen qué agencia tocar, cambio el objetivo
        if (req.user.role === 'SUPER_ADMIN' && targetAgencyId) {
            idToUpdate = targetAgencyId;
        }

        const updatedAgency = await prisma.agency.update({
            where: { id: idToUpdate },
            data: { logo: logoBase64 }
        });

        res.json({ message: 'Logo actualizado', logo: updatedAgency.logo });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al guardar el logo' });
    }
});

// --- RUTA: OBTENER MI AGENCIA (Para ver el logo al entrar) ---
app.get('/api/agency/me', verifyToken, async (req, res) => {
    try {
        const agency = await prisma.agency.findUnique({
            where: { id: req.user.agencyId },
            select: { id: true, name: true, logo: true, active: true } // Solo datos seguros
        });
        res.json(agency);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});
// EDITAR DATOS DE AGENCIA Y DUEÑO (Super Admin)
app.put('/api/admin/agencies/:id/update', verifySuperAdmin, async (req, res) => {
    try {
        const { id } = req.params; // ID de la Agencia
        const { name, ownerEmail, password } = req.body;

        // 1. Actualizar nombre de la Agencia
        await prisma.agency.update({
            where: { id },
            data: { name }
        });

        // 2. Buscar al dueño (Usuario) y actualizar sus datos
        // Buscamos al usuario de esta agencia que tenga rol ADMIN (o simplemente el que tenga ese email)
        const userUpdateData = { email: ownerEmail };
        
        if (password && password.trim() !== "") {
            userUpdateData.password = await bcrypt.hash(password, 10);
        }

        // Actualizamos todos los usuarios asociados a esa agencia que coincidan con el email antiguo o sean el principal
        // Para simplificar, asumimos que editamos el primer usuario encontrado de esa agencia
        // Ojo: Esto asume un dueño por agencia.
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
// INICIAR SERVIDOR
app.listen(PORT, () => {
    console.log(`Sistema SaaS ONLINE en puerto ${PORT} 🚀`);
});
