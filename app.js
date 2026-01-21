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
app.use(express.json());

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

// LOGIN (Corregido para enviar ROL)
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await prisma.user.findUnique({ where: { email } });

        if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) return res.status(401).json({ error: 'Contraseña incorrecta' });

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role, agencyId: user.agencyId },
            SECRET_KEY,
            { expiresIn: '8h' }
        );

        // RESPUESTA COMPLETA CON ROL
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

// CREAR CLIENTE
app.post('/api/clients', verifyToken, async (req, res) => {
    try {
        const { name, contactName, email, adAccountId } = req.body;
        
        // Soporte para crear clientes en otra agencia si soy Super Admin
        let targetAgencyId = req.user.agencyId;
        if (req.user.role === 'SUPER_ADMIN' && req.body.targetAgencyId) {
            targetAgencyId = req.body.targetAgencyId;
        }

        const newClient = await prisma.client.create({
            data: {
                name,
                contactName,
                email,
                adAccountId,
                agencyId: targetAgencyId
            }
        });
        res.json(newClient);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// EDITAR CLIENTE
app.put('/api/clients/:id', verifyToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { name, contactName, email, adAccountId } = req.body;

        // Si NO soy super admin, verifico que el cliente sea mío
        if (req.user.role !== 'SUPER_ADMIN') {
            const check = await prisma.client.findFirst({ where: { id, agencyId: req.user.agencyId } });
            if (!check) return res.status(403).json({ error: 'No tienes permiso' });
        }

        const updated = await prisma.client.update({
            where: { id },
            data: { name, contactName, email, adAccountId }
        });

        res.json({ message: 'Actualizado', client: updated });
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

// ==========================================
//  RUTAS SUPER ADMIN (GOD MODE)
// ==========================================

// VER TODAS LAS AGENCIAS
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
        
        const data = agencies.map(a => ({
            id: a.id,
            name: a.name,
            ownerEmail: a.users[0]?.email || 'Sin Dueño',
            totalClients: a.clients.length,
            balance: a.wallet ? a.wallet.balance : 0,
            active: a.active
        }));

        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ACTIVAR / DESACTIVAR AGENCIA
app.put('/api/admin/agencies/:id/toggle', verifySuperAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const agency = await prisma.agency.findUnique({ where: { id } });
        const updated = await prisma.agency.update({
            where: { id },
            data: { active: !agency.active }
        });
        res.json({ message: 'Estado actualizado', agency: updated });
    } catch (error) {
        res.status(500).json({ error: error.message });
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

// --- RUTA: SUBIR LOGO DE AGENCIA ---
// Recibe una imagen en Base64 y la guarda en la agencia
app.put('/api/agency/logo', verifyToken, async (req, res) => {
    try {
        const { logoBase64 } = req.body;
        
        // Validacion simple: Que no sea una cadena vacia
        if (!logoBase64) return res.status(400).json({ error: 'Falta la imagen' });

        // Guardamos en la BD
        const updatedAgency = await prisma.agency.update({
            where: { id: req.user.agencyId },
            data: { logo: logoBase64 }
        });

        res.json({ message: 'Logo actualizado', logo: updatedAgency.logo });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error al guardar el logo (quizás es muy pesado)' });
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
// INICIAR SERVIDOR
app.listen(PORT, () => {
    console.log(`Sistema SaaS ONLINE en puerto ${PORT} 🚀`);
});
