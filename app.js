require('dotenv').config();
const express = require('express');
const { PrismaClient } = require('@prisma/client');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET;

app.use(express.json());
app.use(cors());

// --- RUTA DE VERIFICACIÓN ---
app.get('/', (req, res) => res.send('<h1>Sistema SaaS ONLINE 🟢</h1>'));

// --- MÓDULO AUTH ---
app.post('/api/register', async (req, res) => {
    try {
        const { agencyName, email, password } = req.body;
        const existingUser = await prisma.user.findUnique({ where: { email } });
        if (existingUser) return res.status(400).json({ error: 'El usuario ya existe' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await prisma.agency.create({
            data: {
                name: agencyName,
                wallet: { create: { balance: 0.00 } },
                users: { create: { email, password: hashedPassword, role: 'AGENCY_ADMIN' } }
            },
            include: { users: true }
        });
        res.json({ message: 'Agencia registrada', agencyId: result.id });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await prisma.user.findUnique({ where: { email } });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }
        const token = jwt.sign({ userId: user.id, agencyId: user.agencyId }, SECRET_KEY, { expiresIn: '24h' });
        res.json({ message: 'Bienvenido', token });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/me', verifyToken, async (req, res) => {
    const user = await prisma.user.findUnique({ 
        where: { id: req.user.userId },
        include: { agency: { include: { wallet: true } } }
    });
    res.json(user);
});

// --- MÓDULO CLIENTES ---
app.post('/api/clients', verifyToken, async (req, res) => {
    try {
        const newClient = await prisma.client.create({
            data: { ...req.body, agencyId: req.user.agencyId }
        });
        res.json({ message: 'Cliente creado', client: newClient });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/clients', verifyToken, async (req, res) => {
    const clients = await prisma.client.findMany({ where: { agencyId: req.user.agencyId } });
    res.json(clients);
});

function verifyToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(403).json({ error: 'Falta Token' });
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Token inválido' });
        req.user = decoded;
        next();
    });
}
// --- RUTA: EDITAR CLIENTE (PUT) ---
app.put('/api/clients/:id', verifyToken, async (req, res) => {
    try {
        const { id } = req.params; 
        const { name, contactName, email, adAccountId } = req.body;

        const existingClient = await prisma.client.findFirst({
            where: { id: id, agencyId: req.user.agencyId }
        });

        if (!existingClient) {
            return res.status(404).json({ error: 'Cliente no encontrado o no tienes permiso.' });
        }

        const updatedClient = await prisma.client.update({
            where: { id: id },
            data: { name, contactName, email, adAccountId }
        });

        res.json({ message: 'Cliente actualizado', client: updatedClient });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// --- RUTA: ELIMINAR CLIENTE (DELETE) ---
app.delete('/api/clients/:id', verifyToken, async (req, res) => {
    try {
        const { id } = req.params;

        const existingClient = await prisma.client.findFirst({
            where: { id: id, agencyId: req.user.agencyId }
        });

        if (!existingClient) {
            return res.status(404).json({ error: 'Cliente no encontrado o no tienes permiso.' });
        }

        await prisma.client.delete({ where: { id: id } });

        res.json({ message: 'Cliente eliminado correctamente' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});
// ==========================================
//  ZONA SUPER ADMIN (SAAS MASTER)
// ==========================================

// Middleware para proteger rutas de Super Admin
const verifySuperAdmin = async (req, res, next) => {
    // Primero verificamos que sea usuario válido
    verifyToken(req, res, async () => {
        // Segundo: Verificamos que tenga el rol especial
        if (req.user.role !== 'SUPER_ADMIN') {
            return res.status(403).json({ error: 'Acceso denegado. Se requiere Nivel Dios.' });
        }
        next();
    });
};

// RUTA: VER TODAS LAS AGENCIAS (Para el dueño del SaaS)
app.get('/api/admin/agencies', verifySuperAdmin, async (req, res) => {
    try {
        const agencies = await prisma.agency.findMany({
            include: { 
                users: { select: { email: true } }, // Traer email del dueño
                clients: true, // Traer sus clientes para saber si usan el sistema
                wallet: true   // Traer su saldo
            },
            orderBy: { createdAt: 'desc' }
        });
        
        // Formateamos la data para que el frontend no sufra
        const data = agencies.map(agency => ({
            id: agency.id,
            name: agency.name,
            ownerEmail: agency.users[0]?.email || 'Sin Dueño',
            totalClients: agency.clients.length,
            balance: agency.wallet ? agency.wallet.balance : 0,
            active: agency.active,
            createdAt: agency.createdAt
        }));

        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// RUTA: BANEAR O ACTIVAR AGENCIA (Interruptor de apagado)
app.put('/api/admin/agencies/:id/toggle', verifySuperAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const agency = await prisma.agency.findUnique({ where: { id } });
        
        const updated = await prisma.agency.update({
            where: { id },
            data: { active: !agency.active } // Invertir estado (Si es true -> false)
        });

        res.json({ message: `Agencia ${updated.active ? 'ACTIVADA' : 'SUSPENDIDA'}`, agency: updated });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.listen(PORT, () => console.log(`Server listo en puerto ${PORT}`));
