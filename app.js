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

// --- RUTA: LOGIN (CON DATOS DE ROL) ---
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // 1. Buscar usuario
        const user = await prisma.user.findUnique({ where: { email } });
        if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });

        // 2. Verificar contraseña
        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) return res.status(401).json({ error: 'Contraseña incorrecta' });

        // 3. Generar Token
        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role, agencyId: user.agencyId },
            process.env.JWT_SECRET,
            { expiresIn: '8h' }
        );

        // 4. RESPONDER (¡AQUÍ ESTABA EL FALLO!)
        // Ahora enviamos el objeto 'user' completo para que el frontend pueda leer el 'role'
        res.json({
            message: 'Bienvenido',
            token,
            user: {
                id: user.id,
                email: user.email,
                role: user.role, // <--- ESTO ES LO QUE FALTABA
                agencyId: user.agencyId
            }
        });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/me', verifyToken, async (req, res) => {
    const user = await prisma.user.findUnique({ 
        where: { id: req.user.userId },
        include: { agency: { include: { wallet: true } } }
    });
    res.json(user);
});

// --- MÓDULO CLIENTES ---
// --- RUTA: OBTENER CLIENTES (Con soporte para Modo Dios) ---
app.get('/api/clients', verifyToken, async (req, res) => {
    try {
        // Por defecto, buscamos los clientes de la agencia del usuario logueado
        let targetAgencyId = req.user.agencyId;

        // PERO, si el usuario es SUPER_ADMIN y pide ver otra agencia (query params), se lo permitimos
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
// RUTA: ELIMINAR AGENCIA (DELETE) - Solo Super Admin
app.delete('/api/admin/agencies/:id', verifySuperAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        
        // Primero borramos clientes y usuarios asociados para no romper la base de datos (Integridad referencial)
        await prisma.client.deleteMany({ where: { agencyId: id } });
        await prisma.user.deleteMany({ where: { agencyId: id } });
        await prisma.wallet.deleteMany({ where: { agencyId: id } });
        
        // Finalmente borramos la agencia
        await prisma.agency.delete({ where: { id } });

        res.json({ message: 'Agencia y todos sus datos eliminados permanentemente.' });
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
