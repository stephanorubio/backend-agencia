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

app.listen(PORT, () => console.log(`Server listo en puerto ${PORT}`));