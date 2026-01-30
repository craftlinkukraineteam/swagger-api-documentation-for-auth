const express = require('express');
const swaggerUI = require('swagger-ui-express');
const YAML = require('yamljs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const swaggerDocument = YAML.load('./swagger.yaml');
const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

let users = [];
const SECRET_KEY = 'mysecretkey';

app.post('/auth/register', async (req, res) => {
    const { username, password } = req.body;

    if (users.find(u => u.username === username)) {
        return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = { id: users.length + 1, username, password: hashedPassword };

    users.push(newUser);
    res.status(201).json({ id: newUser.id, username: newUser.username });
});

app.post('/auth/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);

    if (!user) {
        return res.status(400).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
        return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
});

app.get('/auth/profile', (req, res) => {
    const authHeader = req.headers['authorization'];

    if (!authHeader) {
        return res.status(401).json({message: 'No token provided'});
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        const user = users.find(u => u.id === decoded.id);
        res.json({ id: user.id, username: user.username });
    } catch (err) {
        res.status(401).json({ message: 'Invalid token' });
    }
});

app.use('/api-docs', swaggerUI.serve, swaggerUI.setup(swaggerDocument));

app.listen(port, () => {
    console.log(`Server is running at http://localhost:${port}`);
});