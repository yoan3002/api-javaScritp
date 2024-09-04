const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Inicializar la aplicación Express
const app = express();
app.use(express.json());  // Para poder trabajar con JSON en las solicitudes

// Conectar a la base de datos MongoDB
mongoose.connect('mongodb://localhost:27017/authDB', {

}).then(() => {
    console.log('Conectado a la base de datos MongoDB');
}).catch(err => {
    console.error('Error al conectar a la base de datos MongoDB', err);
});

// Definir un esquema de usuario
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

// Endpoint para registrar un nuevo usuario
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);  // Encriptar la contraseña
        const user = new User({ username, password: hashedPassword });
        await user.save();  // Guardar el usuario en la base de datos
        res.status(201).json({ message: 'Usuario registrado con éxito' });
    } catch (err) {
        res.status(500).json({ error: 'Error registrando el usuario' });
    }
});

// Endpoint para iniciar sesión
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username });  // Buscar el usuario en la base de datos
        if (!user) {
            return res.status(401).json({ error: 'Usuario no encontrado' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);  // Comparar la contraseña
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Contraseña incorrecta' });
        }

        const token = jwt.sign({ id: user._id }, 'secret_key', { expiresIn: '1h' });  // Crear un token JWT
        res.json({ message: 'Autenticación satisfactoria', token });
    } catch (err) {
        res.status(500).json({ error: 'Error en la autenticación' });
    }
});

// Iniciar el servidor
app.listen(3000, () => {
    console.log('Servidor ejecutándose en http://localhost:3000');
});
