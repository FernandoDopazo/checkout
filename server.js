require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.use(express.json());
app.use(cors());


const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

// Middleware para proteger rotas
const authenticate = async (req, res, next) => {
    const token = req.header("Authorization")?.split(" ")[1];
    if (!token) return res.status(401).json({ message: "Acesso negado" });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(400).json({ message: "Token inválido" });
    }
};

 app.get('/', (req, res) => {
    res.send('Servidor está funcionando!');
});


// Rota para registrar usuário
app.post("/register", async (req, res) => {
    const { name, email, password } = req.body;

    const { data: existingUser, error: userError } = await supabase
        .from("users")
        .select("id")
        .eq("email", email)
        .single();

    if (existingUser) return res.status(400).json({ message: "E-mail já cadastrado" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const { data, error } = await supabase
        .from("users")
        .insert([{ name, email, password: hashedPassword }])
        .select()
        .single();

        if (!data) {
            return res.status(400).json({ error: "Nenhum dado encontrado" });
        }        

    res.json({ message: "Usuário cadastrado com sucesso!", user: data });
});

// Rota para login
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    const { data: user, error } = await supabase
        .from("users")
        .select("*")
        .eq("email", email)
        .single();

    if (!user) return res.status(400).json({ message: "Usuário não encontrado" });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ message: "Senha incorreta" });

    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "1h" });

    res.status(200).json({ message: "Login bem-sucedido", token, user: { id: user.id, name: user.name, email: user.email } });
});

// Rota para logout (no front-end, basta excluir o token)
app.post("/logout", (req, res) => {
    res.json({ message: "Logout realizado com sucesso" });
});

// Rota para buscar perfil do usuário logado
app.get("/me", authenticate, async (req, res) => {
    const { data: user, error } = await supabase
        .from("users")
        .select("id, name, email")
        .eq("id", req.user.id)
        .single();

    if (error) return res.status(400).json({ message: error.message });

    res.json({ user });
});

// Rota para excluir conta
app.delete("/delete", authenticate, async (req, res) => {
    const { error } = await supabase.from("users").delete().eq("id", req.user.id);

    if (error) return res.status(400).json({ message: error.message });

    res.json({ message: "Conta excluída com sucesso" });
});

// Inicia o servidor
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Servidor rodando em http://localhost:${PORT}`));
