
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.SESSION_SECRET || !process.env.PASSWORD_HASH) {
    throw new Error("Faltan SESSION_SECRET o PASSWORD_HASH en .env");
}

app.use(helmet());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(session({
    name: "optilens.sid",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 30 * 60 * 1000
    }
}));

app.use(express.static(path.join(__dirname, "public"), {
    index: false
}));

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});

// TEMPORAL: 100 intentos cada 15 minutos
const limitarLogin = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: "Demasiados intentos. Inténtalo de nuevo más tarde."
});

function requiereSesion(req, res, next) {
    if (req.session && req.session.autenticado === true) {
        return next();
    }

    return res.redirect("/");
}

app.post("/login", limitarLogin, async (req, res, next) => {
    try {
        const password = req.body.password;

        if (typeof password !== "string" || password.length > 200) {
            return res.status(400).send("Solicitud inválida.");
        }

        const correcta = await bcrypt.compare(
            password,
            process.env.PASSWORD_HASH
        );

        if (!correcta) {
            return res.status(401).send(
                "Contraseña incorrecta. <a href='/'>Volver</a>"
            );
        }

        req.session.regenerate((error) => {
            if (error) return next(error);

            req.session.autenticado = true;

            req.session.save((error) => {
                if (error) return next(error);
                res.redirect("/app");
            });
        });
    } catch (error) {
        next(error);
    }
});

app.get("/app", requiereSesion, (req, res) => {
    res.set("Cache-Control", "no-store");
    res.sendFile(path.join(__dirname, "private", "index.html"));
});

app.use(
    "/app-assets",
    requiereSesion,
    express.static(path.join(__dirname, "private"), {
        index: false
    })
);

app.post("/logout", requiereSesion, (req, res, next) => {
    req.session.destroy((error) => {
        if (error) return next(error);

        res.clearCookie("optilens.sid", {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict"
        });

        res.redirect("/");
    });
});

app.listen(PORT, () => {
    console.log(`OptiLens Pro disponible en http://localhost:${PORT}`);
});
