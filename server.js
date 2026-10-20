
const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
    throw new Error("Thieu bien moi truong JWT_SECRET");
}

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

let db;

function authenticateToken(req, res, next) {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({ message: "Vui long dang nhap." });
    }

    jwt.verify(token, JWT_SECRET, async (err, decoded) => {
        if (err) {
            return res.status(403).json({ message: "Token khong hop le hoac da het han." });
        }

        try {
            const [users] = await db.execute(
                "SELECT id, username, role, can_control_light FROM users WHERE id = ?",
                [decoded.id]
            );

            if (users.length === 0) {
                return res.status(401).json({ message: "Tai khoan khong ton tai." });
            }

            req.user = users[0];
            next();
        } catch (error) {
            console.error(error);
            res.status(500).json({ message: "Loi xac thuc tai khoan." });
        }
    });
}

function requireOwner(req, res, next) {
    if (req.user.role !== "owner") {
        return res.status(403).json({ message: "Chi owner moi co quyen nay." });
    }
    next();
}

function requireLightPermission(req, res, next) {
    if (req.user.role !== "owner" && !req.user.can_control_light) {
        return res.status(403).json({
            message: "Ban chua duoc cap quyen dieu khien den."
        });
    }
    next();
}

// Dang ky tai khoan
app.post("/api/register", async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                message: "Vui long nhap ten tai khoan va mat khau."
            });
        }

        if (username.length > 50 || password.length < 4) {
            return res.status(400).json({
                message: "Ten tai khoan toi da 50 ky tu, mat khau toi thieu 4 ky tu."
            });
        }

        const [existing] = await db.execute(
            "SELECT id FROM users WHERE username = ?",
            [username]
        );

        if (existing.length > 0) {
            return res.status(409).json({ message: "Ten tai khoan da ton tai." });
        }

        const [owners] = await db.execute(
            "SELECT id FROM users WHERE role = 'owner' LIMIT 1"
        );

        const role = owners.length === 0 ? "owner" : "guest";
        const passwordHash = await bcrypt.hash(password, 10);

        await db.execute(
            `INSERT INTO users (username, password_hash, role, can_control_light)
             VALUES (?, ?, ?, ?)`,
            [username, passwordHash, role, role === "owner" ? 1 : 0]
        );

        res.status(201).json({
            message: "Dang ky thanh cong.",
            role
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Loi dang ky tai khoan." });
    }
});

// Dang nhap
app.post("/api/login", async (req, res) => {
    try {
        const { username, password } = req.body;

        const [users] = await db.execute(
            "SELECT id, username, password_hash, role, can_control_light FROM users WHERE username = ?",
            [username]
        );

        if (users.length === 0) {
            return res.status(401).json({ message: "Sai tai khoan hoac mat khau." });
        }

        const user = users[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);

        if (!validPassword) {
            return res.status(401).json({ message: "Sai tai khoan hoac mat khau." });
        }

        const token = jwt.sign(
            { id: user.id, username: user.username },
            JWT_SECRET,
            { expiresIn: "2h" }
        );

        await db.execute(
            `INSERT INTO activity_logs (username, title, detail, result, icon)
             VALUES (?, ?, ?, ?, ?)`,
            [user.username, "Đăng nhập thành công", "Đăng nhập vào hệ thống", "Thành công", "🔐"]
        );

        res.json({
            message: "Dang nhap thanh cong.",
            token,
            user: {
                id: user.id,
                username: user.username,
                role: user.role,
                can_control_light: !!user.can_control_light
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Loi dang nhap." });
    }
});

// Thong tin tai khoan hien tai
app.get("/api/me", authenticateToken, (req, res) => {
    res.json({
        id: req.user.id,
        username: req.user.username,
        role: req.user.role,
        can_control_light: !!req.user.can_control_light
    });
});

// Lay trang thai den
app.get("/api/light", authenticateToken, async (req, res) => {
    try {
        const [rows] = await db.execute(
            "SELECT value FROM device_state WHERE device_key = 'light'"
        );

        if (rows.length === 0) {
            return res.status(404).json({ message: "Chua co trang thai den trong database." });
        }

        res.json({ on: rows[0].value === 1 });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Loi lay trang thai den." });
    }
});

// Bat den
app.post("/api/light/on", authenticateToken, requireLightPermission, async (req, res) => {
    try {
        await db.execute(
            "UPDATE device_state SET value = 1 WHERE device_key = 'light'"
        );

        await db.execute(
            `INSERT INTO activity_logs (username, title, detail, result, icon)
             VALUES (?, ?, ?, ?, ?)`,
            [req.user.username, "Bật đèn", "Đèn đã được bật", "Thành công", "💡"]
        );

        res.json({ message: "Da bat den.", on: true });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Loi bat den." });
    }
});

// Tat den
app.post("/api/light/off", authenticateToken, requireLightPermission, async (req, res) => {
    try {
        await db.execute(
            "UPDATE device_state SET value = 0 WHERE device_key = 'light'"
        );

        await db.execute(
            `INSERT INTO activity_logs (username, title, detail, result, icon)
             VALUES (?, ?, ?, ?, ?)`,
            [req.user.username, "Tắt đèn", "Đèn đã được tắt", "Thành công", "💡"]
        );

        res.json({ message: "Da tat den.", on: false });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Loi tat den." });
    }
});

// Danh sach tai khoan guest - chi owner
app.get("/api/users", authenticateToken, requireOwner, async (req, res) => {
    try {
        const [users] = await db.execute(
            `SELECT username, role, can_control_light
             FROM users WHERE role = 'guest' ORDER BY username`
        );

        res.json({ users });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Loi lay danh sach tai khoan." });
    }
});

// Cap hoac thu hoi quyen dieu khien den
app.post("/api/users/:username/permission", authenticateToken, requireOwner, async (req, res) => {
    try {
        const { allow } = req.body;
        const username = req.params.username;

        const [result] = await db.execute(
            "UPDATE users SET can_control_light = ? WHERE username = ? AND role = 'guest'",
            [allow ? 1 : 0, username]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: "Khong tim thay tai khoan guest." });
        }

        await db.execute(
            `INSERT INTO activity_logs (username, title, detail, result, icon)
             VALUES (?, ?, ?, ?, ?)`,
            [
                req.user.username,
                allow ? "Cấp quyền điều khiển" : "Thu hồi quyền điều khiển",
                username,
                "Thành công",
                "🔑"
            ]
        );

        res.json({
            message: allow ? "Da cap quyen dieu khien den." : "Da thu hoi quyen dieu khien den."
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Loi thay doi quyen." });
    }
});

// Lay lich su chung
app.get("/api/history", authenticateToken, async (req, res) => {
    try {
        const [events] = await db.execute(
            `SELECT id, username, title, detail, result, icon, created_at
             FROM activity_logs ORDER BY id DESC LIMIT 100`
        );

        res.json({ events });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Loi lay lich su." });
    }
});

// Ghi lich su tu giao dien
app.post("/api/history", authenticateToken, async (req, res) => {
    try {
        const { title, detail, result, icon } = req.body;

        if (!title) {
            return res.status(400).json({ message: "Thieu ten hoat dong." });
        }

        await db.execute(
            `INSERT INTO activity_logs (username, title, detail, result, icon)
             VALUES (?, ?, ?, ?, ?)`,
            [
                req.user.username,
                String(title).slice(0, 100),
                String(detail || "").slice(0, 500),
                String(result || "Thành công").slice(0, 30),
                String(icon || "🔹").slice(0, 10)
            ]
        );

        res.status(201).json({ message: "Da luu lich su." });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Loi luu lich su." });
    }
});

// Kiem tra JWT
app.get("/api/security-test", (req, res) => {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({ message: "Khong co token." });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ message: "Token khong hop le." });
        }

        res.json({
            message: "Token hop le.",
            username: decoded.username
        });
    });
});

async function startServer() {
    try {
        db = await mysql.createConnection({
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT || 3306),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

        await db.query("SELECT 1");

        await db.execute(`
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) NOT NULL,
                title VARCHAR(100) NOT NULL,
                detail VARCHAR(500),
                result VARCHAR(30) NOT NULL,
                icon VARCHAR(20),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        console.log("Da ket noi MySQL.");
        app.listen(PORT, "0.0.0.0", () => {
            console.log("Server dang chay tai http://localhost:" + PORT);
        });
        } catch (error) {
        console.error("Khong khoi dong duoc server:", error);
        process.exit(1);
    }
}
startServer();
