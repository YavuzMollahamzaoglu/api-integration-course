import express, { Application, Request, Response, NextFunction } from "express";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import cors from "cors";
import rateLimit from "express-rate-limit";
import Joi from "joi";  // Joi'yi ekliyoruz

dotenv.config();
const app: Application = express();
const prisma = new PrismaClient();

app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.JWT_SECRET || "supersecretkey";

const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 dakika
  max: 10, // Her dakika başına maksimum 10 istek
  message: "Too many requests from this IP, please try again after a minute",
  standardHeaders: true, // 'RateLimit-*' başlıklarını içerir
  legacyHeaders: false, // 'X-RateLimit-*' başlıklarını içermez
});

app.use(limiter);

// Joi doğrulama şemalarını tanımlıyoruz
const registerSchema = Joi.object({
  email: Joi.string().email().required().messages({
    "string.base": "Email bir metin olmalıdır",
    "string.email": "Geçerli bir email adresi giriniz",
    "any.required": "Email zorunludur",
  }),
  password: Joi.string().min(6).required().messages({
    "string.base": "Şifre bir metin olmalıdır",
    "string.min": "Şifre en az 6 karakter olmalıdır",
    "any.required": "Şifre zorunludur",
  }),
  name: Joi.string().optional(),
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
});

// Kullanıcı Kayıt (POST /api/register)
app.post("/api/register", async (req: Request, res: Response): Promise<any> => {
  try {
    // Joi doğrulaması
    const { error } = registerSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }

    const { email, password, name } = req.body;

    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ message: "Bu email zaten kayıtlı" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await prisma.user.create({
      data: { email, passwordHashed: hashedPassword, name },
    });

    res.status(201).json({ message: "Kullanıcı oluşturuldu", user: newUser });
  } catch (error) {
    res.status(500).json({ message: "Sunucu hatası", error });
  }
});

// Kullanıcı Girişi (POST /api/login)
app.post("/api/login", async (req: Request, res: Response): Promise<any> => {
  try {
    // Joi doğrulaması
    const { error } = loginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }

    const { email, password } = req.body;

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(400).json({ message: "Geçersiz email veya şifre" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.passwordHashed);
    if (!isPasswordValid) {
      return res.status(400).json({ message: "Geçersiz email veya şifre" });
    }

    const token = jwt.sign({ userId: user.id }, SECRET_KEY, {
      expiresIn: "1h",
    });

    res.json({ message: "Giriş başarılı", token });
  } catch (error) {
    res.status(500).json({ message: "Sunucu hatası", error });
  }
});

// Kimlik Doğrulama Middleware
const authenticate = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    res.status(401).json({ message: "Unauthorized" });
    return; // RETURN EKLEDİK
  }

  jwt.verify(token, SECRET_KEY, (err: any, user: any) => {
    if (err) {
      res.status(403).json({ message: "Forbidden" });
      return; // RETURN EKLEDİK
    }
    (req as any).userId = user.id;
    next();
  });
};

// Kullanıcı Bilgilerini Getirme (GET /api/user)
app.get(
  "/api/user",
  authenticate,
  async (req: Request, res: Response): Promise<void> => {
    try {
      const userId = (req as any).userId;

      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { id: true, email: true, name: true, createdAt: true },
      });

      if (!user) {
        res.status(404).json({ message: "Kullanıcı bulunamadı" });
        return;
      }

      res.json(user);
    } catch (error) {
      res.status(500).json({ message: "Sunucu hatası", error });
    }
  }
);

// Sunucuyu Başlat
app.listen(PORT, () => {
  console.log(`🚀 Sunucu ${PORT} portunda çalışıyor`);
});
