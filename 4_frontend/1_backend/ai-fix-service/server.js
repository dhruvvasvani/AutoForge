
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { GoogleGenAI } from "@google/genai";

dotenv.config();

const app = express();
const PORT = 5050;

app.use(cors());
app.use(express.json());

const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
});

app.get("/", (req, res) => {
  res.json({
    message: "AutoForge AI Fix Service is running",
  });
});

app.post("/api/fix", async (req, res) => {
  try {
    const { code, language, vulnerability } = req.body;

    if (!code || !vulnerability) {
      return res.status(400).json({
        error: "code and vulnerability are required",
      });
    }

    const prompt = `
You are a senior application security engineer.

Analyze the following vulnerable code and generate a secure fix.

Vulnerability:
${vulnerability}

Language:
${language || "unknown"}

Vulnerable code:
${code}

Return:

1. A short explanation of the vulnerability.

2. The fixed code.

3. A short explanation of why the fix is secure.

Do not change unrelated functionality.
`;

    const response = await ai.models.generateContent({
      model: "gemini-3.5-flash-lite",
      contents: prompt,
    });

    res.json({
      success: true,
      result: response.text,
    });
  } catch (error) {
    console.error("Gemini error:", error);

    res.status(500).json({
      success: false,
      error: "Failed to generate AI fix",
    });
  }
});

app.listen(PORT, () => {
  console.log(`AI Fix Service running on http://localhost:${PORT}`);
});