import express from "express";
import { query } from "./db.js";
import "dotenv/config";

const app = express();
app.use(express.json());

app.get("/", (req, res) => {
  res.send("API is running");
});

app.get("/health/db", async (req, res) => {
  const result = await query("SELECT NOW() as now");
  res.json(result.rows[0]);
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server listening on ${port}`);
});