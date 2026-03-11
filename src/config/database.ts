import dotenv from "dotenv";
import { Pool } from "pg";
import process from "node:process";

dotenv.config();

const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
	throw new Error("DATABASE_URL is not set in environment variables.");
}

export const pool = new Pool({
	connectionString,
});

export const query = (text: string, params?: unknown[]) => pool.query(text, params);
