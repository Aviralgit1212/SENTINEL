import "dotenv/config";
import Database from "better-sqlite3";
import { createCorsair } from "corsair";
import { slack } from "@corsair-dev/slack";

const db = new Database("corsair.db");

export const corsair = createCorsair({
  plugins: [slack()],
  database: db,
  kek: process.env.CORSAIR_KEK!,
});