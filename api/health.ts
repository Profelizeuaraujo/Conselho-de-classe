import { Request, Response } from "express";

export default function handler(req: Request, res: Response) {
  res.status(200).json({
    status: "ok",
    hasDatabaseUrl: Boolean(process.env.DATABASE_URL),
    nodeEnv: process.env.NODE_ENV,
    time: new Date().toISOString()
  });
}
