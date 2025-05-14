import { PrismaClient } from "@/generated/prisma";

// This file is responsible for creating and exporting a single instance of PrismaClient.
const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined;
};

// This is a work-around for the issue of multiple instances of Prisma Client
// in development mode. It ensures that only one instance is created and reused.
// In production, a new instance is created for each request.
// This is important for performance and to avoid connection issues.
export const prisma = globalForPrisma.prisma ?? new PrismaClient();

// Prevent multiple instances of Prisma Client in development
if (process.env.NODE_ENV !== "production") globalForPrisma.prisma = prisma;
