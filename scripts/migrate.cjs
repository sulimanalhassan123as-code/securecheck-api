/**
 * Auto-migration: creates SecurecheckPayment and SecurecheckQuota tables
 * if they don't exist. Runs on server startup before the app starts.
 */
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function runMigrations() {
  try {
    // Create SecurecheckPayment table
    await prisma.$executeRawUnsafe(`
      CREATE TABLE IF NOT EXISTS "SecurecheckPayment" (
        "id" TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        "deviceId" TEXT NOT NULL,
        "reference" TEXT NOT NULL,
        "amount" DOUBLE PRECISION DEFAULT 10,
        "momoNumber" TEXT DEFAULT '0599931348',
        "momoTransactionId" TEXT DEFAULT '',
        "phoneUsed" TEXT DEFAULT '',
        "status" TEXT DEFAULT 'pending_review',
        "unlockedAt" TIMESTAMP(3),
        "unlockedUntil" TIMESTAMP(3),
        "createdAt" TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
        "updatedAt" TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await prisma.$executeRawUnsafe(`
      CREATE INDEX IF NOT EXISTS "SecurecheckPayment_deviceId_idx" ON "SecurecheckPayment"("deviceId");
      CREATE INDEX IF NOT EXISTS "SecurecheckPayment_reference_idx" ON "SecurecheckPayment"("reference");
      CREATE INDEX IF NOT EXISTS "SecurecheckPayment_status_idx" ON "SecurecheckPayment"("status");
    `);

    // Create SecurecheckQuota table
    await prisma.$executeRawUnsafe(`
      CREATE TABLE IF NOT EXISTS "SecurecheckQuota" (
        "id" TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
        "deviceId" TEXT NOT NULL,
        "date" TEXT NOT NULL,
        "usedToday" INTEGER DEFAULT 0,
        "freeLimit" INTEGER DEFAULT 1,
        "createdAt" TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
        "updatedAt" TIMESTAMP(3) DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT "SecurecheckQuota_deviceId_date_key" UNIQUE ("deviceId", "date")
      );
    `);

    await prisma.$executeRawUnsafe(`
      CREATE INDEX IF NOT EXISTS "SecurecheckQuota_deviceId_idx" ON "SecurecheckQuota"("deviceId");
    `);

    console.log('✅ SecureCheck payment & quota tables ready');
  } catch (err) {
    console.error('⚠️ Migration warning:', err.message);
  } finally {
    await prisma.$disconnect();
  }
}

runMigrations();
