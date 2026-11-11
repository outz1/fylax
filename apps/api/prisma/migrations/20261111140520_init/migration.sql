-- CreateEnum
CREATE TYPE "TargetKind" AS ENUM ('host', 'url', 'openapi', 'mcp');

-- CreateEnum
CREATE TYPE "TargetPlatform" AS ENUM ('htb', 'thm', 'local', 'bounty');

-- CreateEnum
CREATE TYPE "ScanProfile" AS ENUM ('passive', 'standard', 'deep', 'bounty');

-- CreateEnum
CREATE TYPE "ScanStatus" AS ENUM ('queued', 'running', 'done', 'failed', 'canceled');

-- CreateEnum
CREATE TYPE "TaskStatus" AS ENUM ('pending', 'running', 'done', 'failed', 'skipped');

-- CreateEnum
CREATE TYPE "Severity" AS ENUM ('info', 'low', 'medium', 'high', 'critical');

-- CreateEnum
CREATE TYPE "Confidence" AS ENUM ('low', 'medium', 'high');

-- CreateEnum
CREATE TYPE "AutomationPolicy" AS ENUM ('allowed', 'forbidden', 'unspecified');

-- CreateTable
CREATE TABLE "Program" (
    "id" TEXT NOT NULL,
    "platform" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "briefUrl" TEXT NOT NULL,
    "inScope" JSONB NOT NULL,
    "outOfScope" JSONB NOT NULL,
    "rules" JSONB NOT NULL,
    "reviewedAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Program_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Target" (
    "id" TEXT NOT NULL,
    "kind" "TargetKind" NOT NULL,
    "value" TEXT NOT NULL,
    "platform" "TargetPlatform" NOT NULL,
    "programId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Target_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Scan" (
    "id" TEXT NOT NULL,
    "targetId" TEXT NOT NULL,
    "profile" "ScanProfile" NOT NULL,
    "status" "ScanStatus" NOT NULL DEFAULT 'queued',
    "startedAt" TIMESTAMP(3),
    "finishedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Scan_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Task" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "module" TEXT NOT NULL,
    "status" "TaskStatus" NOT NULL DEFAULT 'pending',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "error" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Task_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Asset" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "data" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Asset_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Finding" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "checkId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "severity" "Severity" NOT NULL,
    "confidence" "Confidence" NOT NULL,
    "asset" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "evidence" JSONB NOT NULL,
    "reproduction" TEXT[],
    "references" TEXT[],
    "dedupKey" TEXT NOT NULL,
    "falsePositive" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Finding_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditLog" (
    "id" TEXT NOT NULL,
    "scanId" TEXT,
    "action" TEXT NOT NULL,
    "detail" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuditLog_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Program_name_key" ON "Program"("name");

-- CreateIndex
CREATE UNIQUE INDEX "Target_kind_value_platform_key" ON "Target"("kind", "value", "platform");

-- CreateIndex
CREATE UNIQUE INDEX "Finding_scanId_dedupKey_key" ON "Finding"("scanId", "dedupKey");

-- CreateIndex
CREATE INDEX "AuditLog_scanId_idx" ON "AuditLog"("scanId");

-- AddForeignKey
ALTER TABLE "Target" ADD CONSTRAINT "Target_programId_fkey" FOREIGN KEY ("programId") REFERENCES "Program"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Scan" ADD CONSTRAINT "Scan_targetId_fkey" FOREIGN KEY ("targetId") REFERENCES "Target"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Task" ADD CONSTRAINT "Task_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Asset" ADD CONSTRAINT "Asset_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Finding" ADD CONSTRAINT "Finding_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
