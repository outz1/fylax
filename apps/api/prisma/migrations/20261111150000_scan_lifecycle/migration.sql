-- AlterTable
ALTER TABLE "Asset" ADD COLUMN     "dedupKey" TEXT;

-- AlterTable
ALTER TABLE "Scan" ADD COLUMN     "confirmedAt" TIMESTAMP(3),
ADD COLUMN     "error" TEXT;

-- CreateIndex
CREATE UNIQUE INDEX "Asset_scanId_dedupKey_key" ON "Asset"("scanId", "dedupKey");

