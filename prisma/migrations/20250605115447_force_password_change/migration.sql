-- DropIndex
DROP INDEX "users_email_idx";

-- AlterTable
ALTER TABLE "users" ADD COLUMN     "force_password_change" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "password_changed_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
ADD COLUMN     "password_expires_at" TIMESTAMP(3);

-- CreateIndex
CREATE INDEX "users_email_password_expires_at_idx" ON "users"("email", "password_expires_at");
