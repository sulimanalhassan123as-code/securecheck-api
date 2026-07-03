import { prisma } from '../config/db';

// Checks if a user (by email) is banned from running scans. Used by both the
// quick scan and deep scan endpoints so a ban applies everywhere at once.
export async function checkUserBanned(userEmail?: string | null): Promise<{ banned: boolean; reason?: string | null }> {
  if (!userEmail) return { banned: false };
  const user = await prisma.user.findUnique({ where: { email: userEmail } });
  if (user?.isBanned) {
    return { banned: true, reason: user.banReason };
  }
  return { banned: false };
}
