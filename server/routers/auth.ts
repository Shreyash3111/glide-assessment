import { z } from "zod";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { TRPCError } from "@trpc/server";
import { publicProcedure, router } from "../trpc";
import { db } from "@/lib/db";
import { users, sessions } from "@/lib/db/schema";
import { eq } from "drizzle-orm";

const US_STATES = [
  "AL","AK","AZ","AR","CA","CO","CT","DE","FL","GA",
  "HI","ID","IL","IN","IA","KS","KY","LA","ME","MD",
  "MA","MI","MN","MS","MO","MT","NE","NV","NH","NJ",
  "NM","NY","NC","ND","OH","OK","OR","PA","RI","SC",
  "SD","TN","TX","UT","VT","VA","WA","WV","WI","WY",
];

export const authRouter = router({
  signup: publicProcedure
    .input(
      z.object({
        email: z.string().email(),
        password: z
          .string()
          .min(8, "Password must be at least 8 characters")
          .regex(/[A-Z]/, "Password must include an uppercase letter")
          .regex(/[a-z]/, "Password must include a lowercase letter")
          .regex(/[0-9]/, "Password must include a number")
          .regex(/[^A-Za-z0-9]/, "Password must include a special character"),
        firstName: z.string().min(1),
        lastName: z.string().min(1),
        phoneNumber: z
          .string()
          .regex(/^\+[1-9]\d{7,14}$/, "Phone number must be in international format (e.g., +14155552671)"),
        dateOfBirth: z.
            string().superRefine((dob, ctx) => {
              const birthDate = new Date(dob);
              const today = new Date();

              if (birthDate >= today) {
                ctx.addIssue({
                  code: z.ZodIssueCode.custom,
                  message: "Date of birth must be in the past",
                });
                return;
              }

              let age = today.getFullYear() - birthDate.getFullYear();
              const monthDiff = today.getMonth() - birthDate.getMonth();

              if (
                monthDiff < 0 ||
                (monthDiff === 0 && today.getDate() < birthDate.getDate())
              ) {
                age--;
              }

              if (age < 18) {
                ctx.addIssue({
                  code: z.ZodIssueCode.custom,
                  message: "You must be at least 18 years old",
                });
              }
            }),
        ssn: z.string().regex(/^\d{9}$/),
        address: z.string().min(1),
        city: z.string().min(1),
        state: z
          .string()
          .length(2, "State must be a 2-letter code")
          .transform((val) => val.toUpperCase())
          .refine((val) => US_STATES.includes(val), {
            message: "Invalid US state code",
          }),
        zipCode: z.string().regex(/^\d{5}$/),
      })
    )
    .mutation(async ({ input, ctx }) => {
      const normalizedEmail = input.email.trim().toLowerCase();
      const commonTypos = [".con", ".cmo", ".cim", ".cm"];

      if (commonTypos.some(t => normalizedEmail.endsWith(t))) {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message: "Email domain looks incorrect. Did you mean .com?",
        });
      }
      const existingUser = await db.select().from(users).where(eq(users.email, normalizedEmail)).get();

      if (existingUser) {
        throw new TRPCError({
          code: "CONFLICT",
          message: "User already exists",
        });
      }

      const hashedPassword = await bcrypt.hash(input.password, 10);
      const hashedSSN = await bcrypt.hash(input.ssn, 10);


      await db.insert(users).values({
        ...input,
        email: normalizedEmail,
        password: hashedPassword,
        ssn: hashedSSN,
      });

      // Fetch the created user
      const user = await db.select().from(users).where(eq(users.email, normalizedEmail)).get();

      if (!user) {
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: "Failed to create user",
        });
      }

      // Create session
      const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET || "temporary-secret-for-interview", {
        expiresIn: "7d",
      });

      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 7);

      await db.delete(sessions).where(eq(sessions.userId, user.id));

      await db.insert(sessions).values({
        userId: user.id,
        token,
        expiresAt: expiresAt.toISOString(),
      });

      // Set cookie
      if ("setHeader" in ctx.res) {
        ctx.res.setHeader("Set-Cookie", `session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800`);
      } else {
        (ctx.res as Headers).set("Set-Cookie", `session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800`);
      }

      return { user: { ...user, password: undefined }, token };
    }),

  login: publicProcedure
    .input(
      z.object({
        email: z.string().email(),
        password: z.string(),
      })
    )
    .mutation(async ({ input, ctx }) => {
      const normalizedEmail = input.email.trim().toLowerCase();
      const user = await db.select().from(users).where(eq(users.email, normalizedEmail)).get();

      if (!user) {
        throw new TRPCError({
          code: "UNAUTHORIZED",
          message: "Invalid credentials",
        });
      }

      const validPassword = await bcrypt.compare(input.password, user.password);

      if (!validPassword) {
        throw new TRPCError({
          code: "UNAUTHORIZED",
          message: "Invalid credentials",
        });
      }

      const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET || "temporary-secret-for-interview", {
        expiresIn: "7d",
      });

      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 7);

      await db.delete(sessions).where(eq(sessions.userId, user.id));

      await db.insert(sessions).values({
        userId: user.id,
        token,
        expiresAt: expiresAt.toISOString(),
      });

      if ("setHeader" in ctx.res) {
        ctx.res.setHeader("Set-Cookie", `session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800`);
      } else {
        (ctx.res as Headers).set("Set-Cookie", `session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800`);
      }

      return { user: { ...user, password: undefined }, token };
    }),

  logout: publicProcedure.mutation(async ({ ctx }) => {
    if (ctx.user) {
      // Delete session from database
      let token: string | undefined;
      if ("cookies" in ctx.req) {
        token = (ctx.req as any).cookies.session;
      } else {
        const cookieHeader = ctx.req.headers.get?.("cookie") || (ctx.req.headers as any).cookie;
        token = cookieHeader
          ?.split("; ")
          .find((c: string) => c.startsWith("session="))
          ?.split("=")[1];
      }
      if (ctx.user) {
        await db.delete(sessions).where(eq(sessions.userId, ctx.user.id));
      }

    }

    if ("setHeader" in ctx.res) {
      ctx.res.setHeader("Set-Cookie", `session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`);
    } else {
      (ctx.res as Headers).set("Set-Cookie", `session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`);
    }

    return { success: true, message: ctx.user ? "Logged out successfully" : "No active session" };
  }),
});
