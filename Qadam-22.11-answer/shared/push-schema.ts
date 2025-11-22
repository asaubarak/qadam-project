import { sql } from "drizzle-orm";
import { z } from 'zod';
import { pgTable, varchar, text, jsonb, timestamp, boolean } from 'drizzle-orm/pg-core';
import { createInsertSchema } from 'drizzle-zod';
import { users } from './schema';

// Push subscription schema for validation
export const pushSubscriptionSchema = z.object({
  endpoint: z.string().url(),
  keys: z.object({
    p256dh: z.string(),
    auth: z.string()
  })
});

// Push subscriptions table
export const pushSubscriptions = pgTable("push_subscriptions", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  endpoint: text("endpoint").notNull().unique(),
  p256dh: text("p256dh").notNull(),
  auth: text("auth").notNull(),
  userAgent: text("user_agent"),
  isActive: boolean("is_active").default(true),
  createdAt: timestamp("created_at").defaultNow(),
  lastUsed: timestamp("last_used").defaultNow(),
});

// Create schemas
export const insertPushSubscriptionSchema = createInsertSchema(pushSubscriptions).omit({
  id: true,
  createdAt: true,
  lastUsed: true
});

// Types
export type PushSubscription = typeof pushSubscriptions.$inferSelect;
export type InsertPushSubscription = z.infer<typeof insertPushSubscriptionSchema>;
export type PushSubscriptionData = z.infer<typeof pushSubscriptionSchema>;

// Notification template schemas
export const notificationTemplateSchema = z.object({
  title: z.string().min(1).max(100),
  body: z.string().min(1).max(300),
  icon: z.string().url().optional(),
  badge: z.string().url().optional(),
  tag: z.string().optional(),
  url: z.string().optional(),
  data: z.record(z.any()).optional()
});

export type NotificationTemplate = z.infer<typeof notificationTemplateSchema>;