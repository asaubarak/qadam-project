import { sql } from "drizzle-orm";
import { pgTable, text, varchar, integer, boolean, real, timestamp, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// Notification types enum
export const notificationTypeSchema = z.enum([
  "TEST_COMPLETED",
  "TEST_REMINDER", 
  "SYSTEM_MESSAGE",
  "ACHIEVEMENT"
]);

export type NotificationType = z.infer<typeof notificationTypeSchema>;

export const notifications = pgTable("notifications", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  type: text("type").notNull(),
  title: text("title").notNull(),
  message: text("message").notNull(),
  metadata: jsonb("metadata"),
  isRead: boolean("is_read").default(false),
  createdAt: timestamp("created_at").defaultNow(),
  readAt: timestamp("read_at"),
  channels: text("channels").array().default([]),
});

export const notificationSettings = pgTable("notification_settings", {
  userId: varchar("user_id").primaryKey().references(() => users.id, { onDelete: "cascade" }),
  testCompletedEnabled: boolean("test_completed_enabled").default(true),
  testReminderEnabled: boolean("test_reminder_enabled").default(true),
  systemMessageEnabled: boolean("system_message_enabled").default(true),
  achievementEnabled: boolean("achievement_enabled").default(true),
  inAppEnabled: boolean("in_app_enabled").default(true),
  pushEnabled: boolean("push_enabled").default(false),
  emailEnabled: boolean("email_enabled").default(false),
  reminderIntervalMinutes: integer("reminder_interval_minutes").default(30),
  maxRemindersPerDay: integer("max_reminders_per_day").default(3),
  quietHoursStart: text("quiet_hours_start").default("22:00"),
  quietHoursEnd: text("quiet_hours_end").default("08:00"),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const reminders = pgTable("reminders", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  variantId: varchar("variant_id").notNull().references(() => variants.id, { onDelete: "cascade" }),
  dueAt: timestamp("due_at").notNull(),
  recurrence: text("recurrence"),
  lastSentAt: timestamp("last_sent_at"),
  isActive: boolean("is_active").default(true),
  createdAt: timestamp("created_at").defaultNow(),
});

export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  username: text("username").notNull().unique(),
  email: text("email").notNull().unique(),
  password: text("password").notNull(),
  createdAt: timestamp("created_at").defaultNow(),
});

export const blocks = pgTable("blocks", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull().unique(),
  hasCalculator: boolean("has_calculator").default(false),
  hasPeriodicTable: boolean("has_periodic_table").default(false),
  order: integer("order").default(0),
  // Column `requires_proctoring` removed as video proctoring has been deprecated
});

export const variants = pgTable("variants", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  blockId: varchar("block_id").notNull().references(() => blocks.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  isFree: boolean("is_free").default(false),
  order: integer("order").default(0),
});

export const subjects = pgTable("subjects", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  variantId: varchar("variant_id").notNull().references(() => variants.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  order: integer("order").default(0),
});

export const questions = pgTable("questions", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  subjectId: varchar("subject_id").notNull().references(() => subjects.id, { onDelete: "cascade" }),
  text: text("text").notNull(),
  imageUrl: text("image_url"), // URL изображения для вопроса
  solutionImageUrl: text("solution_image_url"), // URL изображения с решением (показывается после теста)
  order: integer("order").default(0),
});

export const answers = pgTable("answers", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  questionId: varchar("question_id").notNull().references(() => questions.id, { onDelete: "cascade" }),
  text: text("text").notNull(),
  isCorrect: boolean("is_correct").default(false),
  order: integer("order").default(0),
});

export const testResults = pgTable("test_results", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull().references(() => users.id),
  variantId: varchar("variant_id").notNull().references(() => variants.id),
  score: integer("score").notNull(),
  totalQuestions: integer("total_questions").notNull(),
  percentage: real("percentage").notNull(),
  timeSpent: integer("time_spent").notNull(),
  answers: jsonb("answers"),
  completedAt: timestamp("completed_at").defaultNow(),
});

export const subjectProgress = pgTable("subject_progress", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull().references(() => users.id),
  subjectName: text("subject_name").notNull(),
  totalAnswered: integer("total_answered").default(0),
  correctAnswered: integer("correct_answered").default(0),
  lastActivity: timestamp("last_activity").defaultNow(),
});

export const userRankings = pgTable("user_rankings", {
  userId: varchar("user_id").primaryKey().references(() => users.id),
  totalScore: integer("total_score").default(0),
  testsCompleted: integer("tests_completed").default(0),
  averagePercentage: real("average_percentage").default(0),
  lastUpdated: timestamp("last_updated").defaultNow(),
});

// System settings table
export const systemSettings = pgTable("system_settings", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  key: text("key").notNull().unique(),
  value: text("value").notNull(),
  updatedAt: timestamp("updated_at").defaultNow(),
  updatedBy: varchar("updated_by").references(() => users.id),
});

// Quotes table
export const quotes = pgTable("quotes", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  text: text("text").notNull(),
  author: text("author").notNull(),
  month: integer("month").notNull(), // 1-12 для месяцев
  order: integer("order").default(0),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Video proctoring schema removed

// Insert schemas
export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  email: true,
  password: true,
});

export const insertBlockSchema = createInsertSchema(blocks).omit({
  id: true,
});

export const insertVariantSchema = createInsertSchema(variants).omit({
  id: true,
});

export const insertSubjectSchema = createInsertSchema(subjects).omit({
  id: true,
});

export const insertQuestionSchema = createInsertSchema(questions).omit({
  id: true,
});

export const insertAnswerSchema = createInsertSchema(answers).omit({
  id: true,
});

export const updateAnswerSchema = insertAnswerSchema.partial();

export const insertTestResultSchema = createInsertSchema(testResults).omit({
  id: true,
  completedAt: true,
});

export const insertNotificationSchema = createInsertSchema(notifications).omit({
  id: true,
  createdAt: true,
  readAt: true,
});

export const insertNotificationSettingsSchema = createInsertSchema(notificationSettings).omit({
  updatedAt: true,
});

export const insertReminderSchema = createInsertSchema(reminders).omit({
  id: true,
  createdAt: true,
  lastSentAt: true,
});

export const insertQuoteSchema = createInsertSchema(quotes).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

// insertVideoRecordingSchema removed with video proctoring

// Analytics Zod DTO schemas
export const analyticsOverviewSchema = z.object({
  totalTests: z.number(),
  averageScore: z.number(),
  totalTimeSpent: z.number(),
  bestSubject: z.string(),
  worstSubject: z.string(),
  totalQuestions: z.number(),
  correctAnswers: z.number(),
  recentActivity: z.number(),
});

export const subjectAggregateSchema = z.object({
  subjectName: z.string(),
  testsCount: z.number(),
  averageScore: z.number(),
  totalQuestions: z.number(),
  correctAnswers: z.number(),
  averageTimeSpent: z.number(),
});

export const historyPointSchema = z.object({
  date: z.string(),
  testsCompleted: z.number(),
  averageScore: z.number(),
  totalTimeSpent: z.number(),
});

export const correctnessBreakdownSchema = z.object({
  date: z.string(),
  correctAnswers: z.number(),
  incorrectAnswers: z.number(),
  totalQuestions: z.number(),
});

export const comparisonStatsSchema = z.object({
  userRank: z.number(),
  totalUsers: z.number(),
  userScore: z.number(),
  averageScore: z.number(),
  percentile: z.number(),
  topUserScore: z.number(),
});

// Types
export type User = typeof users.$inferSelect;
export type InsertUser = z.infer<typeof insertUserSchema>;

export type Block = typeof blocks.$inferSelect;
export type InsertBlock = z.infer<typeof insertBlockSchema>;

export type Variant = typeof variants.$inferSelect;
export type InsertVariant = z.infer<typeof insertVariantSchema>;

export type Subject = typeof subjects.$inferSelect;
export type InsertSubject = z.infer<typeof insertSubjectSchema>;

export type Question = typeof questions.$inferSelect;
export type InsertQuestion = z.infer<typeof insertQuestionSchema>;

export type Answer = typeof answers.$inferSelect;
export type InsertAnswer = z.infer<typeof insertAnswerSchema>;

export type TestResult = typeof testResults.$inferSelect;
export type InsertTestResult = z.infer<typeof insertTestResultSchema>;

export type SubjectProgress = typeof subjectProgress.$inferSelect;
export type UserRanking = typeof userRankings.$inferSelect;

// VideoRecording types removed with proctoring schema

// Notification types
export type Notification = typeof notifications.$inferSelect;
export type InsertNotification = z.infer<typeof insertNotificationSchema>;

export type NotificationSettings = typeof notificationSettings.$inferSelect;
export type InsertNotificationSettings = z.infer<typeof insertNotificationSettingsSchema>;

export type Reminder = typeof reminders.$inferSelect;
export type InsertReminder = z.infer<typeof insertReminderSchema>;

export type Quote = typeof quotes.$inferSelect;
export type InsertQuote = z.infer<typeof insertQuoteSchema>;

// Analytics types
export type AnalyticsOverview = z.infer<typeof analyticsOverviewSchema>;
export type SubjectAggregate = z.infer<typeof subjectAggregateSchema>;
export type HistoryPoint = z.infer<typeof historyPointSchema>;
export type CorrectnessBreakdown = z.infer<typeof correctnessBreakdownSchema>;
export type ComparisonStats = z.infer<typeof comparisonStatsSchema>;

// Export types and schemas
export const exportTypeSchema = z.enum([
  "TEST_REPORT", 
  "USER_ANALYTICS", 
  "RANKINGS", 
  "PERIOD_SUMMARY"
]);

export const exportFormatSchema = z.enum([
  "PDF",
  "EXCEL"
]);

export const exportStatusSchema = z.enum([
  "PENDING",
  "IN_PROGRESS", 
  "COMPLETED",
  "FAILED"
]);

export type ExportType = z.infer<typeof exportTypeSchema>;
export type ExportFormat = z.infer<typeof exportFormatSchema>;
export type ExportStatus = z.infer<typeof exportStatusSchema>;

// Date range schema for exports
export const dateRangeSchema = z.object({
  from: z.string().optional(),
  to: z.string().optional(),
});

// Export options schema
export const exportOptionsSchema = z.object({
  dateRange: dateRangeSchema.optional(),
  subjects: z.array(z.string()).optional(),
  includeCharts: z.boolean().default(true),
  columns: z.array(z.string()).optional(),
  title: z.string().optional(),
  description: z.string().optional(),
});

// Export jobs table
export const exportJobs = pgTable("export_jobs", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  type: text("type").notNull(),
  format: text("format").notNull(),
  options: jsonb("options"),
  status: text("status").notNull().default("PENDING"),
  progress: integer("progress").default(0),
  fileKey: text("file_key"),
  fileSize: integer("file_size"),
  fileName: text("file_name"),
  errorMessage: text("error_message"),
  createdAt: timestamp("created_at").defaultNow(),
  completedAt: timestamp("completed_at"),
  expiresAt: timestamp("expires_at"),
});

export const insertExportJobSchema = createInsertSchema(exportJobs).omit({
  id: true,
  createdAt: true,
  completedAt: true,
});

export type ExportJob = typeof exportJobs.$inferSelect;
export type InsertExportJob = z.infer<typeof insertExportJobSchema>;
export type ExportOptions = z.infer<typeof exportOptionsSchema>;

// Payment system schemas
export const subscriptionStatusSchema = z.enum([
  "ACTIVE",
  "CANCELLED", 
  "EXPIRED",
  "PENDING"
]);

export const paymentStatusSchema = z.enum([
  "PENDING",
  "COMPLETED",
  "FAILED",
  "CANCELLED",
  "REFUNDED"
]);

export type SubscriptionStatus = z.infer<typeof subscriptionStatusSchema>;
export type PaymentStatus = z.infer<typeof paymentStatusSchema>;

// Subscription plans table
export const subscriptionPlans = pgTable("subscription_plans", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  name: text("name").notNull(),
  description: text("description"),
  price: integer("price").notNull(), // цена в копейках/центах
  currency: text("currency").notNull().default("RUB"),
  durationDays: integer("duration_days").notNull(), // продолжительность в днях
  features: jsonb("features").notNull().default('[]'), // список возможностей
  blockId: varchar("block_id").references(() => blocks.id), // для блок-специфичных планов
  planType: text("plan_type").notNull().default("single_test"), // "single_test" или "block_access"
  isActive: boolean("is_active").default(true),
  sortOrder: integer("sort_order").default(0),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// User subscriptions table  
export const userSubscriptions = pgTable("user_subscriptions", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  planId: varchar("plan_id").notNull().references(() => subscriptionPlans.id),
  blockId: varchar("block_id").references(() => blocks.id), // какой блок доступен
  status: text("status").notNull().default("PENDING"),
  startDate: timestamp("start_date"),
  endDate: timestamp("end_date"),
  autoRenew: boolean("auto_renew").default(false),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Payments table
export const payments = pgTable("payments", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: varchar("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  subscriptionId: varchar("subscription_id").references(() => userSubscriptions.id),
  planId: varchar("plan_id").notNull().references(() => subscriptionPlans.id),
  amount: integer("amount").notNull(), // сумма в копейках/центах
  currency: text("currency").notNull().default("RUB"),
  status: text("status").notNull().default("PENDING"),
  paymentMethod: text("payment_method"), // "card", "paypal", "yookassa" и т.д.
  externalPaymentId: text("external_payment_id"), // ID платежа в платежной системе
  paymentData: jsonb("payment_data"), // дополнительные данные от платежной системы
  createdAt: timestamp("created_at").defaultNow(),
  completedAt: timestamp("completed_at"),
});

// Insert schemas for payments
export const insertSubscriptionPlanSchema = createInsertSchema(subscriptionPlans).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertUserSubscriptionSchema = createInsertSchema(userSubscriptions).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertPaymentSchema = createInsertSchema(payments).omit({
  id: true,
  createdAt: true,
  completedAt: true,
});

export type SubscriptionPlan = typeof subscriptionPlans.$inferSelect;
export type UserSubscription = typeof userSubscriptions.$inferSelect;
export type Payment = typeof payments.$inferSelect;
export type InsertSubscriptionPlan = z.infer<typeof insertSubscriptionPlanSchema>;
export type InsertUserSubscription = z.infer<typeof insertUserSubscriptionSchema>;
export type InsertPayment = z.infer<typeof insertPaymentSchema>;
