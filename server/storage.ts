import { type User, type InsertUser, type Block, type InsertBlock, type Variant, type InsertVariant, 
         type Subject, type InsertSubject, type Question, type InsertQuestion, type Answer, type InsertAnswer,
         type TestResult, type InsertTestResult, type SubjectProgress, type UserRanking,
         type Notification, type InsertNotification, type NotificationSettings, type InsertNotificationSettings,
         type Reminder, type InsertReminder, type NotificationType,
         type AnalyticsOverview, type SubjectAggregate, type HistoryPoint, type CorrectnessBreakdown, type ComparisonStats,
         type ExportJob, type InsertExportJob, type ExportType,
         type Quote, type InsertQuote,
         type SubscriptionPlan, type InsertSubscriptionPlan, type UserSubscription, type InsertUserSubscription,
         type Payment, type InsertPayment,
         users, blocks, variants, subjects, questions, answers, testResults,
         subjectProgress as subjectProgressTable, notifications, notificationSettings,
         reminders, exportJobs, systemSettings, quotes, subscriptionPlans, userSubscriptions, payments } from "@shared/schema";
import { randomUUID } from "crypto";
import session from "express-session";
import createMemoryStore from "memorystore";
import { db } from "./db";
import { eq, and, desc, sql, count, asc } from "drizzle-orm";

const MemoryStore = createMemoryStore(session);

export interface IStorage {
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  getUserByEmail(email: string): Promise<User | undefined>;
  getUserById(id: string): Promise<User | undefined>;
  getAllUsers(): Promise<User[]>;
  createUser(user: InsertUser): Promise<User>;
  deleteUser(id: string): Promise<void>;
  resetUserPassword(id: string): Promise<string>;
  
  // Blocks
  getAllBlocks(): Promise<Block[]>;
  getPublicBlocks(): Promise<(Block & { variantCount: number; totalQuestions: number })[]>;
  getBlock(id: string): Promise<Block | undefined>;
  createBlock(block: InsertBlock): Promise<Block>;
  updateBlock(id: string, block: Partial<InsertBlock>): Promise<Block | undefined>;
  deleteBlock(id: string): Promise<void>;
  reorderBlocks(ids: string[]): Promise<void>;
  
  // Variants
  getVariantsByBlock(blockId: string): Promise<Variant[]>;
  getVariant(id: string): Promise<Variant | undefined>;
  createVariant(variant: InsertVariant): Promise<Variant>;
  updateVariant(id: string, variant: Partial<InsertVariant>): Promise<Variant | undefined>;
  deleteVariant(id: string): Promise<void>;
  reorderVariants(blockId: string, ids: string[]): Promise<void>;
  
  // Subjects
  getSubjectsByVariant(variantId: string): Promise<Subject[]>;
  getSubject(id: string): Promise<Subject | undefined>;
  createSubject(subject: InsertSubject): Promise<Subject>;
  updateSubject(id: string, subject: Partial<InsertSubject>): Promise<Subject | undefined>;
  deleteSubject(id: string): Promise<void>;
  reorderSubjects(variantId: string, ids: string[]): Promise<void>;
  copySubjects(sourceVariantId: string, targetVariantId: string, subjectIds: string[]): Promise<Subject[]>;
  
  // Questions
  getQuestionsBySubject(subjectId: string): Promise<Question[]>;
  getQuestion(id: string): Promise<Question | undefined>;
  createQuestion(question: InsertQuestion): Promise<Question>;
  updateQuestion(id: string, question: Partial<InsertQuestion>): Promise<Question | undefined>;
  deleteQuestion(id: string): Promise<void>;
  reorderQuestions(subjectId: string, ids: string[]): Promise<void>;
  
  // Answers
  getAnswersByQuestion(questionId: string): Promise<Answer[]>;
  getAnswer(id: string): Promise<Answer | undefined>;
  createAnswer(answer: InsertAnswer): Promise<Answer>;
  updateAnswer(id: string, answer: Partial<InsertAnswer>): Promise<Answer | undefined>;
  deleteAnswer(id: string): Promise<void>;
  reorderAnswers(questionId: string, ids: string[]): Promise<void>;
  
  // Test Results
  createTestResult(result: InsertTestResult): Promise<TestResult>;
  getTestResult(id: string): Promise<TestResult | undefined>;
  getTestResultsByUser(userId: string): Promise<TestResult[]>;
  getUserRanking(userId: string): Promise<UserRanking | undefined>;
  updateUserRanking(userId: string): Promise<void>;
  getAllRankings(): Promise<UserRanking[]>;
  getTodayBestResult(): Promise<{ score: number } | undefined>;
  
  // Subject Progress
  getSubjectProgress(userId: string): Promise<SubjectProgress[]>;
  updateSubjectProgress(userId: string, subjectName: string, totalAnswered: number, correctAnswered: number): Promise<void>;
  
  // Analytics
  getAnalyticsOverview(userId: string): Promise<AnalyticsOverview>;
  getSubjectAggregates(userId: string): Promise<SubjectAggregate[]>;
  getHistory(userId: string, rangeDays?: number): Promise<HistoryPoint[]>;
  getCorrectnessBreakdown(userId: string, rangeDays?: number): Promise<CorrectnessBreakdown[]>;
  getComparison(userId: string): Promise<ComparisonStats>;
  
  // Notifications
  createNotification(notification: InsertNotification): Promise<Notification>;
  getNotifications(userId: string, page?: number, limit?: number, type?: NotificationType): Promise<{ notifications: Notification[], total: number }>;
  getUnreadNotificationCount(userId: string): Promise<number>;
  countNotificationsByTypeSince(userId: string, type: NotificationType, since: Date): Promise<number>;
  markNotificationAsRead(id: string, userId: string): Promise<void>;
  markAllNotificationsAsRead(userId: string): Promise<void>;
  deleteNotification(id: string, userId: string): Promise<void>;
  
  // Notification Settings
  getNotificationSettings(userId: string): Promise<NotificationSettings | undefined>;
  upsertNotificationSettings(settings: InsertNotificationSettings): Promise<NotificationSettings>;
  
  // Reminders
  getReminders(userId: string): Promise<Reminder[]>;
  createReminder(reminder: InsertReminder): Promise<Reminder>;
  updateReminder(id: string, reminder: Partial<InsertReminder>): Promise<Reminder | undefined>;
  deleteReminder(id: string, userId: string): Promise<void>;
  getDueReminders(): Promise<Reminder[]>;
  markReminderAsSent(id: string): Promise<void>;
  
  // Export Jobs
  createExportJob(exportJob: InsertExportJob): Promise<ExportJob>;
  getExportJob(id: string): Promise<ExportJob | undefined>;
  listExportJobsByUser(userId: string, limit?: number): Promise<ExportJob[]>;
  updateExportJob(id: string, update: Partial<ExportJob>): Promise<ExportJob | undefined>;
  deleteExportJob(id: string, userId: string): Promise<void>;
  getPendingExportJobs(): Promise<ExportJob[]>;
  
  // File Cache
  storeFile(key: string, buffer: Buffer, ttl?: number): Promise<void>;
  getFile(key: string): Promise<Buffer | undefined>;
  deleteFile(key: string): Promise<void>;
  clearExpiredFiles(): Promise<void>;
  
  // Rate Limiting
  checkExportRateLimit(userId: string): Promise<{ allowed: boolean; reason?: string }>;
  incrementExportCount(userId: string): Promise<void>;
  
  // Video Recordings
  // Video recording methods removed
  
  // System Settings
  getSystemSetting(key: string): Promise<{ key: string; value: string } | undefined>;
  updateSystemSetting(key: string, value: string, updatedBy: string): Promise<{ key: string; value: string }>;
  
  // Quotes
  getAllQuotes(): Promise<Quote[]>;
  getQuotesByMonth(month: number): Promise<Quote[]>;
  getCurrentQuote(): Promise<Quote | null>;
  createQuote(quote: InsertQuote): Promise<Quote>;
  updateQuote(id: string, quote: Partial<InsertQuote>): Promise<Quote | undefined>;
  deleteQuote(id: string): Promise<void>;
  reorderQuotes(month: number, ids: string[]): Promise<void>;
  
  // Payment System
  getSubscriptionPlans(): Promise<SubscriptionPlan[]>;
  getSubscriptionPlan(id: string): Promise<SubscriptionPlan | undefined>;
  createSubscriptionPlan(plan: InsertSubscriptionPlan): Promise<SubscriptionPlan>;
  updateSubscriptionPlan(id: string, plan: Partial<InsertSubscriptionPlan>): Promise<SubscriptionPlan | undefined>;
  getCurrentUserSubscription(userId: string): Promise<UserSubscription | undefined>;
  createOrUpdateUserSubscription(subscription: InsertUserSubscription): Promise<UserSubscription>;
  createPayment(payment: InsertPayment): Promise<Payment>;
  getPayment(id: string): Promise<Payment | undefined>;
  updatePaymentStatus(id: string, status: string): Promise<void>;
  getAllPayments(): Promise<Payment[]>;
  getAllUserSubscriptions(): Promise<UserSubscription[]>;
  hasBlockAccess(userId: string, blockId: string): Promise<boolean>;
  hasSingleTestAccess(userId: string): Promise<boolean>;
  
  sessionStore: session.Store;
}

// DatabaseStorage implementation using PostgreSQL - javascript_database integration
// CRITICAL #1: Durability fix - VideoRecording moved from MemStorage to PostgreSQL
export class DatabaseStorage implements IStorage {
  private fileCache: Map<string, { buffer: Buffer; expiresAt: number }>;
  private exportRateLimit: Map<string, { count: number; lastReset: number; concurrent: number }>;
  private notificationSettings: Map<string, NotificationSettings>;
  private reminders: Map<string, Reminder>;
  private exportJobs: Map<string, ExportJob>;
  
  sessionStore: session.Store;

  constructor() {
    // Keep some in-memory caches for non-persistent data
    this.fileCache = new Map();
    this.exportRateLimit = new Map();
    this.notificationSettings = new Map();
    this.reminders = new Map();
    this.exportJobs = new Map();
    
    const MemoryStore = createMemoryStore(session);
    this.sessionStore = new MemoryStore({
      checkPeriod: 86400000,
    });
  }

  // Video Recordings implementation - CRITICAL #1: Durability fix
  // Video recording methods removed

  // Users implementation
  async getUser(id: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user || undefined;
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.username, username));
    return user || undefined;
  }

  async getUserByEmail(email: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.email, email));
    return user || undefined;
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const [user] = await db
      .insert(users)
      .values(insertUser)
      .returning();
    return user;
  }

  async getUserById(id: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user || undefined;
  }

  async getAllUsers(): Promise<User[]> {
    console.log('[Storage] Getting all users from database...');
    const allUsers = await db.select().from(users).orderBy(asc(users.createdAt));
    console.log('[Storage] Found users:', allUsers.length);
    console.log('[Storage] Users data:', allUsers.map(u => ({ id: u.id, username: u.username, email: u.email })));
    return allUsers;
  }

  async deleteUser(id: string): Promise<void> {
    await db.delete(users).where(eq(users.id, id));
  }

  async resetUserPassword(id: string): Promise<string> {
    // Generate new random password
    const newPassword = Math.random().toString(36).slice(-8);
    
    // Import hash function from crypto
    const crypto = await import("crypto");
    const salt = crypto.randomBytes(16).toString("hex");
    const hashedPassword = crypto.scryptSync(newPassword, salt, 64).toString("hex") + ":" + salt;
    
    // Update user password
    await db.update(users)
      .set({ password: hashedPassword })
      .where(eq(users.id, id));
    
    return newPassword;
  }

  private async initializeSampleData() {
    // Create sample blocks
    const physicsBlock = await this.createBlock({
      name: "Физика-Математика",
      hasCalculator: true,
      hasPeriodicTable: true,
    });
    
    const chemistryBlock = await this.createBlock({
      name: "Химия-Биология",
      hasCalculator: false,
      hasPeriodicTable: true,
    });
    
    // Create sample variants
    for (let i = 1; i <= 8; i++) {
      const variant = await this.createVariant({
        blockId: physicsBlock.id,
        name: `Вариант ${i}`,
      });
      
      // Create subjects for each variant
      const physicsSubject = await this.createSubject({
        variantId: variant.id,
        name: "Физика",
      });
      
      const mathSubject = await this.createSubject({
        variantId: variant.id,
        name: "Математика",
      });
      
      // Create sample questions
      for (let j = 1; j <= 10; j++) {
        const question = await this.createQuestion({
          subjectId: physicsSubject.id,
          text: `Физика вопрос ${j} для варианта ${i}`,
        });
        
        // Create answers for each question
        for (let k = 1; k <= 4; k++) {
          await this.createAnswer({
            questionId: question.id,
            text: `Ответ ${k}`,
            isCorrect: k === 1, // First answer is correct
          });
        }
      }
      
      for (let j = 1; j <= 10; j++) {
        const question = await this.createQuestion({
          subjectId: mathSubject.id,
          text: `Математика вопрос ${j} для варианта ${i}`,
        });
        
        // Create answers for each question
        for (let k = 1; k <= 4; k++) {
          await this.createAnswer({
            questionId: question.id,
            text: `Ответ ${k}`,
            isCorrect: k === 1, // First answer is correct
          });
        }
      }
    }
    
    // Create variants for chemistry block
    for (let i = 1; i <= 6; i++) {
      const variant = await this.createVariant({
        blockId: chemistryBlock.id,
        name: `Вариант ${i}`,
      });
      
      const chemistrySubject = await this.createSubject({
        variantId: variant.id,
        name: "Химия",
      });
      
      const biologySubject = await this.createSubject({
        variantId: variant.id,
        name: "Биология",
      });
      
      // Create sample questions for chemistry and biology
      for (let j = 1; j <= 10; j++) {
        const chemQuestion = await this.createQuestion({
          subjectId: chemistrySubject.id,
          text: `Химия вопрос ${j} для варианта ${i}`,
        });
        
        const bioQuestion = await this.createQuestion({
          subjectId: biologySubject.id,
          text: `Биология вопрос ${j} для варианта ${i}`,
        });
        
        // Create answers
        for (let k = 1; k <= 4; k++) {
          await this.createAnswer({
            questionId: chemQuestion.id,
            text: `Ответ ${k}`,
            isCorrect: k === 1,
          });
          
          await this.createAnswer({
            questionId: bioQuestion.id,
            text: `Ответ ${k}`,
            isCorrect: k === 1,
          });
        }
      }
    }
  }

  async getAllBlocks(): Promise<Block[]> {
    return await db.select().from(blocks).orderBy(asc(blocks.order));
  }

  async getPublicBlocks(): Promise<(Block & { variantCount: number; totalQuestions: number })[]> {
    const result = await db
      .select({
        id: blocks.id,
        name: blocks.name,
        order: blocks.order,
        hasCalculator: blocks.hasCalculator,
        hasPeriodicTable: blocks.hasPeriodicTable,
        variantCount: count(variants.id),
        totalQuestions: sql<number>`COALESCE(SUM(
          (SELECT COUNT(*) FROM ${questions} 
           INNER JOIN ${subjects} ON ${questions.subjectId} = ${subjects.id}
           WHERE ${subjects.variantId} = ${variants.id})
        ), 0)`.as('totalQuestions')
      })
      .from(blocks)
      .leftJoin(variants, eq(variants.blockId, blocks.id))
      .groupBy(blocks.id, blocks.name, blocks.order, blocks.hasCalculator, blocks.hasPeriodicTable)
      .orderBy(asc(blocks.order));
    
    return result;
  }

  async getBlock(id: string): Promise<Block | undefined> {
    const [block] = await db.select().from(blocks).where(eq(blocks.id, id));
    return block || undefined;
  }

  async createBlock(insertBlock: InsertBlock): Promise<Block> {
    const [block] = await db
      .insert(blocks)
      .values({
        ...insertBlock,
        hasCalculator: insertBlock.hasCalculator ?? false,
        hasPeriodicTable: insertBlock.hasPeriodicTable ?? false,
        // requiresProctoring removed
      })
      .returning();
    return block;
  }

  async updateBlock(id: string, updateData: Partial<InsertBlock>): Promise<Block | undefined> {
    const [updated] = await db
      .update(blocks)
      .set(updateData)
      .where(eq(blocks.id, id))
      .returning();
    return updated || undefined;
  }

  async deleteBlock(id: string): Promise<void> {
    await db.delete(blocks).where(eq(blocks.id, id));
  }

  async reorderBlocks(ids: string[]): Promise<void> {
    // Update order for each block based on position in array
    for (let i = 0; i < ids.length; i++) {
      await db.update(blocks).set({ order: i }).where(eq(blocks.id, ids[i]));
    }
  }

  async getVariantsByBlock(blockId: string): Promise<Variant[]> {
    return await db.select().from(variants).where(eq(variants.blockId, blockId)).orderBy(asc(variants.order));
  }

  async getFreeVariants(): Promise<(Variant & { block: Block })[]> {
    const freeVariants = await db
      .select({
        id: variants.id,
        blockId: variants.blockId,
        name: variants.name,
        order: variants.order,
        isFree: variants.isFree,
        block: {
          id: blocks.id,
          name: blocks.name,
          order: blocks.order,
          hasCalculator: blocks.hasCalculator,
          hasPeriodicTable: blocks.hasPeriodicTable,
        }
      })
      .from(variants)
      .innerJoin(blocks, eq(variants.blockId, blocks.id))
      .where(eq(variants.isFree, true))
      .orderBy(blocks.order, variants.order);
    
    return freeVariants.map(row => ({
      id: row.id,
      blockId: row.blockId,
      name: row.name,
      order: row.order,
      isFree: row.isFree,
      block: row.block
    }));
  }

  async getVariant(id: string): Promise<Variant | undefined> {
    const [variant] = await db.select().from(variants).where(eq(variants.id, id));
    return variant || undefined;
  }

  async createVariant(insertVariant: InsertVariant): Promise<Variant> {
    const [variant] = await db
      .insert(variants)
      .values(insertVariant)
      .returning();
    return variant;
  }

  async updateVariant(id: string, updateData: Partial<InsertVariant>): Promise<Variant | undefined> {
    const [updated] = await db
      .update(variants)
      .set(updateData)
      .where(eq(variants.id, id))
      .returning();
    return updated || undefined;
  }

  async deleteVariant(id: string): Promise<void> {
    await db.delete(variants).where(eq(variants.id, id));
  }

  async reorderVariants(blockId: string, ids: string[]): Promise<void> {
    for (let i = 0; i < ids.length; i++) {
      await db.update(variants).set({ order: i }).where(eq(variants.id, ids[i]));
    }
  }

  async getSubjectsByVariant(variantId: string): Promise<Subject[]> {
    return await db.select().from(subjects).where(eq(subjects.variantId, variantId)).orderBy(asc(subjects.order));
  }

  async getSubject(id: string): Promise<Subject | undefined> {
    const [subject] = await db.select().from(subjects).where(eq(subjects.id, id));
    return subject || undefined;
  }

  async createSubject(insertSubject: InsertSubject): Promise<Subject> {
    const [subject] = await db
      .insert(subjects)
      .values(insertSubject)
      .returning();
    return subject;
  }

  async updateSubject(id: string, updateData: Partial<InsertSubject>): Promise<Subject | undefined> {
    const [updated] = await db
      .update(subjects)
      .set(updateData)
      .where(eq(subjects.id, id))
      .returning();
    return updated || undefined;
  }

  async deleteSubject(id: string): Promise<void> {
    await db.delete(subjects).where(eq(subjects.id, id));
  }

  async reorderSubjects(variantId: string, ids: string[]): Promise<void> {
    for (let i = 0; i < ids.length; i++) {
      await db.update(subjects).set({ order: i }).where(eq(subjects.id, ids[i]));
    }
  }

  async copySubjects(sourceVariantId: string, targetVariantId: string, subjectIds: string[]): Promise<Subject[]> {
    const copiedSubjects: Subject[] = [];
    
    for (const subjectId of subjectIds) {
      // Get original subject
      const originalSubject = await this.getSubject(subjectId);
      if (!originalSubject) {
        console.warn(`Subject ${subjectId} not found, skipping`);
        continue;
      }
      
      // Create new subject in target variant
      const newSubject = await this.createSubject({
        variantId: targetVariantId,
        name: originalSubject.name
      });
      
      // Get all questions from original subject
      const originalQuestions = await this.getQuestionsBySubject(subjectId);
      
      // Copy each question with its answers
      for (const originalQuestion of originalQuestions) {
        const newQuestion = await this.createQuestion({
          subjectId: newSubject.id,
          text: originalQuestion.text
        });
        
        // Get and copy all answers for this question
        const originalAnswers = await this.getAnswersByQuestion(originalQuestion.id);
        
        for (const originalAnswer of originalAnswers) {
          await this.createAnswer({
            questionId: newQuestion.id,
            text: originalAnswer.text,
            isCorrect: originalAnswer.isCorrect
          });
        }
      }
      
      copiedSubjects.push(newSubject);
    }
    
    return copiedSubjects;
  }

  async getQuestionsBySubject(subjectId: string): Promise<Question[]> {
    return await db.select().from(questions).where(eq(questions.subjectId, subjectId)).orderBy(asc(questions.order));
  }

  async getQuestion(id: string): Promise<Question | undefined> {
    const [question] = await db.select().from(questions).where(eq(questions.id, id));
    return question || undefined;
  }

  async createQuestion(insertQuestion: InsertQuestion): Promise<Question> {
    const [question] = await db
      .insert(questions)
      .values(insertQuestion)
      .returning();
    return question;
  }

  async updateQuestion(id: string, updateData: Partial<InsertQuestion>): Promise<Question | undefined> {
    const [updated] = await db
      .update(questions)
      .set(updateData)
      .where(eq(questions.id, id))
      .returning();
    return updated || undefined;
  }

  async deleteQuestion(id: string): Promise<void> {
    await db.delete(questions).where(eq(questions.id, id));
  }

  async reorderQuestions(subjectId: string, ids: string[]): Promise<void> {
    for (let i = 0; i < ids.length; i++) {
      await db.update(questions).set({ order: i }).where(eq(questions.id, ids[i]));
    }
  }

  async getAnswersByQuestion(questionId: string): Promise<Answer[]> {
    return await db.select().from(answers).where(eq(answers.questionId, questionId)).orderBy(asc(answers.order));
  }

  async getAnswer(id: string): Promise<Answer | undefined> {
    const [answer] = await db.select().from(answers).where(eq(answers.id, id));
    return answer || undefined;
  }

  async createAnswer(insertAnswer: InsertAnswer): Promise<Answer> {
    const [answer] = await db
      .insert(answers)
      .values({
        ...insertAnswer,
        isCorrect: insertAnswer.isCorrect ?? false
      })
      .returning();
    return answer;
  }

  async updateAnswer(id: string, updateData: Partial<InsertAnswer>): Promise<Answer | undefined> {
    const [updated] = await db
      .update(answers)
      .set(updateData)
      .where(eq(answers.id, id))
      .returning();
    return updated || undefined;
  }

  async deleteAnswer(id: string): Promise<void> {
    await db.delete(answers).where(eq(answers.id, id));
  }

  async reorderAnswers(questionId: string, ids: string[]): Promise<void> {
    for (let i = 0; i < ids.length; i++) {
      await db.update(answers).set({ order: i }).where(eq(answers.id, ids[i]));
    }
  }

  async createTestResult(insertResult: InsertTestResult): Promise<TestResult> {
    const [result] = await db
      .insert(testResults)
      .values({
        ...insertResult,
        completedAt: new Date()
      })
      .returning();
    return result;
  }

  async getTestResult(id: string): Promise<TestResult | undefined> {
    const [result] = await db
      .select()
      .from(testResults)
      .where(eq(testResults.id, id));
    return result;
  }

  async getTestResultsByUser(userId: string): Promise<TestResult[]> {
    return await db.select().from(testResults).where(eq(testResults.userId, userId));
  }

  async getUserRanking(userId: string): Promise<UserRanking | undefined> {
    const userResults = await this.getTestResultsByUser(userId);
    const totalScore = userResults.reduce((sum, result) => sum + result.score, 0);
    const testsCompleted = userResults.length;
    const averagePercentage = testsCompleted > 0 
      ? userResults.reduce((sum, result) => sum + result.percentage, 0) / testsCompleted 
      : 0;

    return {
      userId,
      totalScore,
      testsCompleted,
      averagePercentage,
      lastUpdated: new Date(),
    };
  }

  async updateUserRanking(userId: string): Promise<void> {
    const userResults = await this.getTestResultsByUser(userId);
    const totalScore = userResults.reduce((sum, result) => sum + result.score, 0);
    const testsCompleted = userResults.length;
    const averagePercentage = testsCompleted > 0 
      ? userResults.reduce((sum, result) => sum + result.percentage, 0) / testsCompleted 
      : 0;

    // For now, we don't persist rankings to DB as they can be calculated on demand
    // In production, you might want to create a rankings table for performance
    console.log(`Updated ranking for user ${userId}: ${totalScore} total score, ${testsCompleted} tests, ${averagePercentage.toFixed(1)}% average`);
  }

  async getAllRankings(): Promise<UserRanking[]> {
    // Get all users and calculate their rankings on demand
    const allUsers = await db.select({ id: users.id }).from(users);
    const rankings: UserRanking[] = [];
    
    for (const user of allUsers) {
      const ranking = await this.getUserRanking(user.id);
      if (ranking) {
        rankings.push(ranking);
      }
    }
    
    return rankings.sort((a, b) => (b.totalScore || 0) - (a.totalScore || 0));
  }

  async getTodayBestResult(): Promise<{ score: number } | undefined> {
    try {
      // Get all results and filter by date in JavaScript to avoid timezone issues
      const allResults = await db
        .select({ score: testResults.score, completedAt: testResults.completedAt })
        .from(testResults)
        .orderBy(desc(testResults.score))
        .limit(100); // Get top 100 to be safe
      
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      
      // Filter results from today
      const todayResults = allResults.filter(result => {
        if (!result.completedAt) return false;
        const resultDate = new Date(result.completedAt);
        return resultDate >= today;
      });
      
      if (todayResults.length === 0) {
        return { score: 0 };
      }
      
      // Return the best score
      return { score: todayResults[0].score };
    } catch (error) {
      console.error('[Storage] Error fetching today best result:', error);
      return { score: 0 };
    }
  }

  async getSubjectProgress(userId: string): Promise<SubjectProgress[]> {
    // Calculate progress from test results
    const userResults = await this.getTestResultsByUser(userId);
    const progressMap = new Map<string, { total: number; correct: number }>();
    
    for (const result of userResults) {
      const variant = await this.getVariant(result.variantId);
      if (variant) {
        const subjects = await this.getSubjectsByVariant(variant.id);
        for (const subject of subjects) {
          const existing = progressMap.get(subject.name) || { total: 0, correct: 0 };
          progressMap.set(subject.name, {
            total: existing.total + 1,
            correct: existing.correct + (result.percentage >= 60 ? 1 : 0)
          });
        }
      }
    }
    
    const progress: SubjectProgress[] = [];
    for (const [subjectName, stats] of Array.from(progressMap.entries())) {
      progress.push({
        id: randomUUID(),
        userId,
        subjectName,
        totalAnswered: stats.total,
        correctAnswered: stats.correct,
        lastActivity: new Date()
      });
    }
    
    return progress;
  }

  async updateSubjectProgress(userId: string, subjectName: string, totalAnswered: number, correctAnswered: number): Promise<void> {
    // For now, we calculate progress on demand from test results
    // In production, you might want to create a subject_progress table
    console.log(`Subject progress updated for user ${userId} in ${subjectName}: ${correctAnswered}/${totalAnswered} correct`);
  }

  // Analytics methods
  async getAnalyticsOverview(userId: string): Promise<AnalyticsOverview> {
    const userResults = await this.getTestResultsByUser(userId);
    const subjectProgress = await this.getSubjectProgress(userId);
    
    if (userResults.length === 0) {
      return {
        totalTests: 0,
        averageScore: 0,
        totalTimeSpent: 0,
        bestSubject: "",
        worstSubject: "",
        totalQuestions: 0,
        correctAnswers: 0,
        recentActivity: 0,
      };
    }

    const totalTests = userResults.length;
    const averageScore = userResults.reduce((sum, r) => sum + r.percentage, 0) / totalTests;
    const totalTimeSpent = userResults.reduce((sum, r) => sum + r.timeSpent, 0);
    const totalQuestions = userResults.reduce((sum, r) => sum + r.totalQuestions, 0);
    const correctAnswers = userResults.reduce((sum, r) => sum + r.score, 0);

    // Calculate best and worst subjects
    const subjectStats = subjectProgress.reduce((acc, p) => {
      const totalAnswered = p.totalAnswered || 0;
      const correctAnswered = p.correctAnswered || 0;
      const percentage = totalAnswered > 0 ? (correctAnswered / totalAnswered) * 100 : 0;
      acc[p.subjectName] = percentage;
      return acc;
    }, {} as Record<string, number>);

    const subjects = Object.keys(subjectStats);
    const bestSubject = subjects.reduce((best, current) => 
      subjectStats[current] > subjectStats[best] ? current : best, subjects[0] || "");
    const worstSubject = subjects.reduce((worst, current) => 
      subjectStats[current] < subjectStats[worst] ? current : worst, subjects[0] || "");

    // Calculate recent activity (tests in last 7 days)
    const weekAgo = new Date();
    weekAgo.setDate(weekAgo.getDate() - 7);
    const recentActivity = userResults.filter(r => 
      r.completedAt && new Date(r.completedAt) > weekAgo
    ).length;

    return {
      totalTests,
      averageScore,
      totalTimeSpent,
      bestSubject,
      worstSubject,
      totalQuestions,
      correctAnswers,
      recentActivity,
    };
  }

  async getSubjectAggregates(userId: string): Promise<SubjectAggregate[]> {
    const userResults = await this.getTestResultsByUser(userId);
    const subjectProgress = await this.getSubjectProgress(userId);
    
    // Group test results by subject
    const subjectGroups: Record<string, TestResult[]> = {};
    
    for (const result of userResults) {
      const variant = await this.getVariant(result.variantId);
      if (!variant) continue;
      
      const subjects = await this.getSubjectsByVariant(variant.id);
      for (const subject of subjects) {
        if (!subjectGroups[subject.name]) {
          subjectGroups[subject.name] = [];
        }
        subjectGroups[subject.name].push(result);
      }
    }

    const aggregates: SubjectAggregate[] = [];
    
    for (const subjectName in subjectGroups) {
      const results = subjectGroups[subjectName];
      const progress = subjectProgress.find(p => p.subjectName === subjectName);
      
      const testsCount = results.length;
      const averageScore = testsCount > 0 ? 
        results.reduce((sum, r) => sum + r.percentage, 0) / testsCount : 0;
      const totalQuestions = progress?.totalAnswered || 0;
      const correctAnswers = progress?.correctAnswered || 0;
      const averageTimeSpent = testsCount > 0 ? 
        results.reduce((sum, r) => sum + r.timeSpent, 0) / testsCount : 0;

      aggregates.push({
        subjectName,
        testsCount,
        averageScore,
        totalQuestions,
        correctAnswers,
        averageTimeSpent,
      });
    }

    return aggregates.sort((a, b) => b.averageScore - a.averageScore);
  }

  async getHistory(userId: string, rangeDays: number = 30): Promise<HistoryPoint[]> {
    const userResults = await this.getTestResultsByUser(userId);
    
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - rangeDays);
    
    // Filter results within date range
    const filteredResults = userResults.filter(r => 
      r.completedAt && 
      new Date(r.completedAt) >= startDate && 
      new Date(r.completedAt) <= endDate
    );

    // Group by date
    const dateGroups: Record<string, TestResult[]> = {};
    
    for (const result of filteredResults) {
      if (!result.completedAt) continue;
      const dateKey = new Date(result.completedAt).toISOString().split('T')[0];
      if (!dateGroups[dateKey]) {
        dateGroups[dateKey] = [];
      }
      dateGroups[dateKey].push(result);
    }

    const history: HistoryPoint[] = [];
    
    // Generate all dates in range
    for (let d = new Date(startDate); d <= endDate; d.setDate(d.getDate() + 1)) {
      const dateKey = d.toISOString().split('T')[0];
      const dayResults = dateGroups[dateKey] || [];
      
      const testsCompleted = dayResults.length;
      const averageScore = testsCompleted > 0 ? 
        dayResults.reduce((sum, r) => sum + r.percentage, 0) / testsCompleted : 0;
      const totalTimeSpent = dayResults.reduce((sum, r) => sum + r.timeSpent, 0);

      history.push({
        date: dateKey,
        testsCompleted,
        averageScore,
        totalTimeSpent,
      });
    }

    return history;
  }

  async getCorrectnessBreakdown(userId: string, rangeDays: number = 30): Promise<CorrectnessBreakdown[]> {
    const userResults = await this.getTestResultsByUser(userId);
    
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - rangeDays);
    
    // Filter results within date range
    const filteredResults = userResults.filter(r => 
      r.completedAt && 
      new Date(r.completedAt) >= startDate && 
      new Date(r.completedAt) <= endDate
    );

    // Group by date
    const dateGroups: Record<string, TestResult[]> = {};
    
    for (const result of filteredResults) {
      if (!result.completedAt) continue;
      const dateKey = new Date(result.completedAt).toISOString().split('T')[0];
      if (!dateGroups[dateKey]) {
        dateGroups[dateKey] = [];
      }
      dateGroups[dateKey].push(result);
    }

    const breakdown: CorrectnessBreakdown[] = [];
    
    // Generate all dates in range
    for (let d = new Date(startDate); d <= endDate; d.setDate(d.getDate() + 1)) {
      const dateKey = d.toISOString().split('T')[0];
      const dayResults = dateGroups[dateKey] || [];
      
      const correctAnswers = dayResults.reduce((sum, r) => sum + r.score, 0);
      const totalQuestions = dayResults.reduce((sum, r) => sum + r.totalQuestions, 0);
      const incorrectAnswers = totalQuestions - correctAnswers;

      breakdown.push({
        date: dateKey,
        correctAnswers,
        incorrectAnswers,
        totalQuestions,
      });
    }

    return breakdown;
  }

  async getComparison(userId: string): Promise<ComparisonStats> {
    const allRankings = await this.getAllRankings();
    const userRanking = await this.getUserRanking(userId);
    
    if (!userRanking || allRankings.length === 0) {
      return {
        userRank: 0,
        totalUsers: 0,
        userScore: 0,
        averageScore: 0,
        percentile: 0,
        topUserScore: 0,
      };
    }

    const sortedRankings = allRankings.sort((a, b) => (b.totalScore || 0) - (a.totalScore || 0));
    const userRank = sortedRankings.findIndex(r => r.userId === userId) + 1;
    const totalUsers = sortedRankings.length;
    const userScore = userRanking.averagePercentage || 0;
    const averageScore = sortedRankings.reduce((sum, r) => sum + (r.averagePercentage || 0), 0) / totalUsers;
    const percentile = totalUsers > 0 ? ((totalUsers - userRank + 1) / totalUsers) * 100 : 0;
    const topUserScore = sortedRankings[0]?.averagePercentage || 0;

    return {
      userRank,
      totalUsers,
      userScore,
      averageScore,
      percentile,
      topUserScore,
    };
  }

  // Notification methods
  async createNotification(insertNotification: InsertNotification): Promise<Notification> {
    const [notification] = await db
      .insert(notifications)
      .values({
        ...insertNotification,
        createdAt: new Date(),
        readAt: null
      })
      .returning();
    return notification;
  }

  async getNotifications(userId: string, page: number = 1, limit: number = 10, type?: NotificationType): Promise<{ notifications: Notification[], total: number }> {
    const offset = (page - 1) * limit;

    // Build query with explicit conditions to avoid reassigning query objects
    let userNotifications;
    if (type) {
      userNotifications = await db.select().from(notifications)
        .where(and(eq(notifications.userId, userId), eq(notifications.type, type)))
        .orderBy(desc(notifications.createdAt))
        .limit(limit)
        .offset(offset);
    } else {
      userNotifications = await db.select().from(notifications)
        .where(eq(notifications.userId, userId))
        .orderBy(desc(notifications.createdAt))
        .limit(limit)
        .offset(offset);
    }
    
    // Get total count for pagination
    const [{ count }] = await db
      .select({ count: sql<number>`count(*)` })
      .from(notifications)
      .where(eq(notifications.userId, userId));
    
    return { notifications: userNotifications, total: count };
  }

  async getUnreadNotificationCount(userId: string): Promise<number> {
    const [{ count }] = await db
      .select({ count: sql<number>`count(*)` })
      .from(notifications)
      .where(and(eq(notifications.userId, userId), eq(notifications.isRead, false)));
    return count;
  }

  async markNotificationAsRead(id: string, userId: string): Promise<void> {
    await db
      .update(notifications)
      .set({ isRead: true, readAt: new Date() })
      .where(and(eq(notifications.id, id), eq(notifications.userId, userId)));
  }

  async markAllNotificationsAsRead(userId: string): Promise<void> {
    await db
      .update(notifications)
      .set({ isRead: true, readAt: new Date() })
      .where(and(eq(notifications.userId, userId), eq(notifications.isRead, false)));
  }

  async deleteNotification(id: string, userId: string): Promise<void> {
    await db
      .delete(notifications)
      .where(and(eq(notifications.id, id), eq(notifications.userId, userId)));
  }

  async countNotificationsByTypeSince(userId: string, type: NotificationType, since: Date): Promise<number> {
    const [{ count }] = await db
      .select({ count: sql<number>`count(*)` })
      .from(notifications)
      .where(and(
        eq(notifications.userId, userId),
        eq(notifications.type, type),
        sql`${notifications.createdAt} >= ${since}`
      ));
    return count;
  }

  // Notification Settings methods
  async getNotificationSettings(userId: string): Promise<NotificationSettings | undefined> {
    return this.notificationSettings.get(userId);
  }

  async upsertNotificationSettings(settings: InsertNotificationSettings): Promise<NotificationSettings> {
    const existingSettings = this.notificationSettings.get(settings.userId) || {} as NotificationSettings;
    const updatedSettings: NotificationSettings = {
      userId: settings.userId,
      testCompletedEnabled: settings.testCompletedEnabled !== undefined ? settings.testCompletedEnabled : (existingSettings.testCompletedEnabled ?? true),
      testReminderEnabled: settings.testReminderEnabled !== undefined ? settings.testReminderEnabled : (existingSettings.testReminderEnabled ?? true),
      systemMessageEnabled: settings.systemMessageEnabled !== undefined ? settings.systemMessageEnabled : (existingSettings.systemMessageEnabled ?? true),
      achievementEnabled: settings.achievementEnabled !== undefined ? settings.achievementEnabled : (existingSettings.achievementEnabled ?? true),
      inAppEnabled: settings.inAppEnabled !== undefined ? settings.inAppEnabled : (existingSettings.inAppEnabled ?? true),
      pushEnabled: settings.pushEnabled !== undefined ? settings.pushEnabled : (existingSettings.pushEnabled ?? false),
      emailEnabled: settings.emailEnabled !== undefined ? settings.emailEnabled : (existingSettings.emailEnabled ?? false),
      reminderIntervalMinutes: settings.reminderIntervalMinutes ?? existingSettings.reminderIntervalMinutes ?? 30,
      maxRemindersPerDay: settings.maxRemindersPerDay ?? existingSettings.maxRemindersPerDay ?? 3,
      quietHoursStart: settings.quietHoursStart ?? existingSettings.quietHoursStart ?? "22:00",
      quietHoursEnd: settings.quietHoursEnd ?? existingSettings.quietHoursEnd ?? "08:00",
      updatedAt: new Date(),
    };
    this.notificationSettings.set(settings.userId, updatedSettings);
    return updatedSettings;
  }

  // Reminder methods
  async getReminders(userId: string): Promise<Reminder[]> {
    return Array.from(this.reminders.values())
      .filter((r: Reminder) => r.userId === userId && !!r.isActive)
      .sort((a: Reminder, b: Reminder) => new Date(a.dueAt).getTime() - new Date(b.dueAt).getTime());
  }

  async createReminder(insertReminder: InsertReminder): Promise<Reminder> {
    const id = randomUUID();
    const reminder: Reminder = {
      id,
      createdAt: new Date(),
      variantId: insertReminder.variantId,
      userId: insertReminder.userId,
      dueAt: insertReminder.dueAt,
      recurrence: insertReminder.recurrence ?? null,
      lastSentAt: null,
      isActive: insertReminder.isActive ?? true,
    };
    this.reminders.set(id, reminder);
    return reminder;
  }

  async updateReminder(id: string, reminderUpdate: Partial<InsertReminder>): Promise<Reminder | undefined> {
    const reminder = this.reminders.get(id);
    if (!reminder) return undefined;
    
    const updatedReminder = {
      ...reminder,
      ...reminderUpdate,
    };
    this.reminders.set(id, updatedReminder);
    return updatedReminder;
  }

  async deleteReminder(id: string, userId: string): Promise<void> {
    const reminder = this.reminders.get(id);
    if (reminder && reminder.userId === userId) {
      this.reminders.delete(id);
    }
  }

  async getDueReminders(): Promise<Reminder[]> {
    const now = new Date();
    return Array.from(this.reminders.values())
      .filter(r => r.isActive && new Date(r.dueAt) <= now);
  }

  async markReminderAsSent(id: string): Promise<void> {
    await db
      .update(reminders)
      .set({ lastSentAt: new Date() })
      .where(eq(reminders.id, id));
  }

  // Export Jobs methods
  async createExportJob(insertExportJob: InsertExportJob): Promise<ExportJob> {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + (24 * 60 * 60 * 1000)); // 24 hours from now

    const [exportJob] = await db
      .insert(exportJobs)
      .values({
        ...insertExportJob,
        createdAt: now,
        completedAt: null,
        expiresAt,
      })
      .returning();
    
    return exportJob;
  }

  async getExportJob(id: string): Promise<ExportJob | undefined> {
    const [job] = await db.select().from(exportJobs).where(eq(exportJobs.id, id));
    return job || undefined;
  }

  async listExportJobsByUser(userId: string, limit = 10): Promise<ExportJob[]> {
    return Array.from(this.exportJobs.values())
      .filter(job => job.userId === userId)
      .sort((a, b) => (new Date(b.createdAt ?? 0).getTime() - new Date(a.createdAt ?? 0).getTime()))
      .slice(0, limit);
  }

  async updateExportJob(id: string, update: Partial<ExportJob>): Promise<ExportJob | undefined> {
    const [updatedJob] = await db
      .update(exportJobs)
      .set(update)
      .where(eq(exportJobs.id, id))
      .returning();
    return updatedJob || undefined;
  }

  async deleteExportJob(id: string, userId: string): Promise<void> {
    const job = this.exportJobs.get(id);
    if (job && job.userId === userId) {
      // Clean up associated file if exists
      if (job.fileKey) {
        await this.deleteFile(job.fileKey);
      }
      this.exportJobs.delete(id);
    }
  }

  async getPendingExportJobs(): Promise<ExportJob[]> {
    return await db
      .select()
      .from(exportJobs)
      .where(eq(exportJobs.status, "PENDING"))
      .orderBy(asc(exportJobs.createdAt));
  }

  // File Cache methods
  async storeFile(key: string, buffer: Buffer, ttl = 15): Promise<void> {
    const expiresAt = Date.now() + (ttl * 60 * 1000); // TTL in minutes
    
    // Clean up expired files before storing
    await this.clearExpiredFiles();
    
    // Check total cache size (200MB limit)
    const currentSize = Array.from(this.fileCache.values())
      .reduce((total, item) => total + item.buffer.length, 0);
    
    if (currentSize + buffer.length > 200 * 1024 * 1024) {
      // Remove oldest files to make space
      const entries = Array.from(this.fileCache.entries())
        .sort((a, b) => a[1].expiresAt - b[1].expiresAt);
      
      let removedSize = 0;
      for (const [oldKey] of entries) {
        const item = this.fileCache.get(oldKey);
        if (item) {
          removedSize += item.buffer.length;
          this.fileCache.delete(oldKey);
          if (currentSize - removedSize + buffer.length <= 200 * 1024 * 1024) break;
        }
      }
    }
    
    this.fileCache.set(key, { buffer, expiresAt });
  }

  async getFile(key: string): Promise<Buffer | undefined> {
    const item = this.fileCache.get(key);
    if (!item) return undefined;
    
    // Check if expired
    if (Date.now() > item.expiresAt) {
      this.fileCache.delete(key);
      return undefined;
    }
    
    return item.buffer;
  }

  async deleteFile(key: string): Promise<void> {
    this.fileCache.delete(key);
  }

  async clearExpiredFiles(): Promise<void> {
    const now = Date.now();
    for (const [key, item] of Array.from(this.fileCache.entries())) {
      if (now > item.expiresAt) {
        this.fileCache.delete(key);
      }
    }
  }

  // Rate Limiting methods
  async checkExportRateLimit(userId: string): Promise<{ allowed: boolean; reason?: string }> {
    const now = Date.now();
    const userLimit = this.exportRateLimit.get(userId);
    
    if (!userLimit) {
      return { allowed: true };
    }

    // Reset count if it's been more than an hour
    if (now - userLimit.lastReset > 60 * 60 * 1000) {
      userLimit.count = 0;
      userLimit.lastReset = now;
      this.exportRateLimit.set(userId, userLimit);
    }

    // Check concurrent limit (1 concurrent)
    if (userLimit.concurrent > 0) {
      return { allowed: false, reason: "У вас уже есть запущенный экспорт. Дождитесь его завершения." };
    }

    // Check hourly limit (5 per hour)
    if (userLimit.count >= 5) {
      return { allowed: false, reason: "Превышен лимит: максимум 5 экспортов в час." };
    }

    // Check daily limit (20 per day) - simplified as 24 hours from first export
    const jobsToday = Array.from(this.exportJobs.values())
      .filter(job => 
        job.userId === userId && 
        now - new Date(job.createdAt ?? 0).getTime() < 24 * 60 * 60 * 1000
      ).length;

    if (jobsToday >= 20) {
      return { allowed: false, reason: "Превышен дневной лимит: максимум 20 экспортов в день." };
    }

    return { allowed: true };
  }

  async incrementExportCount(userId: string): Promise<void> {
    const now = Date.now();
    const userLimit = this.exportRateLimit.get(userId);
    
    if (!userLimit) {
      this.exportRateLimit.set(userId, {
        count: 1,
        lastReset: now,
        concurrent: 1,
      });
    } else {
      userLimit.count += 1;
      userLimit.concurrent += 1;
      this.exportRateLimit.set(userId, userLimit);
    }
  }

  // System Settings
  async getSystemSetting(key: string): Promise<{ key: string; value: string } | undefined> {
    try {
      const [setting] = await db
        .select({ key: systemSettings.key, value: systemSettings.value })
        .from(systemSettings)
        .where(eq(systemSettings.key, key))
        .limit(1);
      return setting;
    } catch (error) {
      console.error('[Storage] Error getting system setting:', error);
      return undefined;
    }
  }

  async updateSystemSetting(key: string, value: string, updatedBy: string): Promise<{ key: string; value: string }> {
    try {
      // Try to update existing setting
      const [updated] = await db
        .update(systemSettings)
        .set({ value, updatedAt: new Date(), updatedBy })
        .where(eq(systemSettings.key, key))
        .returning({ key: systemSettings.key, value: systemSettings.value });

      if (updated) {
        return updated;
      }

      // If not exists, insert new setting
      const [created] = await db
        .insert(systemSettings)
        .values({ key, value, updatedBy })
        .returning({ key: systemSettings.key, value: systemSettings.value });

      return created;
    } catch (error) {
      console.error('[Storage] Error updating system setting:', error);
      throw error;
    }
  }

  // Quotes
  async getAllQuotes(): Promise<Quote[]> {
    return await db.select().from(quotes).orderBy(asc(quotes.month), asc(quotes.order));
  }

  async getQuotesByMonth(month: number): Promise<Quote[]> {
    return await db.select().from(quotes).where(eq(quotes.month, month)).orderBy(asc(quotes.order));
  }

  async getCurrentQuote(): Promise<Quote | null> {
    const currentMonth = new Date().getMonth() + 1; // JavaScript months are 0-indexed
    const monthQuotes = await this.getQuotesByMonth(currentMonth);
    
    if (monthQuotes.length === 0) {
      return null;
    }
    
    // Get current day of month (1-31) to determine which quote to show
    const dayOfMonth = new Date().getDate();
    const quoteIndex = (dayOfMonth - 1) % monthQuotes.length;
    
    return monthQuotes[quoteIndex];
  }

  async createQuote(quote: InsertQuote): Promise<Quote> {
    const [newQuote] = await db.insert(quotes).values(quote).returning();
    return newQuote;
  }

  async updateQuote(id: string, quote: Partial<InsertQuote>): Promise<Quote | undefined> {
    const [updated] = await db.update(quotes)
      .set({ ...quote, updatedAt: new Date() })
      .where(eq(quotes.id, id))
      .returning();
    return updated;
  }

  async deleteQuote(id: string): Promise<void> {
    await db.delete(quotes).where(eq(quotes.id, id));
  }

  async reorderQuotes(month: number, ids: string[]): Promise<void> {
    for (let i = 0; i < ids.length; i++) {
      await db.update(quotes)
        .set({ order: i })
        .where(and(eq(quotes.id, ids[i]), eq(quotes.month, month)));
    }
  }

  // Payment System Methods
  async getSubscriptionPlans(): Promise<SubscriptionPlan[]> {
    return await db.select().from(subscriptionPlans)
      .where(eq(subscriptionPlans.isActive, true))
      .orderBy(asc(subscriptionPlans.sortOrder));
  }

  async getSubscriptionPlan(id: string): Promise<SubscriptionPlan | undefined> {
    const [plan] = await db.select().from(subscriptionPlans)
      .where(eq(subscriptionPlans.id, id));
    return plan;
  }

  async createSubscriptionPlan(plan: InsertSubscriptionPlan): Promise<SubscriptionPlan> {
    const [newPlan] = await db.insert(subscriptionPlans).values(plan).returning();
    return newPlan;
  }

  async updateSubscriptionPlan(id: string, plan: Partial<InsertSubscriptionPlan>): Promise<SubscriptionPlan | undefined> {
    const [updated] = await db.update(subscriptionPlans)
      .set({ ...plan, updatedAt: new Date() })
      .where(eq(subscriptionPlans.id, id))
      .returning();
    return updated;
  }

  async getCurrentUserSubscription(userId: string): Promise<UserSubscription | undefined> {
    const [subscription] = await db.select().from(userSubscriptions)
      .where(and(
        eq(userSubscriptions.userId, userId),
        eq(userSubscriptions.status, "ACTIVE")
      ))
      .orderBy(desc(userSubscriptions.createdAt));
    return subscription;
  }

  async createOrUpdateUserSubscription(subscription: InsertUserSubscription): Promise<UserSubscription> {
    // Сначала деактивируем все существующие подписки пользователя
    await db.update(userSubscriptions)
      .set({ status: "CANCELLED", updatedAt: new Date() })
      .where(and(
        eq(userSubscriptions.userId, subscription.userId),
        eq(userSubscriptions.status, "ACTIVE")
      ));

    // Создаем новую подписку
    const [newSubscription] = await db.insert(userSubscriptions)
      .values(subscription)
      .returning();
    return newSubscription;
  }

  async createPayment(payment: InsertPayment): Promise<Payment> {
    const [newPayment] = await db.insert(payments).values(payment).returning();
    return newPayment;
  }

  async getPayment(id: string): Promise<Payment | undefined> {
    const [payment] = await db.select().from(payments)
      .where(eq(payments.id, id));
    return payment;
  }

  async updatePaymentStatus(id: string, status: string): Promise<void> {
    const updateData: any = { status };
    if (status === "COMPLETED") {
      updateData.completedAt = new Date();
    }
    
    await db.update(payments)
      .set(updateData)
      .where(eq(payments.id, id));
  }

  async getAllPayments(): Promise<Payment[]> {
    return await db.select().from(payments)
      .orderBy(desc(payments.createdAt));
  }

  async getAllUserSubscriptions(): Promise<UserSubscription[]> {
    return await db.select().from(userSubscriptions)
      .orderBy(desc(userSubscriptions.createdAt));
  }

  // Check if user has access to a specific block
  async hasBlockAccess(userId: string, blockId: string): Promise<boolean> {
    const now = new Date();
    const [subscription] = await db.select().from(userSubscriptions)
      .where(and(
        eq(userSubscriptions.userId, userId),
        eq(userSubscriptions.blockId, blockId),
        eq(userSubscriptions.status, "ACTIVE"),
        sql`${userSubscriptions.endDate} > ${now}`
      ));
    return !!subscription;
  }

  // Check if user has single test credits
  async hasSingleTestAccess(userId: string): Promise<boolean> {
    const now = new Date();
    const [subscription] = await db.select().from(userSubscriptions)
      .innerJoin(subscriptionPlans, eq(userSubscriptions.planId, subscriptionPlans.id))
      .where(and(
        eq(userSubscriptions.userId, userId),
        eq(userSubscriptions.status, "ACTIVE"),
        eq(subscriptionPlans.planType, "single_test"),
        sql`${userSubscriptions.endDate} > ${now}`
      ));
    return !!subscription;
  }

  // REMOVED: Old MemStorage VideoRecording methods - now using DatabaseStorage
}

export const storage = new DatabaseStorage();
