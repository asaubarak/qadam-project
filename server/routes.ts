import type { Express, Request, Response, NextFunction } from "express";
import { createServer, type Server } from "http";
import multer from "multer";
import path from "path";
import fs from "fs";
import { storage } from "./storage";
import { setupAuth } from "./auth";
import { insertBlockSchema, insertVariantSchema, insertSubjectSchema, insertQuestionSchema, insertAnswerSchema, updateAnswerSchema, insertTestResultSchema,
         insertNotificationSchema, insertNotificationSettingsSchema, insertReminderSchema, notificationTypeSchema,
         analyticsOverviewSchema, subjectAggregateSchema, historyPointSchema, correctnessBreakdownSchema, comparisonStatsSchema,
         insertExportJobSchema, exportTypeSchema, exportFormatSchema, exportOptionsSchema } from "@shared/schema";
import { ObjectStorageService } from "./objectStorage";
// Rate limiting middleware removed for video upload (proctoring removed)
// CRITICAL #5: Operational Hardening - Import health checks and monitoring
import { operationalHardening } from "./operational-hardening";
import { db } from "./db";
import { testResults } from "@shared/schema";
import { desc } from "drizzle-orm";

// Authentication middleware
function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ message: "Требуется авторизация" });
  }
  next();
}

// Admin authorization middleware
function requireAdmin(req: Request, res: Response, next: NextFunction) {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ message: "Требуется авторизация" });
  }
  
  if (!isAdmin(req.user)) {
    return res.status(403).json({ message: "Требуются права администратора" });
  }
  
  next();
}

// Helper function to check if user is admin
function isAdmin(user: any): boolean {
  return user && user.username === "admin";
}

// Rate limiting middleware for exports
async function requireExportRateLimit(req: Request, res: Response, next: NextFunction) {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ message: "Требуется авторизация" });
  }
  
  try {
    const { allowed, reason } = await storage.checkExportRateLimit(req.user?.id!);
    if (!allowed) {
      return res.status(429).json({ message: reason });
    }
    next();
  } catch (error) {
    res.status(500).json({ message: "Ошибка проверки лимитов" });
  }
}

export async function registerRoutes(app: Express): Promise<Server> {
  // Simple health check for Render (always returns OK)
  app.get("/health", (req, res) => {
    res.status(200).json({ 
      status: "ok", 
      timestamp: new Date().toISOString(),
      uptime: process.uptime()
    });
  });

  // CRITICAL #5: Operational Hardening - Detailed health check endpoints
  app.get("/health/detailed", operationalHardening.healthCheckHandler);
  app.get("/ready", operationalHardening.readyHandler);
  
  // System status endpoint for monitoring
  app.get("/api/system/status", requireAuth, (req, res) => {
    const status = operationalHardening.getSystemStatus();
    res.json(status);
  });

  // Setup authentication
  setupAuth(app);

  // Configure multer for file uploads
  const uploadDir = path.join(process.cwd(), 'uploads', 'question-images');
  if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
  }

  const upload = multer({
    storage: multer.diskStorage({
      destination: (req, file, cb) => {
        cb(null, uploadDir);
      },
      filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'question-' + uniqueSuffix + path.extname(file.originalname));
      }
    }),
    limits: {
      fileSize: 5 * 1024 * 1024, // 5MB limit
    },
    fileFilter: (req, file, cb) => {
      if (file.mimetype.startsWith('image/')) {
        cb(null, true);
      } else {
        cb(new Error('Только изображения разрешены'));
      }
    }
  });

  // Image upload endpoint
  app.post("/api/upload/question-image", requireAdmin, upload.single('image'), (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ message: "Файл не загружен" });
      }
      
      // Return the URL to access the uploaded file
      const fileUrl = `/uploads/question-images/${req.file.filename}`;
      res.json({ url: fileUrl });
    } catch (error) {
      res.status(500).json({ message: "Ошибка загрузки файла" });
    }
  });

  // Public routes (no authentication required)
  app.get("/api/public/free-variants", async (req, res) => {
    try {
      const freeVariants = await storage.getFreeVariants();
      res.json(freeVariants);
    } catch (error) {
      res.status(500).json({ message: "Ошибка получения бесплатных вариантов" });
    }
  });

  app.get("/api/public/blocks", async (req, res) => {
    try {
      const blocks = await storage.getPublicBlocks();
      res.json(blocks);
    } catch (error) {
      res.status(500).json({ message: "Ошибка получения блоков тестов" });
    }
  });

  // Blocks routes
  app.get("/api/blocks", async (req, res) => {
    try {
      const blocks = await storage.getAllBlocks();
      res.json(blocks);
    } catch (error) {
      res.status(500).json({ message: "Ошибка получения блоков" });
    }
  });

  app.get("/api/blocks/:id", async (req, res) => {
    try {
      const block = await storage.getBlock(req.params.id);
      if (!block) {
        return res.status(404).json({ message: "Блок не найден" });
      }
      res.json(block);
    } catch (error) {
      res.status(500).json({ message: "Ошибка получения блока" });
    }
  });

  app.post("/api/blocks", requireAdmin, async (req, res) => {
    try {
      const validatedData = insertBlockSchema.parse(req.body);
      const block = await storage.createBlock(validatedData);
      res.status(201).json(block);
    } catch (error) {
      res.status(400).json({ message: "Ошибка создания блока" });
    }
  });

  app.put("/api/blocks/:id", requireAdmin, async (req, res) => {
    try {
      const validatedData = insertBlockSchema.partial().parse(req.body);
      const block = await storage.updateBlock(req.params.id, validatedData);
      if (!block) {
        return res.status(404).json({ message: "Блок не найден" });
      }
      res.json(block);
    } catch (error) {
      res.status(400).json({ message: "Ошибка обновления блока" });
    }
  });

  app.delete("/api/blocks/:id", requireAdmin, async (req, res) => {
    try {
      await storage.deleteBlock(req.params.id);
      res.status(204).send();
    } catch (error) {
      res.status(500).json({ message: "Ошибка удаления блока" });
    }
  });

  // Reorder blocks
  app.post("/api/blocks/reorder", requireAdmin, async (req, res) => {
    try {
      const { ids } = req.body;
      if (!Array.isArray(ids)) {
        return res.status(400).json({ message: "ids должен быть массивом" });
      }
      await storage.reorderBlocks(ids);
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ message: "Ошибка изменения порядка блоков" });
    }
  });

  // Variants routes
  app.get("/api/blocks/:blockId/variants", async (req, res) => {
    try {
      const variants = await storage.getVariantsByBlock(req.params.blockId);
      res.json(variants);
    } catch (error) {
      res.status(500).json({ message: "Ошибка получения вариантов" });
    }
  });

  app.get("/api/variants/:id", async (req, res) => {
    try {
      const variant = await storage.getVariant(req.params.id);
      if (!variant) {
        return res.status(404).json({ message: "Вариант не найден" });
      }
      res.json(variant);
    } catch (error) {
      res.status(500).json({ message: "Ошибка получения варианта" });
    }
  });

  app.post("/api/variants", requireAdmin, async (req, res) => {
    try {
      const validatedData = insertVariantSchema.parse(req.body);
      const variant = await storage.createVariant(validatedData);
      res.status(201).json(variant);
    } catch (error) {
      res.status(400).json({ message: "Ошибка создания варианта" });
    }
  });

  app.put("/api/variants/:id", requireAdmin, async (req, res) => {
    try {
      const validatedData = insertVariantSchema.parse(req.body);
      const variant = await storage.updateVariant(req.params.id, validatedData);
      if (!variant) {
        return res.status(404).json({ message: "Вариант не найден" });
      }
      res.json(variant);
    } catch (error) {
      res.status(400).json({ message: "Ошибка обновления варианта" });
    }
  });

  app.delete("/api/variants/:id", requireAdmin, async (req, res) => {
    try {
      await storage.deleteVariant(req.params.id);
      res.status(204).send();
    } catch (error) {
      res.status(500).json({ message: "Ошибка удаления варианта" });
    }
  });

  // Reorder variants
  app.post("/api/variants/reorder", requireAdmin, async (req, res) => {
    try {
      const { blockId, ids } = req.body;
      if (!blockId || !Array.isArray(ids)) {
        return res.status(400).json({ message: "blockId и ids обязательны" });
      }
      await storage.reorderVariants(blockId, ids);
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ message: "Ошибка изменения порядка вариантов" });
    }
  });

  // Subjects routes
  app.get("/api/variants/:variantId/subjects", async (req, res) => {
    try {
      const subjects = await storage.getSubjectsByVariant(req.params.variantId);
      res.json(subjects);
    } catch (error) {
      res.status(500).json({ message: "Ошибка получения предметов" });
    }
  });

  app.post("/api/subjects", requireAdmin, async (req, res) => {
    try {
      const validatedData = insertSubjectSchema.parse(req.body);
      const subject = await storage.createSubject(validatedData);
      res.status(201).json(subject);
    } catch (error) {
      res.status(400).json({ message: "Ошибка создания предмета" });
    }
  });

  app.put("/api/subjects/:id", requireAdmin, async (req, res) => {
    try {
      const validatedData = insertSubjectSchema.parse(req.body);
      const subject = await storage.updateSubject(req.params.id, validatedData);
      if (!subject) {
        return res.status(404).json({ message: "Предмет не найден" });
      }
      res.json(subject);
    } catch (error) {
      res.status(400).json({ message: "Ошибка обновления предмета" });
    }
  });

  app.delete("/api/subjects/:id", requireAdmin, async (req, res) => {
    try {
      await storage.deleteSubject(req.params.id);
      res.status(204).send();
    } catch (error) {
      res.status(500).json({ message: "Ошибка удаления предмета" });
    }
  });

  // Reorder subjects
  app.post("/api/subjects/reorder", requireAdmin, async (req, res) => {
    try {
      const { variantId, ids } = req.body;
      if (!variantId || !Array.isArray(ids)) {
        return res.status(400).json({ message: "variantId и ids обязательны" });
      }
      await storage.reorderSubjects(variantId, ids);
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ message: "Ошибка изменения порядка предметов" });
    }
  });

  // Bulk import subject with questions
  app.post("/api/subjects/bulk-import", requireAdmin, async (req, res) => {
    try {
      const { variantId, bulkData } = req.body;
      
      if (!variantId || !bulkData) {
        return res.status(400).json({ message: "variantId и bulkData обязательны" });
      }

      // Validate bulk data structure
      if (!bulkData.name || !Array.isArray(bulkData.questions)) {
        return res.status(400).json({ message: "Неверная структура данных. Требуются поля: name, questions" });
      }

      // Validate questions structure
      for (const question of bulkData.questions) {
        if (!question.text || !Array.isArray(question.answers)) {
          return res.status(400).json({ message: "Каждый вопрос должен содержать text и answers" });
        }
        
        if (question.answers.length === 0) {
          return res.status(400).json({ message: "Вопрос должен иметь хотя бы один ответ" });
        }

        const correctAnswers = question.answers.filter((a: any) => a.isCorrect);
        if (correctAnswers.length === 0) {
          return res.status(400).json({ message: "Вопрос должен иметь хотя бы один правильный ответ" });
        }
      }

      // Create subject
      const subjectData = insertSubjectSchema.parse({
        name: bulkData.name,
        variantId: variantId
      });
      const subject = await storage.createSubject(subjectData);

      // Create questions and answers
      for (let i = 0; i < bulkData.questions.length; i++) {
        const questionData = bulkData.questions[i];
        
        const question = await storage.createQuestion({
          text: questionData.text,
          subjectId: subject.id,
          order: i + 1,
          imageUrl: null,
          solutionImageUrl: null
        });

        // Create answers
        for (let j = 0; j < questionData.answers.length; j++) {
          const answerData = questionData.answers[j];
          await storage.createAnswer({
            text: answerData.text,
            isCorrect: answerData.isCorrect,
            questionId: question.id,
            order: j + 1
          });
        }
      }

      res.status(201).json({ 
        success: true, 
        subject,  
        questionsCount: bulkData.questions.length 
      });
    } catch (error) {
      console.error("Bulk import error:", error);
      res.status(500).json({ message: "Ошибка массовой загрузки" });
    }
  });

  // Questions routes
  app.get("/api/subjects/:subjectId/questions", async (req, res) => {
    try {
      const questions = await storage.getQuestionsBySubject(req.params.subjectId);
      res.json(questions);
    } catch (error) {
      res.status(500).json({ message: "Ошибка получения вопросов" });
    }
  });

  app.post("/api/questions", requireAdmin, async (req, res) => {
    try {
      const validatedData = insertQuestionSchema.parse(req.body);
      const question = await storage.createQuestion(validatedData);
      res.status(201).json(question);
    } catch (error) {
      res.status(400).json({ message: "Ошибка создания вопроса" });
    }
  });

  app.put("/api/questions/:id", requireAdmin, async (req, res) => {
    try {
      const validatedData = insertQuestionSchema.partial().parse(req.body);
      const question = await storage.updateQuestion(req.params.id, validatedData);
      if (!question) {
        return res.status(404).json({ message: "Вопрос не найден" });
      }
      res.json(question);
    } catch (error) {
      res.status(400).json({ message: "Ошибка обновления вопроса" });
    }
  });

  app.delete("/api/questions/:id", requireAdmin, async (req, res) => {
    try {
      await storage.deleteQuestion(req.params.id);
      res.status(204).send();
    } catch (error) {
      res.status(500).json({ message: "Ошибка удаления вопроса" });
    }
  });

  // Reorder questions
  app.post("/api/questions/reorder", requireAdmin, async (req, res) => {
    try {
      const { subjectId, ids } = req.body;
      if (!subjectId || !Array.isArray(ids)) {
        return res.status(400).json({ message: "subjectId и ids обязательны" });
      }
      await storage.reorderQuestions(subjectId, ids);
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ message: "Ошибка изменения порядка вопросов" });
    }
  });

  // Answers routes
  app.get("/api/questions/:questionId/answers", async (req, res) => {
    try {
      const answers = await storage.getAnswersByQuestion(req.params.questionId);
      res.json(answers);
    } catch (error) {
      res.status(500).json({ message: "Ошибка получения ответов" });
    }
  });

  app.post("/api/answers", requireAdmin, async (req, res) => {
    try {
      const validatedData = insertAnswerSchema.parse(req.body);
      const answer = await storage.createAnswer(validatedData);
      res.status(201).json(answer);
    } catch (error) {
      res.status(400).json({ message: "Ошибка создания ответа" });
    }
  });

  app.put("/api/answers/:id", requireAdmin, async (req, res) => {
    try {
      const validatedData = updateAnswerSchema.parse(req.body);
      const answer = await storage.updateAnswer(req.params.id, validatedData);
      if (!answer) {
        return res.status(404).json({ message: "Ответ не найден" });
      }
      res.json(answer);
    } catch (error) {
      console.error("Error updating answer:", error);
      res.status(400).json({ message: "Ошибка обновления ответа" });
    }
  });

  app.delete("/api/answers/:id", requireAdmin, async (req, res) => {
    try {
      await storage.deleteAnswer(req.params.id);
      res.status(204).send();
    } catch (error) {
      res.status(500).json({ message: "Ошибка удаления ответа" });
    }
  });

  // Reorder answers
  app.post("/api/answers/reorder", requireAdmin, async (req, res) => {
    try {
      const { questionId, ids } = req.body;
      if (!questionId || !Array.isArray(ids)) {
        return res.status(400).json({ message: "questionId и ids обязательны" });
      }
      await storage.reorderAnswers(questionId, ids);
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ message: "Ошибка изменения порядка ответов" });
    }
  });

  // Reorder answers by question ID
  app.put("/api/questions/:questionId/reorder-answers", requireAdmin, async (req, res) => {
    try {
      const { answerIds } = req.body;
      if (!Array.isArray(answerIds)) {
        return res.status(400).json({ message: "answerIds обязательны и должны быть массивом" });
      }
      await storage.reorderAnswers(req.params.questionId, answerIds);
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ message: "Ошибка изменения порядка ответов" });
    }
  });

  // Test routes  
  // Public test endpoint (no auth required for free variants)
  app.get("/api/public/variants/:variantId/test", async (req, res) => {
    try {
      const variant = await storage.getVariant(req.params.variantId);
      if (!variant) {
        return res.status(404).json({ message: "Вариант не найден" });
      }

      // Check if this variant is free
      if (!variant.isFree) {
        return res.status(403).json({ message: "Доступ к этому тесту требует авторизации" });
      }

      // Get the block for this variant
      const block = await storage.getBlock(variant.blockId);
      if (!block) {
        return res.status(404).json({ message: "Блок не найден" });
      }

      const subjects = await storage.getSubjectsByVariant(req.params.variantId);
      const testData = [];

      for (const subject of subjects) {
        const questions = await storage.getQuestionsBySubject(subject.id);
        const questionsWithAnswers = [];

        for (const question of questions) {
          const answers = await storage.getAnswersByQuestion(question.id);
          // Filter out isCorrect field to prevent revealing correct answers to client
          const safeAnswers = answers.map(answer => ({
            id: answer.id,
            text: answer.text,
          }));
          questionsWithAnswers.push({
            ...question,
            answers: safeAnswers,
          });
        }

        testData.push({
          subject,
          questions: questionsWithAnswers,
        });
      }

      res.json({
        variant: { ...variant, block },
        testData,
      });
    } catch (error) {
      res.status(500).json({ message: "Ошибка получения теста" });
    }
  });

  // Public test results endpoint (no auth required for free variants)
  app.post("/api/public/test-results", async (req, res) => {
    try {
      const { variantId, answers, timeSpent } = req.body;
      
      if (!variantId || !answers || timeSpent === undefined) {
        return res.status(400).json({ message: "Недостаточно данных" });
      }

      // Verify this is a free variant
      const variant = await storage.getVariant(variantId);
      if (!variant || !variant.isFree) {
        return res.status(403).json({ message: "Доступ к результатам этого теста требует авторизации" });
      }

      // Get all questions for this variant to calculate score
      const subjects = await storage.getSubjectsByVariant(variantId);
      let totalQuestions = 0;
      let totalPoints = 0;
      let earnedPoints = 0;
      
      for (const subject of subjects) {
        const questions = await storage.getQuestionsBySubject(subject.id);
        for (const question of questions) {
          totalQuestions++;
          const questionAnswers = await storage.getAnswersByQuestion(question.id);
          const correctAnswers = questionAnswers.filter(a => a.isCorrect);
          
          // 1 point per question: all correct answers selected + nothing else
          totalPoints += 1;
          
          const userAnswer = answers[question.id];
          
          // Convert to array for uniform handling
          let selectedIds: string[] = [];
          if (userAnswer) {
            selectedIds = Array.isArray(userAnswer) ? userAnswer : [userAnswer];
          }
          
          const selectedAnswers = questionAnswers.filter(a => selectedIds.includes(a.id));
          const selectedCorrect = selectedAnswers.filter(a => a.isCorrect);
          const selectedWrong = selectedAnswers.filter(a => !a.isCorrect);
          
          // Award 1 point if selected all correct and only correct
          if (selectedCorrect.length === correctAnswers.length && selectedWrong.length === 0) {
            earnedPoints += 1;
          }
        }
      }
      
      const percentage = totalPoints > 0 ? (earnedPoints / totalPoints) * 100 : 0;
      
      // Return results without saving to database (guest session)
      const result = {
        variantId,
        score: earnedPoints,
        totalQuestions,
        totalPoints,
        percentage: Math.round(percentage),
        timeSpent,
        isGuestResult: true
      };

      res.status(200).json(result);
    } catch (error) {
      res.status(500).json({ message: "Ошибка обработки результата" });
    }
  });

  app.get("/api/variants/:variantId/test", async (req, res) => {
    try {
      const variant = await storage.getVariant(req.params.variantId);
      if (!variant) {
        return res.status(404).json({ message: "Вариант не найден" });
      }

      // Get the block for this variant
      const block = await storage.getBlock(variant.blockId);
      if (!block) {
        return res.status(404).json({ message: "Блок не найден" });
      }

      const subjects = await storage.getSubjectsByVariant(req.params.variantId);
      const testData = [];

      for (const subject of subjects) {
        const questions = await storage.getQuestionsBySubject(subject.id);
        const questionsWithAnswers = [];

        for (const question of questions) {
          const answers = await storage.getAnswersByQuestion(question.id);
          // Filter out isCorrect field to prevent revealing correct answers to client
          const safeAnswers = answers.map(answer => ({
            id: answer.id,
            text: answer.text,
          }));
          questionsWithAnswers.push({
            ...question,
            answers: safeAnswers,
          });
        }

        testData.push({
          subject,
          questions: questionsWithAnswers,
        });
      }

      res.json({
        variant: { ...variant, block },
        testData,
      });
    } catch (error) {
      res.status(500).json({ message: "Ошибка получения теста" });
    }
  });

  app.post("/api/test-results", requireAuth, async (req, res) => {
    try {

      const { variantId, answers, timeSpent } = req.body;
      
      console.log('[DEBUG] Test submission received:', { variantId, timeSpent, answersCount: Object.keys(answers || {}).length });
      
      if (!variantId || !answers || timeSpent === undefined) {
        return res.status(400).json({ message: "Недостаточно данных" });
      }

      // Get all questions for this variant to calculate score
      const subjects = await storage.getSubjectsByVariant(variantId);
      let totalQuestions = 0;
      let totalPoints = 0;
      let earnedPoints = 0;
      
      console.log('[DEBUG] Starting score calculation for variant:', variantId);
      console.log('[DEBUG] Found subjects:', subjects.length);
      console.log('[DEBUG] User answers:', Object.keys(answers || {}).length, 'answers provided');
      
      for (const subject of subjects) {
        const questions = await storage.getQuestionsBySubject(subject.id);
        console.log(`[DEBUG] Subject ${subject.name}: ${questions.length} questions`);
        
        for (const question of questions) {
          totalQuestions++;
          const questionAnswers = await storage.getAnswersByQuestion(question.id);
          const correctAnswers = questionAnswers.filter(a => a.isCorrect);
          
          // Simple logic: 1 point per question if all correct answers selected and nothing else
          totalPoints += 1;
          
          const userAnswer = answers[question.id];
          console.log(`[DEBUG] Question ${question.id}: ${questionAnswers.length} answers, ${correctAnswers.length} correct`);
          console.log(`[DEBUG] User answer:`, userAnswer);
          
          // Convert userAnswer to array for uniform handling
          let selectedIds: string[] = [];
          if (userAnswer) {
            selectedIds = Array.isArray(userAnswer) ? userAnswer : [userAnswer];
          }
          
          // Check if user selected exactly the correct answers
          const selectedAnswers = questionAnswers.filter(a => selectedIds.includes(a.id));
          const selectedCorrect = selectedAnswers.filter(a => a.isCorrect);
          const selectedWrong = selectedAnswers.filter(a => !a.isCorrect);
          
          console.log(`[DEBUG] Selected: ${selectedCorrect.length} correct, ${selectedWrong.length} wrong`);
          
          // Award 1 point only if:
          // 1. Selected all correct answers
          // 2. Selected ONLY correct answers (no wrong ones)
          if (selectedCorrect.length === correctAnswers.length && selectedWrong.length === 0) {
            earnedPoints += 1;
            console.log(`[DEBUG] ✓ CORRECT! +1 point`);
          } else {
            console.log(`[DEBUG] ✗ WRONG. 0 points`);
          }
        }
      }
      
      console.log(`[DEBUG] Final: ${earnedPoints}/${totalPoints} points = ${earnedPoints/totalPoints*100}%`);
      
      const percentage = totalPoints > 0 ? (earnedPoints / totalPoints) * 100 : 0;
      
      const validatedData = insertTestResultSchema.parse({
        userId: req.user?.id,
        variantId,
        score: earnedPoints,
        totalQuestions,
        percentage,
        timeSpent,
        answers,
      });

      const result = await storage.createTestResult(validatedData);
      
      // Update user ranking
      await storage.updateUserRanking(req.user?.id!);

      // Update subject progress if provided
      if (req.body.subjectProgress) {
        for (const [subjectName, progress] of Object.entries(req.body.subjectProgress as Record<string, any>)) {
          await storage.updateSubjectProgress(
            req.user?.id!,
            subjectName,
            progress.totalAnswered,
            progress.correctAnswered
          );
        }
      }

      // Build test data with correct flags to return for review
      const reviewTestData: any[] = [];
      for (const subject of subjects) {
        const questions = await storage.getQuestionsBySubject(subject.id);
        const questionsWithAnswers = [];
        for (const question of questions) {
          const answers = await storage.getAnswersByQuestion(question.id);
          const answersWithFlag = answers.map(a => ({ id: a.id, text: a.text, isCorrect: !!a.isCorrect }));
          questionsWithAnswers.push({ ...question, answers: answersWithFlag });
        }
        reviewTestData.push({ subject, questions: questionsWithAnswers });
      }

      // Create test completion notification
      const variant = await storage.getVariant(variantId);
      if (variant) {
        let achievementMessage = "";
        if (percentage >= 90) {
          achievementMessage = " Отличная работа! 🌟";
        } else if (percentage >= 70) {
          achievementMessage = " Хорошо! 👍";
        }

        await storage.createNotification({
          userId: req.user?.id!,
          type: "TEST_COMPLETED",
          title: "Тест завершен",
          message: `Вы завершили тест ${variant.name}. Результат: ${earnedPoints}/${totalPoints} баллов (${Math.round(percentage)}%).${achievementMessage}`,
          metadata: {
            testResultId: result.id,
            variantId: variant.id,
            score: earnedPoints,
            totalQuestions,
            totalPoints,
            percentage: Math.round(percentage),
            timeSpent,
          },
          isRead: false,
          channels: ["in_app"],
        });

        // Create achievement notification for high scores
        if (percentage >= 95) {
          await storage.createNotification({
            userId: req.user?.id!,
            type: "ACHIEVEMENT",
            title: "Новое достижение! 🏆",
            message: `Превосходный результат! Вы набрали ${Math.round(percentage)}% в тесте ${variant.name}. Поздравляем!`,
            metadata: {
              achievement: "HIGH_SCORE",
              testResultId: result.id,
              percentage: Math.round(percentage),
            },
            isRead: false,
            channels: ["in_app"],
          });
        }
      }

      // Return created result plus full testData with correct flags and the user's answers
      // Wrap in testData structure to match what frontend expects
      const testDataResponse = {
        variant: await storage.getVariant(variantId),
        testData: reviewTestData
      };
      res.status(201).json({ result, testData: testDataResponse, userAnswers: answers });
    } catch (error) {
      res.status(400).json({ message: "Ошибка сохранения результата" });
    }
  });

  // Test progress endpoint for offline sync
  app.post("/api/test-progress", requireAuth, async (req, res) => {
    try {
      const { testId, variantId, answers, timeSpent, lastSavedAt } = req.body;
      
      if (!testId || !variantId || !answers) {
        return res.status(400).json({ message: "Недостаточно данных для сохранения прогресса" });
      }

      // For now, store test progress in memory or return success
      // This can be extended to save to database if needed
      console.log(`[API] Test progress saved for user ${req.user?.id}:`, {
        testId,
        variantId,
        answersCount: Object.keys(answers).length,
        timeSpent,
        lastSavedAt
      });
      
      res.json({
        success: true,
        message: "Прогресс теста сохранен",
        savedAt: new Date().toISOString()
      });
    } catch (error) {
      console.error('[API] Error saving test progress:', error);
      res.status(500).json({ message: "Ошибка сохранения прогресса теста" });
    }
  });

  // Sync endpoint for offline test data
  app.post("/api/sync/tests", requireAuth, async (req, res) => {
    try {
      const { action } = req.body;
      
      if (action === 'sync_offline_tests') {
        console.log(`[API] Syncing offline tests for user ${req.user?.id}`);
        
        // This would handle syncing offline test data
        // For now, just return success
        res.json({
          success: true,
          message: "Офлайн тесты синхронизированы",
          syncedAt: new Date().toISOString()
        });
      } else {
        res.status(400).json({ message: "Неизвестное действие синхронизации" });
      }
    } catch (error) {
      console.error('[API] Error syncing offline tests:', error);
      res.status(500).json({ message: "Ошибка синхронизации офлайн тестов" });
    }
  });

  // Get test result review data
  app.get("/api/test-results/:resultId/review", requireAuth, async (req, res) => {
    try {
      const { resultId } = req.params;
      
      // Get test result and verify it belongs to the current user
      const result = await storage.getTestResult(resultId);
      if (!result) {
        return res.status(404).json({ message: "Результат теста не найден" });
      }
      
      if (result.userId !== req.user?.id) {
        return res.status(403).json({ message: "Нет доступа к этому результату теста" });
      }
      
      // Get variant and test data
      const variant = await storage.getVariant(result.variantId);
      if (!variant) {
        return res.status(404).json({ message: "Вариант теста не найден" });
      }
      
      // Get test data with correct answers - use same structure as POST /api/test-results
      const subjects = await storage.getSubjectsByVariant(result.variantId);
      const reviewTestData: any[] = [];
      
      for (const subject of subjects) {
        const questions = await storage.getQuestionsBySubject(subject.id);
        const questionsWithAnswers = [];
        
        for (const question of questions) {
          const answers = await storage.getAnswersByQuestion(question.id);
          const answersWithFlag = answers.map(a => ({ 
            id: a.id, 
            text: a.text, 
            isCorrect: !!a.isCorrect 
          }));
          questionsWithAnswers.push({ ...question, answers: answersWithFlag });
        }
        
        reviewTestData.push({ subject, questions: questionsWithAnswers });
      }
      
      // Wrap in testData structure to match what frontend expects
      const testDataResponse = {
        variant,
        testData: reviewTestData
      };
      
      // Get user answers from the stored result
      const userAnswers = result.answers || {};
      
      console.log('[API] Review data for result:', result.id, {
        hasUserAnswers: !!result.answers,
        userAnswersCount: Object.keys(userAnswers).length,
        sampleUserAnswer: Object.entries(userAnswers)[0]
      });
      
      res.json({ 
        result, 
        variant,
        testData: testDataResponse, 
        userAnswers 
      });
    } catch (error) {
      console.error('[API] Error getting test review data:', error);
      res.status(500).json({ message: "Ошибка получения данных для просмотра теста" });
    }
  });

  // User profile routes
  app.get("/api/profile", requireAuth, async (req, res) => {
    try {

      const testResults = await storage.getTestResultsByUser(req.user?.id!);
      const ranking = await storage.getUserRanking(req.user?.id!);
      const subjectProgress = await storage.getSubjectProgress(req.user?.id!);

      res.json({
        user: req.user,
        testResults,
        ranking,
        subjectProgress,
      });
    } catch (error) {
      res.status(500).json({ message: "Ошибка получения профиля" });
    }
  });

  // Get latest test result for current user
  app.get("/api/profile/latest-result", requireAuth, async (req, res) => {
    try {

      const testResults = await storage.getTestResultsByUser(req.user?.id!);
      
      if (testResults.length === 0) {
        return res.status(404).json({ message: "Результаты тестов не найдены" });
      }

      // Sort by completedAt and get the latest one
      const latestResult = testResults.sort((a, b) => 
        new Date(b.completedAt!).getTime() - new Date(a.completedAt!).getTime()
      )[0];

      res.json(latestResult);
    } catch (error) {
      res.status(500).json({ message: "Ошибка получения последнего результата" });
    }
  });

  // Rankings routes
  app.get("/api/rankings", async (req, res) => {
    try {
      const rankings = await storage.getAllRankings();
      const rankingsWithUsernames = [];

      for (const ranking of rankings) {
        const user = await storage.getUser(ranking.userId);
        if (user) {
          rankingsWithUsernames.push({
            ...ranking,
            username: user.username,
          });
        }
      }

      res.json(rankingsWithUsernames);
    } catch (error) {
      res.status(500).json({ message: "Ошибка получения рейтинга" });
    }
  });

  // Best result for today (all users)
  app.get("/api/rankings/today-best", async (req, res) => {
    try {
      const bestResult = await storage.getTodayBestResult();
      if (!bestResult) {
        return res.json({ score: 0 });
      }
      res.json({ score: bestResult.score });
    } catch (error) {
      console.error('[API] Error fetching today best result:', error);
      res.status(500).json({ message: "Ошибка получения лучшего результата" });
    }
  });

  // Debug endpoint for today best result
  app.get("/api/debug/today-best", async (req, res) => {
    try {
      console.log('[DEBUG] Starting today best result debug...');
      
      // Get all test results
      const allResults = await db
        .select({ 
          id: testResults.id,
          score: testResults.score, 
          completedAt: testResults.completedAt,
          userId: testResults.userId
        })
        .from(testResults)
        .orderBy(desc(testResults.completedAt))
        .limit(10);
      
      // Get today's date info
      const now = new Date();
      const kazakhstanOffset = 6 * 60;
      const localTime = new Date(now.getTime() + (kazakhstanOffset * 60 * 1000));
      
      const todayStart = new Date(localTime);
      todayStart.setHours(0, 0, 0, 0);
      const todayEnd = new Date(localTime);
      todayEnd.setHours(23, 59, 59, 999);
      
      const utcTodayStart = new Date(todayStart.getTime() - (kazakhstanOffset * 60 * 1000));
      const utcTodayEnd = new Date(todayEnd.getTime() - (kazakhstanOffset * 60 * 1000));
      
      // Filter today's results
      const todayResults = allResults.filter(result => {
        if (!result.completedAt) return false;
        const resultDate = new Date(result.completedAt);
        return resultDate >= utcTodayStart && resultDate <= utcTodayEnd;
      });
      
      const debugInfo = {
        currentUTC: now.toISOString(),
        kazakhstanTime: localTime.toISOString(),
        todayRange: {
          start: utcTodayStart.toISOString(),
          end: utcTodayEnd.toISOString()
        },
        totalResults: allResults.length,
        todayResults: todayResults.length,
        recentResults: allResults.map(r => ({
          id: r.id.substring(0, 8),
          score: r.score,
          completedAt: r.completedAt ? new Date(r.completedAt).toISOString() : null,
          isToday: r.completedAt ? (new Date(r.completedAt) >= utcTodayStart && new Date(r.completedAt) <= utcTodayEnd) : false
        })),
        bestTodayScore: todayResults.length > 0 ? Math.max(...todayResults.map(r => r.score)) : 0
      };
      
      console.log('[DEBUG] Debug info:', JSON.stringify(debugInfo, null, 2));
      res.json(debugInfo);
      
    } catch (error) {
      console.error('[DEBUG] Error in debug endpoint:', error);
      res.status(500).json({ error: error.message });
    }
  });

  // Analytics routes
  app.get("/api/analytics/overview", requireAuth, async (req, res) => {
    try {
      const overview = await storage.getAnalyticsOverview(req.user?.id!);
      const validatedData = analyticsOverviewSchema.parse(overview);
      res.json(validatedData);
    } catch (error) {
      res.status(500).json({ message: "Ошибка получения общей аналитики" });
    }
  });

  app.get("/api/analytics/subjects", requireAuth, async (req, res) => {
    try {
      const subjects = await storage.getSubjectAggregates(req.user?.id!);
      const validatedData = subjects.map(subject => subjectAggregateSchema.parse(subject));
      res.json(validatedData);
    } catch (error) {
      res.status(500).json({ message: "Ошибка получения аналитики по предметам" });
    }
  });

  app.get("/api/analytics/history", requireAuth, async (req, res) => {
    try {
      const rangeDays = req.query.range ? parseInt(req.query.range as string) : 30;
      
      if (isNaN(rangeDays) || rangeDays <= 0 || rangeDays > 365) {
        return res.status(400).json({ message: "Недопустимый диапазон дней (1-365)" });
      }

      const history = await storage.getHistory(req.user?.id!, rangeDays);
      const validatedData = history.map(point => historyPointSchema.parse(point));
      res.json(validatedData);
    } catch (error) {
      res.status(500).json({ message: "Ошибка получения исторической аналитики" });
    }
  });

  app.get("/api/analytics/correctness", requireAuth, async (req, res) => {
    try {
      const rangeDays = req.query.range ? parseInt(req.query.range as string) : 30;
      
      if (isNaN(rangeDays) || rangeDays <= 0 || rangeDays > 365) {
        return res.status(400).json({ message: "Недопустимый диапазон дней (1-365)" });
      }

      const breakdown = await storage.getCorrectnessBreakdown(req.user?.id!, rangeDays);
      const validatedData = breakdown.map(point => correctnessBreakdownSchema.parse(point));
      res.json(validatedData);
    } catch (error) {
      res.status(500).json({ message: "Ошибка получения аналитики правильности ответов" });
    }
  });

  app.get("/api/analytics/comparison", requireAuth, async (req, res) => {
    try {
      const comparison = await storage.getComparison(req.user?.id!);
      const validatedData = comparisonStatsSchema.parse(comparison);
      res.json(validatedData);
    } catch (error) {
      res.status(500).json({ message: "Ошибка получения сравнительной аналитики" });
    }
  });

  // Notification routes
  app.get("/api/notifications", requireAuth, async (req, res) => {
    try {
      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 10;
      const type = req.query.type ? notificationTypeSchema.parse(req.query.type) : undefined;
      
      const result = await storage.getNotifications(req.user?.id!, page, limit, type);
      res.json(result);
    } catch (error) {
      res.status(500).json({ message: "Ошибка получения уведомлений" });
    }
  });

  app.get("/api/notifications/unread-count", requireAuth, async (req, res) => {
    try {
      const count = await storage.getUnreadNotificationCount(req.user?.id!);
      res.json({ count });
    } catch (error) {
      res.status(500).json({ message: "Ошибка получения количества непрочитанных уведомлений" });
    }
  });

  app.post("/api/notifications/:id/mark-read", requireAuth, async (req, res) => {
    try {
      await storage.markNotificationAsRead(req.params.id, req.user?.id!);
      res.status(204).send();
    } catch (error) {
      res.status(500).json({ message: "Ошибка отметки уведомления как прочитанного" });
    }
  });

  app.post("/api/notifications/mark-all-read", requireAuth, async (req, res) => {
    try {
      await storage.markAllNotificationsAsRead(req.user?.id!);
      res.status(204).send();
    } catch (error) {
      res.status(500).json({ message: "Ошибка отметки всех уведомлений как прочитанных" });
    }
  });

  app.delete("/api/notifications/:id", requireAuth, async (req, res) => {
    try {
      await storage.deleteNotification(req.params.id, req.user?.id!);
      res.status(204).send();
    } catch (error) {
      res.status(500).json({ message: "Ошибка удаления уведомления" });
    }
  });

  app.post("/api/notifications/broadcast", requireAdmin, async (req, res) => {
    try {
      const validatedData = insertNotificationSchema.omit({ userId: true }).parse(req.body);
      
      // Get all users and create notifications for each
      const rankings = await storage.getAllRankings();
      const notifications = [];
      
      for (const ranking of rankings) {
        const notification = await storage.createNotification({
          ...validatedData,
          userId: ranking.userId,
        });
        notifications.push(notification);
      }
      
      res.status(201).json({ created: notifications.length });
    } catch (error) {
      res.status(400).json({ message: "Ошибка рассылки уведомлений" });
    }
  });

  // Notification Settings routes
  app.get("/api/notification-settings", requireAuth, async (req, res) => {
    try {
      const settings = await storage.getNotificationSettings(req.user?.id!);
      if (!settings) {
        // Return default settings if none exist
        const defaultSettings = {
          userId: req.user?.id!,
          testCompletedEnabled: true,
          testReminderEnabled: true,
          systemMessageEnabled: true,
          achievementEnabled: true,
          inAppEnabled: true,
          pushEnabled: false,
          emailEnabled: false,
          reminderIntervalMinutes: 30,
          maxRemindersPerDay: 3,
          quietHoursStart: "22:00",
          quietHoursEnd: "08:00",
          updatedAt: new Date(),
        };
        res.json(defaultSettings);
      } else {
        res.json(settings);
      }
    } catch (error) {
      res.status(500).json({ message: "Ошибка получения настроек уведомлений" });
    }
  });

  app.put("/api/notification-settings", requireAuth, async (req, res) => {
    try {
      const validatedData = insertNotificationSettingsSchema.parse({
        ...req.body,
        userId: req.user?.id!,
      });
      const settings = await storage.upsertNotificationSettings(validatedData);
      res.json(settings);
    } catch (error) {
      res.status(400).json({ message: "Ошибка обновления настроек уведомлений" });
    }
  });

  // Reminder routes
  app.get("/api/reminders", requireAuth, async (req, res) => {
    try {
      const reminders = await storage.getReminders(req.user?.id!);
      res.json(reminders);
    } catch (error) {
      res.status(500).json({ message: "Ошибка получения напоминаний" });
    }
  });

  app.post("/api/reminders", requireAuth, async (req, res) => {
    try {
      const validatedData = insertReminderSchema.parse({
        ...req.body,
        userId: req.user?.id!,
      });
      const reminder = await storage.createReminder(validatedData);
      res.status(201).json(reminder);
    } catch (error) {
      res.status(400).json({ message: "Ошибка создания напоминания" });
    }
  });

  app.patch("/api/reminders/:id", requireAuth, async (req, res) => {
    try {
      const validatedData = insertReminderSchema.partial().parse(req.body);
      const reminder = await storage.updateReminder(req.params.id, validatedData);
      if (!reminder) {
        return res.status(404).json({ message: "Напоминание не найдено" });
      }
      res.json(reminder);
    } catch (error) {
      res.status(400).json({ message: "Ошибка обновления напоминания" });
    }
  });

  app.delete("/api/reminders/:id", requireAuth, async (req, res) => {
    try {
      await storage.deleteReminder(req.params.id, req.user?.id!);
      res.status(204).send();
    } catch (error) {
      res.status(500).json({ message: "Ошибка удаления напоминания" });
    }
  });

  // Export routes
  app.post("/api/exports", requireExportRateLimit, async (req, res) => {
    try {
      const { type, format, options } = req.body;
      
      // Validate input
      exportTypeSchema.parse(type);
      exportFormatSchema.parse(format);
      const validatedOptions = exportOptionsSchema.parse(options || {});
      
      const exportJob = await storage.createExportJob({
        userId: req.user?.id!,
        type,
        format,
        options: validatedOptions,
        status: "PENDING",
        progress: 0,
      });

      // Increment rate limiting counters
      await storage.incrementExportCount(req.user?.id!);
      
      res.status(201).json({ jobId: exportJob.id });
    } catch (error) {
      res.status(400).json({ message: "Ошибка создания задания экспорта" });
    }
  });

  app.get("/api/exports/:id/status", requireAuth, async (req, res) => {
    try {
      const job = await storage.getExportJob(req.params.id);
      if (!job || job.userId !== req.user?.id) {
        return res.status(404).json({ message: "Задание не найдено" });
      }

      const response: any = {
        status: job.status,
        progress: job.progress,
        createdAt: job.createdAt,
        completedAt: job.completedAt,
      };

      if (job.status === "COMPLETED" && job.fileKey) {
        response.downloadUrl = `/api/exports/${job.id}/download`;
        response.fileName = job.fileName;
        response.fileSize = job.fileSize;
      }

      if (job.status === "FAILED") {
        response.error = job.errorMessage;
      }

      res.json(response);
    } catch (error) {
      res.status(500).json({ message: "Ошибка получения статуса задания" });
    }
  });

  app.get("/api/exports/:id/download", requireAuth, async (req, res) => {
    try {
      const job = await storage.getExportJob(req.params.id);
      if (!job || job.userId !== req.user?.id) {
        return res.status(404).json({ message: "Задание не найдено" });
      }

      if (job.status !== "COMPLETED" || !job.fileKey) {
        return res.status(404).json({ message: "Файл недоступен" });
      }

      const fileBuffer = await storage.getFile(job.fileKey);
      if (!fileBuffer) {
        return res.status(404).json({ message: "Файл не найден или истек" });
      }

      const contentType = job.format === "PDF" ? "application/pdf" : 
                         "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";

      res.setHeader("Content-Type", contentType);
      res.setHeader("Content-Length", fileBuffer.length);
      res.setHeader("Content-Disposition", `attachment; filename="${job.fileName}"`);
      res.send(fileBuffer);
    } catch (error) {
      res.status(500).json({ message: "Ошибка скачивания файла" });
    }
  });

  app.get("/api/exports", requireAuth, async (req, res) => {
    try {
      const limit = Math.min(parseInt(req.query.limit as string) || 10, 50);
      const jobs = await storage.listExportJobsByUser(req.user?.id!, limit);
      res.json(jobs);
    } catch (error) {
      res.status(500).json({ message: "Ошибка получения списка экспортов" });
    }
  });

  app.delete("/api/exports/:id", requireAuth, async (req, res) => {
    try {
      await storage.deleteExportJob(req.params.id, req.user?.id!);
      res.status(204).send();
    } catch (error) {
      res.status(500).json({ message: "Ошибка удаления задания экспорта" });
    }
  });

  // Admin endpoint for monitoring exports
  app.get("/api/admin/exports", requireAdmin, async (req, res) => {
    try {
      const pendingJobs = await storage.getPendingExportJobs();
      res.json(pendingJobs);
    } catch (error) {
      res.status(500).json({ message: "Ошибка получения заданий экспорта" });
    }
  });

  // Push notification subscription routes
  app.post("/api/push/subscribe", requireAuth, async (req, res) => {
    try {
      const { endpoint, keys } = req.body;
      
      if (!endpoint || !keys || !keys.p256dh || !keys.auth) {
        return res.status(400).json({ message: "Недостаточно данных подписки" });
      }

      // Save subscription to storage (this would need to be implemented in storage)
      console.log(`[Push] Subscription saved for user ${req.user?.id}:`, {
        endpoint,
        p256dh: keys.p256dh.substring(0, 20) + '...',
        auth: keys.auth.substring(0, 20) + '...'
      });
      
      res.json({
        success: true,
        message: "Подписка на уведомления успешно сохранена"
      });
    } catch (error) {
      console.error('[Push] Error saving subscription:', error);
      res.status(500).json({ message: "Ошибка сохранения подписки" });
    }
  });

  app.post("/api/push/unsubscribe", requireAuth, async (req, res) => {
    try {
      const { endpoint } = req.body;
      
      if (!endpoint) {
        return res.status(400).json({ message: "Endpoint не указан" });
      }

      // Remove subscription from storage
      console.log(`[Push] Subscription removed for user ${req.user?.id}, endpoint:`, endpoint);
      
      res.json({
        success: true,
        message: "Подписка на уведомления отменена"
      });
    } catch (error) {
      console.error('[Push] Error removing subscription:', error);
      res.status(500).json({ message: "Ошибка отмены подписки" });
    }
  });

  app.post("/api/push/test", requireAuth, async (req, res) => {
    try {
      // This would send a test push notification
      console.log(`[Push] Test notification requested for user ${req.user?.id}`);
      
      res.json({
        success: true,
        message: "Тестовое уведомление отправлено"
      });
    } catch (error) {
      console.error('[Push] Error sending test notification:', error);
      res.status(500).json({ message: "Ошибка отправки тестового уведомления" });
    }
  });

  // Get VAPID public key for frontend
  app.get("/api/push/vapid-key", (req, res) => {
    res.json({
      publicKey: 'BCHhBDxcAj5TrD2Zzg3g3UjgBHO9SjO9SjO9SjO9SjO9SjO9SjO9SjO9SjO9SjO9SjO9Sj'
    });
  });

  // Video proctoring has been fully removed from the application.
  // All related endpoints and handlers were deleted as part of the proctoring removal.
  
  // Temporary endpoint to create admin user (remove in production)
  app.post("/api/create-admin", async (req, res) => {
    console.log('[API] Creating admin user...');
    try {
      // Check if admin already exists
      const existingAdmin = await storage.getUserByUsername("admin");
      if (existingAdmin) {
        return res.json({ message: "Админ уже существует", user: { username: existingAdmin.username, email: existingAdmin.email } });
      }
      
      // Import hashPassword from auth
      const { hashPassword } = await import('./auth');
      
      // Create admin user
      const adminUser = await storage.createUser({
        username: "admin",
        email: "admin@example.com",
        password: await hashPassword("admin123")
      });
      
      res.json({ message: "Админ создан успешно", user: { username: adminUser.username, email: adminUser.email } });
    } catch (error) {
      console.error('[API] Error creating admin:', error);
      res.status(500).json({ message: "Ошибка создания админа" });
    }
  });

  // Make current user admin (temporary, remove after first use)
  app.post("/api/make-me-admin", requireAuth, async (req, res) => {
    try {
      if (!req.user) {
        return res.status(401).json({ message: "Not authenticated" });
      }
      
      const userId = req.user.id;
      
      // Import db from ./db
      const { db } = await import('./db');
      const { users } = await import('@shared/schema');
      const { eq } = await import('drizzle-orm');
      
      // Update username to "admin" to grant admin privileges
      const result = await db.update(users)
        .set({ username: 'admin' })
        .where(eq(users.id, userId))
        .returning({ id: users.id, username: users.username, email: users.email });
      
      if (result.length > 0) {
        res.json({ message: "You are now admin! Please re-login with username 'admin'.", user: result[0] });
      } else {
        res.status(404).json({ message: "User not found" });
      }
    } catch (error) {
      console.error('[API] Error making user admin:', error);
      res.status(500).json({ message: "Error updating user: " + (error as Error).message });
    }
  });
  
  // System settings endpoints
  app.get("/api/settings/:key", async (req, res) => {
    try {
      const { key } = req.params;
      const setting = await storage.getSystemSetting(key);
      
      if (!setting) {
        return res.status(404).json({ message: "Настройка не найдена" });
      }
      
      res.json({ key: setting.key, value: setting.value });
    } catch (error) {
      console.error('[API] Error fetching setting:', error);
      res.status(500).json({ message: "Ошибка получения настройки" });
    }
  });

  app.put("/api/admin/settings/:key", requireAdmin, async (req, res) => {
    try {
      const { key } = req.params;
      const { value } = req.body;
      
      if (!value) {
        return res.status(400).json({ message: "Значение обязательно" });
      }
      
      const setting = await storage.updateSystemSetting(key, value, req.user!.id);
      res.json(setting);
    } catch (error) {
      console.error('[API] Error updating setting:', error);
      res.status(500).json({ message: "Ошибка обновления настройки" });
    }
  });

  // Admin user management endpoints
  app.get("/api/admin/users", requireAdmin, async (req, res) => {
    try {
      console.log('[API] Fetching all users...');
      const users = await storage.getAllUsers();
      console.log('[API] Users found:', users.length);
      res.json(users);
    } catch (error) {
      console.error('[API] Error fetching users:', error);
      res.status(500).json({ message: "Ошибка получения пользователей" });
    }
  });

  app.delete("/api/admin/users/:userId", requireAdmin, async (req, res) => {
    try {
      const { userId } = req.params;
      
      // Prevent deletion of admin user
      const user = await storage.getUserById(userId);
      if (user?.username === "admin") {
        return res.status(403).json({ message: "Нельзя удалить администратора" });
      }
      
      await storage.deleteUser(userId);
      res.status(204).send();
    } catch (error) {
      console.error('[API] Error deleting user:', error);
      res.status(500).json({ message: "Ошибка удаления пользователя" });
    }
  });

  app.post("/api/admin/users/:userId/reset-password", requireAdmin, async (req, res) => {
    try {
      const { userId } = req.params;
      const newPassword = await storage.resetUserPassword(userId);
      res.json({ newPassword });
    } catch (error) {
      console.error('[API] Error resetting password:', error);
      res.status(500).json({ message: "Ошибка сброса пароля" });
    }
  });

  // Copy subjects between variants endpoint
  app.post("/api/admin/copy-subjects", requireAdmin, async (req, res) => {
    try {
      const { sourceVariantId, targetVariantId, subjectIds } = req.body;
      
      if (!sourceVariantId || !targetVariantId || !subjectIds || !Array.isArray(subjectIds)) {
        return res.status(400).json({ 
          message: "Требуются sourceVariantId, targetVariantId и массив subjectIds" 
        });
      }

      console.log('[API] Copying subjects:', { sourceVariantId, targetVariantId, subjectIds });
      
      const copiedSubjects = await storage.copySubjects(sourceVariantId, targetVariantId, subjectIds);
      
      res.json({ 
        message: "Предметы успешно скопированы",
        copiedSubjects: copiedSubjects.length,
        subjects: copiedSubjects
      });
    } catch (error) {
      console.error('[API] Error copying subjects:', error);
      res.status(500).json({ message: "Ошибка копирования предметов" });
    }
  });

  // Quotes management endpoints
  app.get("/api/quotes", async (req, res) => {
    try {
      const quotes = await storage.getAllQuotes();
      res.json(quotes);
    } catch (error) {
      console.error('[API] Error fetching quotes:', error);
      res.status(500).json({ message: "Ошибка загрузки цитат" });
    }
  });

  app.get("/api/quotes/month/:month", async (req, res) => {
    try {
      const month = parseInt(req.params.month);
      if (month < 1 || month > 12) {
        return res.status(400).json({ message: "Месяц должен быть от 1 до 12" });
      }
      const quotes = await storage.getQuotesByMonth(month);
      res.json(quotes);
    } catch (error) {
      console.error('[API] Error fetching quotes for month:', error);
      res.status(500).json({ message: "Ошибка загрузки цитат" });
    }
  });

  app.get("/api/quotes/current", async (req, res) => {
    try {
      const quote = await storage.getCurrentQuote();
      res.json(quote);
    } catch (error) {
      console.error('[API] Error fetching current quote:', error);
      res.status(500).json({ message: "Ошибка загрузки цитаты" });
    }
  });

  app.post("/api/admin/quotes", requireAdmin, async (req, res) => {
    try {
      const { text, author, month } = req.body;
      if (!text || !author || !month) {
        return res.status(400).json({ message: "Требуются text, author и month" });
      }
      const quote = await storage.createQuote({ text, author, month, order: 0 });
      res.status(201).json(quote);
    } catch (error) {
      console.error('[API] Error creating quote:', error);
      res.status(500).json({ message: "Ошибка создания цитаты" });
    }
  });

  app.put("/api/admin/quotes/:id", requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      const { text, author, month } = req.body;
      const quote = await storage.updateQuote(id, { text, author, month });
      res.json(quote);
    } catch (error) {
      console.error('[API] Error updating quote:', error);
      res.status(500).json({ message: "Ошибка обновления цитаты" });
    }
  });

  app.delete("/api/admin/quotes/:id", requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      await storage.deleteQuote(id);
      res.status(204).send();
    } catch (error) {
      console.error('[API] Error deleting quote:', error);
      res.status(500).json({ message: "Ошибка удаления цитаты" });
    }
  });

  app.post("/api/admin/quotes/reorder", requireAdmin, async (req, res) => {
    try {
      const { month, ids } = req.body;
      if (!month || !ids || !Array.isArray(ids)) {
        return res.status(400).json({ message: "Требуются month и массив ids" });
      }
      await storage.reorderQuotes(month, ids);
      res.json({ message: "Порядок цитат обновлен" });
    } catch (error) {
      console.error('[API] Error reordering quotes:', error);
      res.status(500).json({ message: "Ошибка изменения порядка цитат" });
    }
  });

  // =================== PAYMENT SYSTEM ROUTES ===================
  
  // Get all subscription plans
  app.get("/api/subscription/plans", async (req, res) => {
    try {
      const plans = await storage.getSubscriptionPlans();
      res.json(plans);
    } catch (error) {
      console.error('[API] Error fetching subscription plans:', error);
      res.status(500).json({ message: "Ошибка загрузки тарифных планов" });
    }
  });

  // Get current user subscription
  app.get("/api/subscription/current", requireAuth, async (req, res) => {
    try {
      const subscription = await storage.getCurrentUserSubscription(req.user!.id);
      if (!subscription) {
        return res.status(404).json({ message: "Подписка не найдена" });
      }
      res.json(subscription);
    } catch (error) {
      console.error('[API] Error fetching current subscription:', error);
      res.status(500).json({ message: "Ошибка загрузки подписки" });
    }
  });

  // Create payment for subscription
  app.post("/api/payments/create", requireAuth, async (req, res) => {
    try {
      const { planId } = req.body;
      if (!planId) {
        return res.status(400).json({ message: "Требуется planId" });
      }

      const plan = await storage.getSubscriptionPlan(planId);
      if (!plan) {
        return res.status(404).json({ message: "Тарифный план не найден" });
      }

      // Создаем запись платежа
      const payment = await storage.createPayment({
        userId: req.user!.id,
        planId: planId,
        amount: plan.price,
        currency: plan.currency,
        status: "PENDING",
        paymentMethod: "card", // По умолчанию карта
      });

      // TODO: Интеграция с платежной системой (Stripe, Yookassa и т.д.)
      // Пока возвращаем mock URL для тестирования
      const paymentUrl = `/payment/${payment.id}?mock=true`;

      res.json({
        paymentId: payment.id,
        paymentUrl: paymentUrl,
        amount: plan.price,
        currency: plan.currency,
      });
    } catch (error) {
      console.error('[API] Error creating payment:', error);
      res.status(500).json({ message: "Ошибка создания платежа" });
    }
  });

  // Mock payment completion (для тестирования)
  app.post("/api/payments/:paymentId/complete", async (req, res) => {
    try {
      const { paymentId } = req.params;
      const payment = await storage.getPayment(paymentId);
      
      if (!payment) {
        return res.status(404).json({ message: "Платеж не найден" });
      }

      // Обновляем статус платежа
      await storage.updatePaymentStatus(paymentId, "COMPLETED");

      // Создаем или обновляем подписку пользователя
      const plan = await storage.getSubscriptionPlan(payment.planId);
      if (plan) {
        const startDate = new Date();
        const endDate = new Date();
        endDate.setDate(startDate.getDate() + plan.durationDays);

        await storage.createOrUpdateUserSubscription({
          userId: payment.userId,
          planId: payment.planId,
          blockId: plan.blockId, // Сохраняем blockId из плана
          status: "ACTIVE",
          startDate: startDate,
          endDate: endDate,
          autoRenew: false,
        });
      }

      res.json({ success: true, message: "Платеж успешно обработан" });
    } catch (error) {
      console.error('[API] Error completing payment:', error);
      res.status(500).json({ message: "Ошибка обработки платежа" });
    }
  });

  // Admin: Get all subscription plans
  app.get("/api/admin/subscription/plans", requireAdmin, async (req, res) => {
    try {
      const plans = await storage.getSubscriptionPlans();
      res.json(plans);
    } catch (error) {
      console.error('[API] Error fetching subscription plans:', error);
      res.status(500).json({ message: "Ошибка загрузки тарифных планов" });
    }
  });

  // Admin: Create subscription plan
  app.post("/api/admin/subscription/plans", requireAdmin, async (req, res) => {
    try {
      const plan = await storage.createSubscriptionPlan(req.body);
      res.status(201).json(plan);
    } catch (error) {
      console.error('[API] Error creating subscription plan:', error);
      res.status(500).json({ message: "Ошибка создания тарифного плана" });
    }
  });

  // Admin: Update subscription plan
  app.put("/api/admin/subscription/plans/:id", requireAdmin, async (req, res) => {
    try {
      const plan = await storage.updateSubscriptionPlan(req.params.id, req.body);
      res.json(plan);
    } catch (error) {
      console.error('[API] Error updating subscription plan:', error);
      res.status(500).json({ message: "Ошибка обновления тарифного плана" });
    }
  });

  // Admin: Get all payments
  app.get("/api/admin/payments", requireAdmin, async (req, res) => {
    try {
      const payments = await storage.getAllPayments();
      res.json(payments);
    } catch (error) {
      console.error('[API] Error fetching payments:', error);
      res.status(500).json({ message: "Ошибка загрузки платежей" });
    }
  });

  // Admin: Get all user subscriptions
  app.get("/api/admin/subscriptions", requireAdmin, async (req, res) => {
    try {
      const subscriptions = await storage.getAllUserSubscriptions();
      res.json(subscriptions);
    } catch (error) {
      console.error('[API] Error fetching subscriptions:', error);
      res.status(500).json({ message: "Ошибка загрузки подписок" });
    }
  });

  // Check access to block
  app.get("/api/subscription/block-access/:blockId", requireAuth, async (req, res) => {
    try {
      const { blockId } = req.params;
      const hasAccess = await storage.hasBlockAccess(req.user!.id, blockId);
      res.json({ hasAccess });
    } catch (error) {
      console.error('[API] Error checking block access:', error);
      res.status(500).json({ message: "Ошибка проверки доступа" });
    }
  });

  // Check single test access
  app.get("/api/subscription/single-test-access", requireAuth, async (req, res) => {
    try {
      const hasAccess = await storage.hasSingleTestAccess(req.user!.id);
      res.json({ hasAccess });
    } catch (error) {
      console.error('[API] Error checking single test access:', error);
      res.status(500).json({ message: "Ошибка проверки доступа к тесту" });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
