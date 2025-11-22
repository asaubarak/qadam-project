import PDFDocument from 'pdfkit';
import { createCanvas, loadImage, registerFont } from 'canvas';
import { Chart, registerables } from 'chart.js';
import { 
  ExportType, 
  ExportOptions,
  AnalyticsOverview,
  SubjectAggregate,
  HistoryPoint,
  TestResult,
  UserRanking
} from '@shared/schema';
import { storage } from '../storage';

// Register Chart.js components
Chart.register(...registerables);

export class PDFService {
  private static readonly FONTS = {
    regular: 'Helvetica',
    bold: 'Helvetica-Bold',
    title: 'Helvetica-Bold'
  };

  private static readonly COLORS = {
    primary: '#2563eb',
    accent: '#10b981', 
    text: '#374151',
    lightText: '#6b7280',
    background: '#f9fafb',
    border: '#d1d5db'
  };

  static async generateReport(
    userId: string, 
    type: ExportType, 
    format: 'PDF',
    options: ExportOptions
  ): Promise<Buffer> {
    const doc = new PDFDocument({ 
      size: 'A4', 
      margin: 50,
      info: {
        Title: this.getReportTitle(type),
        Author: 'Test System',
        Subject: 'Test Results Export',
        Keywords: 'test, results, analytics, export'
      }
    });

    const chunks: Buffer[] = [];
    doc.on('data', (chunk) => chunks.push(chunk));
    doc.on('end', () => {});

    try {
      switch (type) {
        case 'USER_ANALYTICS':
          await this.generateUserAnalyticsPDF(doc, userId, options);
          break;
        case 'TEST_REPORT': 
          await this.generateTestReportPDF(doc, userId, options);
          break;
        case 'RANKINGS':
          await this.generateRankingsPDF(doc, userId, options);
          break;
        case 'PERIOD_SUMMARY':
          await this.generatePeriodSummaryPDF(doc, userId, options);
          break;
        default:
          throw new Error(`Неподдерживаемый тип экспорта: ${type}`);
      }

      doc.end();
      await new Promise((resolve) => doc.on('end', resolve));
      return Buffer.concat(chunks);

    } catch (error) {
      doc.end();
      throw error;
    }
  }

  private static async generateUserAnalyticsPDF(
    doc: PDFKit.PDFDocument, 
    userId: string, 
    options: ExportOptions
  ): Promise<void> {
    // Header
    this.addHeader(doc, 'Аналитика результатов', options.title);

    // Get data
    const overview = await storage.getAnalyticsOverview(userId);
    const subjects = await storage.getSubjectAggregates(userId);
    const history = await storage.getHistory(userId, options.dateRange?.from ? 30 : undefined);

    // Overview section
    doc.fontSize(16).fillColor(this.COLORS.primary).text('Общая статистика', 50, 150);
    doc.moveDown();

    const overviewData = [
      ['Всего тестов:', overview.totalTests.toString()],
      ['Средний балл:', `${overview.averageScore.toFixed(1)}%`],
      ['Время изучения:', this.formatTime(overview.totalTimeSpent)],
      ['Лучший предмет:', overview.bestSubject],
      ['Слабый предмет:', overview.worstSubject],
      ['Правильных ответов:', `${overview.correctAnswers}/${overview.totalQuestions}`]
    ];

    this.addTable(doc, overviewData, { startY: doc.y, leftMargin: 50 });

    // Subject breakdown
    if (subjects.length > 0) {
      doc.addPage();
      doc.fontSize(16).fillColor(this.COLORS.primary).text('Результаты по предметам', 50, 50);
      doc.moveDown();

      const subjectData = subjects.map(s => [
        s.subjectName,
        s.testsCount.toString(),
        `${s.averageScore.toFixed(1)}%`,
        this.formatTime(s.averageTimeSpent)
      ]);

      this.addTable(doc, [
        ['Предмет', 'Тестов', 'Средний балл', 'Среднее время'],
        ...subjectData
      ], { startY: doc.y, leftMargin: 50, hasHeader: true });
    }

    // Charts (if enabled)
    if (options.includeCharts && history.length > 0) {
      doc.addPage();
      doc.fontSize(16).fillColor(this.COLORS.primary).text('График прогресса', 50, 50);
      
      try {
        const chartBuffer = await this.generateProgressChart(history);
        doc.image(chartBuffer, 50, 100, { width: 500, height: 300 });
      } catch (error) {
        doc.fontSize(12).fillColor(this.COLORS.lightText)
          .text('Не удалось сгенерировать график', 50, 100);
      }
    }

    // Footer
    this.addFooter(doc);
  }

  private static async generateTestReportPDF(
    doc: PDFKit.PDFDocument,
    userId: string, 
    options: ExportOptions
  ): Promise<void> {
    this.addHeader(doc, 'Отчет по тестам', options.title);

    const testResults = await storage.getTestResultsByUser(userId);
    
    if (testResults.length === 0) {
      doc.fontSize(14).fillColor(this.COLORS.text)
        .text('Тесты не найдены', 50, 150);
      return;
    }

    // Filter by date range if provided
    let filteredResults = testResults;
    if (options.dateRange?.from || options.dateRange?.to) {
      filteredResults = testResults.filter(result => {
        const completedAt = result.completedAt || Date.now();
        const date = new Date(completedAt);
        if (options.dateRange?.from && date < new Date(options.dateRange.from)) return false;
        if (options.dateRange?.to && date > new Date(options.dateRange.to)) return false;
        return true;
      });
    }

    doc.fontSize(16).fillColor(this.COLORS.primary).text('Результаты тестов', 50, 150);
    doc.moveDown();

    const resultsData = filteredResults.map(result => [
      new Date(result.completedAt || Date.now()).toLocaleDateString('ru-RU'),
      `${result.score}/${result.totalQuestions}`,
      `${result.percentage.toFixed(1)}%`,
      this.formatTime(result.timeSpent / 60) // Convert seconds to minutes
    ]);

    this.addTable(doc, [
      ['Дата', 'Баллы', 'Процент', 'Время'],
      ...resultsData
    ], { startY: doc.y, leftMargin: 50, hasHeader: true });

    this.addFooter(doc);
  }

  private static async generateRankingsPDF(
    doc: PDFKit.PDFDocument,
    userId: string,
    options: ExportOptions
  ): Promise<void> {
    this.addHeader(doc, 'Рейтинг пользователей', options.title);

    const rankings = await storage.getAllRankings();
    const userRanking = await storage.getUserRanking(userId);

    doc.fontSize(16).fillColor(this.COLORS.primary).text('Общий рейтинг', 50, 150);
    doc.moveDown();

    if (userRanking) {
      const userRank = rankings.findIndex(r => r.userId === userId) + 1;
      doc.fontSize(14).fillColor(this.COLORS.accent)
        .text(`Ваша позиция: #${userRank}`, 50, doc.y);
      doc.moveDown();
    }

    const rankingData = rankings.slice(0, 20).map((ranking, index) => [
      `#${index + 1}`,
      ranking.userId === userId ? 'Вы' : `User-${ranking.userId.slice(-4)}`,
      String(ranking.totalScore ?? 0),
      String(ranking.testsCompleted ?? 0),
      `${((ranking.averagePercentage ?? 0).toFixed(1))}%`
    ]);

    this.addTable(doc, [
      ['Место', 'Пользователь', 'Баллы', 'Тестов', 'Средний %'],
      ...rankingData
    ], { startY: doc.y, leftMargin: 50, hasHeader: true });

    this.addFooter(doc);
  }

  private static async generatePeriodSummaryPDF(
    doc: PDFKit.PDFDocument,
    userId: string,
    options: ExportOptions
  ): Promise<void> {
    this.addHeader(doc, 'Сводка за период', options.title);

    const dateRange = options.dateRange;
    if (!dateRange?.from || !dateRange?.to) {
      doc.fontSize(14).fillColor(this.COLORS.text)
        .text('Необходимо указать период для формирования сводки', 50, 150);
      return;
    }

    const rangeDays = Math.ceil(
      (new Date(dateRange.to).getTime() - new Date(dateRange.from).getTime()) / (1000 * 60 * 60 * 24)
    );

    const history = await storage.getHistory(userId, rangeDays);
    const correctness = await storage.getCorrectnessBreakdown(userId, rangeDays);

    doc.fontSize(16).fillColor(this.COLORS.primary)
      .text(`Период: ${dateRange.from} - ${dateRange.to}`, 50, 150);
    doc.moveDown();

    // Summary stats
    const totalTests = history.reduce((sum, h) => sum + h.testsCompleted, 0);
    const avgScore = history.length > 0 ? 
      history.reduce((sum, h) => sum + h.averageScore, 0) / history.length : 0;
    const totalTime = history.reduce((sum, h) => sum + h.totalTimeSpent, 0);

    const summaryData = [
      ['Всего тестов за период:', totalTests.toString()],
      ['Средний балл:', `${avgScore.toFixed(1)}%`],
      ['Общее время:', this.formatTime(totalTime)],
      ['Активных дней:', history.filter(h => h.testsCompleted > 0).length.toString()]
    ];

    this.addTable(doc, summaryData, { startY: doc.y, leftMargin: 50 });

    this.addFooter(doc);
  }

  private static addHeader(doc: PDFKit.PDFDocument, title: string, subtitle?: string): void {
    // Logo/Brand area
    doc.fontSize(24).fillColor(this.COLORS.primary).text('Test System', 50, 50);
    doc.fontSize(18).fillColor(this.COLORS.text).text(title, 50, 80);
    
    if (subtitle) {
      doc.fontSize(12).fillColor(this.COLORS.lightText).text(subtitle, 50, 105);
    }

    // Date
    doc.fontSize(10).fillColor(this.COLORS.lightText)
      .text(`Сгенерировано: ${new Date().toLocaleString('ru-RU')}`, 400, 50);

    // Line
    doc.strokeColor(this.COLORS.border).lineWidth(1)
      .moveTo(50, 130).lineTo(550, 130).stroke();
  }

  private static addFooter(doc: PDFKit.PDFDocument): void {
    const pageHeight = doc.page.height;
    doc.fontSize(8).fillColor(this.COLORS.lightText)
      .text('Test System - Система тестирования', 50, pageHeight - 50)
      .text(`Стр. ${doc.bufferedPageRange().count}`, 500, pageHeight - 50);
  }

  private static addTable(
    doc: PDFKit.PDFDocument, 
    data: string[][], 
    options: { startY: number; leftMargin: number; hasHeader?: boolean }
  ): void {
    const { startY, leftMargin, hasHeader = false } = options;
    const cellWidth = 120;
    const cellHeight = 20;
    const cols = Math.max(...data.map(row => row.length));

    let currentY = startY;

    data.forEach((row, rowIndex) => {
      const isHeader = hasHeader && rowIndex === 0;
      
      if (isHeader) {
        doc.fontSize(10).fillColor(this.COLORS.primary).font(this.FONTS.bold);
      } else {
        doc.fontSize(9).fillColor(this.COLORS.text).font(this.FONTS.regular);
      }

      // Background for header
      if (isHeader) {
        doc.save()
          .fillColor(this.COLORS.background)
          .rect(leftMargin, currentY - 5, cols * cellWidth, cellHeight)
          .fill()
          .restore();
      }

      row.forEach((cell, colIndex) => {
        const x = leftMargin + (colIndex * cellWidth);
        doc.text(cell, x + 5, currentY, { width: cellWidth - 10, ellipsis: true });
      });

      // Border
      doc.strokeColor(this.COLORS.border).lineWidth(0.5)
        .rect(leftMargin, currentY - 5, cols * cellWidth, cellHeight)
        .stroke();

      currentY += cellHeight;
    });

    doc.y = currentY + 10;
  }

  private static async generateProgressChart(history: HistoryPoint[]): Promise<Buffer> {
    const canvas = createCanvas(800, 400);
    const ctx = canvas.getContext('2d');

    const chart = new Chart(ctx as any, {
      type: 'line',
      data: {
        labels: history.map(h => new Date(h.date).toLocaleDateString('ru-RU')),
        datasets: [{
          label: 'Средний балл',
          data: history.map(h => h.averageScore),
          borderColor: this.COLORS.primary,
          backgroundColor: this.COLORS.primary + '20',
          tension: 0.1
        }]
      },
      options: {
        responsive: false,
        animation: false,
        scales: {
          y: {
            beginAtZero: true,
            max: 100,
            ticks: { callback: (value) => value + '%' }
          }
        },
        plugins: {
          legend: { display: false },
          title: {
            display: true,
            text: 'Прогресс по времени'
          }
        }
      }
    });

    return canvas.toBuffer('image/png');
  }

  private static formatTime(minutes: number): string {
    const hours = Math.floor(minutes / 60);
    const mins = Math.round(minutes % 60);
    return hours > 0 ? `${hours}ч ${mins}м` : `${mins}м`;
  }

  private static getReportTitle(type: ExportType): string {
    switch (type) {
      case 'USER_ANALYTICS': return 'Аналитика пользователя';
      case 'TEST_REPORT': return 'Отчет по тестам';
      case 'RANKINGS': return 'Рейтинг пользователей';
      case 'PERIOD_SUMMARY': return 'Сводка за период';
      default: return 'Отчет';
    }
  }
}