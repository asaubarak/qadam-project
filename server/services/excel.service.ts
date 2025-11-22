import ExcelJS from 'exceljs';
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

export class ExcelService {
  // NOTE: exceljs types are somewhat strict across versions; keep styles as `any` to avoid type mismatches
  // while preserving runtime behavior. TODO: migrate to exact ExcelJS types later.
  private static readonly STYLES: any = {
    header: {
      font: { bold: true, size: 14, color: { argb: 'FFFFFF' } },
      fill: { type: 'pattern', pattern: 'solid', fgColor: { argb: '2563eb' } },
      alignment: { horizontal: 'center' }
    },
    subHeader: {
      font: { bold: true, size: 12, color: { argb: '374151' } },
      fill: { type: 'pattern', pattern: 'solid', fgColor: { argb: 'f3f4f6' } },
      alignment: { horizontal: 'left' }
    },
    data: {
      font: { size: 10 },
      alignment: { horizontal: 'left' }
    },
    number: {
      font: { size: 10 },
      alignment: { horizontal: 'right' },
      numFmt: '#,##0'
    },
    percentage: {
      font: { size: 10 },
      alignment: { horizontal: 'right' },
      numFmt: '0.0%'
    },
    date: {
      font: { size: 10 },
      alignment: { horizontal: 'center' },
      numFmt: 'dd.mm.yyyy'
    }
  };

  static async generateReport(
    userId: string, 
    type: ExportType, 
    format: 'EXCEL',
    options: ExportOptions
  ): Promise<Buffer> {
    const workbook = new ExcelJS.Workbook();
    
    // Set workbook properties
    workbook.creator = 'Test System';
    workbook.lastModifiedBy = 'Test System';
    workbook.created = new Date();
    workbook.modified = new Date();
    workbook.lastPrinted = new Date();

    try {
      switch (type) {
        case 'USER_ANALYTICS':
          await this.generateUserAnalyticsExcel(workbook, userId, options);
          break;
        case 'TEST_REPORT': 
          await this.generateTestReportExcel(workbook, userId, options);
          break;
        case 'RANKINGS':
          await this.generateRankingsExcel(workbook, userId, options);
          break;
        case 'PERIOD_SUMMARY':
          await this.generatePeriodSummaryExcel(workbook, userId, options);
          break;
        default:
          throw new Error(`Неподдерживаемый тип экспорта: ${type}`);
      }

  return (await workbook.xlsx.writeBuffer()) as unknown as Buffer;

    } catch (error) {
      throw error;
    }
  }

  private static async generateUserAnalyticsExcel(
    workbook: ExcelJS.Workbook,
    userId: string, 
    options: ExportOptions
  ): Promise<void> {
    // Get data
    const overview = await storage.getAnalyticsOverview(userId);
    const subjects = await storage.getSubjectAggregates(userId);
    const history = await storage.getHistory(userId, options.dateRange?.from ? 30 : undefined);

    // Overview sheet
    const overviewSheet = workbook.addWorksheet('Общая статистика');
    this.setupOverviewSheet(overviewSheet, overview);

    // Subjects sheet
    if (subjects.length > 0) {
      const subjectsSheet = workbook.addWorksheet('По предметам');
      this.setupSubjectsSheet(subjectsSheet, subjects);
    }

    // History sheet
    if (history.length > 0) {
      const historySheet = workbook.addWorksheet('История');
      this.setupHistorySheet(historySheet, history);
    }

    // Charts sheet (if enabled)
    if (options.includeCharts && history.length > 0) {
      const chartsSheet = workbook.addWorksheet('Графики');
      this.setupChartsSheet(chartsSheet, history);
    }
  }

  private static async generateTestReportExcel(
    workbook: ExcelJS.Workbook,
    userId: string, 
    options: ExportOptions
  ): Promise<void> {
    const testResults = await storage.getTestResultsByUser(userId);
    
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

    const sheet = workbook.addWorksheet('Результаты тестов');
    this.setupTestResultsSheet(sheet, filteredResults);
  }

  private static async generateRankingsExcel(
    workbook: ExcelJS.Workbook,
    userId: string,
    options: ExportOptions
  ): Promise<void> {
    const rankings = await storage.getAllRankings();
    const userRanking = await storage.getUserRanking(userId);

    const sheet = workbook.addWorksheet('Рейтинг');
    this.setupRankingsSheet(sheet, rankings, userId, userRanking);
  }

  private static async generatePeriodSummaryExcel(
    workbook: ExcelJS.Workbook,
    userId: string,
    options: ExportOptions
  ): Promise<void> {
    const dateRange = options.dateRange;
    if (!dateRange?.from || !dateRange?.to) {
      const sheet = workbook.addWorksheet('Ошибка');
      sheet.getCell('A1').value = 'Необходимо указать период для формирования сводки';
      return;
    }

    const rangeDays = Math.ceil(
      (new Date(dateRange.to).getTime() - new Date(dateRange.from).getTime()) / (1000 * 60 * 60 * 24)
    );

    const history = await storage.getHistory(userId, rangeDays);
    const correctness = await storage.getCorrectnessBreakdown(userId, rangeDays);

    // Summary sheet
    const summarySheet = workbook.addWorksheet('Сводка');
      this.setupSummarySheet(summarySheet, history, dateRange as any);

    // Correctness sheet
    if (correctness.length > 0) {
      const correctnessSheet = workbook.addWorksheet('Правильность ответов');
      this.setupCorrectnessSheet(correctnessSheet, correctness);
    }
  }

  private static setupOverviewSheet(sheet: ExcelJS.Worksheet, overview: AnalyticsOverview): void {
    // Title
    sheet.getCell('A1').value = 'Общая статистика';
  sheet.getCell('A1').style = { ...this.STYLES.header, font: { ...this.STYLES.header.font, size: 16 } } as any;
    sheet.mergeCells('A1:B1');

    // Data
    const data = [
      ['Показатель', 'Значение'],
      ['Всего тестов', overview.totalTests],
      ['Средний балл', `${overview.averageScore.toFixed(1)}%`],
      ['Время изучения', this.formatTime(overview.totalTimeSpent)],
      ['Лучший предмет', overview.bestSubject],
      ['Слабый предмет', overview.worstSubject],
      ['Всего вопросов', overview.totalQuestions],
      ['Правильных ответов', overview.correctAnswers],
      ['Процент правильных', `${((overview.correctAnswers / overview.totalQuestions) * 100).toFixed(1)}%`],
      ['Недавняя активность', overview.recentActivity]
    ];

    data.forEach((row, index) => {
      const rowNum = index + 3;
      sheet.getCell(`A${rowNum}`).value = row[0];
      sheet.getCell(`B${rowNum}`).value = row[1];
      
      if (index === 0) {
        ((sheet.getRow(rowNum) as any) as any).style = this.STYLES.subHeader as any;
      } else {
        (sheet.getCell(`A${rowNum}`) as any).style = this.STYLES.data as any;
        (sheet.getCell(`B${rowNum}`) as any).style = this.STYLES.data as any;
      }
    });

    // Auto-fit columns
    sheet.columns = [
      { width: 25 },
      { width: 20 }
    ];
  }

  private static setupSubjectsSheet(sheet: ExcelJS.Worksheet, subjects: SubjectAggregate[]): void {
    // Headers
    const headers = ['Предмет', 'Тестов', 'Средний балл (%)', 'Всего вопросов', 'Правильных ответов', 'Среднее время (мин)'];
    
    headers.forEach((header, index) => {
      const cell = sheet.getCell(1, index + 1);
      cell.value = header;
  (cell as any).style = this.STYLES.header as any;
    });

    // Data
    subjects.forEach((subject, index) => {
      const row = sheet.getRow(index + 2);
      row.values = [
        subject.subjectName,
        subject.testsCount,
        subject.averageScore / 100, // Convert to decimal for percentage formatting
        subject.totalQuestions,
        subject.correctAnswers,
        subject.averageTimeSpent
      ];

  // Apply styles
  (row.getCell(1) as any).style = this.STYLES.data as any;
  (row.getCell(2) as any).style = this.STYLES.number as any;
  (row.getCell(3) as any).style = this.STYLES.percentage as any;
  (row.getCell(4) as any).style = this.STYLES.number as any;
  (row.getCell(5) as any).style = this.STYLES.number as any;
  (row.getCell(6) as any).style = this.STYLES.number as any;
    });

    // Auto-fit columns
    sheet.columns = [
      { width: 20 }, // Subject
      { width: 10 }, // Tests
      { width: 15 }, // Average score
      { width: 15 }, // Total questions
      { width: 18 }, // Correct answers
      { width: 18 }  // Average time
    ];
  }

  private static setupHistorySheet(sheet: ExcelJS.Worksheet, history: HistoryPoint[]): void {
    // Headers
    const headers = ['Дата', 'Тестов завершено', 'Средний балл (%)', 'Время (мин)'];
    
    headers.forEach((header, index) => {
      const cell = sheet.getCell(1, index + 1);
      cell.value = header;
      cell.style = this.STYLES.header;
    });

    // Data
    history.forEach((point, index) => {
      const row = sheet.getRow(index + 2);
      row.values = [
        new Date(point.date),
        point.testsCompleted,
        point.averageScore / 100,
        point.totalTimeSpent
      ];

      // Apply styles
      row.getCell(1).style = this.STYLES.date;
      row.getCell(2).style = this.STYLES.number;
      row.getCell(3).style = this.STYLES.percentage;
      row.getCell(4).style = this.STYLES.number;
    });

    // Auto-fit columns
    sheet.columns = [
      { width: 12 }, // Date
      { width: 15 }, // Tests completed
      { width: 15 }, // Average score
      { width: 15 }  // Time
    ];
  }

  private static setupTestResultsSheet(sheet: ExcelJS.Worksheet, results: TestResult[]): void {
    // Headers
    const headers = ['Дата', 'Правильных ответов', 'Всего вопросов', 'Процент (%)', 'Время (сек)', 'Время (мин)'];
    
    headers.forEach((header, index) => {
      const cell = sheet.getCell(1, index + 1);
      cell.value = header;
      cell.style = this.STYLES.header;
    });

    // Data
    results.forEach((result, index) => {
      const row = sheet.getRow(index + 2);
      row.values = [
        new Date(result.completedAt || Date.now()),
        result.score,
        result.totalQuestions,
        result.percentage / 100,
        result.timeSpent,
        Math.round(result.timeSpent / 60)
      ];

      // Apply styles
      row.getCell(1).style = this.STYLES.date;
      row.getCell(2).style = this.STYLES.number;
      row.getCell(3).style = this.STYLES.number;
      row.getCell(4).style = this.STYLES.percentage;
      row.getCell(5).style = this.STYLES.number;
      row.getCell(6).style = this.STYLES.number;
    });

    // Auto-fit columns
    sheet.columns = [
      { width: 12 }, // Date
      { width: 15 }, // Score
      { width: 15 }, // Total questions
      { width: 12 }, // Percentage
      { width: 12 }, // Time (sec)
      { width: 12 }  // Time (min)
    ];
  }

  private static setupRankingsSheet(
    sheet: ExcelJS.Worksheet, 
    rankings: UserRanking[], 
    currentUserId: string,
    userRanking?: UserRanking
  ): void {
    // Headers
    const headers = ['Место', 'Пользователь', 'Общий балл', 'Тестов завершено', 'Средний процент (%)'];
    
    headers.forEach((header, index) => {
      const cell = sheet.getCell(1, index + 1);
      cell.value = header;
      cell.style = this.STYLES.header;
    });

    // Data
    rankings.forEach((ranking, index) => {
      const row = sheet.getRow(index + 2);
      const isCurrentUser = ranking.userId === currentUserId;
      
      row.values = [
        index + 1,
        isCurrentUser ? 'Вы' : `User-${ranking.userId.slice(-4)}`,
        ranking.totalScore,
        ranking.testsCompleted,
  (ranking.averagePercentage ?? 0) / 100
      ];

      // Apply styles - highlight current user
      const style = isCurrentUser ? 
        { ...this.STYLES.data, fill: { type: 'pattern', pattern: 'solid', fgColor: { argb: 'e6f3ff' } } } :
        this.STYLES.data;

  (row.getCell(1) as any).style = { ...style, alignment: { horizontal: 'center' } } as any;
  (row.getCell(2) as any).style = style as any;
  (row.getCell(3) as any).style = { ...this.STYLES.number, fill: style.fill } as any;
  (row.getCell(4) as any).style = { ...this.STYLES.number, fill: style.fill } as any;
  (row.getCell(5) as any).style = { ...this.STYLES.percentage, fill: style.fill } as any;
    });

    // Auto-fit columns
    sheet.columns = [
      { width: 8 },  // Rank
      { width: 15 }, // User
      { width: 12 }, // Total score
      { width: 15 }, // Tests completed
      { width: 15 }  // Average percentage
    ];
  }

  private static setupSummarySheet(
    sheet: ExcelJS.Worksheet, 
    history: HistoryPoint[], 
    dateRange: { from: string; to: string }
  ): void {
    // Title
    sheet.getCell('A1').value = `Сводка за период: ${dateRange.from} - ${dateRange.to}`;
    sheet.getCell('A1').style = { ...this.STYLES.header, font: { ...this.STYLES.header.font, size: 16 } };
    sheet.mergeCells('A1:B1');

    // Calculate summary
    const totalTests = history.reduce((sum, h) => sum + h.testsCompleted, 0);
    const avgScore = history.length > 0 ? 
      history.reduce((sum, h) => sum + h.averageScore, 0) / history.length : 0;
    const totalTime = history.reduce((sum, h) => sum + h.totalTimeSpent, 0);
    const activeDays = history.filter(h => h.testsCompleted > 0).length;

    // Summary data
    const summaryData = [
      ['Показатель', 'Значение'],
      ['Всего тестов за период', totalTests],
      ['Средний балл', `${avgScore.toFixed(1)}%`],
      ['Общее время', this.formatTime(totalTime)],
      ['Активных дней', activeDays],
      ['Дней в периоде', history.length],
      ['Тестов в день (в среднем)', (totalTests / Math.max(activeDays, 1)).toFixed(1)]
    ];

    summaryData.forEach((row, index) => {
      const rowNum = index + 3;
      sheet.getCell(`A${rowNum}`).value = row[0];
      sheet.getCell(`B${rowNum}`).value = row[1];
      
      if (index === 0) {
        ((sheet.getRow(rowNum) as any) as any).style = this.STYLES.subHeader as any;
      } else {
        (sheet.getCell(`A${rowNum}`) as any).style = this.STYLES.data as any;
        (sheet.getCell(`B${rowNum}`) as any).style = this.STYLES.data as any;
      }
    });

    // Auto-fit columns
    sheet.columns = [
      { width: 25 },
      { width: 20 }
    ];
  }

  private static setupCorrectnessSheet(sheet: ExcelJS.Worksheet, correctness: any[]): void {
    // Headers
    const headers = ['Дата', 'Правильных ответов', 'Неправильных ответов', 'Всего вопросов', 'Процент правильных (%)'];
    
    headers.forEach((header, index) => {
      const cell = sheet.getCell(1, index + 1);
      cell.value = header;
      cell.style = this.STYLES.header;
    });

    // Data
    correctness.forEach((item, index) => {
      const row = sheet.getRow(index + 2);
      const correctPercentage = item.totalQuestions > 0 ? 
        (item.correctAnswers / item.totalQuestions) : 0;
      
      row.values = [
        new Date(item.date),
        item.correctAnswers,
        item.incorrectAnswers,
        item.totalQuestions,
        correctPercentage
      ];

      // Apply styles
      row.getCell(1).style = this.STYLES.date;
      row.getCell(2).style = this.STYLES.number;
      row.getCell(3).style = this.STYLES.number;
      row.getCell(4).style = this.STYLES.number;
      row.getCell(5).style = this.STYLES.percentage;
    });

    // Auto-fit columns
    sheet.columns = [
      { width: 12 }, // Date
      { width: 18 }, // Correct
      { width: 20 }, // Incorrect
      { width: 15 }, // Total
      { width: 20 }  // Percentage
    ];
  }

  private static setupChartsSheet(sheet: ExcelJS.Worksheet, history: HistoryPoint[]): void {
    // Note: Excel charts would require more complex implementation
    // For now, just add the data that could be used for charts
    
    sheet.getCell('A1').value = 'Данные для графиков';
    sheet.getCell('A1').style = this.STYLES.header;

    // Add chart data
    const headers = ['Дата', 'Средний балл', 'Тестов завершено'];
    headers.forEach((header, index) => {
      const cell = sheet.getCell(3, index + 1);
      cell.value = header;
      cell.style = this.STYLES.subHeader;
    });

    history.forEach((point, index) => {
      const row = sheet.getRow(index + 4);
      row.values = [
        new Date(point.date),
        point.averageScore,
        point.testsCompleted
      ];

      row.getCell(1).style = this.STYLES.date;
      row.getCell(2).style = this.STYLES.number;
      row.getCell(3).style = this.STYLES.number;
    });

    sheet.columns = [
      { width: 12 },
      { width: 15 },
      { width: 15 }
    ];
  }

  private static formatTime(minutes: number): string {
    const hours = Math.floor(minutes / 60);
    const mins = Math.round(minutes % 60);
    return hours > 0 ? `${hours}ч ${mins}м` : `${mins}м`;
  }
}