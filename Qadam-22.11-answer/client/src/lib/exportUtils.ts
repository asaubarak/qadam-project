import jsPDF from 'jspdf';
import html2canvas from 'html2canvas';
import { utils, writeFile } from 'xlsx';
import { 
  ExportType, 
  ExportFormat,
  ExportOptions,
  AnalyticsOverview,
  SubjectAggregate,
  TestResult,
  UserRanking
} from '@shared/schema';

// Fallback export utilities for client-side export when server is unavailable
export class ClientExportUtils {
  /**
   * Export data as PDF using client-side libraries
   */
  static async exportToPDF(
    type: ExportType,
    data: any,
    options: ExportOptions = { includeCharts: false }
  ): Promise<void> {
    const pdf = new jsPDF();
    const pageWidth = pdf.internal.pageSize.getWidth();
    const pageHeight = pdf.internal.pageSize.getHeight();
    const margin = 20;
    let currentY = margin;

    // Header
    pdf.setFontSize(20);
    pdf.setFont('helvetica', 'bold');
    const title = this.getExportTitle(type);
    pdf.text(title, margin, currentY);
    currentY += 15;

    pdf.setFontSize(10);
    pdf.setFont('helvetica', 'normal');
    pdf.text(`Сгенерировано: ${new Date().toLocaleString('ru-RU')}`, margin, currentY);
    currentY += 20;

    try {
      switch (type) {
        case 'USER_ANALYTICS':
          await this.addUserAnalyticsToPDF(pdf, data as AnalyticsOverview & { subjects: SubjectAggregate[] }, margin, currentY, pageWidth);
          break;
        case 'TEST_REPORT':
          this.addTestReportToPDF(pdf, data as TestResult[], margin, currentY, pageWidth);
          break;
        case 'RANKINGS':
          this.addRankingsToPDF(pdf, data as UserRanking[], margin, currentY, pageWidth);
          break;
        case 'PERIOD_SUMMARY':
          this.addPeriodSummaryToPDF(pdf, data, margin, currentY, pageWidth, options);
          break;
      }

      // Footer
      const pageCount = pdf.getNumberOfPages();
      for (let i = 1; i <= pageCount; i++) {
        pdf.setPage(i);
        pdf.setFontSize(8);
        pdf.text(`Стр. ${i} из ${pageCount}`, pageWidth - 30, pageHeight - 10);
        pdf.text('Test System', margin, pageHeight - 10);
      }

      // Download
      const fileName = this.generateFileName(type, 'pdf');
      pdf.save(fileName);

    } catch (error) {
      console.error('Error generating PDF:', error);
      throw new Error('Ошибка создания PDF файла');
    }
  }

  /**
   * Export data as Excel using client-side libraries
   */
  static async exportToExcel(
    type: ExportType,
    data: any,
    options: ExportOptions = { includeCharts: false }
  ): Promise<void> {
    try {
      const workbook = utils.book_new();

      switch (type) {
        case 'USER_ANALYTICS':
          this.addUserAnalyticsToExcel(workbook, data as AnalyticsOverview & { subjects: SubjectAggregate[] });
          break;
        case 'TEST_REPORT':
          this.addTestReportToExcel(workbook, data as TestResult[]);
          break;
        case 'RANKINGS':
          this.addRankingsToExcel(workbook, data as UserRanking[]);
          break;
        case 'PERIOD_SUMMARY':
          this.addPeriodSummaryToExcel(workbook, data, options);
          break;
      }

      const fileName = this.generateFileName(type, 'xlsx');
      writeFile(workbook, fileName);

    } catch (error) {
      console.error('Error generating Excel:', error);
      throw new Error('Ошибка создания Excel файла');
    }
  }

  /**
   * Export current page/section as PDF using html2canvas
   */
  static async exportPageToPDF(
    elementId: string,
    fileName?: string,
    options: { 
      format?: 'a4' | 'letter',
      orientation?: 'portrait' | 'landscape',
      quality?: number 
    } = {}
  ): Promise<void> {
    const element = document.getElementById(elementId);
    if (!element) {
      throw new Error('Элемент для экспорта не найден');
    }

    try {
      const canvas = await html2canvas(element, {
        scale: options.quality || 2,
        useCORS: true,
        allowTaint: true,
        backgroundColor: '#ffffff',
      });

      const imgData = canvas.toDataURL('image/png');
      const pdf = new jsPDF(options.orientation || 'portrait', 'mm', options.format || 'a4');
      
      const pdfWidth = pdf.internal.pageSize.getWidth();
      const pdfHeight = pdf.internal.pageSize.getHeight();
      const imgWidth = canvas.width;
      const imgHeight = canvas.height;
      const ratio = Math.min(pdfWidth / imgWidth, pdfHeight / imgHeight);
      
      const imgX = (pdfWidth - imgWidth * ratio) / 2;
      const imgY = 30;

      pdf.addImage(imgData, 'PNG', imgX, imgY, imgWidth * ratio, imgHeight * ratio);
      
      const pdfFileName = fileName || 'export.pdf';
      pdf.save(pdfFileName);

    } catch (error) {
      console.error('Error exporting page to PDF:', error);
      throw new Error('Ошибка экспорта страницы в PDF');
    }
  }

  // Private helper methods
  private static async addUserAnalyticsToPDF(
    pdf: jsPDF,
    data: AnalyticsOverview & { subjects: SubjectAggregate[] },
    margin: number,
    startY: number,
    pageWidth: number
  ): Promise<void> {
    let currentY = startY;

    // Overview section
    pdf.setFontSize(14);
    pdf.setFont('helvetica', 'bold');
    pdf.text('Общая статистика', margin, currentY);
    currentY += 10;

    pdf.setFontSize(10);
    pdf.setFont('helvetica', 'normal');

    const overviewData = [
      ['Всего тестов:', data.totalTests.toString()],
      ['Средний балл:', `${data.averageScore.toFixed(1)}%`],
      ['Время изучения:', this.formatTime(data.totalTimeSpent)],
      ['Лучший предмет:', data.bestSubject],
      ['Слабый предмет:', data.worstSubject],
      ['Правильных ответов:', `${data.correctAnswers}/${data.totalQuestions}`]
    ];

    overviewData.forEach(([label, value]) => {
      pdf.text(`${label} ${value}`, margin, currentY);
      currentY += 6;
    });

    currentY += 10;

    // Subjects section
    if (data.subjects && data.subjects.length > 0) {
      pdf.setFontSize(14);
      pdf.setFont('helvetica', 'bold');
      pdf.text('Результаты по предметам', margin, currentY);
      currentY += 10;

      pdf.setFontSize(10);
      pdf.setFont('helvetica', 'normal');

      data.subjects.forEach(subject => {
        if (currentY > 250) { // New page if near bottom
          pdf.addPage();
          currentY = margin;
        }

        pdf.text(`${subject.subjectName}:`, margin, currentY);
        pdf.text(`${subject.testsCount} тестов`, margin + 60, currentY);
        pdf.text(`${subject.averageScore.toFixed(1)}%`, margin + 100, currentY);
        currentY += 6;
      });
    }
  }

  private static addTestReportToPDF(
    pdf: jsPDF,
    results: TestResult[],
    margin: number,
    startY: number,
    pageWidth: number
  ): void {
    let currentY = startY;

    pdf.setFontSize(14);
    pdf.setFont('helvetica', 'bold');
    pdf.text('Результаты тестов', margin, currentY);
    currentY += 15;

    pdf.setFontSize(10);
    pdf.setFont('helvetica', 'normal');

    // Header row
    pdf.text('Дата', margin, currentY);
    pdf.text('Баллы', margin + 40, currentY);
    pdf.text('Процент', margin + 80, currentY);
    pdf.text('Время', margin + 120, currentY);
    currentY += 8;

    results.forEach(result => {
      if (currentY > 250) {
        pdf.addPage();
        currentY = margin;
      }

      const date = result.completedAt ? new Date(result.completedAt).toLocaleDateString('ru-RU') : 'Не указано';
      const score = `${result.score}/${result.totalQuestions}`;
      const percentage = `${result.percentage.toFixed(1)}%`;
      const time = this.formatTime(result.timeSpent / 60);

      pdf.text(date, margin, currentY);
      pdf.text(score, margin + 40, currentY);
      pdf.text(percentage, margin + 80, currentY);
      pdf.text(time, margin + 120, currentY);
      currentY += 6;
    });
  }

  private static addRankingsToPDF(
    pdf: jsPDF,
    rankings: UserRanking[],
    margin: number,
    startY: number,
    pageWidth: number
  ): void {
    let currentY = startY;

    pdf.setFontSize(14);
    pdf.setFont('helvetica', 'bold');
    pdf.text('Рейтинг пользователей', margin, currentY);
    currentY += 15;

    pdf.setFontSize(10);
    pdf.setFont('helvetica', 'normal');

    // Header row
    pdf.text('Место', margin, currentY);
    pdf.text('Пользователь', margin + 25, currentY);
    pdf.text('Баллы', margin + 80, currentY);
    pdf.text('Тестов', margin + 120, currentY);
    pdf.text('Средний %', margin + 160, currentY);
    currentY += 8;

    rankings.slice(0, 20).forEach((ranking, index) => {
      if (currentY > 250) {
        pdf.addPage();
        currentY = margin;
      }

      const rank = `#${index + 1}`;
      const user = `User-${ranking.userId.slice(-4)}`;
      const score = (ranking.totalScore ?? 0).toString();
      const tests = (ranking.testsCompleted ?? 0).toString();
      const avgPercentage = `${(ranking.averagePercentage ?? 0).toFixed(1)}%`;

      pdf.text(rank, margin, currentY);
      pdf.text(user, margin + 25, currentY);
      pdf.text(score, margin + 80, currentY);
      pdf.text(tests, margin + 120, currentY);
      pdf.text(avgPercentage, margin + 160, currentY);
      currentY += 6;
    });
  }

  private static addPeriodSummaryToPDF(
    pdf: jsPDF,
    data: any,
    margin: number,
    startY: number,
    pageWidth: number,
    options: ExportOptions
  ): void {
    let currentY = startY;

    pdf.setFontSize(14);
    pdf.setFont('helvetica', 'bold');
    pdf.text('Сводка за период', margin, currentY);
    currentY += 10;

    if (options.dateRange?.from && options.dateRange?.to) {
      pdf.setFontSize(10);
      pdf.setFont('helvetica', 'normal');
      pdf.text(`Период: ${options.dateRange.from} - ${options.dateRange.to}`, margin, currentY);
      currentY += 15;
    }

    // Summary stats (simplified)
    const summaryData = [
      ['Данные за указанный период', ''],
      ['Экспорт создан:', new Date().toLocaleDateString('ru-RU')]
    ];

    summaryData.forEach(([label, value]) => {
      pdf.text(`${label} ${value}`, margin, currentY);
      currentY += 6;
    });
  }

  // Excel helper methods
  private static addUserAnalyticsToExcel(
    workbook: any,
    data: AnalyticsOverview & { subjects: SubjectAggregate[] }
  ): void {
    // Overview sheet
    const overviewData = [
      ['Показатель', 'Значение'],
      ['Всего тестов', data.totalTests],
      ['Средний балл (%)', data.averageScore.toFixed(1)],
      ['Время изучения (мин)', data.totalTimeSpent],
      ['Лучший предмет', data.bestSubject],
      ['Слабый предмет', data.worstSubject],
      ['Правильных ответов', data.correctAnswers],
      ['Всего вопросов', data.totalQuestions]
    ];

    const overviewSheet = utils.aoa_to_sheet(overviewData);
    utils.book_append_sheet(workbook, overviewSheet, 'Общая статистика');

    // Subjects sheet
    if (data.subjects && data.subjects.length > 0) {
      const subjectsData = [
        ['Предмет', 'Тестов', 'Средний балл (%)', 'Всего вопросов', 'Правильных ответов', 'Среднее время (мин)'],
        ...data.subjects.map(subject => [
          subject.subjectName,
          subject.testsCount,
          subject.averageScore.toFixed(1),
          subject.totalQuestions,
          subject.correctAnswers,
          subject.averageTimeSpent
        ])
      ];

      const subjectsSheet = utils.aoa_to_sheet(subjectsData);
      utils.book_append_sheet(workbook, subjectsSheet, 'По предметам');
    }
  }

  private static addTestReportToExcel(workbook: any, results: TestResult[]): void {
    const data = [
      ['Дата', 'Правильных ответов', 'Всего вопросов', 'Процент (%)', 'Время (сек)', 'Время (мин)'],
      ...results.map(result => [
        result.completedAt ? new Date(result.completedAt).toLocaleDateString('ru-RU') : 'Не указано',
        result.score,
        result.totalQuestions,
        result.percentage.toFixed(1),
        result.timeSpent,
        Math.round(result.timeSpent / 60)
      ])
    ];

    const sheet = utils.aoa_to_sheet(data);
    utils.book_append_sheet(workbook, sheet, 'Результаты тестов');
  }

  private static addRankingsToExcel(workbook: any, rankings: UserRanking[]): void {
    const data = [
      ['Место', 'Пользователь', 'Общий балл', 'Тестов завершено', 'Средний процент (%)'],
      ...rankings.slice(0, 50).map((ranking, index) => [
        index + 1,
        `User-${ranking.userId.slice(-4)}`,
        ranking.totalScore ?? 0,
        ranking.testsCompleted ?? 0,
        (ranking.averagePercentage ?? 0).toFixed(1)
      ])
    ];

    const sheet = utils.aoa_to_sheet(data);
    utils.book_append_sheet(workbook, sheet, 'Рейтинг');
  }

  private static addPeriodSummaryToExcel(workbook: any, data: any, options: ExportOptions): void {
    const summaryData = [
      ['Показатель', 'Значение'],
      ['Период от', options.dateRange?.from || 'Не указано'],
      ['Период до', options.dateRange?.to || 'Не указано'],
      ['Дата создания', new Date().toLocaleDateString('ru-RU')]
    ];

    const sheet = utils.aoa_to_sheet(summaryData);
    utils.book_append_sheet(workbook, sheet, 'Сводка за период');
  }

  // Utility methods
  private static formatTime(minutes: number): string {
    const hours = Math.floor(minutes / 60);
    const mins = Math.round(minutes % 60);
    return hours > 0 ? `${hours}ч ${mins}м` : `${mins}м`;
  }

  private static getExportTitle(type: ExportType): string {
    switch (type) {
      case 'USER_ANALYTICS': return 'Аналитика пользователя';
      case 'TEST_REPORT': return 'Отчет по тестам';
      case 'RANKINGS': return 'Рейтинг пользователей';
      case 'PERIOD_SUMMARY': return 'Сводка за период';
      default: return 'Экспорт данных';
    }
  }

  private static generateFileName(type: ExportType, extension: string): string {
    const typeMap = {
      'USER_ANALYTICS': 'analytics',
      'TEST_REPORT': 'test_report',
      'RANKINGS': 'rankings',
      'PERIOD_SUMMARY': 'period_summary'
    };

    const date = new Date().toISOString().split('T')[0];
    return `${typeMap[type]}_${date}.${extension}`;
  }
}

// Export utility functions for direct use
export const exportToPDF = ClientExportUtils.exportToPDF.bind(ClientExportUtils);
export const exportToExcel = ClientExportUtils.exportToExcel.bind(ClientExportUtils);
export const exportPageToPDF = ClientExportUtils.exportPageToPDF.bind(ClientExportUtils);
